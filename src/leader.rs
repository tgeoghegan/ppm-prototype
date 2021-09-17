//! Leader implementation

use crate::{
    aggregate::{
        boolean_query_randomness, dump_accumulators, Accumulator, AggregateRequest,
        AggregateResponse, AggregateSubRequest, ProtocolAggregateSubRequestFields,
        ProtocolAggregateSubResponseFields,
    },
    hpke::{self, Role},
    parameters::{Parameters, TaskId},
    upload::{EncryptedInputShare, Report, ReportExtension},
    Timestamp,
};
use chrono::{DateTime, Utc};
use http::StatusCode;
use prio::{
    field::{merge_vector, Field64, FieldElement, FieldError},
    pcp::{types::Boolean, Value},
    ppm::{verify_finish, verify_start, AggregatorState, PpmError, UploadMessage, VerifierMessage},
};
use reqwest::Client;
use std::{cmp::Ordering, collections::HashMap, fmt::Debug};
use tracing::{error, info, warn};

static LEADER_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "leader"
);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON parse error")]
    JsonParse(#[from] serde_json::error::Error),
    #[error("encryption error")]
    Encryption(#[from] crate::hpke::Error),
    #[error("unknown task ID")]
    UnknownTaskId(TaskId),
    #[error("unknown HPKE config ID {0}")]
    UnknownHpkeConfig(u8),
    #[error("PPM error")]
    Ppm(#[from] PpmError),
    #[error("HTTP client error")]
    HttpClient(#[from] reqwest::Error),
    #[error("Aggregate HTTP request error")]
    AggregateRequest(StatusCode),
    #[error("bad protocol parameters")]
    Parameters(#[from] crate::parameters::Error),
    #[error("aggregate protocol error")]
    AggregateProtocol(String),
    #[error("field error")]
    PrioField(#[from] FieldError),
}

/// In-memory representation of an input stored by the leader
#[derive(Clone, Debug)]
pub struct StoredInputShare<F: FieldElement, V: Value<F>> {
    pub timestamp: Timestamp,
    pub leader_state: AggregatorState<F, V>,
    pub leader_verifier_message: VerifierMessage<F>,
    pub encrypted_helper_share: EncryptedInputShare,
    pub extensions: Vec<ReportExtension>,
}

impl<F: FieldElement, V: Value<F>> PartialEq for StoredInputShare<F, V> {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp.eq(&other.timestamp)
    }
}

impl<F: FieldElement, V: Value<F>> Eq for StoredInputShare<F, V> {}

impl<F: FieldElement, V: Value<F>> Ord for StoredInputShare<F, V> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp.cmp(&other.timestamp)
    }
}

impl<F: FieldElement, V: Value<F>> PartialOrd for StoredInputShare<F, V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Implements endpoints the leader supports and tracks leader state.
// TODO(timg): this should be generic in <F: FieldElement, V: Value<F>>, but I
// don't yet know how to deal with the V::Param argument to `verify_start`
#[derive(Clone, Debug)]
pub struct Leader {
    parameters: Parameters,
    hpke_config: hpke::Config,
    /// Inputs for which the leader has not yet received a VerifierMessage from
    /// the helper (though the leader may have already _sent_ a
    /// VerifierMessage). The vec is kept sorted so that the helper shares and
    /// verifier messages can be sent to helper in increasing order per RFCXXXX
    /// 4.3.1.
    unaggregated_inputs: Vec<StoredInputShare<Field64, Boolean<Field64>>>,
    /// Accumulated sums over inputs that have been verified in conjunction with
    /// the helper. The key is the start of the batch window.
    accumulators: HashMap<DateTime<Utc>, Accumulator>,
    helper_state: Vec<u8>,
}

impl Leader {
    pub fn new(parameters: &Parameters, hpke_config: &hpke::Config) -> Self {
        Self {
            parameters: parameters.clone(),
            hpke_config: hpke_config.clone(),
            unaggregated_inputs: vec![],
            accumulators: HashMap::new(),
            helper_state: vec![],
        }
    }

    pub async fn handle_upload(&mut self, report: &Report) -> Result<(), Error> {
        if report.task_id != self.parameters.task_id {
            // TODO(timg) construct problem document with type=unrecognizedTask
            // per section 3.1
            return Err(Error::UnknownTaskId(report.task_id));
        }

        let leader_share = &report.encrypted_input_shares[Role::Leader.index()];

        if leader_share.aggregator_config_id != self.hpke_config.id {
            // TODO(timg) construct problem document with type=outdatedConfig
            // per section 3.1
            return Err(Error::UnknownHpkeConfig(leader_share.aggregator_config_id));
        }

        // Decrypt and decode leader UploadMessage. We must create a new context
        // for each message or the nonces won't line up with the sender.
        let hpke_recipient = self.hpke_config.report_recipient(
            &report.task_id,
            Role::Leader,
            &leader_share.encapsulated_context,
        )?;

        let decrypted_input_share = hpke_recipient
            .decrypt_input_share(leader_share, &report.timestamp.associated_data())?;

        let upload_message: UploadMessage<Field64> =
            serde_json::from_slice(&decrypted_input_share)?;

        let (state, verifier) = verify_start::<Field64, Boolean<Field64>>(
            upload_message,
            (),
            Role::Leader.index() as u8,
            &boolean_query_randomness(),
        )?;

        self.unaggregated_inputs.push(StoredInputShare {
            timestamp: report.timestamp,
            leader_state: state,
            leader_verifier_message: verifier,
            encrypted_helper_share: report.encrypted_input_shares[Role::Helper.index()].clone(),
            extensions: report.extensions.clone(),
        });
        // TODO use an std::collections::BinaryHeap here for efficient
        // inserts
        self.unaggregated_inputs.sort_unstable();

        info!(?report, "obtained report");

        // Once we have 100 unaggregated inputs, send an aggregate request to
        // helper
        // TODO configure the threshold
        // TODO don't block upload requests on a synchronous aggregate txn
        if self.unaggregated_inputs.len() >= 10 {
            info!(
                sub_request_count = self.unaggregated_inputs.len(),
                "sending aggregate request to helper"
            );
            if let Err(e) = self.send_aggregate_request().await {
                error!(
                    "error when executing aggregate protocol with helper: {:?}",
                    e
                );
            }
        }

        Ok(())
    }

    async fn send_aggregate_request(&mut self) -> Result<(), Error> {
        let aggregate_sub_requests: Vec<AggregateSubRequest<Field64>> = self
            .unaggregated_inputs
            .iter()
            .map(|stored_input| AggregateSubRequest {
                timestamp: stored_input.timestamp,
                extensions: stored_input.extensions.clone(),
                helper_share: stored_input.encrypted_helper_share.clone(),
                protocol_parameters: ProtocolAggregateSubRequestFields::Prio {
                    leader_verifier_message: stored_input.leader_verifier_message.clone(),
                },
            })
            .collect();

        let aggregate_request = AggregateRequest {
            task_id: self.parameters.task_id,
            helper_state: self.helper_state.clone(),
            sub_requests: aggregate_sub_requests,
        };

        let http_client = Client::builder().user_agent(LEADER_USER_AGENT).build()?;

        let http_response = http_client
            .post(self.parameters.aggregate_endpoint()?)
            .json(&aggregate_request)
            .send()
            .await?;

        if !http_response.status().is_success() {
            return Err(Error::AggregateRequest(http_response.status()));
        }

        // At this point we got an HTTP 200 OK from helper, meaning it
        // successfully processed all the reports leader sent it (potentially
        // rejecting some due to bad proofs). That means we don't want to
        // re-send any of the reports we sent in a subsequent call to this
        // method, so reinitialize the leader's unaggregated inputs to empty.
        let leader_inputs = std::mem::take(&mut self.unaggregated_inputs);

        let aggregate_response: AggregateResponse<Field64> = http_response.json().await?;

        if leader_inputs.len() != aggregate_response.sub_responses.len() {
            return Err(Error::AggregateProtocol(format!(
                "unexpected number of sub-responses in helper aggregate response. Got {} wanted {}",
                aggregate_response.sub_responses.len(),
                self.unaggregated_inputs.len()
            )));
        }

        for (leader_input, helper_response) in leader_inputs
            .into_iter()
            .zip(aggregate_response.sub_responses)
        {
            // Sub-responses from helper must appear in the same order as the
            // sub-requests sent by leader
            if leader_input.timestamp != helper_response.timestamp {
                return Err(Error::AggregateProtocol(format!(
                    "helper responses in wrong order. Wanted {}, got {}",
                    leader_input.timestamp, helper_response.timestamp,
                )));
            }

            let helper_verifier_message = match helper_response.protocol_parameters {
                ProtocolAggregateSubResponseFields::Prio {
                    helper_verifier_message: message,
                } => match message {
                    Some(message) => message,
                    None => {
                        info!(
                            time = ?leader_input.timestamp,
                            "helper rejected proof for report"
                        );
                        continue;
                    }
                },
                _ => {
                    return Err(Error::AggregateProtocol(format!(
                        "unsupported protocol in sub-response for report {}",
                        leader_input.timestamp
                    )))
                }
            };

            let interval_start = leader_input
                .timestamp
                .interval_start(self.parameters.min_batch_duration);

            info!(
                timestamp = ?leader_input.timestamp,
                helper_verifier_message = ?helper_verifier_message,
                leader_verifier_message = ?leader_input,
                "verifying proof"
            );

            let input_share =
                match verify_finish(leader_input.leader_state, vec![helper_verifier_message]) {
                    Ok(input_share) => input_share,
                    Err(e) => {
                        // This should never happen, because if the leader can't
                        // verify the proof, then helper almost certainly
                        // rejected the report, too, and so would have not
                        // provided a verifier message.
                        // We should perhaps specify that the helper should
                        // provide a verifier share even if the proof was
                        // invalid. The tradeoff here is between making the
                        // leader do redundant proof verification and the
                        // complexity of an optional field in a protocol
                        // message.
                        let boxed_error: Box<dyn std::error::Error + 'static> = e.into();
                        warn!(
                            time = ?leader_input.timestamp,
                            error = boxed_error.as_ref(),
                            "proof did not check out for report"
                        );
                        continue;
                    }
                };

            // Proof checked out -- sum the input share into the accumulator for
            // the batch interval corresponding to the report timestamp.
            if let Some(sum) = self.accumulators.get_mut(&interval_start) {
                merge_vector(&mut sum.accumulated, input_share.as_slice())?;
                sum.contributions += 1;
            } else {
                // This is the first input we have seen for this batch interval.
                // Initialize the accumulator.
                self.accumulators.insert(
                    interval_start,
                    Accumulator {
                        accumulated: input_share.as_slice().to_vec(),
                        contributions: 1,
                    },
                );
            }
        }

        self.helper_state = aggregate_response.helper_state;

        dump_accumulators(&self.accumulators);

        Ok(())
    }
}
