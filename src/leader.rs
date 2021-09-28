//! Leader implementation

use crate::{
    aggregate::{
        boolean_initial_aggregator_state, dump_accumulators, Accumulator, AggregateRequest,
        AggregateResponse, AggregateSubRequest, ProtocolAggregateSubRequestFields,
        ProtocolAggregateSubResponseFields,
    },
    collect::{
        CollectRequest, CollectResponse, EncryptedOutputShare, OutputShare, OutputShareRequest,
    },
    hpke::{self, Role},
    parameters::{Parameters, TaskId},
    upload::{EncryptedInputShare, Report, ReportExtension},
    IntervalStart, Timestamp,
};
use ::hpke::Serializable;
use chrono::{DateTime, TimeZone, Utc};
use http::StatusCode;
use prio::{
    field::{merge_vector, Field64, FieldElement, FieldError},
    pcp::{types::Boolean, Value},
    vdaf::{
        verify_finish, verify_start, AggregatorState, InputShareMessage, VdafError, VerifierMessage,
    },
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
    #[error("VDAF error")]
    Vdaf(#[from] VdafError),
    #[error("HTTP client error")]
    HttpClient(#[from] reqwest::Error),
    #[error("Aggregate HTTP request error {0}")]
    AggregateRequest(StatusCode),
    #[error("bad protocol parameters")]
    Parameters(#[from] crate::parameters::Error),
    #[error("aggregate protocol error {0}")]
    AggregateProtocol(String),
    #[error("field error")]
    PrioField(#[from] FieldError),
    #[error("Collect HTTP request error {0}")]
    CollectRequest(StatusCode),
    #[error("collect protocol error {0}")]
    CollectProtocol(String),
    #[error("Insufficient contributions in interval described by collect request: {0}")]
    InsufficientContributions(u64),
}

/// In-memory representation of an input stored by the leader
#[derive(Clone, Debug)]
pub struct StoredInputShare<F: FieldElement, V: Value<Field = F>> {
    pub timestamp: Timestamp,
    pub leader_state: AggregatorState<V>,
    pub leader_verifier_message: VerifierMessage<F>,
    pub encrypted_helper_share: EncryptedInputShare,
    pub extensions: Vec<ReportExtension>,
}

impl<F: FieldElement, V: Value<Field = F>> PartialEq for StoredInputShare<F, V> {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp.eq(&other.timestamp)
    }
}

impl<F: FieldElement, V: Value<Field = F>> Eq for StoredInputShare<F, V> {}

impl<F: FieldElement, V: Value<Field = F>> Ord for StoredInputShare<F, V> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp.cmp(&other.timestamp)
    }
}

impl<F: FieldElement, V: Value<Field = F>> PartialOrd for StoredInputShare<F, V> {
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
    http_client: Client,
}

impl Leader {
    pub fn new(parameters: &Parameters, hpke_config: &hpke::Config) -> Result<Self, Error> {
        Ok(Self {
            parameters: parameters.clone(),
            hpke_config: hpke_config.clone(),
            unaggregated_inputs: vec![],
            accumulators: HashMap::new(),
            helper_state: vec![],
            http_client: Client::builder().user_agent(LEADER_USER_AGENT).build()?,
        })
    }

    #[tracing::instrument(skip(self, report), err)]
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

        let leader_state = boolean_initial_aggregator_state(Role::Leader);

        let input_share_message: InputShareMessage<Field64> =
            serde_json::from_slice(&decrypted_input_share)?;

        let (state, verifier) =
            verify_start::<Boolean<Field64>>(leader_state, input_share_message)?;

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

    #[tracing::instrument(err, skip(self))]
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

        let http_response = self
            .http_client
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
                } => message,
                _ => {
                    return Err(Error::AggregateProtocol(format!(
                        "unsupported protocol in sub-response for report {}",
                        leader_input.timestamp
                    )))
                }
            };

            let interval_start = leader_input
                .timestamp
                .time
                .interval_start(self.parameters.min_batch_duration);

            info!(
                timestamp = ?leader_input.timestamp,
                helper_verifier_message = ?helper_verifier_message,
                leader_verifier_message = ?leader_input,
                "verifying proof"
            );

            let input_share = match verify_finish(
                leader_input.leader_state,
                [
                    helper_verifier_message,
                    leader_input.leader_verifier_message,
                ],
            ) {
                Ok(input_share) => input_share,
                Err(e) => {
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
                        privacy_budget: 0,
                    },
                );
            }
        }

        self.helper_state = aggregate_response.helper_state;

        dump_accumulators(&self.accumulators);

        Ok(())
    }

    #[tracing::instrument(skip(self, collect_request), err)]
    pub async fn handle_collect(
        &mut self,
        collect_request: &CollectRequest,
    ) -> Result<CollectResponse, Error> {
        if !self
            .parameters
            .validate_batch_interval(collect_request.batch_interval)
        {
            return Err(Error::CollectProtocol(
                "invalid batch interval in request".to_string(),
            ));
        }

        let num_intervals_in_request = (collect_request.batch_interval.end
            - collect_request.batch_interval.start)
            / self.parameters.min_batch_duration;

        if num_intervals_in_request == 0 {
            // TODO Is this an error or do we send an empty EncryptedOutputShare?
            return Err(Error::CollectProtocol(
                "batch interval is 0 length".to_string(),
            ));
        }

        let output_share_request = OutputShareRequest {
            task_id: collect_request.task_id,
            batch_interval: collect_request.batch_interval,
            helper_state: self.helper_state.clone(),
        };

        let http_response = self
            .http_client
            .post(self.parameters.output_share_endpoint()?)
            .json(&output_share_request)
            .send()
            .await?;

        if !http_response.status().is_success() {
            return Err(Error::CollectRequest(http_response.status()));
        }

        let helper_encrypted_output_share: EncryptedOutputShare = http_response.json().await?;

        let first_interval = collect_request
            .batch_interval
            .start
            .interval_start(self.parameters.min_batch_duration);

        let mut output_sum: Option<Vec<Field64>> = None;
        let mut total_contributions = 0;

        for i in 0..num_intervals_in_request {
            let interval_start = Utc.timestamp(
                first_interval.timestamp() + (i * self.parameters.min_batch_duration) as i64,
                0,
            );
            match self.accumulators.get_mut(&interval_start) {
                Some(accumulator) => {
                    match output_sum {
                        Some(ref mut inner_output_sum) => {
                            // merge in subsequent accumulators
                            merge_vector(inner_output_sum, &accumulator.accumulated)?;
                        }
                        // Initialize output sum with first non-empty accumulator
                        None => output_sum = Some(accumulator.accumulated.clone()),
                    }

                    accumulator.privacy_budget += 1;
                    total_contributions += accumulator.contributions;
                }
                None => {
                    // Most likely there are no contributions for this batch interval yet
                    warn!(
                        "no accumulator found for interval start {:?}",
                        interval_start
                    );
                    continue;
                }
            };
        }

        if total_contributions < self.parameters.min_batch_size {
            return Err(Error::InsufficientContributions(total_contributions));
        }

        let output_share = OutputShare {
            sum: Field64::slice_into_byte_vec(&output_sum.unwrap()),
            contributions: total_contributions,
        };

        let json_output_share = serde_json::to_vec(&output_share)?;

        let hpke_sender = self
            .parameters
            .collector_config
            .output_share_sender(&self.parameters.task_id, Role::Leader)?;

        let (payload, encapped) = hpke_sender
            .encrypt_output_share(output_share_request.batch_interval, &json_output_share)?;

        let leader_output_share = EncryptedOutputShare {
            collector_hpke_config_id: self.parameters.collector_config.id,
            encapsulated_context: encapped.to_bytes().to_vec(),
            payload,
        };

        Ok(CollectResponse {
            encrypted_output_shares: vec![leader_output_share, helper_encrypted_output_share],
        })
    }
}
