//! The aggregate portion of the PPM protocol, per §4.3 of RFCXXXX

use crate::{
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
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::HashMap, fmt::Debug};
use tracing::{error, info, warn};

static LEADER_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "leader"
);

/// Returns a fixed vector of randomness to be used in Boolean<Field64> values,
/// in anticipation of cjpatton working out how aggregators will negotiate
/// query randomness.
fn boolean_query_randomness() -> Vec<u8> {
    vec![1; 32]
}

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

/// An aggregate request sent to a leader from a helper.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AggregateRequest<F: FieldElement> {
    pub task_id: TaskId,
    pub helper_state: Vec<u8>,
    #[serde(rename = "seq")]
    pub sub_requests: Vec<AggregateSubRequest<F>>,
}

/// Sub-request in an aggregate request
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AggregateSubRequest<F: FieldElement> {
    #[serde(flatten)]
    pub timestamp: Timestamp,
    pub extensions: Vec<ReportExtension>,
    pub helper_share: EncryptedInputShare,
    #[serde(flatten)]
    pub protocol_parameters: ProtocolAggregateSubRequestFields<F>,
}

/// The protocol specific portions of AggregateSubRequest
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ProtocolAggregateSubRequestFields<F: FieldElement> {
    /// Prio-specific parameters
    Prio {
        /// Message containing the leader's proof/verifier share.
        leader_verifier_message: VerifierMessage<F>,
    },
    Hits {},
}

/// The response to an aggregation request
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AggregateResponse<F: FieldElement> {
    pub helper_state: Vec<u8>,
    pub sub_responses: Vec<AggregateSubResponse<F>>,
}

/// Sub-response in an aggregation response
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AggregateSubResponse<F: FieldElement> {
    #[serde(flatten)]
    pub timestamp: Timestamp,
    #[serde(flatten)]
    pub protocol_parameters: ProtocolAggregateSubResponseFields<F>,
}

/// The protocol specific portions of AggregateSubResponse
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ProtocolAggregateSubResponseFields<F: FieldElement> {
    /// Prio-specific parameters
    Prio {
        /// If the helper was able to verify the proof using the leader's
        /// verifier share, this will be the helper's verifier/proof share. If
        /// the proof verification failed, this will be None.
        helper_verifier_message: Option<VerifierMessage<F>>,
    },
    Hits {},
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

/// Accumulator for some aggregation interval
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Accumulator {
    /// The value accumulated thus far
    accumulated: Vec<Field64>,
    /// How many contributions are included
    contributions: usize,
}

fn dump_accumulators(accumulators: &HashMap<DateTime<Utc>, Accumulator>) {
    for (interval_start, accumulated) in accumulators {
        info!(
            interval_start = ?interval_start,
            accumulated = ?accumulated,
            "accumulated value for interval"
        );
    }
}

/// Implements endpoints the leader supports and tracks leader state.
// TODO(timg): this should be generic in <F: FieldElement, V: Value<F>>, but I
// don't yet know how to deal with the V::Param argument to `verify_start`
#[derive(Clone, Debug)]
pub struct LeaderAggregator {
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

impl LeaderAggregator {
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

#[derive(Debug, Serialize, Deserialize)]
struct HelperState {
    accumulators: HashMap<DateTime<Utc>, Accumulator>,
    last_timestamp_seen: Timestamp,
}

/// Implements endpoints for helper.
#[derive(Debug)]
pub struct HelperAggregator {
    parameters: Parameters,
    hpke_config: hpke::Config,
    helper_state: HelperState,
}

impl HelperAggregator {
    pub fn new(
        parameters: &Parameters,
        hpke_config: &hpke::Config,
        state_blob: &[u8],
    ) -> Result<Self, Error> {
        // TODO(timg): encrypt helper state to protect it from leader and put
        // some kind of anti-replay token in there
        let helper_state: HelperState = if state_blob.is_empty() {
            // Empty state
            HelperState {
                accumulators: HashMap::new(),
                last_timestamp_seen: Timestamp { time: 0, nonce: 0 },
            }
        } else {
            serde_json::from_slice(state_blob)?
        };
        Ok(Self {
            parameters: parameters.clone(),
            hpke_config: hpke_config.clone(),
            helper_state,
        })
    }

    pub fn handle_aggregate(
        &mut self,
        request: &AggregateRequest<Field64>,
    ) -> Result<AggregateResponse<Field64>, Error> {
        info!(
            sub_request_count = request.sub_requests.len(),
            "got aggregate request"
        );

        if request.task_id != self.parameters.task_id {
            return Err(Error::UnknownTaskId(request.task_id));
        }

        let mut sub_responses = vec![];

        for sub_request in &request.sub_requests {
            if sub_request
                .timestamp
                .cmp(&self.helper_state.last_timestamp_seen)
                != Ordering::Greater
            {
                warn!(
                    request_timestamp = ?sub_request.timestamp,
                    last_timestamp_seen = ?self.helper_state.last_timestamp_seen,
                    "ignoring report whose timestamp is too old"
                );
                continue;
            }

            if sub_request.helper_share.aggregator_config_id != self.hpke_config.id {
                // TODO(timg) construct problem document with type=outdatedConfig
                // per section 3.1
                return Err(Error::UnknownHpkeConfig(
                    sub_request.helper_share.aggregator_config_id,
                ));
            }

            // Decrypt and decode helper UploadMessage. We must create a new context
            // for each message or the nonces won't line up with the sender.
            let hpke_recipient = self.hpke_config.report_recipient(
                &request.task_id,
                Role::Helper,
                &sub_request.helper_share.encapsulated_context,
            )?;

            let decrypted_input_share = hpke_recipient.decrypt_input_share(
                &sub_request.helper_share,
                &sub_request.timestamp.associated_data(),
            )?;

            let upload_message: UploadMessage<Field64> =
                serde_json::from_slice(&decrypted_input_share)?;

            // Construct helper verifier message
            let (state, helper_verifier_message) = verify_start::<Field64, Boolean<Field64>>(
                upload_message,
                (),
                Role::Helper.index() as u8,
                &boolean_query_randomness(),
            )?;

            let leader_verifier_message = match &sub_request.protocol_parameters {
                ProtocolAggregateSubRequestFields::Prio {
                    leader_verifier_message: message,
                } => message,
                _ => {
                    return Err(Error::AggregateProtocol(format!(
                        "unsupported protocol in sub-response for report {}",
                        sub_request.timestamp
                    )))
                }
            };

            info!(
                timestamp = ?sub_request.timestamp,
                leader_verifier_message = ?leader_verifier_message,
                helper_verifier_message = ?state,
                "verifying proof"
            );

            // Kinda unfortunate here that `verify_finish` consumes verifier
            // shares:
            // 1 - I need a reference to the verifier message so I can send it
            //     back to leader
            // 2 - Having Vec<VerifierMessage> instead of &[VerifierMessage]
            //     forces allocation + copy to the heap
            let helper_verifier_message =
                match verify_finish(state, vec![leader_verifier_message.clone()]) {
                    Ok(input_share) => {
                        // Proof is OK. Accumulate this share and send helper
                        // verifier share to leader so they can verify the proof
                        // too.
                        let interval_start = sub_request
                            .timestamp
                            .interval_start(self.parameters.min_batch_duration);
                        if let Some(sum) = self.helper_state.accumulators.get_mut(&interval_start) {
                            merge_vector(&mut sum.accumulated, input_share.as_slice())?;
                            sum.contributions += 1;
                        } else {
                            // This is the first input we have seen for this batch interval.
                            // Initialize the accumulator.
                            self.helper_state.accumulators.insert(
                                interval_start,
                                Accumulator {
                                    accumulated: input_share.as_slice().to_vec(),
                                    contributions: 1,
                                },
                            );
                        }
                        Some(helper_verifier_message)
                    }
                    Err(e) => {
                        let boxed_error: Box<dyn std::error::Error + 'static> = e.into();
                        warn!(
                            time = ?sub_request.timestamp,
                            error = boxed_error.as_ref(),
                            "proof did not check out for aggregate sub-request"
                        );
                        None
                    }
                };

            sub_responses.push(AggregateSubResponse {
                timestamp: sub_request.timestamp,
                protocol_parameters: ProtocolAggregateSubResponseFields::Prio {
                    helper_verifier_message,
                },
            });

            self.helper_state.last_timestamp_seen = sub_request.timestamp;
        }

        dump_accumulators(&self.helper_state.accumulators);

        Ok(AggregateResponse {
            helper_state: serde_json::to_vec(&self.helper_state)?,
            sub_responses,
        })
    }
}
