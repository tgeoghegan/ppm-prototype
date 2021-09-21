//! Helper implementation

use crate::{
    aggregate::{
        boolean_query_randomness, dump_accumulators, Accumulator, AggregateRequest,
        AggregateResponse, AggregateSubResponse, ProtocolAggregateSubRequestFields,
        ProtocolAggregateSubResponseFields,
    },
    hpke::{self, Role},
    parameters::{Parameters, TaskId},
    Timestamp,
};
use chrono::{DateTime, Utc};
use http::StatusCode;
use prio::{
    field::{merge_vector, Field64, FieldError},
    pcp::{types::Boolean, Value},
    vdaf::{suite::Suite, verify_finish, verify_start, UploadMessage, VdafError},
};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::HashMap, fmt::Debug};
use tracing::{error, info, warn};

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
    #[error("Aggregate HTTP request error")]
    AggregateRequest(StatusCode),
    #[error("bad protocol parameters")]
    Parameters(#[from] crate::parameters::Error),
    #[error("aggregate protocol error")]
    AggregateProtocol(String),
    #[error("field error")]
    PrioField(#[from] FieldError),
}

#[derive(Debug, Serialize, Deserialize)]
struct HelperState {
    accumulators: HashMap<DateTime<Utc>, Accumulator>,
    last_timestamp_seen: Timestamp,
}

/// Implements endpoints for helper.
#[derive(Debug)]
pub struct Helper {
    parameters: Parameters,
    hpke_config: hpke::Config,
    helper_state: HelperState,
}

impl Helper {
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
                Suite::Aes128CtrHmacSha256,
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
            // shares: taking Vec<VerifierMessage> instead of &[VerifierMessage]
            // forces allocation + copy to the heap, even if I own the value of
            // leader_verifier_message, and it's not clear that I do.
            match verify_finish(
                Suite::Aes128CtrHmacSha256,
                state,
                vec![
                    leader_verifier_message.clone(),
                    helper_verifier_message.clone(),
                ],
            ) {
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
                }
                Err(e) => {
                    let boxed_error: Box<dyn std::error::Error + 'static> = e.into();
                    warn!(
                        time = ?sub_request.timestamp,
                        error = boxed_error.as_ref(),
                        "proof did not check out for aggregate sub-request"
                    );
                }
            }

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
