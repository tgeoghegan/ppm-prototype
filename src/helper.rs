//! Helper implementation

use crate::{
    aggregate::{
        boolean_verify_parameter, dump_accumulators, Accumulator, VerifyResponse,
        VerifyStartRequest, VerifySubResponse,
    },
    collect::{EncryptedOutputShare, OutputShare, OutputShareRequest},
    handle_rejection,
    hpke::{self, Role},
    merge_vector,
    parameters::{Parameters, TaskId},
    with_shared_value, IntervalStart, Timestamp,
};
use ::hpke::Serializable;
use chrono::{DateTime, TimeZone, Utc};
use color_eyre::eyre::Result;
use http::StatusCode;
use prio::{
    field::{Field64, FieldElement, FieldError},
    pcp::{types::Boolean, Value},
    vdaf::{prio3_finish, prio3_start, InputShareMessage, VdafError, VerifyMessage},
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::{cmp::Ordering, collections::HashMap, fmt::Debug};
use tracing::{error, info, warn};
use warp::{reply, Filter};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON parse error {0}")]
    JsonParse(#[from] serde_json::error::Error),
    #[error("encryption error {0}")]
    Encryption(#[from] crate::hpke::Error),
    #[error("unknown task ID")]
    UnknownTaskId(TaskId),
    #[error("unknown HPKE config ID {0}")]
    UnknownHpkeConfig(u8),
    #[error("VDAF error {0}")]
    Vdaf(#[from] VdafError),
    #[error("HTTP client error {0}")]
    HttpClient(#[from] reqwest::Error),
    #[error("Aggregate HTTP request error")]
    AggregateRequest(StatusCode),
    #[error("bad protocol parameters {0}")]
    Parameters(#[from] crate::parameters::Error),
    #[error("aggregate protocol error {0}")]
    AggregateProtocol(String),
    #[error("field error")]
    PrioField(#[from] FieldError),
    #[error("Insufficient contributions in interval described by collect request: {0}")]
    InsufficientContributions(u64),
    #[error("Length mismatch")]
    LengthMismatch,
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
    #[tracing::instrument(err, skip(hpke_config, state_blob))]
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

    #[tracing::instrument(skip(request, self), err)]
    pub fn handle_aggregate(
        &mut self,
        request: &VerifyStartRequest,
    ) -> Result<VerifyResponse, Error> {
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

            let input_share_message: InputShareMessage<Field64> =
                serde_json::from_slice(&decrypted_input_share)?;

            // Construct helper verifier message
            let (state, helper_verifier_message) = prio3_start::<Boolean<Field64>>(
                &boolean_verify_parameter(Role::Helper),
                &sub_request.timestamp.associated_data(),
                input_share_message,
            )?;

            let leader_verifier_message: VerifyMessage<Field64> =
                serde_json::from_slice(&sub_request.verify_message)?;

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
            match prio3_finish(
                state,
                [
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
                        .time
                        .interval_start(self.parameters.min_batch_duration);
                    if let Some(sum) = self.helper_state.accumulators.get_mut(&interval_start) {
                        merge_vector(&mut sum.accumulated, input_share.as_slice())
                            .map_err(|_| Error::LengthMismatch)?;
                        sum.contributions += 1;
                    } else {
                        // This is the first input we have seen for this batch interval.
                        // Initialize the accumulator.
                        self.helper_state.accumulators.insert(
                            interval_start,
                            Accumulator {
                                accumulated: input_share.as_slice().to_vec(),
                                contributions: 1,
                                privacy_budget: 0,
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

            sub_responses.push(VerifySubResponse {
                timestamp: sub_request.timestamp,
                verification_message: serde_json::to_vec(&helper_verifier_message)?,
            });

            self.helper_state.last_timestamp_seen = sub_request.timestamp;
        }

        dump_accumulators(&self.helper_state.accumulators);

        Ok(VerifyResponse {
            helper_state: serde_json::to_vec(&self.helper_state)?,
            sub_responses,
        })
    }

    #[tracing::instrument(skip(self, output_share_request), err)]
    pub fn handle_output_share(
        &mut self,
        output_share_request: &OutputShareRequest,
    ) -> Result<EncryptedOutputShare, Error> {
        if !self
            .parameters
            .validate_batch_interval(output_share_request.batch_interval)
        {
            return Err(Error::AggregateProtocol(
                "invalid batch interval in request".to_string(),
            ));
        }

        let num_intervals_in_request = (output_share_request.batch_interval.end
            - output_share_request.batch_interval.start)
            / self.parameters.min_batch_duration;
        info!(?num_intervals_in_request, ?output_share_request.batch_interval, self.parameters.min_batch_duration);

        if num_intervals_in_request == 0 {
            // TODO Is this an error or do we send an empty EncryptedOutputShare?
            return Err(Error::AggregateProtocol(
                "batch interval is 0 length".to_string(),
            ));
        }

        let first_interval = output_share_request
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
            info!(?interval_start);
            match self.helper_state.accumulators.get_mut(&interval_start) {
                Some(accumulator) => {
                    if accumulator.privacy_budget == self.parameters.max_batch_lifetime {
                        return Err(Error::AggregateProtocol(format!(
                            "privacy budget exceeded ({})",
                            self.parameters.max_batch_lifetime
                        )));
                    }
                    match output_sum {
                        Some(ref mut inner_output_sum) => {
                            // merge in subsequent accumulators
                            merge_vector(inner_output_sum, &accumulator.accumulated)
                                .map_err(|_| Error::LengthMismatch)?;
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
            .output_share_sender(&self.parameters.task_id, Role::Helper)?;

        let (payload, encapped) = hpke_sender
            .encrypt_output_share(output_share_request.batch_interval, &json_output_share)?;

        Ok(EncryptedOutputShare {
            collector_hpke_config_id: self.parameters.collector_config.id,
            encapsulated_context: encapped.to_bytes().to_vec(),
            payload,
        })
    }
}

pub async fn run_helper(ppm_parameters: Parameters, hpke_config: hpke::Config) -> Result<()> {
    let port = ppm_parameters.aggregator_urls[Role::Helper.index()]
        .port()
        .unwrap_or(80);

    let hpke_config_endpoint = hpke_config.warp_endpoint();

    let aggregate = warp::post()
        .and(warp::path("aggregate"))
        .and(warp::body::json())
        .and(with_shared_value(ppm_parameters.clone()))
        .and(with_shared_value(hpke_config.clone()))
        .map(
            move |aggregate_request: VerifyStartRequest,
                  ppm_parameters: Parameters,
                  hpke_config: hpke::Config| {
                // We intentionally create a new instance of Helper every time we
                // handle a request to prove that we can successfully execute the
                // protocol without maintaining local state
                let mut helper_aggregator = match Helper::new(
                    &ppm_parameters,
                    &hpke_config,
                    &aggregate_request.helper_state,
                ) {
                    Ok(helper) => helper,
                    Err(e) => {
                        error!(error = ?e, "failed to create helper aggregator with state");
                        return reply::with_status(reply::json(&()), StatusCode::BAD_REQUEST);
                    }
                };

                match helper_aggregator.handle_aggregate(&aggregate_request) {
                    Ok(response) => reply::with_status(reply::json(&response), StatusCode::OK),
                    Err(e) => {
                        error!(error = ?e, "failed to handle aggregate request");
                        reply::with_status(reply::json(&()), StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            },
        )
        .with(warp::trace::named("aggregate"));

    let output_share = warp::post()
        .and(warp::path("output_share"))
        .and(warp::body::json())
        .and(with_shared_value(ppm_parameters.clone()))
        .and(with_shared_value(hpke_config.clone()))
        .map(
            move |output_share_request: OutputShareRequest,
                  ppm_parameters: Parameters,
                  hpke_config: hpke::Config| {
                let mut helper_aggregator = match Helper::new(
                    &ppm_parameters,
                    &hpke_config,
                    &output_share_request.helper_state,
                ) {
                    Ok(helper) => helper,
                    Err(_) => {
                        return reply::with_status(reply::json(&()), StatusCode::BAD_REQUEST);
                    }
                };

                match helper_aggregator.handle_output_share(&output_share_request) {
                    Ok(response) => reply::with_status(reply::json(&response), StatusCode::OK),
                    Err(_) => {
                        reply::with_status(reply::json(&()), StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            },
        )
        .with(warp::trace::named("output_share"));

    let routes = hpke_config_endpoint
        .or(aggregate)
        .or(output_share)
        .recover(handle_rejection)
        .with(warp::trace::request());

    info!("helper serving on 0.0.0.0:{}", port);
    warp::serve(routes)
        .run(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
        .await;

    unreachable!()
}
