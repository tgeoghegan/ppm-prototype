//! Helper implementation

use crate::{
    aggregate::{
        dump_accumulators, prio3_verify_parameter, Accumulator, VerifyResponse, VerifyStartRequest,
        VerifySubResponse,
    },
    collect::{EncryptedOutputShare, OutputShare, OutputShareRequest},
    error::{handle_rejection, IntoHttpApiProblem, ProblemDocumentType},
    hpke::{self, Role},
    parameters::{Parameters, TaskId},
    with_shared_value, Interval, Time, Timestamp,
};
use ::hpke::Serializable;
use chrono::{DateTime, TimeZone, Utc};
use color_eyre::eyre::Result;
use http::StatusCode;
use prio::vdaf::{prio3::Prio3Sum64, suite::Suite, Aggregatable, Aggregator, Vdaf, VdafError};
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
    UnrecognizedTask(TaskId),
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
    #[error("invalid batch interval {0}")]
    InvalidBatchInterval(Interval),
    #[error("insufficient batch size {0}")]
    InsufficientBatchSize(u64),
    #[error("request exceeds the batch's privacy budget")]
    PrivacyBudgetExceeded,
    #[error("Length mismatch")]
    LengthMismatch,
    #[error("Unspecified: {0}")]
    Unspecified(String),
}

impl IntoHttpApiProblem for Error {
    fn problem_document_type(&self) -> Option<ProblemDocumentType> {
        match self {
            Self::JsonParse(_) => Some(ProblemDocumentType::UnrecognizedMessage),
            // TODO: not all encryption errors will be client errors so we
            // perhaps need a bool field on Error::Encryption to indicate
            // client vs. server error
            Self::Encryption(_) => Some(ProblemDocumentType::UnrecognizedMessage),
            Self::UnrecognizedTask(_) => Some(ProblemDocumentType::UnrecognizedTask),
            Self::UnknownHpkeConfig(_) => Some(ProblemDocumentType::OutdatedConfig),
            Self::InvalidBatchInterval(_) => Some(ProblemDocumentType::InvalidBatchInterval),
            Self::InsufficientBatchSize(_) => Some(ProblemDocumentType::InsufficientBatchSize),
            Self::PrivacyBudgetExceeded => Some(ProblemDocumentType::PrivacyBudgetExceeded),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct HelperState<S> {
    accumulators: HashMap<DateTime<Utc>, Accumulator<S>>,
    last_timestamp_seen: Timestamp,
}

/// Implements endpoints for helper.
#[derive(Debug)]
pub struct Helper {
    parameters: Parameters,
    hpke_config: hpke::Config,
    // TODO make Helper generic over Vdaf of has-a `Box<dyn Vdaf>`
    vdaf: Prio3Sum64,
    helper_state: HelperState<<Prio3Sum64 as Vdaf>::AggregateShare>,
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
        let helper_state: HelperState<<Prio3Sum64 as Vdaf>::AggregateShare> =
            if state_blob.is_empty() {
                // Start with empty state
                HelperState {
                    accumulators: HashMap::new(),
                    last_timestamp_seen: Timestamp {
                        time: Time(0),
                        nonce: 0,
                    },
                }
            } else {
                serde_json::from_slice(state_blob)?
            };
        Ok(Self {
            parameters: parameters.clone(),
            hpke_config: hpke_config.clone(),
            vdaf: Prio3Sum64::new(Suite::Blake3, 2, 63)?,
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
            return Err(Error::UnrecognizedTask(request.task_id));
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

            // TODO make this generic over Vdaf
            let input_share_message: <Prio3Sum64 as Vdaf>::InputShare =
                serde_json::from_slice(&decrypted_input_share)?;

            let state = self.vdaf.prepare_init(
                &prio3_verify_parameter(Role::Helper),
                &(),
                &sub_request.timestamp.associated_data(),
                &input_share_message,
            )?;

            // Construct helper verifier message
            let (state, helper_verifier_message) = self.vdaf.prepare_start(state)?;

            let leader_verifier_message: <Prio3Sum64 as Aggregator>::PrepareMessage =
                serde_json::from_slice(&sub_request.verify_message)?;

            info!(
                timestamp = ?sub_request.timestamp,
                leader_verifier_message = ?leader_verifier_message,
                helper_verifier_message = ?helper_verifier_message,
                "verifying proof"
            );

            // Kinda unfortunate here that `verify_finish` consumes verifier
            // shares: taking Vec<VerifierMessage> instead of &[VerifierMessage]
            // forces allocation + copy to the heap, even if I own the value of
            // leader_verifier_message, and it's not clear that I do.
            match self.vdaf.prepare_finish(
                state,
                [leader_verifier_message, helper_verifier_message.clone()],
            ) {
                Ok(output_share) => {
                    // Proof is OK. Accumulate this share and send helper
                    // verifier share to leader so they can verify the proof
                    // too.
                    let interval_start = sub_request
                        .timestamp
                        .time
                        .interval_start(self.parameters.min_batch_duration);
                    if let Some(sum) = self.helper_state.accumulators.get_mut(&interval_start) {
                        self.vdaf
                            .accumulate(&(), &mut sum.accumulated, &output_share)?;
                        sum.contributions += 1;
                    } else {
                        // This is the first input we have seen for this batch interval.
                        // Initialize the accumulator.
                        let accumulated = self.vdaf.aggregate(&(), [output_share])?;
                        self.helper_state.accumulators.insert(
                            interval_start,
                            Accumulator {
                                accumulated,
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
            return Err(Error::InvalidBatchInterval(
                output_share_request.batch_interval,
            ));
        }

        let num_intervals_in_request = output_share_request
            .batch_interval
            .min_intervals_in_interval(self.parameters.min_batch_duration);

        let first_interval = output_share_request
            .batch_interval
            .start
            .interval_start(self.parameters.min_batch_duration);

        let mut output_shares = vec![];
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
                        return Err(Error::PrivacyBudgetExceeded);
                    }
                    output_shares.push(accumulator.accumulated.clone());

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
            return Err(Error::InsufficientBatchSize(total_contributions));
        }

        let rest = output_shares.split_off(1);
        rest.iter()
            .try_for_each(|agg_share| output_shares[0].merge(agg_share))?;

        let output_share = OutputShare {
            sum: output_shares[0].clone(),
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
        .and_then(
            |aggregate_request: VerifyStartRequest,
             ppm_parameters: Parameters,
             hpke_config: hpke::Config| async move {
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
                        return Err(warp::reject::custom(
                            e.problem_document(&ppm_parameters, "aggregate"),
                        ))
                    }
                };

                match helper_aggregator.handle_aggregate(&aggregate_request) {
                    Ok(response) => Ok(reply::with_status(reply::json(&response), StatusCode::OK)),
                    Err(e) => Err(warp::reject::custom(
                        e.problem_document(&ppm_parameters, "aggregate"),
                    )),
                }
            },
        )
        .with(warp::trace::named("aggregate"));

    let output_share = warp::post()
        .and(warp::path("output_share"))
        .and(warp::body::json())
        .and(with_shared_value(ppm_parameters.clone()))
        .and(with_shared_value(hpke_config.clone()))
        .and_then(
            |output_share_request: OutputShareRequest,
             ppm_parameters: Parameters,
             hpke_config: hpke::Config| async move {
                let mut helper_aggregator = match Helper::new(
                    &ppm_parameters,
                    &hpke_config,
                    &output_share_request.helper_state,
                ) {
                    Ok(helper) => helper,
                    Err(e) => {
                        return Err(warp::reject::custom(
                            e.problem_document(&ppm_parameters, "output_share"),
                        ))
                    }
                };

                match helper_aggregator.handle_output_share(&output_share_request) {
                    Ok(response) => Ok(reply::with_status(reply::json(&response), StatusCode::OK)),
                    Err(e) => Err(warp::reject::custom(
                        e.problem_document(&ppm_parameters, "output_share"),
                    )),
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
