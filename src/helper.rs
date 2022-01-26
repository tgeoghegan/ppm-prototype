//! Helper implementation

use crate::{
    aggregate::{
        aggregate_report, dump_accumulators, extract_output_share, prio3_verify_parameter,
        Accumulator, VerifyResponse, VerifyStartRequest, VerifySubResponse,
    },
    collect::{EncryptedOutputShare, OutputShareRequest},
    error::{handle_rejection, IntoHttpApiProblem, ProblemDocumentType},
    hpke::{self, Role},
    parameters::{Parameters, TaskId},
    with_shared_value, Time, Timestamp,
};
use chrono::{DateTime, Utc};
use color_eyre::eyre::Result;
use http::StatusCode;
use prio::vdaf::{prio3::Prio3Sum64, suite::Suite, Aggregator, Vdaf, VdafError};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
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
    #[error("Aggregation error")]
    Aggregation(#[from] crate::aggregate::Error),
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
            Self::Aggregation(e) => e.problem_document_type(),
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

            aggregate_report(
                &self.vdaf,
                &self.parameters,
                &mut self.helper_state.accumulators,
                // TODO wire up poplar1 agg param
                &(),
                sub_request.timestamp,
                state,
                leader_verifier_message,
                helper_verifier_message.clone(),
            )?;

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
        Ok(extract_output_share::<Prio3Sum64>(
            Role::Helper,
            &self.parameters,
            output_share_request.batch_interval,
            &mut self.helper_state.accumulators,
        )?)
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
