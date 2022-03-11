//! Helper implementation

use crate::{
    aggregate::{
        Aggregate, AggregateInitReq, AggregateMessage, AggregateReq, AggregateResp, Aggregator,
        Transition, TransitionError, TransitionMessage,
    },
    error::{handle_rejection, IntoHttpApiProblem, ProblemDocumentType},
    hpke,
    parameters::{Parameters, TaskId},
    with_shared_value, Nonce, Role,
};
use bytes::Bytes;
use color_eyre::eyre::Result;
use http::{Response, StatusCode};
use prio::{
    codec::{Decode, Encode, ParameterizedDecode},
    vdaf::{self, PrepareTransition, VdafError},
};
use std::{
    collections::HashMap,
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use warp::{Filter, Rejection};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON parse error {0}")]
    JsonParse(#[from] serde_json::error::Error),
    #[error("encryption error {0}")]
    Encryption(#[from] crate::hpke::Error),
    #[error("unknown task ID")]
    UnrecognizedTask(TaskId),
    #[error("unknown HPKE config ID {0}")]
    UnknownHpkeConfig(hpke::ConfigId),
    #[error("VDAF error {0}")]
    Vdaf(#[from] VdafError),
    #[error("HTTP client error {0}")]
    HttpClient(#[from] reqwest::Error),
    #[error("Aggregate HTTP request error")]
    AggregateRequest(StatusCode),
    #[error("Aggregation error {0}")]
    Aggregation(#[from] crate::aggregate::Error),
    #[error("aggregate protocol error {0}")]
    AggregateProtocol(String),
    #[error("Codec error")]
    Codec(#[from] prio::codec::CodecError),
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

/// In-memory representation of a report stored by the leader
#[derive(Clone, Debug)]
pub enum StoredReport<A: vdaf::Aggregator> {
    Waiting { step: A::PrepareStep },
    Accumulated,
}

/// Implements endpoints for helper.
#[derive(Debug)]
pub struct Helper<A: vdaf::Aggregator + Debug> {
    parameters: Parameters,
    aggregator: Aggregator<A>,
    stored_reports: HashMap<Nonce, StoredReport<A>>,
}

impl<A: vdaf::Aggregator + Debug> Helper<A> {
    #[tracing::instrument(err, skip(hpke_config))]
    pub fn new(
        parameters: &Parameters,
        vdaf_aggregator: &A,
        verify_parameter: &A::VerifyParam,
        aggregation_parameter: &A::AggregationParam,
        hpke_config: &hpke::Config,
    ) -> Result<Self, Error> {
        let aggregator = Aggregator::new(
            Role::Helper,
            hpke_config,
            vdaf_aggregator,
            verify_parameter,
            aggregation_parameter,
            // TODO: lame that both structs own a copy of parameters
            parameters,
        );

        Ok(Self {
            parameters: parameters.clone(),
            aggregator,
            stored_reports: HashMap::new(),
        })
    }

    #[tracing::instrument(skip(self, aggregate_message), err)]
    pub fn handle_aggregate(
        &mut self,
        aggregate_message: &AggregateMessage,
    ) -> Result<AggregateMessage, Error> {
        // TODO: verify HMAC

        let inner_response = match aggregate_message.aggregate {
            Aggregate::Initialize(ref req) => Aggregate::Response(self.handle_aggregate_init(req)?),
            Aggregate::Request(ref req) => Aggregate::Response(self.handle_aggregate_req(req)?),
            ref message => {
                return Err(Error::AggregateProtocol(format!(
                    "unexpected aggregate message {:?}",
                    message
                )))
            }
        };

        Ok(AggregateMessage {
            aggregate: inner_response,
            tag: [0u8; 32],
        })
    }

    #[tracing::instrument(skip(self, request), err)]
    fn handle_aggregate_init(
        &mut self,
        request: &AggregateInitReq,
    ) -> Result<AggregateResp, Error> {
        info!(
            sub_request_count = request.report_shares.len(),
            "got aggregate request"
        );

        let mut transitions = vec![];

        for report_share in &request.report_shares {
            if self.stored_reports.contains_key(&report_share.nonce) {
                warn!(report_nonce = ?report_share.nonce, "duplicate report nonce");
                transitions.push(TransitionMessage {
                    nonce: report_share.nonce,
                    transition: Transition::Failed {
                        error: TransitionError::ReportReplayed,
                    },
                });
            }

            let (step, prepare_message) = match self.aggregator.prepare_message(
                request.task_id,
                report_share.nonce,
                &report_share.extensions,
                &report_share.encrypted_input_share,
            ) {
                Ok(v) => v,
                Err(prep_error) => {
                    warn!(?prep_error, "prepare start of report failed");
                    transitions.push(TransitionMessage {
                        nonce: report_share.nonce,
                        transition: Transition::Failed {
                            error: prep_error.into(),
                        },
                    });
                    continue;
                }
            };

            transitions.push(TransitionMessage {
                nonce: report_share.nonce,
                transition: Transition::Continued {
                    payload: prepare_message.get_encoded(),
                },
            });

            self.stored_reports
                .insert(report_share.nonce, StoredReport::Waiting { step });
        }

        self.aggregator.dump_accumulators();

        Ok(AggregateResp {
            helper_state: vec![],
            transitions,
        })
    }

    #[tracing::instrument(skip(self, request), err)]
    fn handle_aggregate_req(&mut self, request: &AggregateReq) -> Result<AggregateResp, Error> {
        if request.task_id != self.parameters.task_id {
            return Err(Error::UnrecognizedTask(request.task_id));
        }

        // We ignore helper state. I think realistically, we would use it to store a key that would
        // identify one of many HashMap<Nonce, StoredReport>s so that we could service multiple
        // aggregate protocols concurrently. Right now we take a lock on a single Helper that
        // stores ALL reports.

        let mut transitions = vec![];

        for leader_transition in &request.transitions {
            let stored_report = match self.stored_reports.get_mut(&leader_transition.nonce) {
                Some(v) => v,
                None => {
                    warn!(leader_transition_nonce = ?leader_transition.nonce, "unrecognized nonce in leader transition");
                    transitions.push(TransitionMessage {
                        nonce: leader_transition.nonce,
                        transition: Transition::Failed {
                            error: TransitionError::UnrecognizedNonce,
                        },
                    });
                    continue;
                }
            };

            match &leader_transition.transition {
                Transition::Continued { payload } => {
                    info!(?leader_transition.nonce, "leader continued");
                    let step = if let StoredReport::Waiting { step } = stored_report {
                        step
                    } else {
                        return Err(Error::AggregateProtocol(
                            "leader unexpectedly continued".to_string(),
                        ));
                    };

                    let preprocessed_prepare_message =
                        A::PrepareMessage::get_decoded_with_param(step, payload)?;

                    // Advance self to round n + 1
                    let transition = match self
                        .aggregator
                        .aggregator
                        .prepare_step(step.clone(), Some(preprocessed_prepare_message))
                    {
                        PrepareTransition::Continue(
                            next_round_step,
                            next_round_prepare_message,
                        ) => {
                            *stored_report = StoredReport::Waiting {
                                step: next_round_step,
                            };
                            Transition::Continued {
                                payload: next_round_prepare_message.get_encoded(),
                            }
                        }
                        PrepareTransition::Finish(output_share) => {
                            *stored_report = StoredReport::Accumulated;
                            info!(?leader_transition.nonce, "accumulating report");
                            self.aggregator
                                .accumulate_report(leader_transition.nonce, output_share)?;
                            Transition::Finished
                        }
                        PrepareTransition::Fail(error) => {
                            warn!(
                                time = ?leader_transition.nonce,
                                ?error,
                                "proof did not check out for report"
                            );
                            // Process other transitions
                            continue;
                        }
                    };

                    transitions.push(TransitionMessage {
                        nonce: leader_transition.nonce,
                        transition,
                    });
                }
                Transition::Finished => {
                    // Leader never sends helper finished
                    warn!(?leader_transition.nonce, "leader unexpectedly finished");
                    return Err(Error::AggregateProtocol(
                        "leader unexpectedly finished".to_string(),
                    ));
                }
                Transition::Failed { error } => {
                    // Leader should never send helper failed
                    warn!(leader_error = ?error, ?leader_transition.nonce, "leader unexpected failed");
                    return Err(Error::AggregateProtocol(
                        "leader unexpectedly failed".to_string(),
                    ));
                }
            }
        }

        info!("dumping accumulators");
        self.aggregator.dump_accumulators();

        Ok(AggregateResp {
            helper_state: vec![],
            transitions,
        })
    }

    #[tracing::instrument(skip(self), err)]
    pub fn handle_aggregate_share(
        &mut self,
        aggregate_message: &AggregateMessage,
    ) -> Result<AggregateMessage, Error> {
        // TODO: verify HMAC

        let request = match aggregate_message.aggregate {
            Aggregate::ShareRequest(ref req) => req,
            ref message => {
                return Err(Error::AggregateProtocol(format!(
                    "unexpected aggregate share message {message:?}"
                )))
            }
        };

        Ok(AggregateMessage {
            aggregate: Aggregate::ShareResponse(
                self.aggregator
                    .extract_aggregate_share(request.task_id, request.batch_interval)?,
            ),
            tag: [0u8; 32],
        })
    }
}

pub async fn run_helper<A>(
    ppm_parameters: &Parameters,
    vdaf_aggregator: &A,
    verify_parameter: &A::VerifyParam,
    aggregation_parameter: &A::AggregationParam,
    hpke_config: &hpke::Config,
) -> Result<()>
where
    A: vdaf::Aggregator + 'static + Send + Sync,
    A::VerifyParam: Send + Sync,
    A::AggregationParam: Send + Sync,
    A::PrepareStep: Send + Sync,
    A::AggregateShare: Send + Sync,
{
    let port = ppm_parameters.aggregator_endpoints[Role::Helper.index()]
        .port()
        .unwrap_or(80);

    let hpke_config_endpoint = hpke_config.warp_endpoint()?;

    let helper_aggregator = Arc::new(Mutex::new(Helper::new(
        ppm_parameters,
        vdaf_aggregator,
        verify_parameter,
        aggregation_parameter,
        hpke_config,
    )?));

    let aggregate = warp::post()
        .and(warp::path("aggregate"))
        .and(warp::body::bytes())
        .and(with_shared_value(helper_aggregator.clone()))
        .and_then(|body: Bytes, helper: Arc<Mutex<Helper<_>>>| async move {
            let mut helper = helper.lock().await;
            let aggregate_message = AggregateMessage::get_decoded(&body).map_err(|e| {
                warp::reject::custom(e.problem_document(Some(&helper.parameters), "aggregate"))
            })?;

            let response = helper.handle_aggregate(&aggregate_message).map_err(|e| {
                warp::reject::custom(e.problem_document(Some(&helper.parameters), "aggregate"))
            })?;

            let response = Response::builder()
                .status(StatusCode::OK)
                .body(response.get_encoded())
                .map_err(|e| {
                    warp::reject::custom(e.problem_document(Some(&helper.parameters), "aggregate"))
                })?;

            Ok(response) as Result<_, Rejection>
        })
        .with(warp::trace::named("aggregate"));

    let aggregate_share = warp::post()
        .and(warp::path("aggregate_share"))
        .and(warp::body::bytes())
        .and(with_shared_value(helper_aggregator.clone()))
        .and_then(|body: Bytes, helper: Arc<Mutex<Helper<_>>>| async move {
            let mut helper = helper.lock().await;
            let aggregate_message = AggregateMessage::get_decoded(&body).map_err(|e| {
                warp::reject::custom(
                    e.problem_document(Some(&helper.parameters), "aggregate_share"),
                )
            })?;

            let response = helper
                .handle_aggregate_share(&aggregate_message)
                .map_err(|e| {
                    warp::reject::custom(
                        e.problem_document(Some(&helper.parameters), "aggregate_share"),
                    )
                })?;

            let response = Response::builder()
                .status(StatusCode::OK)
                .body(response.get_encoded())
                .map_err(|e| {
                    warp::reject::custom(
                        e.problem_document(Some(&helper.parameters), "aggregate_share"),
                    )
                })?;

            Ok(response) as Result<_, Rejection>
        })
        .with(warp::trace::named("aggregate_share"));

    let routes = hpke_config_endpoint
        .or(aggregate)
        .or(aggregate_share)
        .recover(handle_rejection)
        .with(warp::trace::request());

    info!("helper serving on 0.0.0.0:{}", port);
    warp::serve(routes)
        .run(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
        .await;

    unreachable!()
}
