//! Leader implementation
use crate::{
    aggregate::{
        Aggregate, AggregateInitReq, AggregateMessage, AggregateReq, AggregateShareReq, Aggregator,
        ReportShare, Transition, TransitionMessage,
    },
    collect::{CollectRequest, CollectResponse},
    error::{handle_rejection, response_to_api_problem, IntoHttpApiProblem, ProblemDocumentType},
    hpke::{self, Ciphertext},
    parameters::Parameters,
    report::{self, Report},
    with_shared_value, Interval, Nonce, Role,
};
use bytes::Bytes;
use color_eyre::eyre::Result;
use http::{Response, StatusCode};
use http_api_problem::HttpApiProblem;
use prio::{
    codec::{Decode, Encode},
    vdaf::{self, Aggregator as VdafAggregator, PrepareTransition, VdafError},
};
use reqwest::Client;
use std::{
    cmp::Ordering,
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use warp::{reply, Filter, Rejection};

static LEADER_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "leader"
);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("VDAF error {0}")]
    Vdaf(#[from] VdafError),
    #[error("HTTP client error {0}")]
    HttpClient(#[from] reqwest::Error),
    #[error("Helper HTTP request error {1}")]
    HelperHttpRequest(StatusCode, String),
    #[error("bad protocol parameters")]
    Parameters(#[from] crate::parameters::Error),
    #[error("invalid batch interval {0}")]
    InvalidBatchInterval(Interval),
    #[error("aggregate protocol error {0}")]
    AggregateProtocol(String),
    #[error("helper error {0}")]
    HelperError(#[source] HttpApiProblem),
    #[error("Aggregation error {0}")]
    Aggregation(#[from] crate::aggregate::Error),
    #[error("Codec error")]
    Codec(#[from] prio::codec::CodecError),
}

impl IntoHttpApiProblem for Error {
    fn problem_document_type(&self) -> Option<ProblemDocumentType> {
        match self {
            Self::HelperError(_) => Some(ProblemDocumentType::HelperError),
            Self::HelperHttpRequest(_, _) => Some(ProblemDocumentType::HelperError),
            Self::InvalidBatchInterval(_) => Some(ProblemDocumentType::InvalidBatchInterval),
            Self::Aggregation(e) => e.problem_document_type(),
            _ => None,
        }
    }

    fn source_problem_document(&self) -> Option<&HttpApiProblem> {
        if let Self::HelperError(problem_document) = self {
            Some(problem_document)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
enum StoredReportState<A: vdaf::Aggregator> {
    Waiting {
        state: A::PrepareStep,
        prepare_message: A::PrepareMessage,
    },
    Finished {
        output_share: A::OutputShare,
    },
    Accumulated,
}

/// In-memory representation of a report stored by the leader
#[derive(Clone, Debug)]
pub struct StoredReport<A: vdaf::Aggregator> {
    pub nonce: Nonce,
    state: StoredReportState<A>,
    pub encrypted_helper_share: Ciphertext,
    pub extensions: Vec<report::Extension>,
}

impl<A: vdaf::Aggregator> PartialEq for StoredReport<A> {
    fn eq(&self, other: &Self) -> bool {
        self.nonce.eq(&other.nonce)
    }
}

impl<A: vdaf::Aggregator> Eq for StoredReport<A> {}

impl<A: vdaf::Aggregator> Ord for StoredReport<A> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.nonce.cmp(&other.nonce)
    }
}

impl<A: vdaf::Aggregator> PartialOrd for StoredReport<A> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Implements endpoints the leader supports and tracks leader state.
#[derive(Debug)]
pub struct Leader<A: VdafAggregator + Debug> {
    parameters: Parameters,
    aggregator: Aggregator<A>,
    /// Reports received by the leader.
    reports: Vec<StoredReport<A>>,
    helper_state: Vec<u8>,
    http_client: Client,
}

impl<A: VdafAggregator + Debug> Leader<A> {
    pub fn new(
        parameters: &Parameters,
        vdaf_aggregator: &A,
        verify_parameter: &A::VerifyParam,
        aggregation_parameter: &A::AggregationParam,
        hpke_config: &hpke::Config,
    ) -> Result<Self, Error> {
        let aggregator = Aggregator::new(
            Role::Leader,
            // TODO make leader generic over Vdaf
            hpke_config,
            vdaf_aggregator,
            verify_parameter,
            aggregation_parameter,
            parameters,
        );

        Ok(Self {
            parameters: parameters.clone(),
            aggregator,
            reports: vec![],
            helper_state: vec![],
            http_client: Client::builder().user_agent(LEADER_USER_AGENT).build()?,
        })
    }

    #[tracing::instrument(skip(self, report), err)]
    pub async fn handle_upload(&mut self, report: &Report) -> Result<(), Error> {
        debug!(?report, "obtained report");

        // TODO reject reports from the future
        // The leader is required to buffer reports while waiting to aggregate them. The
        // leader SHOULD NOT accept reports whose timestamps are too far in the future.
        // Implementors MAY provide for some small leeway, usually no more than a few
        // minutes, to account for clock skew.

        let (step, prepare_message) = self.aggregator.prepare_message(
            report.task_id,
            report.nonce,
            &report.extensions,
            &report.encrypted_input_shares[Role::Leader.index()],
        )?;

        self.reports.push(StoredReport {
            nonce: report.nonce,
            state: StoredReportState::Waiting {
                state: step,
                prepare_message,
            },
            encrypted_helper_share: report.encrypted_input_shares[Role::Helper.index()].clone(),
            extensions: report.extensions.clone(),
        });

        Ok(())
    }

    #[tracing::instrument(err, skip(self))]
    async fn send_aggregate_init_request(&mut self) -> Result<Option<AggregateMessage>, Error> {
        let report_shares: Vec<ReportShare> = self
            .reports
            .iter()
            .filter(|stored_report| !matches!(stored_report.state, StoredReportState::Accumulated))
            .map(|stored_report| ReportShare {
                nonce: stored_report.nonce,
                extensions: stored_report.extensions.clone(),
                encrypted_input_share: stored_report.encrypted_helper_share.clone(),
            })
            .collect();

        let aggregate_init_request = AggregateMessage {
            aggregate: Aggregate::Initialize(AggregateInitReq {
                task_id: self.parameters.task_id,
                aggregation_parameter: vec![],
                report_shares,
            }),
            // TODO: HMAC
            tag: [0u8; 32],
        };

        let http_response = self
            .http_client
            .post(self.parameters.aggregate_endpoint()?)
            .body(aggregate_init_request.get_encoded())
            .send()
            .await?;
        let http_response_status = http_response.status();

        if !http_response_status.is_success() {
            return match response_to_api_problem(http_response).await {
                Ok(document) => Err(Error::HelperError(document)),
                Err(message) => Err(Error::HelperHttpRequest(http_response_status, message)),
            };
        }

        let aggregate_response = AggregateMessage::get_decoded(&(), &http_response.bytes().await?)?;

        self.aggregator.dump_accumulators();

        self.handle_aggregate_resp(aggregate_response).await
    }

    #[tracing::instrument(err, skip(self, aggregate_req))]
    async fn send_aggregate_request(
        &mut self,
        aggregate_req: &AggregateMessage,
    ) -> Result<Option<AggregateMessage>, Error> {
        let http_response = self
            .http_client
            .post(self.parameters.aggregate_endpoint()?)
            .body(aggregate_req.get_encoded())
            .send()
            .await?;
        let http_response_status = http_response.status();

        if !http_response_status.is_success() {
            return match response_to_api_problem(http_response).await {
                Ok(document) => Err(Error::HelperError(document)),
                Err(message) => Err(Error::HelperHttpRequest(http_response_status, message)),
            };
        }

        let aggregate_response = AggregateMessage::get_decoded(&(), &http_response.bytes().await?)?;

        self.handle_aggregate_resp(aggregate_response).await
    }

    #[tracing::instrument(skip(self, aggregate_response), err)]
    async fn handle_aggregate_resp(
        &mut self,
        aggregate_response: AggregateMessage,
    ) -> Result<Option<AggregateMessage>, Error> {
        let aggregate_response = if let Aggregate::Response(resp) = aggregate_response.aggregate {
            resp
        } else {
            return Err(Error::AggregateProtocol(
                "unexpected message type in aggregate message".to_string(),
            ));
        };

        if self.reports.len() != aggregate_response.transitions.len() {
            return Err(Error::AggregateProtocol(format!(
                "unexpected number of sub-responses in helper aggregate response. Got {} wanted {}",
                aggregate_response.transitions.len(),
                self.reports.len()
            )));
        }
        self.helper_state = aggregate_response.helper_state;

        let mut transitions = vec![];

        for (leader_report, helper_transition) in
            self.reports.iter_mut().zip(aggregate_response.transitions)
        {
            // Sub-responses from helper must appear in the same order as the
            // sub-requests sent by leader
            if leader_report.nonce != helper_transition.nonce {
                return Err(Error::AggregateProtocol(format!(
                    "helper responses in wrong order. Wanted {}, got {}",
                    leader_report.nonce, helper_transition.nonce,
                )));
            }

            match helper_transition.transition {
                Transition::Continued { payload } => {
                    info!(?helper_transition.nonce, "helper continued");
                    let (state, leader_prepare_message) = if let StoredReportState::Waiting {
                        state,
                        prepare_message,
                    } = &leader_report.state
                    {
                        (state, prepare_message)
                    } else {
                        return Err(Error::AggregateProtocol(
                            "helper unexpectedly continued".to_string(),
                        ));
                    };
                    // Join helper and leader prepare message shares into prepare message for round
                    // n
                    let helper_prepare_message = A::PrepareMessage::get_decoded(state, &payload)?;
                    let prepare_message = self.aggregator.aggregator.prepare_preprocess([
                        helper_prepare_message,
                        leader_prepare_message.clone(),
                    ])?;

                    // Advance self to round n + 1
                    match self
                        .aggregator
                        .aggregator
                        .prepare_step(state.clone(), Some(prepare_message.clone()))
                    {
                        PrepareTransition::Continue(
                            next_round_state,
                            next_round_prepare_message,
                        ) => {
                            leader_report.state = StoredReportState::Waiting {
                                state: next_round_state,
                                prepare_message: next_round_prepare_message,
                            };
                        }
                        PrepareTransition::Finish(output_share) => {
                            leader_report.state = StoredReportState::Finished { output_share };
                        }
                        PrepareTransition::Fail(error) => {
                            warn!(
                                time = ?leader_report.nonce,
                                ?error,
                                "proof did not check out for report"
                            );
                            // Process other transitions
                            continue;
                        }
                    }

                    // Send round n prepare message to helper
                    info!(?leader_report.nonce, "pushing continue transition to helper");
                    transitions.push(TransitionMessage {
                        nonce: leader_report.nonce,
                        transition: Transition::Continued {
                            payload: prepare_message.get_encoded(),
                        },
                    });
                }
                Transition::Finished => {
                    info!(?helper_transition.nonce, "helper finished");
                    let output_share = if let StoredReportState::Finished { output_share } =
                        &leader_report.state
                    {
                        output_share
                    } else {
                        return Err(Error::AggregateProtocol(
                            "helper unexpectedly finished".to_string(),
                        ));
                    };

                    info!("accumulating report");
                    // Helper has confirmed they have accumulated the report. We do the same.
                    self.aggregator
                        .accumulate_report(leader_report.nonce, output_share.clone())?;

                    leader_report.state = StoredReportState::Accumulated;
                }
                Transition::Failed { error } => {
                    warn!(helper_error = ?error, nonce = ?leader_report.nonce, "helper rejected report");
                    continue;
                }
            }
        }

        info!("dumping accumulators");
        self.aggregator.dump_accumulators();

        if !transitions.is_empty() {
            info!(
                length = transitions.len(),
                "building aggregate request to helper"
            );
            Ok(Some(AggregateMessage {
                aggregate: Aggregate::Request(AggregateReq {
                    task_id: self.parameters.task_id,
                    helper_state: self.helper_state.clone(),
                    transitions,
                }),
                // TODO: HMAC
                tag: [0u8; 32],
            }))
        } else {
            Ok(None)
        }
    }

    #[tracing::instrument(skip(self, collect_request), err)]
    pub async fn handle_collect(
        &mut self,
        collect_request: &CollectRequest<A>,
    ) -> Result<CollectResponse, Error> {
        // Extract own aggregate share. We do this before requesting the helper's aggregate share
        // because it also does request validation.
        let leader_aggregate_share = self
            .aggregator
            .extract_aggregate_share(collect_request.task_id, collect_request.batch_interval)?;

        // Request aggregate share from the helper
        let aggregate_message = AggregateMessage {
            aggregate: Aggregate::ShareRequest(AggregateShareReq {
                task_id: self.parameters.task_id,
                batch_interval: collect_request.batch_interval,
            }),
            tag: [0u8; 32],
        };

        let http_response = self
            .http_client
            .post(self.parameters.aggregate_share_endpoint()?)
            .body(aggregate_message.get_encoded())
            .send()
            .await?;
        let http_response_status = http_response.status();

        if !http_response_status.is_success() {
            return match response_to_api_problem(http_response).await {
                Ok(document) => Err(Error::HelperError(document)),
                Err(message) => Err(Error::HelperHttpRequest(http_response_status, message)),
            };
        }

        let aggregate_response = AggregateMessage::get_decoded(&(), &http_response.bytes().await?)?;

        // Ship encrypted aggregate shares to collector
        match aggregate_response.aggregate {
            Aggregate::ShareResponse(helper_ciphertext) => Ok(CollectResponse {
                encrypted_agg_shares: vec![leader_aggregate_share, helper_ciphertext],
            }),
            message => {
                return Err(Error::AggregateProtocol(format!(
                    "helper unexpectedly did not provide share response: {message:?}"
                )))
            }
        }
    }
}

#[tracing::instrument(err)]
pub async fn run_leader<A>(
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
    A::PrepareMessage: Send + Sync,
    A::OutputShare: Send + Sync,
{
    let port = ppm_parameters.aggregator_endpoints[Role::Leader.index()]
        .port()
        .unwrap_or(80);
    let hpke_config_endpoint = hpke_config.warp_endpoint()?;

    let leader_aggregator = Arc::new(Mutex::new(Leader::new(
        ppm_parameters,
        vdaf_aggregator,
        verify_parameter,
        aggregation_parameter,
        hpke_config,
    )?));

    let upload = warp::post()
        .and(warp::path("upload"))
        .and(warp::body::bytes())
        .and(with_shared_value(leader_aggregator.clone()))
        .and_then(|body: Bytes, leader: Arc<Mutex<Leader<_>>>| async move {
            let mut leader = leader.lock().await;

            let report = Report::get_decoded(&(), &body).map_err(|e| {
                warp::reject::custom(e.problem_document(Some(&leader.parameters), "upload"))
            })?;

            leader.handle_upload(&report).await.map_err(|e| {
                warp::reject::custom(e.problem_document(Some(&leader.parameters), "upload"))
            })?;

            Ok(reply::with_status(warp::reply(), StatusCode::OK)) as Result<_, Rejection>
        })
        .with(warp::trace::named("upload"));

    let aggregate = warp::post()
        .and(warp::path("aggregate"))
        .and(with_shared_value(leader_aggregator.clone()))
        .and_then(|leader: Arc<Mutex<Leader<_>>>| async move {
            let mut leader = leader.lock().await;

            let mut next_aggregate_message =
                leader.send_aggregate_init_request().await.map_err(|e| {
                    warp::reject::custom(e.problem_document(Some(&leader.parameters), "aggregate"))
                })?;

            while let Some(message) = &next_aggregate_message {
                next_aggregate_message =
                    leader.send_aggregate_request(message).await.map_err(|e| {
                        warp::reject::custom(
                            e.problem_document(Some(&leader.parameters), "aggregate"),
                        )
                    })?;
            }

            Ok(reply::with_status(warp::reply(), StatusCode::OK)) as Result<_, Rejection>
        })
        .with(warp::trace::named("aggregate"));

    let collect = warp::post()
        .and(warp::path("collect"))
        .and(warp::body::bytes())
        .and(with_shared_value(leader_aggregator.clone()))
        .and_then(|body: Bytes, leader: Arc<Mutex<Leader<_>>>| async move {
            let mut leader = leader.lock().await;

            let collect_request = CollectRequest::get_decoded(&(), &body).map_err(|e| {
                warp::reject::custom(e.problem_document(Some(&leader.parameters), "collect"))
            })?;

            let response = leader.handle_collect(&collect_request).await.map_err(|e| {
                warp::reject::custom(e.problem_document(Some(&leader.parameters), "collect"))
            })?;

            let response = Response::builder()
                .status(StatusCode::OK)
                .body(response.get_encoded())
                .map_err(|e| {
                    warp::reject::custom(e.problem_document(Some(&leader.parameters), "collect"))
                })?;

            Ok(response) as Result<_, Rejection>
        })
        .with(warp::trace::named("collect"));

    let routes = hpke_config_endpoint
        .or(upload)
        .or(aggregate)
        .or(collect)
        .recover(handle_rejection)
        .with(warp::trace::request());

    info!("leader serving on 0.0.0.0:{}", port);
    warp::serve(routes)
        .run(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
        .await;

    unreachable!()
}
