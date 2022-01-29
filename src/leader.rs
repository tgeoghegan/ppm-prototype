//! Leader implementation
use crate::{
    aggregate::{Aggregator, VerifyResponse, VerifyStartRequest, VerifyStartSubRequest},
    collect::{CollectRequest, CollectResponse, EncryptedOutputShare, OutputShareRequest},
    error::{handle_rejection, response_to_api_problem, IntoHttpApiProblem, ProblemDocumentType},
    hpke,
    parameters::{Parameters, TaskId},
    upload::{EncryptedInputShare, Report, ReportExtension},
    with_shared_value, Interval, Nonce, Role,
};
use color_eyre::eyre::Result;
use http::StatusCode;
use http_api_problem::HttpApiProblem;
use prio::{
    field::FieldError,
    vdaf::{self, prio3::Prio3Sum64, suite::Suite, Vdaf, VdafError},
};
use reqwest::Client;
use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::sync::Mutex;
use tracing::{debug, error, info};
use warp::{reply, Filter};

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
    JsonParse(#[from] serde_json::Error),
    #[error("encryption error")]
    Encryption(#[from] crate::hpke::Error),
    #[error("unrecognized task ID")]
    UnrecognizedTask(TaskId),
    #[error("unknown HPKE config ID {0}")]
    UnknownHpkeConfig(u8),
    #[error("VDAF error")]
    Vdaf(#[from] VdafError),
    #[error("HTTP client error")]
    HttpClient(#[from] reqwest::Error),
    #[error("{1}")]
    HelperHttpRequest(StatusCode, String),
    #[error("bad protocol parameters")]
    Parameters(#[from] crate::parameters::Error),
    #[error("invalid batch interval {0}")]
    InvalidBatchInterval(Interval),
    #[error("aggregate protocol error {0}")]
    AggregateProtocol(String),
    #[error("field error")]
    PrioField(#[from] FieldError),
    #[error("helper error")]
    HelperError(#[source] HttpApiProblem),
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

/// In-memory representation of an input stored by the leader
#[derive(Clone, Debug)]
pub struct StoredInputShare<A: vdaf::Aggregator> {
    pub timestamp: Nonce,
    pub leader_state: A::PrepareStep,
    pub leader_prepare_message: A::PrepareMessage,
    pub encrypted_helper_share: EncryptedInputShare,
    pub extensions: Vec<ReportExtension>,
}

impl<A: vdaf::Aggregator> PartialEq for StoredInputShare<A> {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp.eq(&other.timestamp)
    }
}

impl<A: vdaf::Aggregator> Eq for StoredInputShare<A> {}

impl<A: vdaf::Aggregator> Ord for StoredInputShare<A> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp.cmp(&other.timestamp)
    }
}

impl<A: vdaf::Aggregator> PartialOrd for StoredInputShare<A> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Implements endpoints the leader supports and tracks leader state.
#[derive(Clone, Debug)]
pub struct Leader {
    parameters: Parameters,
    hpke_config: hpke::Config,
    // TODO make this generic over trait Vdaf/Aggregator
    aggregator: Aggregator<Prio3Sum64>,
    /// Inputs for which the leader has not yet received a VerifierMessage from
    /// the helper (though the leader may have already _sent_ a
    /// VerifierMessage). The vec is kept sorted so that the helper shares and
    /// verifier messages can be sent to helper in increasing order per RFCXXXX
    /// 4.3.1.
    unaggregated_inputs: Vec<StoredInputShare<Prio3Sum64>>,
    // TODO kill helper state
    helper_state: Vec<u8>,
    http_client: Client,
}

impl Leader {
    pub fn new(parameters: &Parameters, hpke_config: &hpke::Config) -> Result<Self, Error> {
        let aggregator = Aggregator::new(
            Role::Leader,
            // TODO make leader generic over Vdaf
            Prio3Sum64::new(Suite::Blake3, 2, 63)?,
            parameters.clone(),
            // TODO: wire up aggregation parameter for poplar
            (),
            HashMap::new(),
        );

        Ok(Self {
            parameters: parameters.clone(),
            hpke_config: hpke_config.clone(),
            aggregator,
            unaggregated_inputs: vec![],
            helper_state: vec![],
            http_client: Client::builder().user_agent(LEADER_USER_AGENT).build()?,
        })
    }

    #[tracing::instrument(skip(self, report), err)]
    pub async fn handle_upload(&mut self, report: &Report) -> Result<(), Error> {
        debug!(?report, "obtained report");

        if report.task_id != self.parameters.task_id {
            return Err(Error::UnrecognizedTask(report.task_id));
        }

        let leader_share = &report.encrypted_input_shares[Role::Leader.index()];

        if leader_share.aggregator_config_id != self.hpke_config.id.0 {
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

        let input_share_message: <Prio3Sum64 as Vdaf>::InputShare =
            serde_json::from_slice(&decrypted_input_share)?;

        let (step, leader_prepare_message) = self
            .aggregator
            .prepare_message(report.timestamp, &input_share_message)?;

        self.unaggregated_inputs.push(StoredInputShare {
            timestamp: report.timestamp,
            leader_state: step,
            leader_prepare_message,
            encrypted_helper_share: report.encrypted_input_shares[Role::Helper.index()].clone(),
            extensions: report.extensions.clone(),
        });
        // TODO use an std::collections::BinaryHeap here for efficient
        // inserts
        self.unaggregated_inputs.sort_unstable();

        // Once we have 10 unaggregated inputs, send an aggregate request to
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
        let aggregate_sub_requests: Vec<VerifyStartSubRequest> = self
            .unaggregated_inputs
            .iter()
            .map(|stored_input| {
                Ok(VerifyStartSubRequest {
                    timestamp: stored_input.timestamp,
                    extensions: stored_input.extensions.clone(),
                    verify_message: serde_json::to_vec(&stored_input.leader_prepare_message)?,
                    helper_share: stored_input.encrypted_helper_share.clone(),
                })
            })
            .collect::<Result<_, serde_json::Error>>()?;

        let aggregate_request = VerifyStartRequest {
            task_id: self.parameters.task_id,
            aggregation_parameter: None,
            helper_state: self.helper_state.clone(),
            sub_requests: aggregate_sub_requests,
        };

        let http_response = self
            .http_client
            .post(self.parameters.aggregate_endpoint()?)
            .json(&aggregate_request)
            .send()
            .await?;
        let http_response_status = http_response.status();

        if !http_response_status.is_success() {
            return match response_to_api_problem(http_response).await {
                Ok(document) => Err(Error::HelperError(document)),
                Err(message) => Err(Error::HelperHttpRequest(http_response_status, message)),
            };
        }

        // At this point we got an HTTP 200 OK from helper, meaning it
        // successfully processed all the reports leader sent it (potentially
        // rejecting some due to bad proofs). That means we don't want to
        // re-send any of the reports we sent in a subsequent call to this
        // method, so reinitialize the leader's unaggregated inputs to empty.
        let leader_inputs = std::mem::take(&mut self.unaggregated_inputs);

        let aggregate_response: VerifyResponse = http_response.json().await?;

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

            // TODO: make this generic over Vdaf
            let helper_verifier_message: <Prio3Sum64 as vdaf::Aggregator>::PrepareMessage =
                serde_json::from_slice(&helper_response.verification_message)?;

            self.aggregator.aggregate_report(
                leader_input.timestamp,
                leader_input.leader_state,
                [leader_input.leader_prepare_message, helper_verifier_message],
            )?;
        }

        self.helper_state = aggregate_response.helper_state;

        self.aggregator.dump_accumulators();

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
            return Err(Error::InvalidBatchInterval(collect_request.batch_interval));
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
        let http_response_status = http_response.status();

        if !http_response_status.is_success() {
            return match response_to_api_problem(http_response).await {
                Ok(document) => Err(Error::HelperError(document)),
                Err(message) => Err(Error::HelperHttpRequest(http_response_status, message)),
            };
        }

        let helper_encrypted_output_share: EncryptedOutputShare = http_response.json().await?;

        let leader_output_share = self
            .aggregator
            .extract_output_share(collect_request.batch_interval)?;

        Ok(CollectResponse {
            encrypted_output_shares: vec![leader_output_share, helper_encrypted_output_share],
        })
    }
}

pub async fn run_leader(ppm_parameters: Parameters, hpke_config: hpke::Config) -> Result<()> {
    let port = ppm_parameters.aggregator_endpoints[Role::Leader.index()]
        .port()
        .unwrap_or(80);
    let hpke_config_endpoint = hpke_config.warp_endpoint();

    let leader_aggregator = Arc::new(Mutex::new(Leader::new(&ppm_parameters, &hpke_config)?));

    let upload = warp::post()
        .and(warp::path("upload"))
        .and(warp::body::json())
        .and(with_shared_value(leader_aggregator.clone()))
        .and_then(|report: Report, leader: Arc<Mutex<Leader>>| async move {
            let mut leader = leader.lock().await;
            match leader.handle_upload(&report).await {
                Ok(()) => Ok(reply::with_status(reply(), StatusCode::OK)),
                Err(e) => Err(warp::reject::custom(
                    e.problem_document(&leader.parameters, "upload"),
                )),
            }
        })
        .with(warp::trace::named("upload"));

    let collect = warp::post()
        .and(warp::path("collect"))
        .and(warp::body::json())
        .and(with_shared_value(leader_aggregator.clone()))
        .and_then(
            |collect_request: CollectRequest, leader: Arc<Mutex<Leader>>| async move {
                let mut leader = leader.lock().await;
                match leader.handle_collect(&collect_request).await {
                    Ok(response) => Ok(reply::with_status(reply::json(&response), StatusCode::OK)),
                    Err(e) => Err(warp::reject::custom(
                        e.problem_document(&leader.parameters, "collect"),
                    )),
                }
            },
        )
        .with(warp::trace::named("collect"));

    let routes = hpke_config_endpoint
        .or(upload)
        .or(collect)
        .recover(handle_rejection)
        .with(warp::trace::request());

    info!("leader serving on 0.0.0.0:{}", port);
    warp::serve(routes)
        .run(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port))
        .await;

    unreachable!()
}
