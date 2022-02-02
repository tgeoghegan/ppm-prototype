use crate::{hpke, parameters::Parameters, report::Report, Nonce, Role, Time};
use http::{header::CONTENT_TYPE, StatusCode};
use http_api_problem::HttpApiProblem;
use prio::{codec::Encode, vdaf::Client};
use reqwest::Response;
use tracing::info;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("encryption error")]
    Encryption(#[from] crate::hpke::Error),
    #[error("HTTP client error")]
    HttpClient(#[from] reqwest::Error),
    #[error("bad protocol parameters")]
    Parameters(#[from] crate::parameters::Error),
    #[error("VDAF error")]
    Vdaf(#[from] prio::vdaf::VdafError),
    #[error("Suite error")]
    Suite(#[from] prio::vdaf::suite::SuiteError),
    #[error("JSON error")]
    Json(#[from] serde_json::Error),
    #[error("Unspecified error: {0}")]
    Unspecified(String),
    #[error("HTTP problem document {0}")]
    ProblemDocument(HttpApiProblem),
    #[error("HTTP response status {0} body:\n{1:?}")]
    HttpFailure(StatusCode, Option<Response>),
}

static CLIENT_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "client"
);

#[derive(Debug)]
pub struct PpmClient<C: Client> {
    http_client: reqwest::Client,
    parameters: Parameters,
    leader_hpke_config: hpke::Config,
    helper_hpke_config: hpke::Config,
    vdaf: C,
    public_parameter: C::PublicParam,
}

impl<C: Client> PpmClient<C> {
    #[tracing::instrument(err)]
    pub async fn new(
        ppm_parameters: &Parameters,
        vdaf_client: &C,
        public_parameter: C::PublicParam,
    ) -> Result<Self, Error> {
        let http_client = reqwest::Client::builder()
            .user_agent(CLIENT_USER_AGENT)
            .build()?;
        let leader_hpke_config = ppm_parameters
            .hpke_config(Role::Leader, &http_client)
            .await?;
        let helper_hpke_config = ppm_parameters
            .hpke_config(Role::Helper, &http_client)
            .await?;

        info!(?leader_hpke_config);

        Ok(Self {
            http_client,
            parameters: ppm_parameters.clone(),
            leader_hpke_config,
            helper_hpke_config,
            vdaf: vdaf_client.clone(),
            public_parameter,
        })
    }

    pub async fn do_upload(&self, time: u64, input: &C::Measurement) -> Result<(), Error> {
        let tamper_func = |input_share: &C::InputShare| input_share.clone();
        let tamper_func_ref = &tamper_func as &dyn Fn(&C::InputShare) -> C::InputShare;

        self.do_upload_tamper(time, input, tamper_func_ref, tamper_func_ref)
            .await
    }

    pub async fn do_upload_tamper(
        &self,
        time: u64,
        input: &C::Measurement,
        tamper_leader_share: &dyn Fn(&C::InputShare) -> C::InputShare,
        tamper_helper_share: &dyn Fn(&C::InputShare) -> C::InputShare,
    ) -> Result<(), Error> {
        let timestamp = Nonce {
            time: Time(time),
            rand: rand::random(),
        };

        // Generate a Prio input and proof. The serialized format is input share
        // then proof share.
        let upload_shares = self.vdaf.shard(&self.public_parameter, input)?;

        // Allow the caller to tamper with the input shares to force proof
        // verification to fail
        let leader_upload_share =
            tamper_leader_share(&upload_shares[Role::Leader.index()]).get_encoded();
        let helper_upload_share =
            tamper_helper_share(&upload_shares[Role::Helper.index()]).get_encoded();
        info!(
            helper_upload_share = ?upload_shares[Role::Helper.index()],
            tampered_helper_upload_share =
                ?tamper_helper_share(&upload_shares[Role::Helper.index()]),
            tampered_helper_upload_share_len = helper_upload_share.len(),
            "encoding helper share"
        );

        let leader_hpke_sender = self.leader_hpke_config.sender(
            &self.parameters.task_id,
            hpke::Label::InputShare,
            Role::Client,
            Role::Leader,
        )?;

        let helper_hpke_sender = self.helper_hpke_config.sender(
            &self.parameters.task_id,
            hpke::Label::InputShare,
            Role::Client,
            Role::Helper,
        )?;

        let extensions = vec![];
        let associated_data = Report::associated_data(timestamp, &extensions);

        let report = Report {
            nonce: timestamp,
            task_id: self.parameters.task_id,
            encrypted_input_shares: vec![
                leader_hpke_sender.seal(&leader_upload_share, &associated_data)?,
                helper_hpke_sender.seal(&helper_upload_share, &associated_data)?,
            ],
            extensions: vec![],
        };

        let upload_response = self
            .http_client
            .post(self.parameters.upload_endpoint()?)
            .body(report.get_encoded())
            .send()
            .await?;
        let status = upload_response.status();
        if !status.is_success() {
            match upload_response.headers().get(CONTENT_TYPE) {
                Some(content_type) if content_type == "application/problem+json" => {
                    match upload_response.json().await {
                        Ok(problem_document) => {
                            return Err(Error::ProblemDocument(problem_document))
                        }
                        Err(_) => return Err(Error::HttpFailure(status, None)),
                    }
                }
                _ => return Err(Error::HttpFailure(status, Some(upload_response))),
            }
        }

        Ok(())
    }

    pub async fn run_aggregate(&self) -> Result<(), Error> {
        let aggregate_response = self
            .http_client
            .post(self.parameters.leader_aggregate_endpoint()?)
            .send()
            .await?;
        let status = aggregate_response.status();
        if !status.is_success() {
            match aggregate_response.headers().get(CONTENT_TYPE) {
                Some(content_type) if content_type == "application/problem+json" => {
                    match aggregate_response.json().await {
                        Ok(problem_document) => {
                            return Err(Error::ProblemDocument(problem_document))
                        }
                        Err(_) => return Err(Error::HttpFailure(status, None)),
                    }
                }
                _ => return Err(Error::HttpFailure(status, Some(aggregate_response))),
            }
        }

        Ok(())
    }
}
