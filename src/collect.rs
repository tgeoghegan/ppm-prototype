//! The collect portion of the PPM protocol, per §4.4 of RFCXXXX

use crate::{
    hpke::{self, Role},
    parameters::{Parameters, TaskId},
    Interval,
};
use derivative::Derivative;
use http::{header::CONTENT_TYPE, StatusCode};
use http_api_problem::HttpApiProblem;
use prio::vdaf::{
    prio3::{Prio3Result, Prio3Sum64},
    suite::Suite,
    Collector, Vdaf,
};
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use tracing::info;

static COLLECTOR_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    "/",
    "collector"
);
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON parse error")]
    JsonParse(#[from] serde_json::error::Error),
    #[error("encryption error")]
    Encryption(#[from] crate::hpke::Error),
    #[error("HTTP problem document {0}")]
    ProblemDocument(HttpApiProblem),
    #[error("HTTP response status {0} body:\n{1:?}")]
    HttpFailure(StatusCode, Option<Response>),
    #[error("lengths do not match: leader {0} helper {1}")]
    LengthMismatch(u64, u64),
    #[error("reqwest error")]
    Reqwest(#[from] reqwest::Error),
    #[error("parameters")]
    Parameters(#[from] crate::parameters::Error),
    #[error("field error")]
    Field(#[from] prio::field::FieldError),
    #[error("VDAF error")]
    Vdaf(#[from] prio::vdaf::VdafError),
    #[error("{0}")]
    Unspecified(&'static str),
}

/// A collect request sent to a leader from a collector.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CollectRequest {
    pub task_id: TaskId,
    pub batch_interval: Interval,
    #[serde(skip_serializing_if = "Option::is_none", rename = "aggregation_param")]
    pub aggregation_parameter: Option<Vec<u8>>,
}

/// The protocol specific portions of CollectRequest
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum ProtocolCollectFields {
    /// Prio-specific parameters
    Prio {},
    Hits {},
}

/// The response to a collect request
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CollectResponse {
    pub encrypted_output_shares: Vec<EncryptedOutputShare>,
}

/// Output share request from leader to helper
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct OutputShareRequest {
    pub task_id: TaskId,
    pub batch_interval: Interval,
    pub helper_state: Vec<u8>,
}

/// An output share, sent from an aggregator to the collector
#[derive(Clone, Debug, Derivative, PartialEq, Eq, Deserialize, Serialize)]
pub struct OutputShare<V: Vdaf> {
    // Workaround for alleged compiler bug: https://github.com/serde-rs/serde/issues/1296
    #[serde(deserialize_with = "V::AggregateShare::deserialize")]
    pub sum: V::AggregateShare,
    pub contributions: u64,
}

/// An encrypted output share, sent from an aggregator to the collector
#[derive(Clone, Derivative, PartialEq, Eq, Deserialize, Serialize)]
#[derivative(Debug)]
pub struct EncryptedOutputShare {
    pub collector_hpke_config_id: u8,
    #[serde(rename = "enc")]
    #[derivative(Debug = "ignore")]
    pub encapsulated_context: Vec<u8>,
    /// This is understood to be ciphertext || tag
    #[derivative(Debug = "ignore")]
    pub payload: Vec<u8>,
}

pub async fn run_collect(
    ppm_parameters: &Parameters,
    hpke_config: &hpke::Config,
    batch_interval: Interval,
) -> Result<Prio3Result<u64>, Error> {
    // TODO: make this generic over Vdaf
    let vdaf = Prio3Sum64::new(Suite::Blake3, 2, 63)?;

    let http_client = Client::builder().user_agent(COLLECTOR_USER_AGENT).build()?;

    let collect_request = CollectRequest {
        task_id: ppm_parameters.task_id,
        batch_interval,
        aggregation_parameter: None,
    };

    let collect_response = http_client
        .post(ppm_parameters.collect_endpoint()?)
        .json(&collect_request)
        .send()
        .await?;

    let status = collect_response.status();
    info!(http_status = ?status, "collect request HTTP status");
    if !status.is_success() {
        match collect_response.headers().get(CONTENT_TYPE) {
            Some(content_type) if content_type == "application/problem+json" => {
                match collect_response.json().await {
                    Ok(problem_document) => return Err(Error::ProblemDocument(problem_document)),
                    Err(_) => return Err(Error::HttpFailure(status, None)),
                }
            }
            _ => return Err(Error::HttpFailure(status, Some(collect_response))),
        }
    }

    let collect_response_body: CollectResponse = collect_response.json().await?;
    let leader_recipient = hpke_config.output_share_recipient(
        &ppm_parameters.task_id,
        Role::Leader,
        &collect_response_body.encrypted_output_shares[Role::Leader.index()].encapsulated_context,
    )?;

    // TODO: make this generic over Vdaf
    let decrypted_leader_share: OutputShare<Prio3Sum64> =
        serde_json::from_slice(&leader_recipient.decrypt_output_share(
            &collect_response_body.encrypted_output_shares[Role::Leader.index()],
            batch_interval,
        )?)?;

    let helper_recipient = hpke_config.output_share_recipient(
        &ppm_parameters.task_id,
        Role::Helper,
        &collect_response_body.encrypted_output_shares[Role::Helper.index()].encapsulated_context,
    )?;
    let decrypted_helper_share: OutputShare<Prio3Sum64> =
        serde_json::from_slice(&helper_recipient.decrypt_output_share(
            &collect_response_body.encrypted_output_shares[Role::Helper.index()],
            batch_interval,
        )?)?;

    if decrypted_leader_share.contributions != decrypted_helper_share.contributions {
        return Err(Error::LengthMismatch(
            decrypted_leader_share.contributions,
            decrypted_helper_share.contributions,
        ));
    }

    Ok(vdaf.unshard(
        &(),
        [decrypted_leader_share.sum, decrypted_helper_share.sum],
    )?)
}
