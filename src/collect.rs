//! The collect portion of the PPM protocol

use crate::{
    error::{IntoHttpApiProblem, ProblemDocumentType},
    hpke,
    parameters::{Parameters, TaskId},
    Interval, Role,
};
use http::{header::CONTENT_TYPE, StatusCode};
use http_api_problem::HttpApiProblem;
use prio::{
    codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode, ParameterizedDecode},
    vdaf::{Collector, Vdaf},
};
use reqwest::{Client, Response};
use std::io::Cursor;
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
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("Codec error")]
    Codec(#[from] prio::codec::CodecError),
}

impl IntoHttpApiProblem for Error {
    fn problem_document_type(&self) -> Option<ProblemDocumentType> {
        Some(ProblemDocumentType::UnrecognizedMessage)
    }
}

/// A collect request sent to a leader from a collector.
///
/// struct {
///   TaskID task_id;
///   Interval batch_interval;
///   opaque agg_param<0..2^16-1>;
/// } CollectReq;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectRequest<V: Vdaf> {
    pub task_id: TaskId,
    pub batch_interval: Interval,
    pub aggregation_parameter: V::AggregationParam,
}

impl<V: Vdaf> Encode for CollectRequest<V> {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.batch_interval.encode(bytes);
        // CollectReq.agg_param is encoded as a variable length opaque byte
        // string
        let aggregation_parameter_bytes = self.aggregation_parameter.get_encoded();
        encode_u16_items(bytes, &(), &aggregation_parameter_bytes);
    }
}

impl<V: Vdaf> Decode for CollectRequest<V> {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(bytes)?;
        let batch_interval = Interval::decode(bytes)?;
        // CollectReq.agg_param is encoded as a variable length opaque byte
        // string. Decode the byte string into Vec<u8>, then decode that into
        // V::AggregationParam.
        let aggregation_parameter_bytes = decode_u16_items(&(), bytes)?;
        let aggregation_parameter = V::AggregationParam::get_decoded(&aggregation_parameter_bytes)?;

        Ok(Self {
            task_id,
            batch_interval,
            aggregation_parameter,
        })
    }
}

/// The response to a collect request
/// struct {
///   HpkeCiphertext encrypted_agg_shares shares<1..2^16-1>;
/// } CollectResp;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectResponse {
    pub encrypted_agg_shares: Vec<hpke::Ciphertext>,
}

impl Encode for CollectResponse {
    fn encode(&self, bytes: &mut Vec<u8>) {
        encode_u16_items(bytes, &(), &self.encrypted_agg_shares);
    }
}

impl Decode for CollectResponse {
    fn decode(bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let encrypted_output_shares = decode_u16_items(&(), bytes)?;

        Ok(Self {
            encrypted_agg_shares: encrypted_output_shares,
        })
    }
}

pub async fn run_collect<C: Collector>(
    ppm_parameters: &Parameters,
    hpke_config: &hpke::Config,
    batch_interval: Interval,
    vdaf: C,
    aggregation_parameter: &C::AggregationParam,
    aggregate_share_length: usize,
) -> Result<C::AggregateResult, Error> {
    let http_client = Client::builder().user_agent(COLLECTOR_USER_AGENT).build()?;

    let collect_request: CollectRequest<C> = CollectRequest {
        task_id: ppm_parameters.task_id,
        batch_interval,
        aggregation_parameter: aggregation_parameter.clone(),
    };

    let collect_response = http_client
        .post(ppm_parameters.collect_endpoint()?)
        .body(collect_request.get_encoded())
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

    let collect_response = CollectResponse::get_decoded(&collect_response.bytes().await?)?;

    let leader_ciphertext = &collect_response.encrypted_agg_shares[Role::Leader.index()];

    let leader_recipient = hpke_config.recipient(
        &ppm_parameters.task_id,
        hpke::Label::AggregateShare,
        Role::Leader,
        Role::Collector,
        &leader_ciphertext.encapsulated_context,
    )?;

    let leader_share = C::AggregateShare::get_decoded_with_param(
        &aggregate_share_length,
        &leader_recipient.open(leader_ciphertext, &batch_interval.associated_data())?,
    )?;

    let helper_ciphertext = &collect_response.encrypted_agg_shares[Role::Helper.index()];

    let helper_recipient = hpke_config.recipient(
        &ppm_parameters.task_id,
        hpke::Label::AggregateShare,
        Role::Helper,
        Role::Collector,
        &helper_ciphertext.encapsulated_context,
    )?;

    let helper_share = C::AggregateShare::get_decoded_with_param(
        &aggregate_share_length,
        &helper_recipient.open(helper_ciphertext, &batch_interval.associated_data())?,
    )?;

    // TODO: include contribution count in aggregate share somehow
    // if decrypted_leader_share.contributions != decrypted_helper_share.contributions {
    //     return Err(Error::LengthMismatch(
    //         decrypted_leader_share.contributions,
    //         decrypted_helper_share.contributions,
    //     ));
    // }

    Ok(vdaf.unshard(aggregation_parameter, [leader_share, helper_share])?)
}
