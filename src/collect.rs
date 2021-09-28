//! The collect portion of the PPM protocol, per §4.4 of RFCXXXX

use crate::{parameters::TaskId, Interval};
use derivative::Derivative;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON parse error")]
    JsonParse(#[from] serde_json::error::Error),
    #[error("encryption error")]
    Encryption(#[from] crate::hpke::Error),
}

/// A collect request sent to a leader from a collector.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct CollectRequest {
    pub task_id: TaskId,
    pub batch_interval: Interval,
    #[serde(flatten)]
    pub protocol_parameters: ProtocolCollectFields,
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
// TODO this is a guess at what a Prio output share looks like
#[derive(Clone, Debug, Derivative, PartialEq, Eq, Deserialize, Serialize)]
pub struct OutputShare {
    pub sum: Vec<u8>,
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
