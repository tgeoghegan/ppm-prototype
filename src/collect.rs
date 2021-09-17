//! The collect portion of the PPM protocol, per §4.4 of RFCXXXX

use crate::{parameters::TaskId, Interval};
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

/// An encrypted output share, sent from an aggregator to the collector
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct EncryptedOutputShare {
    pub collector_hpke_config_id: u8,
    #[serde(rename = "enc")]
    pub encapsulated_context: Vec<u8>,
    /// This is understood to be ciphertext || tag
    pub encrypted_output_share: Vec<u8>,
}
