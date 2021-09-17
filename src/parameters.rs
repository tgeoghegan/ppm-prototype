//! PPM parameters.
//!
//! Provides structures and functionality for dealing with a `struct PPMParam`
//! and related types.

use crate::{
    config_path,
    hpke::{self, Role},
    Duration,
};
use rand::{thread_rng, Rng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{fs::File, io::Read};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON parse error")]
    JsonParse(#[from] serde_json::error::Error),
    #[error("URL error")]
    Url(#[from] url::ParseError),
    #[error("reqwest error")]
    Reqwest(#[from] reqwest::Error),
    #[error("file error: {1}")]
    File(#[source] std::io::Error, PathBuf),
}

/// The configuration parameters for a PPM task, corresponding to
/// `struct Param` in §4.1 of RFCXXXX.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Parameters {
    pub task_id: TaskId,
    pub aggregator_urls: Vec<Url>,
    pub collector_config: hpke::Config,
    /// Maximum number of queries allowed against a batch.
    pub max_batch_lifetime: u64,
    /// Minimum number of reports in a batch
    pub min_batch_size: u64,
    /// Minimum time elapsed between start and end of a batch
    pub min_batch_duration: Duration,
    #[serde(flatten)]
    pub protocol_parameters: ProtocolParameters,
}

impl Parameters {
    pub fn from_config_file() -> Result<Self, Error> {
        let ppm_parameters_path = config_path().join("parameters.json");

        Self::from_json_reader(
            File::open(&ppm_parameters_path).map_err(|e| Error::File(e, ppm_parameters_path))?,
        )
    }

    /// Read in a JSON encoded Param from the provided `std::io::Read` and
    /// construct an instance of `Parameters`.
    ///
    /// Ideally this would be an implementation of `TryFrom<R: Read>` on
    /// `Parameters` but you can't provide generic implementations of `TryFrom`:
    /// https://github.com/rust-lang/rust/issues/50133
    fn from_json_reader<R: Read>(reader: R) -> Result<Self, Error> {
        Ok(serde_json::from_reader(reader)?)
    }

    fn aggregator_endpoint(&self, role: Role) -> &Url {
        &self.aggregator_urls[role.index()]
    }

    fn hpke_config_endpoint(&self, role: Role) -> Result<Url, Error> {
        Ok(self.aggregator_endpoint(role).join("hpke_config")?)
    }

    #[tracing::instrument]
    pub async fn hpke_config(
        &self,
        role: Role,
        http_client: &Client,
    ) -> Result<hpke::Config, Error> {
        let hpke_config = http_client
            .get(self.hpke_config_endpoint(role)?)
            .send()
            .await?
            .json()
            .await?;
        Ok(hpke_config)
    }

    pub fn upload_endpoint(&self) -> Result<Url, Error> {
        Ok(self.aggregator_endpoint(Role::Leader).join("upload")?)
    }

    pub fn collect_endpoint(&self) -> Result<Url, Error> {
        Ok(self.aggregator_endpoint(Role::Leader).join("collect")?)
    }

    pub fn aggregate_endpoint(&self) -> Result<Url, Error> {
        Ok(self.aggregator_endpoint(Role::Helper).join("aggregate")?)
    }

    pub fn output_share_endpoint(&self) -> Result<Url, Error> {
        Ok(self
            .aggregator_endpoint(Role::Helper)
            .join("output_share")?)
    }
}

/// Corresponds to a `TaskID`, defined in §4.1 of RFCXXXX. The task ID is
/// the SHA-256 over a `struct PPMParam`.
pub type TaskId = [u8; 32];

pub fn new_task_id() -> TaskId {
    thread_rng().gen::<[u8; 32]>()
}

/// The protocol specific portions of Parameters
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum ProtocolParameters {
    /// Prio-specific parameters
    Prio {
        field: PrioField,
        // `type` is a reserved keyword in Rust
        #[serde(rename = "type")]
        prio_type: PrioType,
    },
    Hits {},
}

/// Field sizes for use in Prio types. These correspond to types in
/// prio::pcp::field.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum PrioField {
    Field64,
    Field80,
    Field126,
}

/// Types for use in Prio. These correspond to types in prio::pcp::types.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum PrioType {
    Boolean,
    MeanVarUnsignedVector { bits: usize },
    PolyCheckedVector { start: usize, end: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_json_parse() {
        let json_string = r#"
{
    "task_id": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    "aggregator_urls": [
        "https://leader.fake",
        "https://helper.fake"
    ],
    "collector_config": {
        "id": 1,
        "kem_id": 16,
        "kdf_id": 1,
        "aead_id": 3,
        "public_key": [0, 1, 2, 3]
    },
    "max_batch_lifetime": 1,
    "min_batch_size": 100,
    "min_batch_duration": 100000,
    "Prio": {
        "field": "Field80",
        "type": {
            "PolyCheckedVector": {
                "start": 0,
                "end": 2
            }
        }
    }
}
"#;

        let params = Parameters::from_json_reader(json_string.as_bytes()).unwrap();
        let back_to_json = serde_json::to_string(&params).unwrap();
        let params_again = Parameters::from_json_reader(back_to_json.as_bytes()).unwrap();

        assert_eq!(params, params_again);
    }
}
