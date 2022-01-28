//! PPM parameters.
//!
//! Provides structures and functionality for dealing with a `struct PPMParam`
//! and related types.

use crate::{
    config_path,
    hpke::{self, Role},
    Duration, Interval,
};
use chrono::{TimeZone, Utc};
use rand::{thread_rng, Rng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, path::PathBuf};
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
    #[serde(
        serialize_with = "base64::serialize_taskid",
        deserialize_with = "base64::deserialize_taskid"
    )]
    pub task_id: TaskId,
    pub aggregator_urls: Vec<Url>,
    pub collector_config: hpke::Config,
    /// Maximum number of queries allowed against a batch.
    pub max_batch_lifetime: u64,
    /// Minimum number of reports in a batch
    pub min_batch_size: u64,
    /// Minimum time elapsed between start and end of a batch
    pub min_batch_duration: Duration,
    /// What VDAF are we running
    pub vdaf: VdafLabel,
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
    pub fn from_json_reader<R: Read>(reader: R) -> Result<Self, Error> {
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

    /// Returns true if the batch interval is aligned with and greater than the
    /// minimum batch duration
    pub(crate) fn validate_batch_interval(&self, batch_interval: Interval) -> bool {
        batch_interval.duration.0 >= self.min_batch_duration.0
            && batch_interval.start.interval_start(self.min_batch_duration)
                == Utc.timestamp(batch_interval.start.0 as i64, 0)
            && batch_interval.duration.0 % self.min_batch_duration.0 == 0
    }
}

/// Corresponds to a `TaskID`, defined in §4.1 of RFCXXXX. The task ID is
/// the SHA-256 over a `struct PPMParam`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskId([u8; 32]);

impl TaskId {
    pub fn random() -> Self {
        Self(thread_rng().gen::<[u8; 32]>())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

mod base64 {
    //! Custom serialization module used to serialize TaskId to base64
    use super::TaskId;
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};
    use std::convert::TryInto;

    pub fn serialize_taskid<S: Serializer>(v: &TaskId, s: S) -> Result<S::Ok, S::Error> {
        String::serialize(&base64::encode(v.0), s)
    }

    pub fn deserialize_taskid<'de, D: Deserializer<'de>>(d: D) -> Result<TaskId, D::Error> {
        let slice = base64::decode(String::deserialize(d)?.as_bytes())
            .map_err(Error::custom)?
            .try_into()
            .map_err(|_| Error::custom("can't convert vec into TaskId"))?;
        Ok(TaskId(slice))
    }
}

/// VDAFs supported. Each entry should correspond to a VDAF instantiation in
/// libprio
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum VdafLabel {
    Prio3Count64,
    Prio3Sum64 { bits: u32 },
    Prio3Histogram64 { buckets: Vec<u64> },
    Hits,
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use super::*;

    #[test]
    fn parameters_json_parse() {
        let params = Parameters {
            task_id: TaskId([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                10, 11, 12, 13, 14, 15,
            ]),
            aggregator_urls: vec![
                "https://leader.fake".try_into().unwrap(),
                "https://helper.fake".try_into().unwrap(),
            ],
            collector_config: hpke::Config {
                id: 1,
                kem_id: hpke::KeyEncapsulationMechanism::X25519HkdfSha256,
                kdf_id: hpke::KeyDerivationFunction::HkdfSha256,
                aead_id: hpke::AuthenticatedEncryptionWithAssociatedData::ChaCha20Poly1305,
                public_key: vec![
                    3, 20, 3, 245, 218, 218, 141, 106, 244, 32, 137, 7, 239, 142, 236, 187, 223,
                    40, 226, 20, 103, 206, 127, 111, 201, 43, 163, 129, 97, 74, 254, 75,
                ],
                private_key: Some(vec![
                    200, 136, 138, 82, 174, 13, 162, 51, 213, 94, 11, 15, 141, 167, 166, 44, 216,
                    99, 180, 36, 212, 230, 85, 89, 67, 139, 199, 181, 108, 134, 250, 89,
                ]),
            },
            max_batch_lifetime: 1,
            min_batch_size: 100,
            min_batch_duration: Duration(100000),
            vdaf: VdafLabel::Prio3Sum64 { bits: 64 },
        };

        let json_string = r#"
{
    "task_id": "AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKCwwNDg8=",
    "aggregator_urls": [
        "https://leader.fake/",
        "https://helper.fake/"
    ],
    "collector_config": {
        "id": 1,
        "kem_id": 32,
        "kdf_id": 1,
        "aead_id": 3,
        "public_key": "AxQD9drajWr0IIkH747su98o4hRnzn9vySujgWFK/ks=",
        "private_key": "yIiKUq4NojPVXgsPjaemLNhjtCTU5lVZQ4vHtWyG+lk="
    },
    "max_batch_lifetime": 1,
    "min_batch_size": 100,
    "min_batch_duration": 100000,
    "vdaf": {
        "Prio3Sum64": {
            "bits": 64
        }
    }
}
"#;

        let params_from_json = Parameters::from_json_reader(json_string.as_bytes()).unwrap();
        let back_to_json = serde_json::to_string(&params).unwrap();
        let params_again = Parameters::from_json_reader(back_to_json.as_bytes()).unwrap();

        assert_eq!(params, params_again);
        assert_eq!(params_from_json, params);
    }
}
