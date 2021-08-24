//! PPM parameters.
//!
//! Provides structures and functionality for dealing with a `struct PPMParam`
//! and related types.

use serde::{Deserialize, Serialize};
use std::io::Read;
use url::Url;

use crate::hpke;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::error::Error),
}

/// The configuration parameters for a PPM task, corresponding to
/// `struct Param` in §4.1 of RFCXXXX.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Parameters {
    pub nonce: [u8; 16],
    pub leader_url: Url,
    pub helper_url: Url,
    pub collector_config: hpke::Config,
    pub batch_size: u64,
    // TODO: use something like std::time::Duration or chrono::Duration _but_
    // with serde support
    pub batch_window: u64,
    pub protocol: Protocol,
    // TBD Prio or Hits specific fields
}

impl Parameters {
    /// Read in a JSON encoded Param from the provided `std::io::Read` and
    /// construct an instance of `Parameters`.
    ///
    /// Ideally this would be an implementation of `TryFrom<R: Read>` on
    /// `Parameters` but you can't provide generic implementations of `TryFrom`:
    /// https://github.com/rust-lang/rust/issues/50133
    pub fn from_json_reader<R: Read>(reader: R) -> Result<Self, Error> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Compute the `TaskId` for this `Parameters` instance.
    pub fn task_id(&self) -> TaskId {
        // ekr points out in prio-documents issue #104 that we might not want to
        // bother specifying the layout of `struct Param` and I think he is
        // probably right. To spare myself the trouble of figuring out how to
        // consistently hash `Parameters`, I'm cheating by just returning the
        // nonce, zero-padded to 32 bytes.
        let mut task_id = [0u8; 32];
        task_id[..self.nonce.len()].copy_from_slice(&self.nonce);
        task_id
    }
}

/// Corresponds to a `TaskID`, defined in §4.1 of RFCXXXX. The task ID is
/// the SHA-256 over a `struct PPMParam`.
pub type TaskId = [u8; 32];

/// The PPM protocols supported in this implementation.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum Protocol {
    /// The Prio private aggregation system
    Prio,
    /// Heavy Hitters
    HeavyHitters,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpke::{
        AuthenticatedEncryptionWithAssociatedData, KeyDerivationFunction, KeyEncapsulationMechanism,
    };

    #[test]
    fn parameters_json_parse() {
        let json_string = r#"
{
    "nonce": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    "leader_url": "https://leader.fake",
    "helper_url": "https://helper.fake",
    "collector_config": {
        "id": 1,
        "kem_id": 16,
        "kdf_id": 1,
        "aead_id": 3,
        "public_key": [0, 1, 2, 3]
    },
    "batch_size": 100,
    "batch_window": 100000,
    "protocol": "Prio"
}
"#;

        let params = Parameters::from_json_reader(json_string.as_bytes()).unwrap();
        let back_to_json = serde_json::to_string(&params).unwrap();
        let params_again = Parameters::from_json_reader(back_to_json.as_bytes()).unwrap();

        assert_eq!(params, params_again);
    }

    #[test]
    fn task_id() {
        let params = Parameters {
            nonce: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            leader_url: Url::parse("https://leader.fake").unwrap(),
            helper_url: Url::parse("https://helper.fake").unwrap(),
            collector_config: hpke::Config {
                id: 0,
                kem_id: KeyEncapsulationMechanism::X25519HkdfSha256,
                kdf_id: KeyDerivationFunction::HkdfSha384,
                aead_id: AuthenticatedEncryptionWithAssociatedData::ChaCha20Poly1305,
                public_key: vec![0, 1, 2, 3],
                private_key: None,
            },
            batch_size: 100,
            batch_window: 100,
            protocol: Protocol::Prio,
        };

        let other_params = Parameters {
            nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            leader_url: Url::parse("https://leader.fake").unwrap(),
            helper_url: Url::parse("https://helper.fake").unwrap(),
            collector_config: hpke::Config {
                id: 0,
                kem_id: KeyEncapsulationMechanism::X25519HkdfSha256,
                kdf_id: KeyDerivationFunction::HkdfSha384,
                aead_id: AuthenticatedEncryptionWithAssociatedData::ChaCha20Poly1305,
                public_key: vec![4, 5, 6, 7],
                private_key: None,
            },
            batch_size: 100,
            batch_window: 100,
            protocol: Protocol::Prio,
        };

        assert_ne!(params.task_id(), other_params.task_id());
    }
}
