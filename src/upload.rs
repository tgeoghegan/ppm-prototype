//! The upload portion of the PPM protocol, per §3.3 of RFCXXXX

use crate::{parameters::TaskId, Timestamp};
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use std::io::Read;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON parse error")]
    JsonParse(#[from] serde_json::error::Error),
    #[error("encryption error")]
    Encryption(#[from] crate::hpke::Error),
}

/// A report submitted by a client to a leader, corresponding to `struct
/// Report` in §4.2.2 of RFCXXXX.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Report {
    pub task_id: TaskId,
    #[serde(flatten)]
    pub timestamp: Timestamp,
    pub extensions: Vec<ReportExtension>,
    pub encrypted_input_shares: Vec<EncryptedInputShare>,
}

impl Report {
    /// Read in a JSON encoded Report from the provided `std::io::Read` and
    /// construct an instance of `Report`.
    pub fn from_json_reader<R: Read>(reader: R) -> Result<Self, Error> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Construct associated data string suitable for HPKE encryption or
    /// decryption of an EncryptedInputShare
    pub(crate) fn associated_data(&self) -> Vec<u8> {
        // Associated data is time || nonce || extensions, input_share per
        // §4.2.2. In TLS presentation language, multi-byte values are
        // represented in network or big endian order. At the moment we use JSON
        // on the wire, but abide by TLS rules here.
        // https://datatracker.ietf.org/doc/html/rfc8446#section-3.1
        // TODO(timg) include upload extensions in AAD
        self.timestamp.associated_data()
    }
}

/// An extension to a `Report`, allowing clients to tunnel arbitrary information
/// to the helper, corresponding to `struct Extension` in §4.2.3 of RFCXXXX.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ReportExtension {
    extension_type: ReportExtensionType,
    /// Opaque bytes of extension
    extension_data: Vec<u8>,
}

/// Types of report extensions
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum ReportExtensionType {
    AuthenticationInformation = 1,
    MaximumExtensionType = 65535,
}

/// An input share encrypted to an HPKE configuration, corresponding to `struct
/// EncryptedInputShare` in §4.2.2 of RFCXXXX
#[derive(Clone, Derivative, PartialEq, Eq, Deserialize, Serialize)]
#[derivative(Debug)]
pub struct EncryptedInputShare {
    pub aggregator_config_id: u8,
    #[serde(rename = "enc")]
    #[derivative(Debug = "ignore")]
    pub encapsulated_context: Vec<u8>,
    /// This is understood to be ciphertext || tag
    #[derivative(Debug = "ignore")]
    pub payload: Vec<u8>,
}

/// The decrypted contents of EncryptedInputShare.payload for Prio
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PrioInputShare {
    proof: Vec<u8>,
    input: Vec<u8>,
    joint_rand: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_json_parse() {
        let json_string = r#"
{
    "task_id": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    "time": 1001,
    "nonce": 100,
    "extensions": [
        {
            "extension_type": "AuthenticationInformation",
            "extension_data": [0, 1, 2]
        }
    ],
    "encrypted_input_shares": [
        {
            "aggregator_config_id": 1,
            "enc": [0, 1, 2, 3, 4, 5, 6, 7, 8],
            "payload": [0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8]
        }
    ]
}
"#;

        let report = Report::from_json_reader(json_string.as_bytes()).unwrap();
        let back_to_json = serde_json::to_string(&report).unwrap();
        let report_again = Report::from_json_reader(back_to_json.as_bytes()).unwrap();

        assert_eq!(report, report_again);
    }
}
