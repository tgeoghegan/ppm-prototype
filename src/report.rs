//! Messages and common functionality related to PPM reports

use crate::{
    error::{IntoHttpApiProblem, ProblemDocumentType},
    hpke,
    parameters::TaskId,
    Nonce,
};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use prio::codec::{decode_u16_items, encode_u16_items, CodecError, Decode, Encode};
use std::{convert::TryFrom, io::Cursor};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("JSON parse error")]
    JsonParse(#[from] serde_json::error::Error),
    #[error("encryption error")]
    Encryption(#[from] crate::hpke::Error),
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("Bad task parameters")]
    Parameters(#[from] crate::parameters::Error),
    #[error("Primitive conversion: {0}")]
    Primitive(String),
}

impl IntoHttpApiProblem for Error {
    fn problem_document_type(&self) -> Option<ProblemDocumentType> {
        Some(ProblemDocumentType::UnrecognizedMessage)
    }
}

/// A report submitted by a client to a leader, corresponding to `struct
/// Report` in §x.x.x of RFCXXXX.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub task_id: TaskId,
    pub nonce: Nonce,
    pub extensions: Vec<Extension>,
    pub encrypted_input_shares: Vec<hpke::Ciphertext>,
}

impl Decode<()> for Report {
    fn decode(_decoding_parameter: &(), bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let task_id = TaskId::decode(&(), bytes)?;
        let timestamp = Nonce::decode(&(), bytes)?;
        let extensions = decode_u16_items(&(), bytes)?;
        let encrypted_input_shares = decode_u16_items(&(), bytes)?;

        Ok(Self {
            task_id,
            nonce: timestamp,
            extensions,
            encrypted_input_shares,
        })
    }
}

impl Encode for Report {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.task_id.encode(bytes);
        self.nonce.encode(bytes);
        encode_u16_items(bytes, &self.extensions);
        encode_u16_items(bytes, &self.encrypted_input_shares);
    }
}

impl Report {
    pub fn associated_data(timestamp: Nonce, extensions: &[Extension]) -> Vec<u8> {
        let mut associated_data = vec![];
        timestamp.encode(&mut associated_data);
        encode_u16_items(&mut associated_data, extensions);

        associated_data
    }
}

/// An extension to a `Report`, allowing clients to tunnel arbitrary information
/// to the helper, corresponding to `struct Extension` in §4.2.3 of RFCXXXX.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    extension_type: ExtensionType,
    /// Opaque bytes of extension
    extension_data: Vec<u8>,
}

impl Decode<()> for Extension {
    fn decode(_decoding_parameter: &(), bytes: &mut Cursor<&[u8]>) -> Result<Self, CodecError> {
        let extension_type = ExtensionType::try_from(u16::decode(&(), bytes)?)
            .map_err(|e| CodecError::Other(Box::new(e)))?;
        let extension_data = decode_u16_items(&(), bytes)?;

        Ok(Self {
            extension_type,
            extension_data,
        })
    }
}

impl Encode for Extension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        u16::from(self.extension_type).encode(bytes);
        encode_u16_items(bytes, &self.extension_data);
    }
}

/// Types of report extensions
#[derive(Clone, Copy, Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u16)]
pub enum ExtensionType {
    TBD = 0,
    MaximumExtensionType = 65535,
}
