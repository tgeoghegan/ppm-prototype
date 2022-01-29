use crate::{
    collect::EncryptedOutputShare, config_path, parameters::TaskId, upload::EncryptedInputShare,
    Interval, Nonce, Role,
};
use ::hpke::{
    aead::{Aead, AeadCtxR, AeadCtxS, AesGcm128, AesGcm256, ChaCha20Poly1305},
    kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf},
    kem::{DhP256HkdfSha256, X25519HkdfSha256},
    setup_receiver, setup_sender, Deserializable, HpkeError, Kem, OpModeR, OpModeS, Serializable,
};
use derivative::Derivative;
use http::StatusCode;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::{fs::File, io::Read, path::PathBuf};
use warp::{filters::BoxedFilter, reply, Filter, Reply};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Wrapper around errors from crate hpke. See `hpke::HpkeError` for more
    /// details on possible variants.
    #[error("HPKE error")]
    Hpke(#[from] HpkeError),
    #[error("Serde error")]
    Serde(#[from] serde_json::error::Error),
    #[error("invalid HPKE configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("file error: {1}")]
    File(#[source] std::io::Error, PathBuf),
}

/// Identifier for an HPKE configuration
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfigId(pub u8);

/// An HPKE ciphertext
#[derive(Clone, Derivative, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct Ciphertext {
    /// Identifier of the HPKE configuration used to seal the message
    config_id: ConfigId,
    /// Encasulated HPKE context
    #[serde(rename = "enc")]
    #[derivative(Debug = "ignore")]
    encapsulated_context: Vec<u8>,
    /// Ciphertext
    #[derivative(Debug = "ignore")]
    payload: Vec<u8>,
}

/// Configuration file containing multiple HPKE configs
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ConfigFile {
    pub helper: Config,
    pub leader: Config,
    pub collector: Config,
}

impl ConfigFile {
    /// Load HPKE config from the JSON configuration file in the provided Read
    pub fn from_json_reader<R: Read>(reader: R) -> Result<Self, Error> {
        Ok(serde_json::from_reader(reader)?)
    }
}

/// HPKE configuration for a PPM participant, corresponding to `struct
/// HpkeConfig` in RFCXXXX.
// TODO: I wish we could do better than u16 for the kem/kedf/aead IDs, and
// better than Vec<u8> for the PK.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    /// Identifier of the HPKE configuration
    pub id: ConfigId,
    pub(crate) kem_id: KeyEncapsulationMechanism,
    pub(crate) kdf_id: KeyDerivationFunction,
    pub(crate) aead_id: AuthenticatedEncryptionWithAssociatedData,
    /// The public key, serialized using the `SerializePublicKey` function as
    /// described in draft-irtf-cfrg-hpke-11, §4 and §7.1.1.
    #[serde(
        serialize_with = "base64::serialize_bytes",
        deserialize_with = "base64::deserialize_bytes"
    )]
    pub(crate) public_key: Vec<u8>,
    /// The private key, serialized using the `SerializePrivateKey` function as
    /// described in draft-irtf-cfrg-hpke-11, §4 and §7.1.2. This value will not
    /// be present when advertised by a server from hpke_config.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "base64::serialize_bytes_option",
        deserialize_with = "base64::deserialize_bytes_option"
    )]
    pub(crate) private_key: Option<Vec<u8>>,
}

impl Config {
    /// Load HPKE config from default configuration file
    pub fn from_config_file(role: Role) -> Result<Self, Error> {
        let hpke_config_path = config_path().join("hpke.json");
        let config_file = ConfigFile::from_json_reader(
            File::open(&hpke_config_path).map_err(|e| Error::File(e, hpke_config_path))?,
        )?;

        let config = match role {
            Role::Helper => config_file.helper,
            Role::Leader => config_file.leader,
            Role::Collector => config_file.collector,
            Role::Client => {
                return Err(Error::InvalidConfiguration(
                    "can't get HPKE config for client role",
                ));
            }
        };

        Ok(config)
    }

    /// Generate a new keypair for the requested algorithm and construct a
    /// Config for it
    pub fn new_recipient(
        kem: KeyEncapsulationMechanism,
        kdf: KeyDerivationFunction,
        aead: AuthenticatedEncryptionWithAssociatedData,
    ) -> Self {
        let mut rng = thread_rng();
        // Create and serialize a keypair in the requested algorithm.
        // Crate hpke uses associated types on trait `Kem` to represent public
        // and private keys, but since there's no trait implemented by all of
        // them, we can't deal with them generically except in their serialized
        // form.
        let (serialized_private_key, serialized_public_key) = match kem {
            KeyEncapsulationMechanism::P256HkdfSha256 => {
                let (private_key, public_key) = DhP256HkdfSha256::gen_keypair(&mut rng);
                (
                    private_key.to_bytes().as_slice().to_vec(),
                    public_key.to_bytes().as_slice().to_vec(),
                )
            }
            KeyEncapsulationMechanism::X25519HkdfSha256 => {
                let (private_key, public_key) = X25519HkdfSha256::gen_keypair(&mut rng);
                (
                    private_key.to_bytes().as_slice().to_vec(),
                    public_key.to_bytes().as_slice().to_vec(),
                )
            }
        };

        Config {
            id: ConfigId(0),
            kem_id: kem,
            kdf_id: kdf,
            aead_id: aead,
            public_key: serialized_public_key,
            private_key: Some(serialized_private_key),
        }
    }

    pub fn warp_endpoint(&self) -> BoxedFilter<(impl Reply,)> {
        let config_without_private_key = self.without_private_key();
        warp::get()
            .and(warp::path("hpke_config"))
            .map(move || {
                reply::with_status(reply::json(&config_without_private_key), StatusCode::OK)
            })
            .map(|r| reply::with_header(r, http::header::CACHE_CONTROL, "max-age=86400"))
            .with(warp::trace::named("hpke_config"))
            .boxed()
    }

    /// Create a copy of the config without the private key, suitable for
    /// public advertising of HPKE config
    fn without_private_key(&self) -> Self {
        let mut copy = self.clone();
        copy.private_key = None;
        copy
    }

    /// True if this HPKE config's algos are supported by this implementation.
    // TODO(timg) figure out a more graceful way to dispatch to different
    // specializations of Sender or Receiver
    fn supported_configuration(&self) -> Result<(), Error> {
        if self.kem_id == KeyEncapsulationMechanism::X25519HkdfSha256
            && self.kdf_id == KeyDerivationFunction::HkdfSha256
            && self.aead_id == AuthenticatedEncryptionWithAssociatedData::ChaCha20Poly1305
        {
            Ok(())
        } else {
            Err(Error::InvalidConfiguration("unsupported HPKE algorithms"))
        }
    }

    /// Construct an application into string suitable for constructing HPKE
    /// contexts for sealing or opening PPM reports.
    fn report_application_info(task_id: &TaskId, recipient_role: Role) -> Vec<u8> {
        // application info is `"pda input share" || task_id || server_role` per
        // §4.2.2 Upload Request and §4.3.1 Aggregate Request
        [
            "pda input share".as_bytes(),
            task_id.as_bytes(),
            &[recipient_role as u8],
        ]
        .concat()
    }

    /// Construct an application info string suitable for constructing HPKE
    /// contexts for sealing or opening PPM output shares
    fn output_share_application_info(task_id: &TaskId, sender_role: Role) -> Vec<u8> {
        [
            "pda output share".as_bytes(),
            task_id.as_bytes(),
            &[sender_role as u8],
        ]
        .concat()
    }

    /// Construct an HPKE Sender suitable for encrypting `EncryptedInputShare`
    /// structures for inclusion in a PPM `Report`.
    pub fn report_sender(
        &self,
        task_id: &TaskId,
        recipient_role: Role,
    ) -> Result<Sender<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>, Error> {
        // TODO(timg) deal with algo IDs besides these ones -- but what would
        // this function even return then?
        self.supported_configuration()?;

        Sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>::new(
            self.id,
            &Self::report_application_info(task_id, recipient_role),
            &self.public_key,
        )
    }

    /// Construct an HPKE Recipient suitable for decrypting
    /// `EncryptedInputShare` structures from a PPM `Report`.
    pub fn report_recipient(
        &self,
        task_id: &TaskId,
        recipient_role: Role,
        encapsulated_context: &[u8],
    ) -> Result<Recipient<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>, Error> {
        // TODO(timg): as in sender(), figure out how to handle other specializations
        self.supported_configuration()?;

        let private_key = self
            .private_key
            .as_ref()
            .ok_or(Error::InvalidConfiguration("no private key"))?;

        Recipient::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>::new(
            &Self::report_application_info(task_id, recipient_role),
            private_key,
            encapsulated_context,
        )
    }

    /// Construct an HPKE sender suitable for use by leader or helper to encrypt
    /// `EncryptedOutputShare` structures to collector
    pub(crate) fn output_share_sender(
        &self,
        task_id: &TaskId,
        sender_role: Role,
    ) -> Result<Sender<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>, Error> {
        self.supported_configuration()?;

        Sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>::new(
            self.id,
            &Self::output_share_application_info(task_id, sender_role),
            &self.public_key,
        )
    }

    /// Construct an HPKE recipient suitable for use by collector to decrypt
    /// `EncryptedOutputShare` structures sent by leader or helper
    pub fn output_share_recipient(
        &self,
        task_id: &TaskId,
        sender_role: Role,
        encapsulated_context: &[u8],
    ) -> Result<Recipient<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>, Error> {
        self.supported_configuration()?;

        let private_key = self
            .private_key
            .as_ref()
            .ok_or(Error::InvalidConfiguration("no private key"))?;

        Recipient::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>::new(
            &Self::output_share_application_info(task_id, sender_role),
            private_key,
            encapsulated_context,
        )
    }
}

mod base64 {
    //! Custom serialization module used to serialize TaskId to base64
    use serde::{de::Error, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize_bytes<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        String::serialize(&base64::encode(v), s)
    }

    pub fn deserialize_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        base64::decode(String::deserialize(d)?.as_bytes()).map_err(Error::custom)
    }

    pub fn serialize_bytes_option<S: Serializer>(
        v: &Option<Vec<u8>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => String::serialize(&base64::encode(v), s),
            None => <Option<Vec<u8>>>::serialize(&None, s),
        }
    }

    pub fn deserialize_bytes_option<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Ok(Some(
            base64::decode(String::deserialize(d)?.as_bytes()).map_err(Error::custom)?,
        ))
    }
}

/// HPKE key encapsulation mechanism identifiers. For (de)serialization.
// TODO(timg) HPKE defines three more KEMs, but crate hpke only supports the
// following two
#[derive(Clone, Debug, Serialize_repr, Deserialize_repr, Eq, PartialEq)]
#[repr(u16)]
pub enum KeyEncapsulationMechanism {
    /// NIST P-256 keys and HKDF SHA-256
    P256HkdfSha256 = <DhP256HkdfSha256 as Kem>::KEM_ID,
    /// X25519 keys and HKDF SHA-256
    X25519HkdfSha256 = <X25519HkdfSha256 as Kem>::KEM_ID,
}

/// HPKE key derivation functions. For (de)serialization.
#[derive(Clone, Debug, Serialize_repr, Deserialize_repr, Eq, PartialEq)]
#[repr(u16)]
pub enum KeyDerivationFunction {
    /// HMAC Key Derivation Function SHA-256
    HkdfSha256 = <HkdfSha256 as Kdf>::KDF_ID,
    /// HMAC Key Derivation Function SHA-384
    HkdfSha384 = <HkdfSha384 as Kdf>::KDF_ID,
    /// HMAC Key Derivation Function SHA-512
    HkdfSha512 = <HkdfSha512 as Kdf>::KDF_ID,
}

/// HPKE authenticated encryption with associated data functions. For
/// (de)serialization.
#[derive(Clone, Debug, Serialize_repr, Deserialize_repr, Eq, PartialEq)]
#[repr(u16)]
pub enum AuthenticatedEncryptionWithAssociatedData {
    /// AES-128 in GCM mode
    AesGcm128 = <AesGcm128 as Aead>::AEAD_ID,
    /// AES-256 in GCM mode
    AesGcm256 = <AesGcm256 as Aead>::AEAD_ID,
    /// ChaCha20Poly1305
    ChaCha20Poly1305 = <ChaCha20Poly1305 as Aead>::AEAD_ID,
}

pub type DefaultSender =
    Sender<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, hpke::kem::X25519HkdfSha256>;

/// An HPKE sender that encrypts messages to some recipient public key using
/// a chosen set of AEAD, key derivation and key encapsulation algorithms.
pub struct Sender<Encrypt: Aead, Derive: Kdf, Encapsulate: Kem> {
    config_id: ConfigId,
    encapped_key: Encapsulate::EncappedKey,
    context: AeadCtxS<Encrypt, Derive, Encapsulate>,
}

impl<Encrypt: Aead, Derive: Kdf, Encapsulate: Kem> Sender<Encrypt, Derive, Encapsulate> {
    /// Instantiate a new Sender that encrypts messages to the provided
    /// recipient public key, entangling the provided application info into the
    /// context construction.)
    pub fn new(
        config_id: ConfigId,
        application_info: &[u8],
        serialized_recipient_public_key: &[u8],
    ) -> Result<Self, Error> {
        let mut rng = thread_rng();

        // Deserialize recipient pub into the appropriate PublicKey type for the
        // KEM
        let recipient_public_key =
            Encapsulate::PublicKey::from_bytes(serialized_recipient_public_key)?;

        let (encapped_key, context) = setup_sender::<Encrypt, Derive, Encapsulate, _>(
            &OpModeS::Base,
            &recipient_public_key,
            application_info,
            &mut rng,
        )?;

        Ok(Self {
            config_id,
            encapped_key,
            context,
        })
    }

    /// Encrypt the plaintext, incorporating AAD derived from `report`, and
    /// return the ciphertext, which consists of (ciphertext || tag), and is
    /// suitable as the value of `EncryptedInputShare.payload`. Also returns the
    /// encapped public key for sending to recipient.
    ///
    /// In PPM, an HPKE context can only be used once (we have no means of
    /// ensuring that sender and recipient "increment" nonces in lockstep), so
    /// this method consumes self.
    pub fn encrypt_input_share(
        mut self,
        timestamp: Nonce,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Encapsulate::EncappedKey), Error> {
        Ok((
            self.seal2(plaintext, &timestamp.associated_data())?,
            self.encapped_key,
        ))
    }

    pub fn encrypt_output_share(
        mut self,
        batch_interval: Interval,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Encapsulate::EncappedKey), Error> {
        Ok((
            self.seal2(plaintext, &batch_interval.associated_data())?,
            self.encapped_key,
        ))
    }

    pub fn seal(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<Ciphertext, Error> {
        Ok(Ciphertext {
            config_id: self.config_id,
            encapsulated_context: self.encapped_key.to_bytes().to_vec(),
            payload: self.context.seal(plaintext, associated_data)?,
        })
    }

    // TODO: Delete this once struct Report, etc. are updated
    fn seal2(&mut self, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.context.seal(plaintext, associated_data)?)
    }
}

/// An HPKE recipient that decrypts messages encrypted to its public key by some
/// sender public key, using a chosen set of AEAD, key derivation and key
/// encapsulation algorithms.
pub struct Recipient<Encrypt: Aead, Derive: Kdf, Encapsulate: Kem> {
    context: AeadCtxR<Encrypt, Derive, Encapsulate>,
}

impl<Encrypt: Aead, Derive: Kdf, Encapsulate: Kem> Recipient<Encrypt, Derive, Encapsulate> {
    pub fn new(
        application_info: &[u8],
        serialized_recipient_private_key: &[u8],
        serialized_sender_encapsulated_key: &[u8],
    ) -> Result<Self, Error> {
        // Deserialize recipient priv into the appropriate PrivateKey type for
        // the KEM
        let recipient_private_key =
            Encapsulate::PrivateKey::from_bytes(serialized_recipient_private_key)?;

        // Deserialize sender encapsulated pub into the appropriate EncappedKey
        // for the KEM
        let sender_encapped_key =
            Encapsulate::EncappedKey::from_bytes(serialized_sender_encapsulated_key)?;

        let context = setup_receiver::<Encrypt, Derive, Encapsulate>(
            &OpModeR::Base,
            &recipient_private_key,
            &sender_encapped_key,
            application_info,
        )?;

        Ok(Self { context })
    }

    /// Decrypt the input share from `report` for this `Recipient`'s server role
    /// and return the plaintext.
    ///
    /// In PPM, an HPKE context can only be used once (we have no means of
    /// ensuring that sender and recipient "increment" nonces in lockstep), so
    /// this method consumes self.
    pub fn decrypt_input_share(
        mut self,
        encrypted_input_share: &EncryptedInputShare,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.open2(&encrypted_input_share.payload, associated_data)
    }

    pub fn decrypt_output_share(
        mut self,
        encrypted_output_share: &EncryptedOutputShare,
        batch_interval: Interval,
    ) -> Result<Vec<u8>, Error> {
        self.open2(
            &encrypted_output_share.payload,
            &batch_interval.associated_data(),
        )
    }

    pub fn open(
        &mut self,
        ciphertext: &Ciphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Ok(self.context.open(&ciphertext.payload, associated_data)?)
    }

    //TODO: delete this once I clean up Report, etc.
    fn open2(&mut self, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.context.open(ciphertext, associated_data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchange_message() {
        // Sender and receiver must agree on info for all messages
        let application_info = b"shared application info";

        // Sender and receiver must agree on AAD for each message
        let message_associated_data = b"message associated data";

        let message = b"a message that is secret";

        let config = Config::new_recipient(
            KeyEncapsulationMechanism::X25519HkdfSha256,
            KeyDerivationFunction::HkdfSha256,
            AuthenticatedEncryptionWithAssociatedData::ChaCha20Poly1305,
        );

        // TODO(timg): Right now Sender is generic in algos, matching the generics
        // usage in crate hpke. That isn't especially graceful for our needs, since
        // we don't generally know at compile time what algorithms we use (that will
        // be determined by config files or by deserializing HPKE configs into
        // `Config`). The only way I can think of to do this right now is a big
        // match over fields of config so we can dispatch to the appropriate
        // specialization of Sender, but that is _a lot_ of match arms to write!
        let mut sender = match (&config.kem_id, &config.kdf_id, &config.aead_id) {
            (
                KeyEncapsulationMechanism::X25519HkdfSha256,
                KeyDerivationFunction::HkdfSha256,
                AuthenticatedEncryptionWithAssociatedData::ChaCha20Poly1305,
            ) => Sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>::new(
                config.id,
                application_info,
                &config.public_key,
            )
            .unwrap(),
            // TODO(timg): wire up more tuples of algos
            (_, _, _) => unimplemented!("unsupported set of algos"),
        };

        let ciphertext = sender.seal(message, message_associated_data).unwrap();

        let mut recipient = match (&config.kem_id, &config.kdf_id, &config.aead_id) {
            (
                KeyEncapsulationMechanism::X25519HkdfSha256,
                KeyDerivationFunction::HkdfSha256,
                AuthenticatedEncryptionWithAssociatedData::ChaCha20Poly1305,
            ) => Recipient::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>::new(
                application_info,
                &config.private_key.unwrap(),
                &sender.encapped_key.to_bytes(),
            )
            .unwrap(),
            (_, _, _) => unimplemented!("unsupported set of algos"),
        };

        let plaintext = recipient
            .open(&ciphertext, message_associated_data)
            .unwrap();

        assert_eq!(plaintext, message);
    }
}
