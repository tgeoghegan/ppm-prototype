use ::hpke::{
    aead::{Aead, AeadTag, AesGcm128, AesGcm256, ChaCha20Poly1305},
    kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf},
    kem::{DhP256HkdfSha256, X25519HkdfSha256},
    kex::KeyExchange,
    setup_receiver, setup_sender, AeadCtxR, AeadCtxS, Deserializable, EncappedKey, HpkeError, Kem,
    OpModeR, OpModeS, Serializable,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{parameters::TaskId, upload::Report};

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
}

#[derive(Copy, Clone, Debug, Serialize_repr, Deserialize_repr, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    Leader = 0x01,
    Helper = 0x00,
}

impl Role {
    /// Returns the index into protocol message vectors at which this role's
    /// entry can be found. e.g., the leader's input share in a `Report` is
    /// `Report.encrypted_input_shares[Role::Leader.role_index()]`.
    pub(crate) fn index(self) -> usize {
        match self {
            Role::Leader => 0,
            Role::Helper => 1,
        }
    }
}

/// HPKE configuration for a PPM participant, corresponding to `struct
/// HpkeConfig` in RFCXXXX.
// TODO: I wish we could do better than u16 for the kem/kedf/aead IDs, and
// better than Vec<u8> for the PK.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    /// Identifier of the HPKE configuration
    pub id: u8,
    pub(crate) kem_id: KeyEncapsulationMechanism,
    pub(crate) kdf_id: KeyDerivationFunction,
    pub(crate) aead_id: AuthenticatedEncryptionWithAssociatedData,
    /// The public key, serialized using the `SerializePublicKey` function as
    /// described in draft-irtf-cfrg-hpke-11, §4 and §7.1.1.
    pub(crate) public_key: Vec<u8>,
    /// The private key, serialized using the `SerializePrivateKey` function as
    /// described in draft-irtf-cfrg-hpke-11, §4 and §7.1.2. This value will not
    /// be present when advertised by a server from hpke_config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) private_key: Option<Vec<u8>>,
}

impl Config {
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
            id: 0,
            kem_id: kem,
            kdf_id: kdf,
            aead_id: aead,
            public_key: serialized_public_key,
            private_key: Some(serialized_private_key),
        }
    }

    /// Create a copy of the config without the private key, suitable for
    /// public advertising of HPKE config
    pub fn without_private_key(&self) -> Self {
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
            task_id,
            &[recipient_role as u8],
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
        report: &Report,
    ) -> Result<Recipient<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>, Error> {
        // TODO(timg): as in sender(), figure out how to handle other specializations
        self.supported_configuration()?;

        let private_key = self
            .private_key
            .as_ref()
            .ok_or(Error::InvalidConfiguration("no private key"))?;

        Recipient::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>::new(
            recipient_role,
            &Self::report_application_info(task_id, recipient_role),
            private_key,
            &report.encrypted_input_shares[recipient_role.index()].encapsulated_context,
        )
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

/// An HPKE sender that encrypts messages to some recipient public key using
/// a chosen set of AEAD, key derivation and key encapsulation algorithms.
pub struct Sender<Encrypt: Aead, Derive: Kdf, Encapsulate: Kem> {
    pub encapped_key: EncappedKey<Encapsulate::Kex>,
    context: AeadCtxS<Encrypt, Derive, Encapsulate>,
}

impl<Encrypt: Aead, Derive: Kdf, Encapsulate: Kem> Sender<Encrypt, Derive, Encapsulate> {
    /// Instantiate a new Sender that encrypts messages to the provided
    /// recipient public key, entangling the provided application info into the
    /// context construction.)
    pub fn new(
        application_info: &[u8],
        serialized_recipient_public_key: &[u8],
    ) -> Result<Self, Error> {
        let mut rng = thread_rng();

        // Deserialize recipient pub into the appropriate PublicKey type for the
        // KEM
        let recipient_public_key = <Encapsulate::Kex as KeyExchange>::PublicKey::from_bytes(
            serialized_recipient_public_key,
        )?;

        let (encapped_key, context) = setup_sender::<Encrypt, Derive, Encapsulate, _>(
            &OpModeS::Base,
            &recipient_public_key,
            application_info,
            &mut rng,
        )?;

        Ok(Self {
            encapped_key,
            context,
        })
    }

    /// Encrypt the plaintext, incorporating AAD derived from `report`, and
    /// return the ciphertext, which consists of (ciphertext || tag), and is
    /// suitable as the value of `EncryptedInputShare.payload`.
    pub fn encrypt_input_share(
        &mut self,
        report: &Report,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let (ciphertext, tag) = self.seal(plaintext, &report.associated_data())?;
        Ok([&ciphertext, tag.to_bytes().as_slice()].concat())
    }

    fn seal(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, AeadTag<Encrypt>), Error> {
        // AeadCtxS.seal() encrypts in-place, so make a copy to return to the
        // caller
        // TODO(timg): provide a seal_in_place variant for performance
        let mut plaintext_copy = plaintext.to_vec();
        let tag = self.context.seal(&mut plaintext_copy, associated_data)?;

        Ok((plaintext_copy, tag))
    }
}

/// An HPKE recipient that decrypts messages encrypted to its public key by some
/// sender public key, using a chosen set of AEAD, key derivation and key
/// encapsulation algorithms.
pub struct Recipient<Encrypt: Aead, Derive: Kdf, Encapsulate: Kem> {
    context: AeadCtxR<Encrypt, Derive, Encapsulate>,
    role: Role,
}

impl<Encrypt: Aead, Derive: Kdf, Encapsulate: Kem> Recipient<Encrypt, Derive, Encapsulate> {
    pub fn new(
        role: Role,
        application_info: &[u8],
        serialized_recipient_private_key: &[u8],
        serialized_sender_encapsulated_key: &[u8],
    ) -> Result<Self, Error> {
        // Deserialize recipient priv into the appropriate PrivateKey type for
        // the KEM
        let recipient_private_key = <Encapsulate::Kex as KeyExchange>::PrivateKey::from_bytes(
            serialized_recipient_private_key,
        )?;

        // Deserialize sender encapsulated pub into the appropriate EncappedKey
        // for the KEM
        let sender_encapped_key =
            EncappedKey::<Encapsulate::Kex>::from_bytes(serialized_sender_encapsulated_key)?;

        let context = setup_receiver::<Encrypt, Derive, Encapsulate>(
            &OpModeR::Base,
            &recipient_private_key,
            &sender_encapped_key,
            application_info,
        )?;

        Ok(Self { context, role })
    }

    /// Decrypt the input share from `report` for this `Recipient`'s server role
    /// and return the plaintext.
    pub fn decrypt_input_share(&mut self, report: &Report) -> Result<Vec<u8>, Error> {
        let tag_len = AeadTag::<Encrypt>::size();
        let payload = &report.encrypted_input_shares[self.role.index()].payload;

        // This assumes that `EncryptedInputShare.payload` consists of
        // (ciphertext || tag). That's true for all AEADs currently supported by
        // HPKE but may not always be true.
        let (ciphertext, tag) = payload.split_at(payload.len() - tag_len);
        self.open(ciphertext, &report.associated_data(), tag)
    }

    fn open(
        &mut self,
        ciphertext: &[u8],
        associated_data: &[u8],
        serialized_tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Deserialize tag into the appropriate AeadTag type for the cipher
        let tag = AeadTag::<Encrypt>::from_bytes(serialized_tag)?;

        // AeadCtxR.open() decrypts in-place, so make a copy to return to the
        // caller
        // TODO(timg): provide an open_in_place variant for performance
        let mut ciphertext_copy = ciphertext.to_vec();
        self.context
            .open(&mut ciphertext_copy, associated_data, &tag)?;

        Ok(ciphertext_copy)
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
        let message_associated_data_one = b"first message associated data";
        let message_associated_data_two = b"second message associated data";

        let message_one = b"a message that is secret";
        let message_two = b"another message that is secret";

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
                application_info,
                &config.public_key,
            )
            .unwrap(),
            // TODO(timg): wire up more tuples of algos
            (_, _, _) => unimplemented!("unsupported set of algos"),
        };

        let (ciphertext_one, tag_one) = sender
            .seal(message_one, message_associated_data_one)
            .unwrap();
        let (ciphertext_two, tag_two) = sender
            .seal(message_two, message_associated_data_two)
            .unwrap();

        let mut recipient = match (&config.kem_id, &config.kdf_id, &config.aead_id) {
            (
                KeyEncapsulationMechanism::X25519HkdfSha256,
                KeyDerivationFunction::HkdfSha256,
                AuthenticatedEncryptionWithAssociatedData::ChaCha20Poly1305,
            ) => Recipient::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>::new(
                Role::Leader,
                application_info,
                &config.private_key.unwrap(),
                &sender.encapped_key.to_bytes(),
            )
            .unwrap(),
            (_, _, _) => unimplemented!("unsupported set of algos"),
        };

        let plaintext_one = recipient
            .open(
                &ciphertext_one,
                message_associated_data_one,
                &tag_one.to_bytes(),
            )
            .unwrap();
        let plaintext_two = recipient
            .open(
                &ciphertext_two,
                message_associated_data_two,
                &tag_two.to_bytes(),
            )
            .unwrap();

        assert_eq!(plaintext_one, message_one);
        assert_eq!(plaintext_two, message_two);
    }
}