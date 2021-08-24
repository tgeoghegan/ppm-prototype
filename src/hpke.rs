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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Wrapper around errors from crate hpke. See `hpke::HpkeError` for more
    /// details on possible variants.
    #[error("HPKE error")]
    Hpke(#[from] HpkeError),
}

/// HPKE configuration for a PPM participant, corresponding to `struct
/// HpkeConfig` in RFCXXXX.
// TODO: I wish we could do better than u16 for the kem/kedf/aead IDs, and
// better than Vec<u8> for the PK.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    /// Identifier of the HPKE configuration
    pub(crate) id: u8,
    pub(crate) kem_id: KeyEncapsulationMechanism,
    pub(crate) kdf_id: KeyDerivationFunction,
    pub(crate) aead_id: AuthenticatedEncryptionWithAssociatedData,
    /// The public key, serialized using the `SerializePublicKey` function as
    /// described in draft-irtf-cfrg-hpke-11, §4 and §7.1.1.
    pub(crate) public_key: Vec<u8>,
    /// The private key, serialized using the `SerializePrivateKey` function as
    /// described in draft-irtf-cfrg-hpke-11, §4 and §7.1.2. This value will not
    /// be present when advertised by a server from hpke_config.
    pub(crate) private_key: Option<Vec<u8>>,
}

impl Config {
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

    pub fn seal(
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
}

impl<Encrypt: Aead, Derive: Kdf, Encapsulate: Kem> Recipient<Encrypt, Derive, Encapsulate> {
    pub fn new(
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

        Ok(Self { context })
    }

    pub fn open(
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
mod hpke {
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
