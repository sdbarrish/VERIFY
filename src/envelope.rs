//! Sealed evidence envelopes (white paper §6.1): quantum-safe confidentiality.
//!
//! Signatures protect integrity. Confidential evidence also needs encryption
//! that stays secret after quantum computers arrive, because ciphertext can be
//! harvested today and decrypted later. Each envelope uses:
//!
//! * **Hybrid key establishment**: X25519 *and* ML-KEM-768 (FIPS 203). The two
//!   shared secrets are combined with SHA3-256 over both secrets, both
//!   ciphertexts and the recipient key ID (an X-Wing-style combiner), so the
//!   key stays secret as long as either scheme holds.
//! * **Authenticated encryption**: ChaCha20-Poly1305 with the full envelope
//!   header as associated data.
//! * **Signed outer envelope**: the sender's hybrid signature binds the protocol
//!   version, destination, recipient key ID and ciphertext digest. Re-encryption
//!   to a new recipient produces a new, separately signed envelope.
//!
//! Only `Envelope::digest()` goes on the ledger, as an `evidence_commitment`.

use crate::codec::{Canonical, Dec, Decode, DecodeError, Enc};
use crate::crypto::{
    hash, random_32, verify, Hash, HybridKeypair, HybridPublicKey, HybridSignature, KeyId,
};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use std::fmt;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

pub const ENVELOPE_VERSION: u16 = 1;
pub const KEM_SUITE_X25519_MLKEM768: u16 = 0x0201;
const ENVELOPE_DOMAIN: &str = "VERIFY/envelope/v1";
/// Largest plaintext an envelope will carry (scanned images, worksheets).
pub const MAX_PLAINTEXT: usize = 16 << 20;

#[derive(Clone, PartialEq, Eq)]
pub struct KemPublicKey {
    pub suite: u16,
    pub x25519: [u8; 32],
    pub mlkem768: Vec<u8>,
}

impl fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemPublicKey({})", crate::crypto::short(&self.id()))
    }
}

impl Canonical for KemPublicKey {
    fn encode(&self, e: &mut Enc) {
        e.u16(self.suite).bytes(&self.x25519).bytes(&self.mlkem768);
    }
}

impl Decode for KemPublicKey {
    fn decode(d: &mut Dec<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            suite: d.u16()?,
            x25519: d.fixed()?,
            mlkem768: d.bytes()?,
        })
    }
}

impl KemPublicKey {
    pub fn id(&self) -> KeyId {
        hash("VERIFY/kem-key-id/v1", &self.to_canonical())
    }
}

/// A recipient's decryption key. Kept separate from signing keys (§6.2).
pub struct KemKeypair {
    x: StaticSecret,
    dk: ml_kem_768::DecapsKey,
    public: KemPublicKey,
}

impl KemKeypair {
    pub fn generate() -> Self {
        Self::from_seed(&random_32())
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let x = StaticSecret::from(hash("VERIFY/kemgen/x25519", seed));
        let (ek, dk) = ml_kem_768::KG::keygen_from_seed(
            hash("VERIFY/kemgen/ml-kem-d", seed),
            hash("VERIFY/kemgen/ml-kem-z", seed),
        );
        let public = KemPublicKey {
            suite: KEM_SUITE_X25519_MLKEM768,
            x25519: XPublic::from(&x).to_bytes(),
            mlkem768: ek.into_bytes().to_vec(),
        };
        Self { x, dk, public }
    }

    pub fn public(&self) -> &KemPublicKey {
        &self.public
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub version: u16,
    pub kem_suite: u16,
    pub sender: KeyId,
    pub recipient: KeyId,
    pub destination: String,
    pub x25519_ephemeral: [u8; 32],
    pub mlkem_ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub signature: HybridSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    UnsupportedVersion,
    WrongRecipient,
    WrongDestination,
    WrongSender,
    BadSignature,
    Malformed,
    DecryptionFailed,
    TooLarge,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = match self {
            EnvelopeError::UnsupportedVersion => "unsupported envelope version or KEM suite",
            EnvelopeError::WrongRecipient => "envelope is addressed to a different key",
            EnvelopeError::WrongDestination => "envelope is addressed to a different destination",
            EnvelopeError::WrongSender => "envelope was not sent by the expected key",
            EnvelopeError::BadSignature => "outer signature invalid",
            EnvelopeError::Malformed => "malformed key or ciphertext",
            EnvelopeError::DecryptionFailed => "authenticated decryption failed",
            EnvelopeError::TooLarge => "plaintext exceeds limit",
        };
        f.write_str(m)
    }
}

impl std::error::Error for EnvelopeError {}

impl Envelope {
    /// Everything except the signature: AEAD associated data and signed content.
    fn header(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u16(self.version)
            .u16(self.kem_suite)
            .hash(&self.sender)
            .hash(&self.recipient)
            .str(&self.destination);
        e.hash(&self.x25519_ephemeral)
            .bytes(&self.mlkem_ciphertext)
            .bytes(&self.nonce);
        e.finish()
    }

    fn signed_message(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.bytes(&self.header())
            .hash(&hash("VERIFY/envelope-ct/v1", &self.ciphertext));
        e.finish()
    }

    /// The value recorded on the ledger as an evidence commitment.
    pub fn digest(&self) -> Hash {
        hash("VERIFY/envelope-digest/v1", &self.to_canonical())
    }

    pub fn seal(
        sender: &HybridKeypair,
        recipient: &KemPublicKey,
        destination: &str,
        plaintext: &[u8],
    ) -> Result<Self, EnvelopeError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(EnvelopeError::TooLarge);
        }
        if recipient.suite != KEM_SUITE_X25519_MLKEM768 {
            return Err(EnvelopeError::UnsupportedVersion);
        }
        let eph = StaticSecret::from(random_32());
        let x_ss = eph.diffie_hellman(&XPublic::from(recipient.x25519));
        if !x_ss.was_contributory() {
            return Err(EnvelopeError::Malformed);
        }
        let ek_bytes: [u8; ml_kem_768::EK_LEN] = recipient
            .mlkem768
            .as_slice()
            .try_into()
            .map_err(|_| EnvelopeError::Malformed)?;
        let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_bytes)
            .map_err(|_| EnvelopeError::Malformed)?;
        let (pq_ss, pq_ct) = ek.try_encaps().map_err(|_| EnvelopeError::Malformed)?;

        let mut env = Envelope {
            version: ENVELOPE_VERSION,
            kem_suite: KEM_SUITE_X25519_MLKEM768,
            sender: sender.id(),
            recipient: recipient.id(),
            destination: destination.to_string(),
            x25519_ephemeral: XPublic::from(&eph).to_bytes(),
            mlkem_ciphertext: pq_ct.into_bytes().to_vec(),
            nonce: random_32()[..12].try_into().expect("12 bytes"),
            ciphertext: vec![],
            signature: HybridSignature {
                suite: 0,
                ed25519: vec![],
                mldsa65: vec![],
            },
        };
        let key = combine(x_ss.as_bytes(), &pq_ss.into_bytes(), &env);
        let aad = env.header();
        env.ciphertext = ChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(
                Nonce::from_slice(&env.nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| EnvelopeError::Malformed)?;
        env.signature = sender.sign(ENVELOPE_DOMAIN, &env.signed_message());
        Ok(env)
    }

    /// Verify the sender's signature first, then decrypt. Nothing is decrypted
    /// for an envelope whose origin or addressing does not check out.
    pub fn open(
        &self,
        recipient: &KemKeypair,
        sender: &HybridPublicKey,
        expected_destination: &str,
    ) -> Result<Vec<u8>, EnvelopeError> {
        if self.version != ENVELOPE_VERSION || self.kem_suite != KEM_SUITE_X25519_MLKEM768 {
            return Err(EnvelopeError::UnsupportedVersion);
        }
        if self.recipient != recipient.public.id() {
            return Err(EnvelopeError::WrongRecipient);
        }
        if self.destination != expected_destination {
            return Err(EnvelopeError::WrongDestination);
        }
        if self.sender != sender.id() {
            return Err(EnvelopeError::WrongSender);
        }
        verify(
            sender,
            ENVELOPE_DOMAIN,
            &self.signed_message(),
            &self.signature,
        )
        .map_err(|_| EnvelopeError::BadSignature)?;

        let x_ss = recipient
            .x
            .diffie_hellman(&XPublic::from(self.x25519_ephemeral));
        if !x_ss.was_contributory() {
            return Err(EnvelopeError::Malformed);
        }
        let ct_bytes: [u8; ml_kem_768::CT_LEN] = self
            .mlkem_ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| EnvelopeError::Malformed)?;
        let ct = ml_kem_768::CipherText::try_from_bytes(ct_bytes)
            .map_err(|_| EnvelopeError::Malformed)?;
        let pq_ss = recipient
            .dk
            .try_decaps(&ct)
            .map_err(|_| EnvelopeError::Malformed)?;
        let key = combine(x_ss.as_bytes(), &pq_ss.into_bytes(), self);
        ChaCha20Poly1305::new(Key::from_slice(&key))
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &self.header(),
                },
            )
            .map_err(|_| EnvelopeError::DecryptionFailed)
    }
}

/// Hybrid combiner: the key depends on both shared secrets and on the full
/// transcript, so neither KEM alone determines it.
fn combine(x_ss: &[u8; 32], pq_ss: &[u8; 32], env: &Envelope) -> [u8; 32] {
    let mut e = Enc::new();
    e.hash(x_ss)
        .hash(pq_ss)
        .hash(&env.x25519_ephemeral)
        .bytes(&env.mlkem_ciphertext)
        .hash(&env.recipient);
    hash("VERIFY/kem-combiner/x25519-mlkem768/v1", &e.finish())
}

impl Canonical for Envelope {
    fn encode(&self, e: &mut Enc) {
        e.u16(self.version)
            .u16(self.kem_suite)
            .hash(&self.sender)
            .hash(&self.recipient)
            .str(&self.destination);
        e.hash(&self.x25519_ephemeral)
            .bytes(&self.mlkem_ciphertext)
            .bytes(&self.nonce)
            .bytes(&self.ciphertext);
        self.signature.encode(e);
    }
}

impl Decode for Envelope {
    fn decode(d: &mut Dec<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            version: d.u16()?,
            kem_suite: d.u16()?,
            sender: d.hash()?,
            recipient: d.hash()?,
            destination: d.str()?,
            x25519_ephemeral: d.hash()?,
            mlkem_ciphertext: d.bytes()?,
            nonce: d.fixed()?,
            ciphertext: d.bytes()?,
            signature: HybridSignature::decode(d)?,
        })
    }
}
