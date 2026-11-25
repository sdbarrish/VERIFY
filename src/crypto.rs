//! Hybrid classical + post-quantum cryptography (white paper §6.2).
//!
//! * Hashing: SHA3-256 with a mandatory domain-separation tag. Against a
//!   quantum adversary (Grover) preimage resistance stays at roughly 128 bits.
//! * Signatures: every signature is an AND-composition of Ed25519 (RFC 8032)
//!   and ML-DSA-65 (FIPS 204, NIST security category 3). Both halves sign the
//!   same canonical message, which also binds the suite identifier, so an
//!   attacker must break *both* schemes, and cannot strip one half or claim a
//!   weaker suite (downgrade).
//! * Commitments: salted with 256 bits of fresh randomness, so low-entropy
//!   values (a seal number, a ballot count) cannot be recovered by guessing,
//!   however much compute or AI assistance an attacker brings.

use crate::codec::{Canonical, Enc};
use ed25519_dalek::{Signature as EdSignature, Signer as _, SigningKey, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use sha3::{Digest, Sha3_256};
use std::fmt;

pub type Hash = [u8; 32];

/// Hybrid Ed25519 + ML-DSA-65. The only suite this build accepts.
pub const SUITE_HYBRID_ED25519_MLDSA65: u16 = 0x0101;

/// FIPS 204 context string. Binds every ML-DSA signature to this protocol.
const MLDSA_CTX: &[u8] = b"VERIFY-v1";

/// Domain-separated SHA3-256.
pub fn hash(domain: &str, data: &[u8]) -> Hash {
    let mut h = Sha3_256::new();
    h.update((domain.len() as u32).to_be_bytes());
    h.update(domain.as_bytes());
    h.update(data);
    h.finalize().into()
}

pub fn random_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS randomness unavailable");
    b
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn short(h: &Hash) -> String {
    hex(&h[..6])
}

/// Identifier of a public key: the hash of its canonical encoding.
pub type KeyId = Hash;

#[derive(Clone, PartialEq, Eq)]
pub struct HybridPublicKey {
    pub suite: u16,
    pub ed25519: [u8; 32],
    pub mldsa65: Vec<u8>,
}

impl fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridPublicKey({})", short(&self.id()))
    }
}

impl Canonical for HybridPublicKey {
    fn encode(&self, e: &mut Enc) {
        e.u16(self.suite).bytes(&self.ed25519).bytes(&self.mldsa65);
    }
}

impl HybridPublicKey {
    pub fn id(&self) -> KeyId {
        hash("VERIFY/key-id/v1", &self.to_canonical())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HybridSignature {
    pub suite: u16,
    pub ed25519: Vec<u8>,
    pub mldsa65: Vec<u8>,
}

impl fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HybridSignature(suite={:#06x}, {} bytes)", self.suite, self.ed25519.len() + self.mldsa65.len())
    }
}

impl Canonical for HybridSignature {
    fn encode(&self, e: &mut Enc) {
        e.u16(self.suite).bytes(&self.ed25519).bytes(&self.mldsa65);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigError {
    UnsupportedSuite(u16),
    Malformed,
    ClassicalInvalid,
    PostQuantumInvalid,
}

impl fmt::Display for SigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigError::UnsupportedSuite(s) => write!(f, "unsupported or downgraded signature suite {s:#06x}"),
            SigError::Malformed => write!(f, "malformed key or signature"),
            SigError::ClassicalInvalid => write!(f, "Ed25519 half of hybrid signature invalid"),
            SigError::PostQuantumInvalid => write!(f, "ML-DSA-65 half of hybrid signature invalid"),
        }
    }
}

/// Bytes actually signed by both halves: suite, domain and message, canonically encoded.
fn signing_input(suite: u16, domain: &str, msg: &[u8]) -> Vec<u8> {
    let mut e = Enc::new();
    e.str("VERIFY/sig/v1").u16(suite).str(domain).bytes(msg);
    e.finish()
}

/// A hybrid signing key. Secret material is zeroized on drop by the underlying crates.
pub struct HybridKeypair {
    ed: SigningKey,
    pq: ml_dsa_65::PrivateKey,
    public: HybridPublicKey,
}

impl HybridKeypair {
    /// Fresh key from OS randomness.
    pub fn generate() -> Self {
        Self::from_seed(&random_32())
    }

    /// Deterministic key from a 32-byte seed (key ceremonies, tests).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let ed_seed = hash("VERIFY/keygen/ed25519", seed);
        let pq_seed = hash("VERIFY/keygen/ml-dsa-65", seed);
        let ed = SigningKey::from_bytes(&ed_seed);
        let (pq_pk, pq) = ml_dsa_65::KG::keygen_from_seed(&pq_seed);
        let public = HybridPublicKey {
            suite: SUITE_HYBRID_ED25519_MLDSA65,
            ed25519: ed.verifying_key().to_bytes(),
            mldsa65: pq_pk.into_bytes().to_vec(),
        };
        Self { ed, pq, public }
    }

    pub fn public(&self) -> &HybridPublicKey {
        &self.public
    }

    pub fn id(&self) -> KeyId {
        self.public.id()
    }

    pub fn sign(&self, domain: &str, msg: &[u8]) -> HybridSignature {
        let input = signing_input(SUITE_HYBRID_ED25519_MLDSA65, domain, msg);
        let ed_sig = self.ed.sign(&input);
        let pq_sig = self.pq.try_sign(&input, MLDSA_CTX).expect("ML-DSA signing failed");
        HybridSignature {
            suite: SUITE_HYBRID_ED25519_MLDSA65,
            ed25519: ed_sig.to_bytes().to_vec(),
            mldsa65: pq_sig.to_vec(),
        }
    }
}

/// Verify a hybrid signature. Both halves must be valid; there is no fallback.
pub fn verify(pk: &HybridPublicKey, domain: &str, msg: &[u8], sig: &HybridSignature) -> Result<(), SigError> {
    if pk.suite != SUITE_HYBRID_ED25519_MLDSA65 {
        return Err(SigError::UnsupportedSuite(pk.suite));
    }
    if sig.suite != SUITE_HYBRID_ED25519_MLDSA65 {
        return Err(SigError::UnsupportedSuite(sig.suite));
    }
    let input = signing_input(sig.suite, domain, msg);

    let ed_pk = VerifyingKey::from_bytes(&pk.ed25519).map_err(|_| SigError::Malformed)?;
    let ed_bytes: [u8; 64] = sig.ed25519.as_slice().try_into().map_err(|_| SigError::Malformed)?;
    ed_pk
        .verify_strict(&input, &EdSignature::from_bytes(&ed_bytes))
        .map_err(|_| SigError::ClassicalInvalid)?;

    let pk_bytes: [u8; ml_dsa_65::PK_LEN] = pk.mldsa65.as_slice().try_into().map_err(|_| SigError::Malformed)?;
    let pq_pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes).map_err(|_| SigError::Malformed)?;
    let sig_bytes: [u8; ml_dsa_65::SIG_LEN] = sig.mldsa65.as_slice().try_into().map_err(|_| SigError::Malformed)?;
    if !pq_pk.verify(&input, &sig_bytes, MLDSA_CTX) {
        return Err(SigError::PostQuantumInvalid);
    }
    Ok(())
}

/// A hiding, binding commitment: `H(salt || value)` with a 256-bit random salt.
/// Only the commitment goes on the ledger; the opening stays with the custodian.
#[derive(Clone)]
pub struct CommitmentOpening {
    pub salt: [u8; 32],
    pub value: Vec<u8>,
}

impl CommitmentOpening {
    pub fn new(value: &[u8]) -> Self {
        Self { salt: random_32(), value: value.to_vec() }
    }
    pub fn commitment(&self) -> Hash {
        let mut e = Enc::new();
        e.hash(&self.salt).bytes(&self.value);
        hash("VERIFY/commitment/v1", &e.finish())
    }
    pub fn opens(&self, c: &Hash) -> bool {
        &self.commitment() == c
    }
}
