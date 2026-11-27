//! Authenticated, quantum-safe validator transport (SR-06 applied to links,
//! SR-18 over real networks).
//!
//! **Handshake** (initiator I dials responder R; both know the validator set):
//!
//! 1. I → R `Hello`: chain ID, I's key ID, a fresh X25519 public key, a fresh
//!    ML-KEM-768 encapsulation key, and a 32-byte nonce.
//! 2. R → I `Reply`: R's key ID, a fresh X25519 public key, an ML-KEM
//!    ciphertext encapsulated to I's key, a nonce, and R's hybrid
//!    (Ed25519 + ML-DSA-65) signature over the transcript so far.
//! 3. I → R `Finish`: I's hybrid signature over the whole transcript.
//!
//! Session keys come from SHA3 over both shared secrets and the transcript
//! hash. Both KEM keys are ephemeral, so recording traffic today and breaking
//! a long-term key later reveals nothing: forward secrecy, against classical
//! and quantum attackers. Each side proves possession of its validator key, so
//! no one outside the validator set can join or impersonate a member.
//!
//! **Frames:** a 4-byte length, then ChaCha20-Poly1305 with a per-direction
//! key and a strictly increasing 64-bit counter as the nonce. A replayed,
//! reordered, dropped-then-resent or modified frame fails authentication and
//! closes the channel.

use crate::codec::{Canonical, Dec, Decode, Enc};
use crate::crypto::{
    hash, random_32, verify, Hash, HybridKeypair, HybridPublicKey, HybridSignature, KeyId,
};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

const PROTOCOL: &str = "VERIFY-P2P/v1";
const MAX_HANDSHAKE_FRAME: usize = 64 * 1024;
/// Largest encrypted frame accepted (a full block with its certificate fits).
pub const MAX_FRAME: usize = 64 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    Protocol(String),
    UnknownPeer,
    WrongPeer,
    BadSignature,
    FrameTooLarge(usize),
    /// Frame failed authentication: tampered, replayed, reordered or wrong key.
    Authentication,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "I/O: {e}"),
            TransportError::Protocol(m) => write!(f, "protocol: {m}"),
            TransportError::UnknownPeer => write!(f, "peer is not a validator"),
            TransportError::WrongPeer => write!(f, "peer is not the validator we dialled"),
            TransportError::BadSignature => write!(f, "handshake signature invalid"),
            TransportError::FrameTooLarge(n) => write!(f, "frame of {n} bytes exceeds limit"),
            TransportError::Authentication => write!(f, "frame failed authentication"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        TransportError::Io(e)
    }
}

fn perr<T>(m: impl Into<String>) -> Result<T, TransportError> {
    Err(TransportError::Protocol(m.into()))
}

fn write_plain(s: &mut TcpStream, b: &[u8]) -> Result<(), TransportError> {
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(b)?;
    s.flush()?;
    Ok(())
}

fn read_len(s: &mut TcpStream, max: usize) -> Result<Vec<u8>, TransportError> {
    let mut l = [0u8; 4];
    s.read_exact(&mut l)?;
    let n = u32::from_be_bytes(l) as usize;
    if n > max {
        return Err(TransportError::FrameTooLarge(n));
    }
    let mut b = vec![0u8; n];
    s.read_exact(&mut b)?;
    Ok(b)
}

/// One direction of an established channel: key plus frame counter.
struct CipherState {
    aead: ChaCha20Poly1305,
    counter: u64,
}

impl CipherState {
    fn new(key: &Hash) -> Self {
        Self {
            aead: ChaCha20Poly1305::new(Key::from_slice(key)),
            counter: 0,
        }
    }
    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.counter.to_be_bytes());
        n
    }
    fn seal(&mut self, pt: &[u8]) -> Vec<u8> {
        let ct = self
            .aead
            .encrypt(Nonce::from_slice(&self.nonce()), pt)
            .expect("encryption cannot fail");
        self.counter = self
            .counter
            .checked_add(1)
            .expect("frame counter exhausted");
        ct
    }
    fn open(&mut self, ct: &[u8]) -> Result<Vec<u8>, TransportError> {
        let pt = self
            .aead
            .decrypt(Nonce::from_slice(&self.nonce()), ct)
            .map_err(|_| TransportError::Authentication)?;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(TransportError::Authentication)?;
        Ok(pt)
    }
}

pub struct SecureWriter {
    stream: TcpStream,
    cipher: CipherState,
}

impl SecureWriter {
    /// Encrypt one frame without sending it.
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.cipher.seal(plaintext)
    }
    /// Send an already-sealed frame. Exposed so tests can attempt replays and
    /// tampering; a frame not produced in sequence by this channel is rejected.
    pub fn send_sealed(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > MAX_FRAME {
            return Err(TransportError::FrameTooLarge(frame.len()));
        }
        write_plain(&mut self.stream, frame)
    }
    pub fn send(&mut self, plaintext: &[u8]) -> Result<(), TransportError> {
        let f = self.seal(plaintext);
        self.send_sealed(&f)
    }
}

pub struct SecureReader {
    stream: TcpStream,
    cipher: CipherState,
}

impl SecureReader {
    pub fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        let f = read_len(&mut self.stream, MAX_FRAME)?;
        self.cipher.open(&f)
    }
}

/// An authenticated channel: who is on the other end, and both halves.
pub struct Channel {
    pub peer: HybridPublicKey,
    pub reader: SecureReader,
    pub writer: SecureWriter,
}

struct Hello {
    chain_id: Hash,
    initiator: KeyId,
    x25519: [u8; 32],
    mlkem_ek: Vec<u8>,
    nonce: Hash,
}

impl Hello {
    fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.str(PROTOCOL)
            .hash(&self.chain_id)
            .hash(&self.initiator)
            .hash(&self.x25519)
            .bytes(&self.mlkem_ek)
            .hash(&self.nonce);
        e.finish()
    }
    fn decode(b: &[u8]) -> Result<Self, TransportError> {
        let mut d = Dec::new(b);
        let r = (|| {
            if d.str()? != PROTOCOL {
                return crate::codec::derr("protocol");
            }
            Ok(Hello {
                chain_id: d.hash()?,
                initiator: d.hash()?,
                x25519: d.hash()?,
                mlkem_ek: d.bytes()?,
                nonce: d.hash()?,
            })
        })();
        let h = r.map_err(|e| TransportError::Protocol(e.to_string()))?;
        d.finish()
            .map_err(|e| TransportError::Protocol(e.to_string()))?;
        Ok(h)
    }
}

/// Reply without its signature: what the responder signs (with the Hello).
fn reply_body(responder: &KeyId, x25519: &[u8; 32], ct: &[u8], nonce: &Hash) -> Vec<u8> {
    let mut e = Enc::new();
    e.hash(responder).hash(x25519).bytes(ct).hash(nonce);
    e.finish()
}

fn transcript(parts: &[&[u8]]) -> Hash {
    let mut e = Enc::new();
    for p in parts {
        e.bytes(p);
    }
    hash("VERIFY/p2p-transcript/v1", &e.finish())
}

fn session_keys(x_ss: &[u8; 32], pq_ss: &[u8; 32], th: &Hash) -> (Hash, Hash) {
    let mut e = Enc::new();
    e.hash(x_ss).hash(pq_ss).hash(th);
    let master = hash("VERIFY/p2p-kdf/x25519-mlkem768/v1", &e.finish());
    (
        hash("VERIFY/p2p-key/initiator-to-responder", &master),
        hash("VERIFY/p2p-key/responder-to-initiator", &master),
    )
}

fn split(
    stream: TcpStream,
    send: Hash,
    recv: Hash,
    peer: HybridPublicKey,
) -> Result<Channel, TransportError> {
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    stream.set_nodelay(true)?;
    let r = stream.try_clone()?;
    Ok(Channel {
        peer,
        reader: SecureReader {
            stream: r,
            cipher: CipherState::new(&recv),
        },
        writer: SecureWriter {
            stream,
            cipher: CipherState::new(&send),
        },
    })
}

/// Dial side. `expected` is the validator we meant to reach.
pub fn connect(
    mut stream: TcpStream,
    me: &HybridKeypair,
    chain_id: Hash,
    expected: &HybridPublicKey,
) -> Result<Channel, TransportError> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let eph = StaticSecret::from(random_32());
    let (ek, dk) = ml_kem_768::KG::try_keygen().map_err(|e| TransportError::Protocol(e.into()))?;
    let hello = Hello {
        chain_id,
        initiator: me.id(),
        x25519: XPublic::from(&eph).to_bytes(),
        mlkem_ek: ek.into_bytes().to_vec(),
        nonce: random_32(),
    };
    let hello_b = hello.encode();
    write_plain(&mut stream, &hello_b)?;

    let reply = read_len(&mut stream, MAX_HANDSHAKE_FRAME)?;
    let mut d = Dec::new(&reply);
    let parsed = (|| {
        Ok::<_, crate::codec::DecodeError>((
            d.hash()?,
            d.hash()?,
            d.bytes()?,
            d.hash()?,
            HybridSignature::decode(&mut d)?,
        ))
    })();
    let (rid, rx, ct, rnonce, rsig) =
        parsed.map_err(|e| TransportError::Protocol(e.to_string()))?;
    d.finish()
        .map_err(|e| TransportError::Protocol(e.to_string()))?;
    if rid != expected.id() {
        return Err(TransportError::WrongPeer);
    }
    let body = reply_body(&rid, &rx, &ct, &rnonce);
    let th2 = transcript(&[&hello_b, &body]);
    verify(expected, "VERIFY/p2p-responder/v1", &th2, &rsig)
        .map_err(|_| TransportError::BadSignature)?;

    let x_ss = eph.diffie_hellman(&XPublic::from(rx));
    if !x_ss.was_contributory() {
        return perr("non-contributory X25519 share");
    }
    let ct_arr: [u8; ml_kem_768::CT_LEN] = ct
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::Protocol("ML-KEM ciphertext length".into()))?;
    let ct = ml_kem_768::CipherText::try_from_bytes(ct_arr)
        .map_err(|e| TransportError::Protocol(e.into()))?;
    let pq_ss = dk
        .try_decaps(&ct)
        .map_err(|e| TransportError::Protocol(e.into()))?;

    let th3 = transcript(&[&hello_b, &body, &rsig.to_canonical()]);
    let fin = me.sign("VERIFY/p2p-initiator/v1", &th3);
    write_plain(&mut stream, &fin.to_canonical())?;

    let (i2r, r2i) = session_keys(x_ss.as_bytes(), &pq_ss.into_bytes(), &th3);
    split(stream, i2r, r2i, expected.clone())
}

/// Listen side. Accepts only initiators in `validators` (and never itself).
pub fn accept(
    mut stream: TcpStream,
    me: &HybridKeypair,
    chain_id: Hash,
    validators: &[HybridPublicKey],
) -> Result<Channel, TransportError> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let hello_b = read_len(&mut stream, MAX_HANDSHAKE_FRAME)?;
    let hello = Hello::decode(&hello_b)?;
    if hello.chain_id != chain_id {
        return perr("different chain");
    }
    let peer = validators
        .iter()
        .find(|k| k.id() == hello.initiator && k.id() != me.id())
        .cloned()
        .ok_or(TransportError::UnknownPeer)?;
    let ek_arr: [u8; ml_kem_768::EK_LEN] = hello
        .mlkem_ek
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::Protocol("ML-KEM key length".into()))?;
    let ek = ml_kem_768::EncapsKey::try_from_bytes(ek_arr)
        .map_err(|e| TransportError::Protocol(e.into()))?;
    let (pq_ss, ct) = ek
        .try_encaps()
        .map_err(|e| TransportError::Protocol(e.into()))?;
    let eph = StaticSecret::from(random_32());
    let x_ss = eph.diffie_hellman(&XPublic::from(hello.x25519));
    if !x_ss.was_contributory() {
        return perr("non-contributory X25519 share");
    }
    let rx = XPublic::from(&eph).to_bytes();
    let ct_b = ct.into_bytes().to_vec();
    let nonce = random_32();
    let body = reply_body(&me.id(), &rx, &ct_b, &nonce);
    let th2 = transcript(&[&hello_b, &body]);
    let sig = me.sign("VERIFY/p2p-responder/v1", &th2);
    let mut e = Enc::new();
    e.hash(&me.id()).hash(&rx).bytes(&ct_b).hash(&nonce);
    sig.encode(&mut e);
    write_plain(&mut stream, &e.finish())?;

    let fin_b = read_len(&mut stream, MAX_HANDSHAKE_FRAME)?;
    let fin = HybridSignature::from_canonical(&fin_b)
        .map_err(|e| TransportError::Protocol(e.to_string()))?;
    let th3 = transcript(&[&hello_b, &body, &sig.to_canonical()]);
    verify(&peer, "VERIFY/p2p-initiator/v1", &th3, &fin)
        .map_err(|_| TransportError::BadSignature)?;

    let (i2r, r2i) = session_keys(x_ss.as_bytes(), &pq_ss.into_bytes(), &th3);
    split(stream, r2i, i2r, peer)
}
