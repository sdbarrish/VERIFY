//! Canonical, unambiguous binary encoding (white paper §6.1).
//!
//! Everything that is hashed or signed is encoded through [`Enc`]. The format
//! is deliberately trivial: fixed-width big-endian integers, and every
//! variable-length field is length-prefixed. There is exactly one encoding for
//! any value, so two parties can never disagree about what was signed, and a
//! field boundary can never be shifted to make one message read as another.

use crate::crypto::Hash;

#[derive(Default)]
pub struct Enc(Vec<u8>);

impl Enc {
    pub fn new() -> Self {
        Self(Vec::with_capacity(256))
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(v as u8)
    }
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        let len = u32::try_from(v.len()).expect("field exceeds 4 GiB");
        self.u32(len);
        self.0.extend_from_slice(v);
        self
    }
    pub fn str(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }
    pub fn hash(&mut self, v: &Hash) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }
    pub fn opt_hash(&mut self, v: &Option<Hash>) -> &mut Self {
        match v {
            None => self.u8(0),
            Some(h) => self.u8(1).hash(h),
        }
    }
    pub fn list<T: Canonical>(&mut self, items: &[T]) -> &mut Self {
        let len = u32::try_from(items.len()).expect("list too long");
        self.u32(len);
        for it in items {
            it.encode(self);
        }
        self
    }
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// A type with exactly one byte representation.
pub trait Canonical {
    fn encode(&self, e: &mut Enc);

    fn to_canonical(&self) -> Vec<u8> {
        let mut e = Enc::new();
        self.encode(&mut e);
        e.finish()
    }
}

impl Canonical for String {
    fn encode(&self, e: &mut Enc) {
        e.str(self);
    }
}

impl Canonical for Hash {
    fn encode(&self, e: &mut Enc) {
        e.hash(self);
    }
}

/// Why bytes were refused. Decoding is strict: one encoding per value, so
/// decode-then-encode always reproduces the input exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "decode error: {}", self.0)
    }
}

impl std::error::Error for DecodeError {}

pub fn derr<T>(m: impl Into<String>) -> Result<T, DecodeError> {
    Err(DecodeError(m.into()))
}

/// Bounded reader over untrusted bytes. Never panics and never allocates more
/// than the input could justify.
pub struct Dec<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Dec<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return derr(format!("truncated: need {n} bytes at offset {}", self.pos));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.arr()?))
    }
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.arr()?))
    }
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.arr()?))
    }
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            b => derr(format!("non-canonical bool {b}")),
        }
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let v = self.bytes()?;
        v.as_slice()
            .try_into()
            .map_err(|_| DecodeError(format!("expected {N} bytes, got {}", v.len())))
    }
    pub fn str(&mut self) -> Result<String, DecodeError> {
        String::from_utf8(self.bytes()?).map_err(|_| DecodeError("invalid UTF-8".into()))
    }
    pub fn hash(&mut self) -> Result<Hash, DecodeError> {
        self.arr()
    }
    pub fn opt_hash(&mut self) -> Result<Option<Hash>, DecodeError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.hash()?)),
            t => derr(format!("bad option tag {t}")),
        }
    }
    /// Every element encodes to at least one byte, so a count larger than the
    /// remaining input is rejected before allocating.
    pub fn list<T: Decode>(&mut self, max: usize) -> Result<Vec<T>, DecodeError> {
        let n = self.u32()? as usize;
        if n > max || n > self.remaining() {
            return derr(format!("list of {n} exceeds bound"));
        }
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(T::decode(self)?);
        }
        Ok(v)
    }
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.remaining() != 0 {
            return derr(format!("{} trailing bytes", self.remaining()));
        }
        Ok(())
    }
}

pub trait Decode: Sized {
    fn decode(d: &mut Dec<'_>) -> Result<Self, DecodeError>;

    fn from_canonical(b: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Dec::new(b);
        let v = Self::decode(&mut d)?;
        d.finish()?;
        Ok(v)
    }
}

/// Upper bound for small lists (roles, states, approvals).
pub const SMALL_LIST: usize = 1 << 12;

impl Decode for String {
    fn decode(d: &mut Dec<'_>) -> Result<Self, DecodeError> {
        d.str()
    }
}

impl Decode for Hash {
    fn decode(d: &mut Dec<'_>) -> Result<Self, DecodeError> {
        d.hash()
    }
}
