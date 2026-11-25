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
