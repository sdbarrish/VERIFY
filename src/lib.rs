//! # VERIFY ledger prototype
//!
//! A purpose-built permissioned chain for the VERIFY election-integrity overlay
//! (Master White Paper, §6.3 "purpose-built chain" option).
//!
//! * **Quantum resistant**: every signature (transactions, block proposals,
//!   validator votes) is hybrid Ed25519 + ML-DSA-65 (FIPS 204); hashing is
//!   SHA3-256 with domain separation.
//! * **AI resistant**: AI/analytics keys are barred from signing, approving or
//!   validating by a CORE invariant no policy can override; consensus and
//!   validation are deterministic rule checks, not heuristics; low-entropy
//!   values are committed with 256-bit salts; all authority is multi-party.
//! * **Election-specific**: jurisdiction policy objects, m-of-n custody
//!   transitions, ballot reconciliation with quarantine, and 3-of-3
//!   independent emergency correction that appends rather than rewrites.
//!
//! No voter identity or vote selection can be expressed by any transaction type.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod codec;
pub mod consensus;
pub mod crypto;
pub mod merkle;
pub mod node;
pub mod policy;
pub mod state;
pub mod testkit;
pub mod tx;
