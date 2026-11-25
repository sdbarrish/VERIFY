# VERIFY Chain

A purpose-built permissioned ledger for **VERIFY** (Verifiable Election Framework for Integrity, Records & securitY), implementing the "purpose-built chain" option in Master White Paper §6.3.

It records election custody evidence, not votes. No transaction type can express a voter identity or a ballot selection.

> **Status: research prototype.** It runs a simulated custody workflow end to end and passes its acceptance tests. It has not had an independent security assessment, is not certified, and must not be used in a real election. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what is and is not covered.

## What makes it different

| Property | How it is achieved |
|---|---|
| **Quantum resistant** | Every signature (transaction approvals, block proposals, validator votes) is **hybrid Ed25519 + ML-DSA-65 (NIST FIPS 204)**. Both halves are mandatory, so an attacker has to break both. The suite ID is signed, so a signature cannot be downgraded. Hashing is SHA3-256 with domain separation, which leaves about 128-bit security against Grover's algorithm. |
| **AI resistant** | (1) **AI isolation is a protocol invariant (§8.4).** A key registered as analytics/AI can never sign, co-sign, approve or validate, and no policy can grant it a role. (2) **Nothing is decided by a heuristic.** Validity is deterministic rule checking over signed data, so there is no model to fool, poison or prompt-inject. (3) **Authority is cryptographic and multi-party.** Persuasive text, deepfaked voices and forged documents cannot produce an m-of-n hybrid signature quorum. (4) **No guessable secrets on the ledger.** Low-entropy values such as seal numbers and counts are committed with 256-bit random salts, so no amount of AI-assisted guessing recovers them. |
| **Byzantine fault tolerant** | n = 3f+1 validators. A block is final only with a quorum certificate of n−f hybrid-signed votes, each from a validator that re-executed the block and got the same state root. Double voting produces offline-verifiable equivocation evidence. |
| **Election-native rules** | Jurisdiction policy objects (§2), m-of-n custody transitions with role independence (§4.2), ballot reconciliation that quarantines on discrepancy (§1.2), a configuration lock at election commencement (§2.3), and 3-of-3 independent emergency correction that appends to history and never rewrites it (§4.3). |
| **Independently auditable** | `audit()` holds no keys and trusts no node. Starting from genesis it re-verifies every hash link, certificate, Merkle root and state transition, so edits, deletions, reordering and stripped signatures are detected. |

## Quick start

```bash
cargo test --release          # 16 acceptance and unit tests
cargo run --release --bin verify-sim
```

The simulator registers a 110,000-ballot batch and moves it through warehouse, transport, polling place, return and secure storage. It then reconciles the batch using the white paper's own figures (100,000 cast + 750 spoiled + 25 unreturned + 9,225 unused) and runs these attacks, each of which fails:

- an AI key moving custody, or co-signing with a valid quorum
- a single insider acting alone
- a forged post-quantum signature half
- replay of a final transaction
- a policy change in the middle of an election
- a Byzantine leader forging a state root
- validator double-voting
- editing or deleting stored history

A second batch with 3 missing ballots is quarantined. It is blocked from canvass, refused a 2-of-3 correction, and released only by the county + state + independent 3-of-3 correction, with the original finding preserved.

## Layout

```
src/crypto.rs     hybrid Ed25519 + ML-DSA-65 signatures, SHA3-256, salted commitments
src/codec.rs      canonical length-prefixed encoding for everything signed or hashed
src/merkle.rs     RFC 9162-shaped Merkle trees and inclusion proofs
src/policy.rs     jurisdiction policy objects, approval rules, CORE invariants
src/tx.rs         transaction types (§6.1)
src/state.rs      CORE state machine: deterministic validation and application
src/consensus.rs  validator set, proposals, votes, quorum certificates, equivocation
src/node.rs       validator node, block execution, independent auditor
src/testkit.rs    reference county policy and in-process network harness
src/bin/verify-sim.rs   narrated simulation
tests/acceptance.rs     acceptance tests mapped to white paper sections
docs/             architecture and threat model
```

Written in Rust with `#![forbid(unsafe_code)]`, bounded inputs and explicit errors, following the §6.4 high-assurance guidance.
