# VERIFY Chain

A purpose-built permissioned ledger for **VERIFY** (Verifiable Election Framework for Integrity, Records & securitY), implementing the "purpose-built chain" option in Master White Paper §6.3.

It records election custody evidence, not votes. No transaction type can express a voter identity or a ballot selection.

> **Status: research prototype.** It runs a simulated custody workflow end to end and passes its acceptance tests. It has not had an independent security assessment, is not certified, and must not be used in a real election. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what is and is not covered.

## What makes it different

| Property | How it is achieved |
|---|---|
| **Quantum resistant** | Every signature (transaction approvals, block proposals, validator votes) is **hybrid Ed25519 + ML-DSA-65 (NIST FIPS 204)**. Both halves are mandatory, so an attacker has to break both. The suite ID is signed, so a signature cannot be downgraded. Hashing is SHA3-256 with domain separation, which leaves about 128-bit security against Grover's algorithm. |
| **AI resistant** | (1) **AI isolation is a protocol invariant (§8.4).** A key registered as analytics/AI can never sign, co-sign, approve or validate, and no policy can grant it a role. (2) **Nothing is decided by a heuristic.** Validity is deterministic rule checking over signed data, so there is no model to fool, poison or prompt-inject. (3) **Authority is cryptographic and multi-party.** Persuasive text, deepfaked voices and forged documents cannot produce an m-of-n hybrid signature quorum. (4) **No guessable secrets on the ledger.** Low-entropy values such as seal numbers and counts are committed with 256-bit random salts, so no amount of AI-assisted guessing recovers them. |
| **Quantum-safe confidentiality** | Confidential evidence (scanner images, recount worksheets) is sealed in envelopes using **hybrid X25519 + ML-KEM-768 (FIPS 203)** key establishment and ChaCha20-Poly1305, under a signed outer envelope that binds destination, recipient and ciphertext digest (§6.1). Only the envelope digest goes on the ledger. Ciphertext harvested today stays unreadable to a future quantum attacker. |
| **Byzantine fault tolerant, safe and live** | n = 3f+1 validators run round-based consensus with locking: proposal, prevote, precommit, then timeouts and view change. It follows the published Tendermint algorithm. A block is final only with n−f hybrid-signed precommits from validators that each re-executed it. A crashed or lying leader is replaced by view change, and offline validators catch up from peers, checking every certificate themselves. Double voting produces offline-verifiable equivocation evidence. |
| **Election-native rules** | Jurisdiction policy objects (§2), m-of-n custody transitions with role independence (§4.2), ballot reconciliation that quarantines on discrepancy (§1.2), a configuration lock at election commencement (§2.3), and 3-of-3 independent emergency correction that appends to history and never rewrites it (§4.3). |
| **Independently auditable** | Any operator can export the chain to a single canonical file. The separate `verify-audit` program holds no keys and trusts no node. Given the chain ID published by the election authority, it decodes the file strictly and replays it from genesis, re-checking every hash link, certificate, Merkle root and state transition. Any edit, deletion, reordering, stripped signature or single flipped bit is detected. |

## Quick start

```bash
cargo test --release                                     # 36 tests
cargo run --release --bin verify-sim -- --export chain.verify
cargo run --release --bin verify-audit -- chain.verify --expect-chain-id <id printed by the simulator>
```

`verify-audit` exits 0 when the file verifies, 1 when verification fails, and 2 on a usage or I/O error, so it can be scripted.

The simulator registers a 110,000-ballot batch and moves it through warehouse, transport, polling place, return and secure storage. It then reconciles the batch using the white paper's own figures (100,000 cast + 750 spoiled + 25 unreturned + 9,225 unused) and runs these attacks, each of which fails:

- an AI key moving custody, or co-signing with a valid quorum
- a single insider acting alone
- a forged post-quantum signature half
- replay of a final transaction
- a policy change in the middle of an election
- a Byzantine leader forging a state root
- validator double-voting
- editing or deleting stored history

It ends by running consensus on a simulated network under faults: a crashed leader, a 2|2 partition, loss of quorum and its recovery, an equivocating leader, and 7 validators with 2 Byzantine. Every run must stay safe (honest validators agree) and live (5 blocks final).

A second batch with 3 missing ballots is quarantined. The recount worksheet is sealed to the state division in a post-quantum envelope. It is blocked from canvass, refused a 2-of-3 correction, and released only by the county + state + independent 3-of-3 correction, with the original finding preserved.

## Layout

```
src/crypto.rs     hybrid Ed25519 + ML-DSA-65 signatures, SHA3-256, salted commitments
src/envelope.rs   sealed evidence: X25519 + ML-KEM-768, ChaCha20-Poly1305, signed outer envelope
src/codec.rs      canonical encoding and strict, bounded decoding of untrusted bytes
src/merkle.rs     RFC 9162-shaped Merkle trees and inclusion proofs
src/policy.rs     jurisdiction policy objects, approval rules, CORE invariants
src/tx.rs         transaction types (§6.1)
src/state.rs      CORE state machine: deterministic validation and application
src/consensus.rs  validator set, blocks, prevote/precommit votes, certificates, equivocation
src/bft.rs        round-based BFT (locking, timeouts, view change, catch-up) + simulated network
src/node.rs       validator node, block execution, independent auditor, chain export/import
src/testkit.rs    reference county policy and in-process network harness
src/bin/verify-sim.rs    narrated simulation (optionally exports the chain)
src/bin/verify-audit.rs  standalone auditor for exported chains
tests/acceptance.rs      acceptance tests mapped to white paper sections
tests/envelope.rs        sealed-envelope tests
tests/robustness.rs      strict decoding, random-input and bit-flip tests
tests/liveness.rs        crashes, partitions, asynchrony, Byzantine validators, lock rule
.github/workflows/ci.yml format, lint, test, simulate-export-audit on every push
docs/             architecture and threat model
```

Written in Rust with `#![forbid(unsafe_code)]`, bounded inputs and explicit errors, following the §6.4 high-assurance guidance.
