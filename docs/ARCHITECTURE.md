# VERIFY Chain architecture

This document maps the prototype to the VERIFY Master White Paper (Rev 1.0, 25 Nov 2026).

## 1. Layers

```
 ┌───────────────────────────────────────────────────────────────┐
 │ Independent auditor (node::audit)  — no keys, replays from genesis
 ├───────────────────────────────────────────────────────────────┤
 │ Consensus (consensus.rs, node.rs)                             │
 │   leader schedule · proposal sig · re-execution · votes · QC  │
 ├───────────────────────────────────────────────────────────────┤
 │ CORE state machine (state.rs)                                 │
 │   CORE invariants · policy rules · custody · reconciliation   │
 ├───────────────────────────────────────────────────────────────┤
 │ Policy objects (policy.rs)   Transactions (tx.rs)             │
 ├───────────────────────────────────────────────────────────────┤
 │ Crypto (crypto.rs) · Canonical codec (codec.rs) · Merkle      │
 └───────────────────────────────────────────────────────────────┘
```

## 2. Cryptography (§6.2)

| Use | Primitive | Notes |
|---|---|---|
| All signatures | Ed25519 **AND** ML-DSA-65 | Both verify over `("VERIFY/sig/v1", suite, domain, message)`. ML-DSA also uses the FIPS 204 context `VERIFY-v1`. |
| Hash | SHA3-256 | Each use has its own domain tag: `key-id`, `tx`, `block`, `vote`, `proposal`, `policy`, `state-root`, `merkle/leaf`, `merkle/node`, `commitment`, `chain-id`. |
| Commitments | `H(salt₂₅₆ ‖ value)` | The opening stays with the custodian, and only the commitment goes on the ledger. |
| Key IDs | `H(canonical public key)` | Binds the suite and both public keys. |
| Confidential evidence | X25519 **AND** ML-KEM-768, ChaCha20-Poly1305 | Key = SHA3(`ss_x25519 ‖ ss_mlkem ‖ eph ‖ kem_ct ‖ recipient_id`), an X-Wing-style combiner. The AEAD's associated data is the whole header. The sender's hybrid signature covers header + ciphertext digest and is checked **before** decryption. Recipients' KEM keys are separate from their signing keys. |

**Downgrade resistance:** this build accepts exactly one suite, `0x0101`. The suite ID is inside the signed bytes, so altering it invalidates both halves.

**Key separation (§6.2):** genesis rejects overlap between validator and root keys, and policy activation rejects any principal that reuses a validator or root key.

**Why hybrid rather than PQ-only:** ML-DSA is new, and implementation bugs in new schemes are the realistic near-term risk. Ed25519 is mature but would fall to a cryptographically relevant quantum computer. Requiring both means the system stays secure as long as either scheme holds.

## 3. Transactions (§6.1)

Each transaction body binds the following fields:

- protocol version and chain ID (cross-chain replay)
- election and jurisdiction scope
- origin key, which must also approve
- a strictly increasing per-origin nonce (replay)
- an expiry height, at most `MAX_TTL` ahead
- the predecessor, which must be the batch's latest transaction so parallel or forked histories are rejected
- the payload

`tx id = H(body)`. Every approver signs the id, so all approvers sign the same canonical message.

The payload is one of: `ActivatePolicy`, `CommenceElection`, `RegisterBatch`, `CustodyTransfer`, `Reconcile`, `EmergencyCorrection`.

## 4. CORE invariants (cannot be changed by policy)

1. **AI isolation.** An `AnalyticsAi` principal never holds a role, and any transaction with an AI signer is rejected, in every jurisdiction.
2. **Multi-party root authority.** Genesis needs at least 2 root approvers to activate policy or commence an election.
3. **Approver eligibility.** Every approver must be eligible, meet the m-of-n threshold, and cover the required number of distinct roles.
4. **Configuration lock.** Once an election commences, its policy cannot change.
5. **Append-only correction.** Emergency correction needs at least 2 distinct roles including an independent authority, exactly one signer per role, and no signer of the corrected transaction. It appends a record and preserves the original finding.
6. **Exceptions are findings, not verdicts.** A broken seal or a reconciliation discrepancy is recorded and the batch is quarantined. The transaction is not silently rejected and the batch is not silently passed.
7. **No vote data.** No transaction type has a field for voter identity or selection.

## 5. Consensus (§6.3)

- n = 3f+1 validators, quorum = n−f. The leader is chosen round-robin by `(height + round) mod n`.
- The leader proposes a header containing `prev`, `tx_root`, `tx_count`, `state_root` and `proposer`, and signs it.
- Each validator checks the link, the leader schedule, the proposer signature and the Merkle root. It then **re-executes every transaction** and votes only if its own state root matches.
- A quorum certificate holds n−f distinct, valid, hybrid-signed votes for exactly that header. Nodes commit only with a valid quorum certificate.
- `EquivocationEvidence` is two valid votes from one validator for different blocks at the same height and round.
- **Safety argument:** any two quorums of size n−f intersect in at least n−2f ≥ f+1 validators, so at least one honest validator is in both, and that validator never signs two blocks at one height.

**Not yet implemented:** peer-to-peer networking, view change and timeouts (liveness under a faulty leader), validator set reconfiguration, and slashing or removal flows. A production design would adopt a published protocol such as HotStuff-2 or Tendermint for these and keep the existing safety core and hybrid signatures.

## 6. Export and independent audit

`export_chain` writes `"VERIFY-CHAIN-EXPORT/v1" ‖ genesis ‖ blocks` in canonical encoding. `import_chain` is strict:

- Every length is bounded by the remaining input before anything is allocated.
- Tags and booleans must take one of their defined values.
- Strings must be valid UTF-8.
- Trailing bytes are rejected.

As a result, decode-then-encode reproduces the file byte for byte (tested), so there is never a second encoding of the same history.

Trust comes from the **chain ID**, which is the hash of the genesis. The election authority publishes it through a separate channel, such as a public notice or a signed press release. `verify-audit --expect-chain-id` then needs no other trust.

**Storage cost:** post-quantum signatures are large. ML-DSA-65 signatures are 3,309 bytes, and with four votes per block the demo chain of 29 blocks and 21 transactions exports to about 0.74 MB. That suits custody events, which number in the thousands to millions per election, not per second. Benchmarking at realistic scale is still to do (§6.2).

## 7. Mapping to the white paper's open decisions (§10.2)

| Open decision | Prototype choice | Status |
|---|---|---|
| Exact algorithms and hybrid policy | Ed25519 + ML-DSA-65, AND-composition, SHA3-256 | Proposed; needs independent cryptographic review |
| Consensus and validator governance | Permissioned BFT, n=3f+1, round-robin leader | Safety core only |
| Ballot unlinkability protocol | Batch-level commitments only (§3.1 recommendation) | Individual BPA design deferred |
| Legal role thresholds | 2-of-3 / 3-of-4 / 3-of-5 from §4.2 as an illustrative policy | Policy data, not code; per jurisdiction |
| Retention | Not modelled | Open |

## 8. Roadmap

Done:
- ML-KEM-768 hybrid envelopes for confidential evidence.
- Strict decoder, chain export and standalone auditor.
- Randomized robustness tests.
- CI.

Next:
1. Swap the demo seeds for HSM-backed keys and a documented key ceremony. SLH-DSA (FIPS 205) is the candidate for long-lived root keys.
2. Networking with view change, using a published BFT protocol. Validator transport would reuse the hybrid KEM.
3. Persistent storage, checkpoints, and independent witness checkpoints held by separate operators.
4. A sanitized, one-way export path for certified historical data feeding the isolated AI gateway (§8.4), with no reverse API.
5. Coverage-guided fuzzing (cargo-fuzz) of the codec and state machine, reproducible builds and signed releases (§6.4).
6. A formal requirements and threat-model package for the simulated custody workflow (§10.4).
