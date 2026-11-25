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

## 6. Mapping to the white paper's open decisions (§10.2)

| Open decision | Prototype choice | Status |
|---|---|---|
| Exact algorithms and hybrid policy | Ed25519 + ML-DSA-65, AND-composition, SHA3-256 | Proposed; needs independent cryptographic review |
| Consensus and validator governance | Permissioned BFT, n=3f+1, round-robin leader | Safety core only |
| Ballot unlinkability protocol | Batch-level commitments only (§3.1 recommendation) | Individual BPA design deferred |
| Legal role thresholds | 2-of-3 / 3-of-4 / 3-of-5 from §4.2 as an illustrative policy | Policy data, not code; per jurisdiction |
| Retention | Not modelled | Open |

## 7. Roadmap

1. Swap the demo seeds for HSM-backed keys and a documented key ceremony. SLH-DSA (FIPS 205) is the candidate for long-lived root keys.
2. Add ML-KEM-768 (FIPS 203) hybrid key establishment for confidential payloads and validator transport.
3. Networking with view change, using a published BFT protocol.
4. Persistent storage, checkpoints, and independent witness checkpoints exported to separate operators.
5. A sanitized, one-way export path for certified historical data feeding the isolated AI gateway (§8.4), with no reverse API.
6. Fuzzing of the codec and state machine, property tests, reproducible builds and signed releases (§6.4).
