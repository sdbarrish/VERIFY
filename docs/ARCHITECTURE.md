# VERIFY Chain architecture

This document maps the prototype to the VERIFY Master White Paper (Rev 1.0, 25 Nov 2026).

## 1. Layers

```
 ┌───────────────────────────────────────────────────────────────┐
 │ Independent auditor (node::audit)  — no keys, replays from genesis
 ├───────────────────────────────────────────────────────────────┤
 │ Consensus (bft.rs, consensus.rs, node.rs)                     │
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
- Votes come in two kinds, **prevote** and **precommit**. The kind is inside the signed bytes, and a vote may target a block or **nil**.
- A quorum certificate holds n−f distinct, valid precommits for exactly that header, all from one round. Nodes commit only with a valid quorum certificate.
- `EquivocationEvidence` is two valid votes of the same kind from one validator for different targets at the same height and round.

### Round-based protocol (`bft.rs`)

The protocol follows the published Tendermint algorithm (Buchman, Kwon and Milosevic, 2018). At each height, round r runs as follows:

1. **Propose.** The leader of (height, r) signs a proposal. If it holds a block that already gathered n−f prevotes (a "polka"), it re-proposes that block and names the round of the polka.
2. **Prevote.** A validator prevotes the proposal only if it re-executes validly and is compatible with the validator's lock: it is not locked, it is locked on this same block, or the proposal carries a polka newer than the lock. Otherwise it prevotes nil, or it prevotes nil when the propose timeout expires.
3. **Precommit.** On n−f prevotes for the proposal, the validator **locks** on the block and precommits it. On n−f nil prevotes, or when the prevote timeout expires, it precommits nil.
4. **Commit or next round.** n−f precommits for a block in any round commit it. Otherwise the precommit timeout starts round r+1 with the next leader. Timeouts grow by a fixed step each round. Seeing f+1 validators in a later round makes a validator jump ahead, because at least one of them is honest.

**Safety argument:** any two quorums of size n−f intersect in at least n−2f ≥ f+1 validators, so at least one honest validator is in both.
- Within a round, that honest validator does not precommit two blocks.
- Across rounds, the lock stops it prevoting a conflicting block unless a newer polka exists, and a newer polka also needs that overlap.

This holds under any message timing.

**Liveness:** once message delays fall below the growing timeouts, some round has an honest leader, and every honest validator commits.

**Catch-up and recovery:**
- A validator's consensus state is durable. After a restart it resumes its round and step, never an earlier step, so it cannot vote twice.
- It asks peers for committed blocks and re-verifies every certificate itself.
- Peers also re-send their signed proposals and votes for the current height. Relaying is safe because everything is signed.

### Simulated network and tests

`SimNet` is a deterministic, seeded, in-process network. It models random delays, validator outages with or without recovery, partitions (messages held until the split heals) and equivocating Byzantine validators. `tests/liveness.rs` covers:

- honest runs across seeds, with the independent audit;
- view change after a crashed leader;
- f+1 validators down (no commits), then recovery;
- catch-up of a recovered validator;
- a 2|2 partition (no commits), then heal;
- an equivocating leader and voter (agreement holds, evidence collected, no honest validator accused);
- 7 validators with 2 Byzantine;
- delays far beyond the timeouts, where safety holds without liveness;
- a message-by-message test of the lock rule.

Two quality checks were run outside the committed suite:
- A 200-run seed sweep found 0 forks.
- Disabling the lock rule was caught by the lock-rule test. The randomized tests alone did not catch it, which is why that test exists.

### Validator processes, transport and storage

`verify-node` runs the same replica logic as the simulation, as an OS process:

- **Transport** (`transport.rs`). The dialler sends an ephemeral X25519 key and an ephemeral ML-KEM-768 encapsulation key. The responder encapsulates and signs the transcript with its hybrid validator key; the dialler checks it is the validator it meant to reach, then signs the full transcript.
  - Session keys come from SHA3 over both shared secrets and the transcript, one key per direction.
  - Frames are ChaCha20-Poly1305 with a 64-bit counter nonce, so a replayed, reordered or altered frame closes the channel.
  - Only validators in the genesis set can complete a handshake. Both KEM keys are ephemeral, so the links are forward secret against classical and quantum attackers.
- **Storage** (`store.rs`). Committed blocks are appended and synced. A torn final write is trimmed on start, and every stored block is re-verified (certificate, links, re-execution) before it is trusted.
  - Consensus state ([`Durable`]: round, step, lock, valid block, own votes and proposals) is replaced atomically.
- **Write-ahead rule.** After every event the node persists new blocks, then consensus state, and only then lets the event's messages out. A crash can lose messages, which peers recover by re-sync, but never a vote or a lock. A restarted validator resumes at its saved step, so it cannot vote twice.
- **Re-sync.** Dialers reconnect forever. A node that has not advanced for 3 seconds asks peers for committed blocks and for current-height messages.
- **Block rate.** A configurable pause between heights (`--block-interval-ms`, Tendermint's commit timeout) stops a fast network minting empty blocks continuously.

`tests/network.rs` runs four `verify-node` processes on localhost.
- It SIGKILLs one validator, checks the other three continue, restarts it from disk and checks it catches up.
- It starts only two of four and checks nothing commits, then adds a third and checks progress.
- After each run, every stored chain must agree, and the longest must pass the independent audit.

**Not yet implemented:**
- deployment across separate sites and operators;
- validator keys loaded from HSMs (the processes use demo keys);
- a transaction submission API (the demo loads transactions from a file);
- validator set reconfiguration;
- removal or slashing based on equivocation evidence;
- rate limiting and denial-of-service protection for connections and gossip.

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
2. Multi-site deployment tests of `verify-node` over real networks (single-machine multi-process tests are done), then connection rate limiting and a transaction submission API.
3. Persistent storage, checkpoints, and independent witness checkpoints held by separate operators.
4. A sanitized, one-way export path for certified historical data feeding the isolated AI gateway (§8.4), with no reverse API.
5. Coverage-guided fuzzing (cargo-fuzz) of the codec and state machine, reproducible builds and signed releases (§6.4).
6. A formal requirements and threat-model package for the simulated custody workflow (§10.4).
