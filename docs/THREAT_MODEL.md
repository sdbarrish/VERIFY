# Threat model and test mapping

This document scopes the prototype against White Paper §8.1. Each row names the acceptance test that exercises the control, where one exists.

## What "quantum resistant" means here

A future cryptographically relevant quantum computer breaks Ed25519 and other elliptic-curve and RSA signatures (Shor's algorithm) and halves the effective strength of hashes (Grover's algorithm).

- Signatures: every authorizing signature also carries ML-DSA-65 (FIPS 204, NIST category 3), and verification requires it. Forging an approval, a proposal or a vote needs an ML-DSA forgery.
- Hashes: SHA3-256 keeps about 128-bit preimage security under Grover.
- **Harvest-now-forge-later:** the ledger's integrity rests on hybrid signatures from day one, so recorded history stays unforgeable after classical signatures fall.
- **Harvest-now-decrypt-later:** confidential evidence is sealed with hybrid X25519 + ML-KEM-768, so it stays secret unless both schemes are broken (`tests/envelope.rs`).
- **Not yet covered:** validator-to-validator transport, because there is no networking yet. Archives still need re-anchoring if ML-DSA itself is weakened (§6.2).

## What "AI resistant" means here

No system is AI-proof. This design uses a concrete threat list and gives a mitigation for each item.

| AI-enabled threat | Mitigation in this design | Test |
|---|---|---|
| An AI system with access to live election systems acts or is manipulated into acting | AI keys can never sign or co-sign, and policy cannot grant them a role (CORE invariant) | `ai_key_cannot_sign_even_alongside_a_valid_quorum`, `policy_cannot_grant_ai_a_role_or_reuse_validator_keys` |
| Deepfakes, social engineering and fabricated documents used to obtain approvals | Approval is an m-of-n hybrid signature quorum across independent roles. Persuasion alone cannot produce one; it has to compromise several keys held by independent people | `thresholds_roles_and_independence_are_enforced` |
| Adversarial inputs, poisoning or prompt injection against a detector | There is no ML in validation or consensus. Validity is deterministic rule evaluation, and every honest node computes the same answer | all state tests |
| AI-accelerated brute force of low-entropy identifiers | Values are committed with 256-bit salts, and only commitments are on the ledger | `commitments_hide_low_entropy_values` |
| AI-assisted fabrication of plausible records or history | Records need valid hybrid signatures, links to their predecessors, and quorum certificates. The independent auditor detects any edit | `auditor_verifies_honest_chain_and_detects_tampering` |
| AI-assisted discovery of implementation bugs | Rust with `forbid(unsafe_code)`, bounded inputs, explicit errors, one strict canonical codec, randomized robustness tests, and CI on every push. **Coverage-guided fuzzing and independent review are still required** | `tests/robustness.rs` |

## Controls by threat (§8.1)

| Threat | Control | Test |
|---|---|---|
| Single-insider custody change | m-of-n plus role independence | `thresholds_roles_and_independence_are_enforced` |
| Skipped custody states | Only declared transitions, and `from` must equal the current state | same |
| Replay, cross-chain replay | Monotonic nonce, chain ID in body, expiry window | `replay_cross_chain_expiry_and_predecessor_protection` |
| Forked or reordered batch history | Predecessor must be the batch tip | same |
| Payload altered after approval | Approvals sign `H(body)` | `tampered_approval_is_rejected` |
| Signature downgrade, stripping one half | Suite ID is signed, and both halves are required | `hybrid_signature_requires_both_halves_and_rejects_downgrade` |
| Unauthorized mid-election policy change | Configuration lock, 2-of-3 roots | `policy_is_locked_after_commencement` |
| Missing ballots treated as zero | Reconciliation identity, quarantine, block on further custody | `discrepancy_quarantine_and_emergency_correction` |
| Abuse of emergency override | Exactly one signer per required role, an independent authority, no signer of the original transaction, append-only | same |
| Broken seal | Recorded as an exception, batch quarantined | `broken_seal_is_recorded_and_quarantines` |
| Byzantine leader forges result | Validators re-execute and compare state roots | `byzantine_leader_cannot_forge_state` |
| Under-signed or forged certificate | Requires n−f distinct, valid votes | `certificates_need_a_quorum_of_distinct_valid_votes` |
| Validator equivocation | Verifiable evidence | `equivocation_produces_verifiable_evidence` |
| Edited, deleted, reordered or re-signed history | Independent full replay | `auditor_verifies_honest_chain_and_detects_tampering` |
| Malformed or hostile input bytes | Strict bounded decoder, no panics, no oversized allocations | `random_bytes_never_panic_the_decoders`, `every_truncation_and_extension_is_rejected` |
| Silent corruption or tampering of an exported chain | Every byte is covered by a hash or signature, and the standalone auditor replays everything | `any_single_bit_flip_is_detected`, `export_round_trips_exactly_and_audits` |
| Fake chain substituted wholesale | Auditor checks the chain ID against the value published out of band | `verify-audit --expect-chain-id` |
| Evidence read or redirected in transit | Hybrid KEM + AEAD; signed outer envelope checked before decryption | `round_trip_and_addressing`, `any_modification_is_detected` |
| Validator/official key reuse | Rejected at genesis and at policy activation | `policy_cannot_grant_ai_a_role_or_reuse_validator_keys` |

## Out of scope / residual risk

These items are not addressed by the prototype. Nothing on this list is claimed as covered.

- More than f colluding validators, or more than the threshold of colluding officials. Independence is an organizational property.
- Key theft from endpoints. HSMs and authenticators (§3.2) are not modelled.
- Coercion, vote buying, false source data and physical destruction (§8.1). The ledger proves who signed, not what is physically true.
- Liveness and denial of service: no networking, view change or rate limiting yet.
- Metadata linkage from timing (§3.1).
- Completeness: Merkle inclusion proves membership only. Completeness comes from reconciliation against physical inventory.
- Demo keys are derived from public seeds and are **for simulation only**.
