//! Acceptance tests mapped to white paper requirements (section numbers in names/comments).

use verify_chain::consensus::{Block, EquivocationEvidence, QuorumCertificate, Vote};
use verify_chain::crypto::{verify, CommitmentOpening, HybridKeypair, SigError, SUITE_HYBRID_ED25519_MLDSA65};
use verify_chain::node::{audit, certify};
use verify_chain::policy::PrincipalClass;
use verify_chain::state::{Outcome, Reject};
use verify_chain::testkit::*;
use verify_chain::tx::{Payload, Reconciliation};

fn walk_to_secure_storage(net: &mut Network, batch: &str) {
    for (from, to, who) in HAPPY_PATH {
        let tx = net.transfer_tx(batch, from, to, who, true);
        assert_eq!(net.submit_one(tx), Ok(Outcome::Applied), "{from} -> {to}");
    }
}

fn leader_key(net: &Network) -> HybridKeypair {
    let id = net.nodes[0].validators.leader(net.height(), 0);
    VALIDATORS.iter().map(|v| demo_key(v)).find(|k| k.id() == id).unwrap()
}

// §6.2 — hybrid classical + post-quantum signatures, both halves mandatory.
#[test]
fn hybrid_signature_requires_both_halves_and_rejects_downgrade() {
    let k = HybridKeypair::generate();
    let sig = k.sign("test", b"message");
    assert!(verify(k.public(), "test", b"message", &sig).is_ok());
    assert!(verify(k.public(), "other-domain", b"message", &sig).is_err(), "domain separation");

    let mut bad = sig.clone();
    bad.ed25519[5] ^= 1;
    assert_eq!(verify(k.public(), "test", b"message", &bad), Err(SigError::ClassicalInvalid));

    let mut bad = sig.clone();
    bad.mldsa65[100] ^= 1;
    assert_eq!(verify(k.public(), "test", b"message", &bad), Err(SigError::PostQuantumInvalid));

    let mut stripped = sig.clone();
    stripped.mldsa65.clear();
    assert_eq!(verify(k.public(), "test", b"message", &stripped), Err(SigError::Malformed));

    let mut downgraded = sig;
    downgraded.suite = 0x0001;
    assert!(matches!(verify(k.public(), "test", b"message", &downgraded), Err(SigError::UnsupportedSuite(_))));
    assert_eq!(k.public().suite, SUITE_HYBRID_ED25519_MLDSA65);
}

// §4.1, §4.2 — full custody lifecycle and the white paper's reconciliation example.
#[test]
fn custody_lifecycle_and_balanced_reconciliation() {
    let mut net = Network::new();
    net.bootstrap();
    net.register("PCT-0001", 110_000);
    walk_to_secure_storage(&mut net, "PCT-0001");

    let pred = net.batch_tip("PCT-0001");
    let report = Reconciliation { supplied: 110_000, cast: 100_000, spoiled: 750, issued_unreturned: 25, unused: 9_225, ..Default::default() };
    let tx = net.tx(&["canvass-1", "canvass-2", "canvass-3"], Payload::Reconcile { batch_id: "PCT-0001".into(), report }, Some(pred));
    assert_eq!(net.submit_one(tx), Ok(Outcome::Applied));

    let b = &net.nodes[0].state.batches["PCT-0001"];
    assert_eq!(b.state, "SecureStorage");
    assert!(!b.quarantined);
    assert_eq!(b.history.len(), 8);
    // Every validator independently reached the same state.
    let root = net.nodes[0].state.root();
    assert!(net.nodes.iter().all(|n| n.state.root() == root));
}

// §8.4 — AI isolation is a CORE invariant.
#[test]
fn ai_key_cannot_sign_even_alongside_a_valid_quorum() {
    let mut net = Network::new();
    net.bootstrap();
    net.register("PCT-0001", 500);
    let tx = net.transfer_tx("PCT-0001", "Produced", "WarehouseSealed", &["insights-ai"], true);
    assert!(matches!(net.submit_one(tx), Err(Reject::AiIsolation(_))));

    let tx = net.transfer_tx("PCT-0001", "Produced", "WarehouseSealed", &["warehouse-1", "warehouse-2", "insights-ai"], true);
    assert!(matches!(net.submit_one(tx), Err(Reject::AiIsolation(_))));
    assert_eq!(net.nodes[0].state.batches["PCT-0001"].state, "Produced");
}

#[test]
fn policy_cannot_grant_ai_a_role_or_reuse_validator_keys() {
    let mut net = Network::new();
    let mut p = reference_policy();
    p.principals.iter_mut().find(|x| x.class == PrincipalClass::AnalyticsAi).unwrap().role = Some("canvassing_board".into());
    let tx = net.tx(&["root-county", "root-state"], Payload::ActivatePolicy(p), None);
    assert!(matches!(net.submit_one(tx), Err(Reject::AiIsolation(_))));

    let mut p = reference_policy();
    p.principals[0].key = demo_key(VALIDATORS[0]).public().clone();
    let tx = net.tx(&["root-county", "root-state"], Payload::ActivatePolicy(p), None);
    assert!(matches!(net.submit_one(tx), Err(Reject::PolicyViolation(_))));
}

// §4.2 — m-of-n thresholds, eligible roles, and role independence.
#[test]
fn thresholds_roles_and_independence_are_enforced() {
    let mut net = Network::new();
    net.bootstrap();
    net.register("PCT-0001", 500);

    let tx = net.transfer_tx("PCT-0001", "Produced", "WarehouseSealed", &["warehouse-1"], true);
    assert!(matches!(net.submit_one(tx), Err(Reject::InsufficientApprovals(_))), "1-of-3 is not 2-of-3");

    let tx = net.transfer_tx("PCT-0001", "Produced", "WarehouseSealed", &["warehouse-1", "clerk-1"], true);
    assert!(matches!(net.submit_one(tx), Err(Reject::Unauthorized(_))), "clerk is not eligible");

    let tx = net.transfer_tx("PCT-0001", "Produced", "WarehouseSealed", &["warehouse-1", "warehouse-2"], true);
    assert_eq!(net.submit_one(tx), Ok(Outcome::Applied));

    // Release needs two *different* roles: two warehouse custodians are not independent.
    let tx = net.transfer_tx("PCT-0001", "WarehouseSealed", "OutboundTransit", &["warehouse-1", "warehouse-2"], true);
    assert!(matches!(net.submit_one(tx), Err(Reject::InsufficientApprovals(_))));

    // Skipping states is not a permitted transition.
    let tx = net.transfer_tx("PCT-0001", "WarehouseSealed", "SecureStorage", &["warehouse-1", "transport-1", "warehouse-3"], true);
    assert!(matches!(net.submit_one(tx), Err(Reject::PolicyViolation(_))));
}

// §6.1 — replay, cross-chain replay, expiry and predecessor binding.
#[test]
fn replay_cross_chain_expiry_and_predecessor_protection() {
    let mut net = Network::new();
    net.bootstrap();
    net.register("PCT-0001", 500);
    let tx = net.transfer_tx("PCT-0001", "Produced", "WarehouseSealed", &["warehouse-1", "warehouse-2"], true);
    assert_eq!(net.submit_one(tx.clone()), Ok(Outcome::Applied));
    assert_eq!(net.submit_one(tx), Err(Reject::Replay));

    let mut other = net.transfer_tx("PCT-0001", "WarehouseSealed", "OutboundTransit", &["warehouse-3", "transport-1"], true);
    other.body.chain_id[0] ^= 1;
    assert_eq!(net.submit_one(other), Err(Reject::WrongChain));

    let resign = |mut tx: verify_chain::tx::Transaction| {
        tx.approvals.clear();
        tx.approve(&demo_key("warehouse-3")).approve(&demo_key("transport-1"))
    };
    let mut late = net.transfer_tx("PCT-0001", "WarehouseSealed", "OutboundTransit", &["warehouse-3"], true);
    late.body.expiry_height = 1;
    let late = resign(late);
    assert_eq!(net.submit_one(late), Err(Reject::Expired));

    let mut stale = net.transfer_tx("PCT-0001", "WarehouseSealed", "OutboundTransit", &["warehouse-3"], true);
    stale.body.predecessor = Some([7u8; 32]);
    let stale = resign(stale);
    assert_eq!(net.submit_one(stale), Err(Reject::PredecessorMismatch));
}

#[test]
fn tampered_approval_is_rejected() {
    let mut net = Network::new();
    net.bootstrap();
    net.register("PCT-0001", 500);
    let mut tx = net.transfer_tx("PCT-0001", "Produced", "WarehouseSealed", &["warehouse-1", "warehouse-2"], true);
    tx.approvals[1].signature.mldsa65[42] ^= 0x80; // break only the post-quantum half
    assert!(matches!(net.submit_one(tx), Err(Reject::BadSignature(_))));

    // Changing the payload after signing invalidates every approval.
    let mut tx = net.transfer_tx("PCT-0001", "Produced", "WarehouseSealed", &["warehouse-1", "warehouse-2"], true);
    if let Payload::CustodyTransfer { seal_intact, .. } = &mut tx.body.payload {
        *seal_intact = false;
    }
    assert!(matches!(net.submit_one(tx), Err(Reject::BadSignature(_))));
}

// §2.3 — configuration locks at commencement.
#[test]
fn policy_is_locked_after_commencement() {
    let mut net = Network::new();
    net.bootstrap();
    let mut p = reference_policy();
    p.version = 2;
    p.predecessor = Some(net.nodes[0].state.policies[JURISDICTION].hash());
    let tx = net.tx(&["root-county", "root-state"], Payload::ActivatePolicy(p), None);
    assert_eq!(net.submit_one(tx), Err(Reject::ConfigurationLocked));

    let one_root = net.tx(&["root-state"], Payload::CommenceElection, None);
    assert!(matches!(net.submit_one(one_root), Err(Reject::InsufficientApprovals(_))));
}

// §1.2, §4.2, §4.3 — discrepancy quarantines; IEOA 3-of-3 correction appends.
#[test]
fn discrepancy_quarantine_and_emergency_correction() {
    let mut net = Network::new();
    net.bootstrap();
    net.register("PCT-0002", 2_000);
    walk_to_secure_storage(&mut net, "PCT-0002");

    let pred = net.batch_tip("PCT-0002");
    let report = Reconciliation { supplied: 2_000, cast: 1_700, spoiled: 10, unused: 287, ..Default::default() }; // 3 missing
    let recon = net.tx(&["canvass-1", "canvass-2", "canvass-3"], Payload::Reconcile { batch_id: "PCT-0002".into(), report }, Some(pred));
    let recon_id = recon.id();
    assert!(matches!(net.submit_one(recon), Ok(Outcome::Exception(m)) if m.contains("discrepancy of 3")));
    assert!(net.nodes[0].state.batches["PCT-0002"].quarantined);

    let tx = net.transfer_tx("PCT-0002", "SecureStorage", "Canvassed", &["canvass-1", "canvass-2", "canvass-3"], true);
    assert!(matches!(net.submit_one(tx), Err(Reject::Quarantined(_))));

    let correction = |net: &mut Network, who: &[&str]| {
        let pred = net.batch_tip("PCT-0002");
        net.tx(
            who,
            Payload::EmergencyCorrection {
                batch_id: "PCT-0002".into(),
                original_tx: recon_id,
                corrected_state: "SecureStorage".into(),
                reason: "3 ballots located in spoiled-ballot envelope; recount confirmed".into(),
                legal_authority: "Canvassing board order 2026-114".into(),
                evidence_commitment: CommitmentOpening::new(b"recount worksheet").commitment(),
            },
            Some(pred),
        )
    };
    let two_of_three = correction(&mut net, &["county-soe", "state-doe"]);
    assert!(matches!(net.submit_one(two_of_three), Err(Reject::InsufficientApprovals(_))));

    let tx = correction(&mut net, &["county-soe", "state-doe", "ieoa-external"]);
    assert_eq!(net.submit_one(tx), Ok(Outcome::Applied));
    let b = &net.nodes[0].state.batches["PCT-0002"];
    assert!(!b.quarantined);
    assert_eq!(b.exceptions.len(), 1, "the original finding is preserved, not erased");
    assert!(b.history.iter().any(|h| h.tx == recon_id), "history is appended, never rewritten");
}

#[test]
fn broken_seal_is_recorded_and_quarantines() {
    let mut net = Network::new();
    net.bootstrap();
    net.register("PCT-0003", 100);
    let tx = net.transfer_tx("PCT-0003", "Produced", "WarehouseSealed", &["warehouse-1", "warehouse-2"], false);
    assert!(matches!(net.submit_one(tx), Ok(Outcome::Exception(_))));
    assert!(net.nodes[0].state.batches["PCT-0003"].quarantined);
}

// §6.3 — BFT: validators re-execute; forged state roots get no votes.
#[test]
fn byzantine_leader_cannot_forge_state() {
    let mut net = Network::new();
    net.bootstrap();
    let leader = leader_key(&net);
    let leader_node = net.nodes.iter().find(|n| n.id() == leader.id()).unwrap();
    let (mut block, _) = leader_node.propose(vec![]);
    block.header.state_root = [0xAB; 32];
    block.proposer_signature = Block::sign_proposal(&leader, &block.header);
    for n in &net.nodes {
        let err = n.validate_and_vote(&block).unwrap_err();
        assert!(err.contains("state root"), "{err}");
    }

    // A non-leader cannot propose at all.
    let impostor = demo_key(VALIDATORS.iter().find(|v| demo_key(v).id() != leader.id()).unwrap());
    let (mut block, _) = leader_node.propose(vec![]);
    block.header.proposer = impostor.id();
    block.proposer_signature = Block::sign_proposal(&impostor, &block.header);
    assert!(net.nodes[0].validate_and_vote(&block).unwrap_err().contains("leader"));
}

#[test]
fn certificates_need_a_quorum_of_distinct_valid_votes() {
    let mut net = Network::new();
    let leader = leader_key(&net);
    let leader_node = net.nodes.iter().find(|n| n.id() == leader.id()).unwrap();
    let (block, _) = leader_node.propose(vec![]);
    let votes: Vec<Vote> = net.nodes.iter().map(|n| n.validate_and_vote(&block).unwrap()).collect();
    assert_eq!(net.nodes[0].validators.quorum(), 3);

    let short = certify(block.clone(), votes[..2].to_vec());
    assert!(net.nodes[0].check_commit(&short).is_err());

    let dup = certify(block.clone(), vec![votes[0].clone(), votes[0].clone(), votes[1].clone()]);
    assert!(net.nodes[0].check_commit(&dup).is_err());

    let mut forged = votes[..3].to_vec();
    forged[2].signature.mldsa65[0] ^= 1;
    assert!(net.nodes[0].check_commit(&certify(block.clone(), forged)).is_err());

    let ok = certify(block, votes[..3].to_vec());
    assert!(net.nodes[0].check_commit(&ok).is_ok());
    let _ = &mut net;
}

#[test]
fn equivocation_produces_verifiable_evidence() {
    let net = Network::new();
    let vs = &net.nodes[0].validators;
    let leader_node = &net.nodes.iter().find(|n| n.id() == vs.leader(1, 0)).unwrap();
    let (a, _) = leader_node.propose(vec![]);
    let mut other = a.header.clone();
    other.tx_root = [1; 32];
    let byz = demo_key(VALIDATORS[2]);
    let va = Vote::sign(&byz, &a.header);
    let vb = Vote::sign(&byz, &other);
    assert!(EquivocationEvidence::check(&va, &vb, vs).is_some());
    assert!(EquivocationEvidence::check(&va, &va, vs).is_none());
    let _ = QuorumCertificate { votes: vec![va] };
}

// §6.5 — an independent auditor with no keys detects any history change.
#[test]
fn auditor_verifies_honest_chain_and_detects_tampering() {
    let mut net = Network::new();
    net.bootstrap();
    net.register("PCT-0001", 500);
    walk_to_secure_storage(&mut net, "PCT-0001");
    let chain = net.nodes[0].chain.clone();
    let report = audit(&net.genesis, &chain).expect("honest chain audits clean");
    assert_eq!(report.blocks, chain.len());
    assert_eq!(report.final_state_root, net.nodes[3].state.root());

    // Edit one approval-bearing field deep in history.
    let mut edited = chain.clone();
    if let Payload::CustodyTransfer { to, .. } = &mut edited[4].txs[0].body.payload {
        *to = "Archived".into();
    }
    assert!(audit(&net.genesis, &edited).is_err());

    // Delete a block.
    let mut deleted = chain.clone();
    deleted.remove(3);
    assert!(audit(&net.genesis, &deleted).is_err());

    // Swap two blocks.
    let mut swapped = chain.clone();
    swapped.swap(2, 3);
    assert!(audit(&net.genesis, &swapped).is_err());

    // Swap in a different approver set on a stored transaction.
    let mut resigned = chain.clone();
    let extra = verify_chain::tx::Approval {
        signer: demo_key("warehouse-3").id(),
        signature: demo_key("warehouse-3").sign(verify_chain::tx::TX_APPROVAL_DOMAIN, &resigned[3].txs[0].id()),
    };
    resigned[3].txs[0].approvals.push(extra);
    assert!(audit(&net.genesis, &resigned).unwrap_err().contains("Merkle"));

    // Strip a certificate.
    let mut uncertified = chain;
    uncertified[1].qc = None;
    assert!(audit(&net.genesis, &uncertified).is_err());
}

// §6.1 — low-entropy values are salted before commitment.
#[test]
fn commitments_hide_low_entropy_values() {
    let a = CommitmentOpening::new(b"seal 0001");
    let b = CommitmentOpening::new(b"seal 0001");
    assert_ne!(a.commitment(), b.commitment(), "same value, different salts");
    assert!(a.opens(&a.commitment()));
    assert!(!a.opens(&b.commitment()));
}
