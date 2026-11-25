//! Simulated custody workflow (white paper §10.4 "next deliverable").
//! Run: cargo run --release --bin verify-sim [-- --export chain.verify]

use verify_chain::consensus::{Block, EquivocationEvidence, Vote};
use verify_chain::crypto::short;
use verify_chain::envelope::{Envelope, KemKeypair};
use verify_chain::node::{audit, export_chain};
use verify_chain::state::{Outcome, Reject};
use verify_chain::testkit::*;
use verify_chain::tx::{Payload, Reconciliation};

fn show(label: &str, r: &Result<Outcome, Reject>) {
    match r {
        Ok(Outcome::Applied) => println!("  [FINAL]     {label}"),
        Ok(Outcome::Exception(m)) => println!("  [EXCEPTION] {label}\n              -> {m}"),
        Err(e) => println!("  [REJECTED]  {label}\n              -> {e}"),
    }
}

fn section(t: &str) {
    println!("\n== {t} ==");
}

fn main() {
    let mut net = Network::new();
    let vs = net.nodes[0].validators.clone();
    section("Genesis");
    println!("  chain id      {}", short(&net.genesis.chain_id()));
    println!(
        "  validators    n={} f={} quorum={}   (BFT, n = 3f+1)",
        vs.n(),
        vs.f(),
        vs.quorum()
    );
    println!(
        "  root keys     {} of {}",
        net.genesis.root_threshold,
        net.genesis.root_authorities.len()
    );
    println!("  signatures    Ed25519 + ML-DSA-65 (FIPS 204), both required");
    println!("  hashing       SHA3-256, domain-separated");

    section("Governance: policy activation and configuration lock");
    let p = net.tx(
        &["root-county", "root-state"],
        Payload::ActivatePolicy(reference_policy()),
        None,
    );
    show(
        "Activate county custody policy v1 (2-of-3 root keys)",
        &net.submit_one(p),
    );
    let c = net.tx(
        &["root-county", "root-independent"],
        Payload::CommenceElection,
        None,
    );
    show(
        "Commence election; configuration locked",
        &net.submit_one(c),
    );

    section("Batch PCT-0001: 110,000 ballots through full custody");
    net.register("PCT-0001", 110_000);
    println!(
        "  [FINAL]     Register batch (inventory and seal numbers committed with 256-bit salts)"
    );
    for (from, to, who) in HAPPY_PATH {
        let tx = net.transfer_tx("PCT-0001", from, to, who, true);
        show(
            &format!("{from} -> {to}  ({} approvers)", who.len()),
            &net.submit_one(tx),
        );
    }
    let pred = net.batch_tip("PCT-0001");
    let report = Reconciliation {
        supplied: 110_000,
        cast: 100_000,
        spoiled: 750,
        issued_unreturned: 25,
        unused: 9_225,
        ..Default::default()
    };
    let tx = net.tx(
        &["canvass-1", "canvass-2", "canvass-3"],
        Payload::Reconcile {
            batch_id: "PCT-0001".into(),
            report,
        },
        Some(pred),
    );
    show(
        "Reconcile: 110,000 = 100,000 cast + 750 spoiled + 25 unreturned + 9,225 unused",
        &net.submit_one(tx),
    );

    section("Attacks on a fresh batch PCT-0009 (all must fail)");
    net.register("PCT-0009", 1_000);
    let tx = net.transfer_tx(
        "PCT-0009",
        "Produced",
        "WarehouseSealed",
        &["insights-ai"],
        true,
    );
    show(
        "AI analytics key tries to move custody",
        &net.submit_one(tx),
    );
    let tx = net.transfer_tx(
        "PCT-0009",
        "Produced",
        "WarehouseSealed",
        &["warehouse-1", "warehouse-2", "insights-ai"],
        true,
    );
    show(
        "AI key co-signs alongside a valid 2-of-3",
        &net.submit_one(tx),
    );
    let tx = net.transfer_tx(
        "PCT-0009",
        "Produced",
        "WarehouseSealed",
        &["warehouse-1"],
        true,
    );
    show(
        "Single insider moves a batch (1 of required 2)",
        &net.submit_one(tx),
    );
    let mut tx = net.transfer_tx(
        "PCT-0009",
        "Produced",
        "WarehouseSealed",
        &["warehouse-1", "warehouse-2"],
        true,
    );
    tx.approvals[1].signature.mldsa65[7] ^= 1;
    show(
        "Forged post-quantum half of a signature",
        &net.submit_one(tx),
    );
    let tx = net.transfer_tx(
        "PCT-0009",
        "Produced",
        "WarehouseSealed",
        &["warehouse-1", "warehouse-2"],
        true,
    );
    net.submit_one(tx.clone()).expect("legitimate transfer");
    show(
        "Replay of an already-final transaction",
        &net.submit_one(tx),
    );
    let mut p2 = reference_policy();
    p2.version = 2;
    p2.predecessor = Some(net.nodes[0].state.policies[JURISDICTION].hash());
    let tx = net.tx(
        &["root-county", "root-state"],
        Payload::ActivatePolicy(p2),
        None,
    );
    show("Mid-election policy change", &net.submit_one(tx));

    section("Byzantine validators");
    let leader_id = vs.leader(net.height(), 0);
    let leader = VALIDATORS
        .iter()
        .map(|v| (v, demo_key(v)))
        .find(|(_, k)| k.id() == leader_id)
        .unwrap();
    let leader_node = net.nodes.iter().find(|n| n.id() == leader_id).unwrap();
    let (mut block, _) = leader_node.propose(vec![]);
    block.header.state_root = [0xEE; 32];
    block.proposer_signature = Block::sign_proposal(&leader.1, &block.header);
    let refusals = net
        .nodes
        .iter()
        .filter(|n| n.validate_and_vote(&block).is_err())
        .count();
    println!("  [REJECTED]  Leader {} proposes a forged state root\n              -> {refusals} of {} validators refuse to vote; no quorum, no finality", leader.0, vs.n());
    let (a, _) = leader_node.propose(vec![]);
    let mut b = a.header.clone();
    b.tx_root = [1; 32];
    let ev = EquivocationEvidence::check(
        &Vote::sign(&leader.1, &a.header),
        &Vote::sign(&leader.1, &b),
        &vs,
    );
    println!(
        "  [EVIDENCE]  Leader double-votes at height {}: equivocation proof {}",
        a.header.height,
        if ev.is_some() { "produced" } else { "MISSING" }
    );

    section("Batch PCT-0002: discrepancy, quarantine, independent correction");
    net.register("PCT-0002", 2_000);
    for (from, to, who) in HAPPY_PATH {
        let tx = net.transfer_tx("PCT-0002", from, to, who, true);
        net.submit_one(tx).expect("custody step");
    }
    println!("  [FINAL]     Custody walk to SecureStorage (6 transfers)");
    let pred = net.batch_tip("PCT-0002");
    let report = Reconciliation {
        supplied: 2_000,
        cast: 1_700,
        spoiled: 10,
        unused: 287,
        ..Default::default()
    };
    let recon = net.tx(
        &["canvass-1", "canvass-2", "canvass-3"],
        Payload::Reconcile {
            batch_id: "PCT-0002".into(),
            report,
        },
        Some(pred),
    );
    let recon_id = recon.id();
    show(
        "Reconcile: 2,000 supplied, 1,997 accounted for",
        &net.submit_one(recon),
    );
    let tx = net.transfer_tx(
        "PCT-0002",
        "SecureStorage",
        "Canvassed",
        &["canvass-1", "canvass-2", "canvass-3"],
        true,
    );
    show("Canvass a quarantined batch", &net.submit_one(tx));
    // Quantum-safe sealed evidence: only the state division can read the
    // worksheet; only its digest goes on the ledger.
    let state_kem = KemKeypair::from_seed(&verify_chain::crypto::hash("demo-kem", b"state-doe"));
    let worksheet = b"Recount worksheet PCT-0002: 3 ballots found in spoiled-ballot envelope. Signed: canvassing board.";
    let envelope = Envelope::seal(
        &demo_key("county-soe"),
        state_kem.public(),
        "state-division-of-elections",
        worksheet,
    )
    .expect("seal");
    let evidence = envelope.digest();
    println!("  [SEALED]    Recount worksheet sealed to state division (X25519 + ML-KEM-768, ChaCha20-Poly1305)");
    println!(
        "              ledger stores only digest {}",
        short(&evidence)
    );
    let opened = envelope.open(
        &state_kem,
        demo_key("county-soe").public(),
        "state-division-of-elections",
    );
    println!(
        "              state division opens it: {}",
        if opened.as_deref() == Ok(&worksheet[..]) {
            "ok"
        } else {
            "FAILED"
        }
    );
    let outsider = KemKeypair::generate();
    println!(
        "              anyone else: {}",
        envelope
            .open(
                &outsider,
                demo_key("county-soe").public(),
                "state-division-of-elections"
            )
            .unwrap_err()
    );
    let mk = |net: &mut Network, who: &[&str]| {
        let pred = net.batch_tip("PCT-0002");
        net.tx(
            who,
            Payload::EmergencyCorrection {
                batch_id: "PCT-0002".into(),
                original_tx: recon_id,
                corrected_state: "SecureStorage".into(),
                reason: "3 ballots found in spoiled envelope; recount confirmed".into(),
                legal_authority: "Canvassing board order 2026-114".into(),
                evidence_commitment: evidence,
            },
            Some(pred),
        )
    };
    let tx = mk(&mut net, &["county-soe", "state-doe"]);
    show("Correction with county + state only", &net.submit_one(tx));
    let tx = mk(&mut net, &["county-soe", "state-doe", "ieoa-external"]);
    show(
        "Correction with county + state + independent authority (3-of-3)",
        &net.submit_one(tx),
    );
    let b = &net.nodes[0].state.batches["PCT-0002"];
    println!(
        "              batch state {}, quarantined={}, {} findings preserved, {} history records",
        b.state,
        b.quarantined,
        b.exceptions.len(),
        b.history.len()
    );

    section("Independent audit (no keys, trusts no node)");
    let chain = net.nodes[0].chain.clone();
    match audit(&net.genesis, &chain) {
        Ok(r) => {
            println!("  [VERIFIED]  {} blocks, {} transactions, every certificate and state root re-checked", r.blocks, r.transactions);
            for (h, m) in &r.exceptions {
                println!("              finding at height {h}: {m}");
            }
            let agree = net
                .nodes
                .iter()
                .all(|n| n.state.root() == r.final_state_root);
            println!(
                "              all {} validators agree on state root {}: {agree}",
                net.nodes.len(),
                short(&r.final_state_root)
            );
        }
        Err(e) => println!("  [FAILED]    {e}"),
    }
    let mut tampered = chain.clone();
    if let Payload::Reconcile { report, .. } = &mut tampered
        .iter_mut()
        .flat_map(|b| b.txs.iter_mut())
        .find(|t| matches!(t.body.payload, Payload::Reconcile { .. }))
        .unwrap()
        .body
        .payload
    {
        report.cast += 500;
    }
    match audit(&net.genesis, &tampered) {
        Ok(_) => println!("  [MISSED]    tampering was not detected"),
        Err(e) => println!(
            "  [DETECTED]  Someone edits a stored reconciliation (+500 cast)\n              -> {e}"
        ),
    }
    if let Some(i) = std::env::args().position(|a| a == "--export") {
        let path = std::env::args()
            .nth(i + 1)
            .expect("--export needs a file path");
        std::fs::write(&path, export_chain(&net.genesis, &chain)).expect("write export");
        println!(
            "  [EXPORTED]  {path}  (check with: verify-audit {path} --expect-chain-id {})",
            verify_chain::crypto::hex(&net.genesis.chain_id())
        );
    }
    let mut truncated = chain;
    truncated.remove(2);
    match audit(&net.genesis, &truncated) {
        Ok(_) => println!("  [MISSED]    deletion was not detected"),
        Err(e) => println!("  [DETECTED]  Someone deletes block 3\n              -> {e}"),
    }
}
