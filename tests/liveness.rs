//! AT-26 (SR-18, FR-16): liveness and safety of round-based BFT under
//! crashes, partitions, asynchrony and Byzantine validators, on the
//! deterministic simulated network. Every scenario is reproducible from its seed.

use verify_chain::bft::{Outage, Partition, SimConfig, SimNet};
use verify_chain::testkit::*;
use verify_chain::tx::Transaction;

/// Policy, commencement and `batches` registrations, all valid in one block.
fn workload(net: &mut Network, batches: usize) -> Vec<Transaction> {
    let mut txs = net.bootstrap_txs();
    for i in 0..batches {
        txs.push(net.register_tx(&format!("PCT-{i:04}"), 1_000 + i as u64));
    }
    txs
}

fn sim(validators: usize, batches: usize, cfg: SimConfig) -> SimNet {
    let mut net = Network::with_validators(validators);
    let txs = workload(&mut net, batches);
    let mut s = net.into_sim(cfg);
    for t in txs {
        s.submit(t);
    }
    s
}

fn all_registered(s: &SimNet, batches: usize, who: &[usize]) {
    for &i in who {
        let st = &s.replicas[i].node.state;
        assert_eq!(
            st.batches.len(),
            batches,
            "replica {i} is missing committed transactions"
        );
    }
}

fn view_changed(s: &SimNet) -> bool {
    s.replicas
        .iter()
        .flat_map(|r| r.node.chain.iter())
        .any(|b| b.qc.as_ref().is_some_and(|qc| qc.votes[0].round > 0))
}

#[test]
fn honest_network_commits_and_agrees_across_seeds() {
    for seed in 1..=5 {
        let mut s = sim(
            4,
            3,
            SimConfig {
                seed,
                ..Default::default()
            },
        );
        assert!(s.run_until_height(5, 50_000), "seed {seed}: no progress");
        s.check_agreement().unwrap();
        all_registered(&s, 3, &[0, 1, 2, 3]);
        // Every honest chain passes the independent audit.
        let chain = s.replicas[0].node.chain.clone();
        verify_chain::node::audit(&s.replicas[0].node.genesis, &chain).expect("audit");
    }
}

#[test]
fn crashed_leader_is_replaced_by_view_change() {
    // Validator 1 leads height 1, round 0, and is down for the whole run.
    let cfg = SimConfig {
        outages: vec![Outage {
            node: 1,
            from: 0,
            until: None,
        }],
        ..Default::default()
    };
    let mut s = sim(4, 2, cfg);
    assert!(
        s.run_until_height(4, 60_000),
        "no progress without the leader"
    );
    s.check_agreement().unwrap();
    assert!(view_changed(&s), "commit should have needed a later round");
    all_registered(&s, 2, &[0, 2, 3]);
}

#[test]
fn f_plus_one_down_halts_safely_then_resumes_with_catch_up() {
    // n = 4 tolerates f = 1. Two down: no quorum, so nothing may commit.
    let cfg = SimConfig {
        outages: vec![
            Outage {
                node: 2,
                from: 0,
                until: None,
            },
            Outage {
                node: 3,
                from: 0,
                until: Some(5_000),
            },
        ],
        ..Default::default()
    };
    let mut s = sim(4, 1, cfg);
    s.run_until(4_900);
    assert_eq!(
        s.replicas[0].node.chain.len(),
        0,
        "committed without a quorum"
    );
    assert_eq!(
        s.replicas[1].node.chain.len(),
        0,
        "committed without a quorum"
    );

    // Node 3 returns: quorum restored, progress resumes.
    s.run_until(5_000);
    assert!(s.run_until_height(3, 80_000), "no progress after recovery");
    s.check_agreement().unwrap();
    all_registered(&s, 1, &[0, 1, 3]);
}

#[test]
fn recovered_node_catches_up_from_peers() {
    let cfg = SimConfig {
        outages: vec![Outage {
            node: 0,
            from: 0,
            until: Some(6_000),
        }],
        ..Default::default()
    };
    let mut s = sim(4, 1, cfg);
    s.run_until(5_900);
    let ahead = s.replicas[1].node.chain.len();
    assert!(ahead >= 2, "the other three should progress without node 0");
    assert_eq!(s.replicas[0].node.chain.len(), 0);
    s.run_until(6_000); // node 0 comes back
    assert!(s.run_until_height(ahead + 1, 80_000));
    s.check_agreement().unwrap();
    assert!(
        s.replicas[0].node.chain.len() >= ahead,
        "node 0 did not catch up"
    );
}

#[test]
fn even_partition_stops_commits_then_heals() {
    let cfg = SimConfig {
        partitions: vec![Partition {
            groups: vec![vec![0, 1], vec![2, 3]],
            from: 0,
            until: 4_000,
        }],
        ..Default::default()
    };
    let mut s = sim(4, 2, cfg);
    s.run_until(3_900);
    assert_eq!(s.min_honest_height(), 0);
    assert!(
        s.replicas.iter().all(|r| r.node.chain.is_empty()),
        "a 2|2 split must not commit"
    );
    assert!(
        s.run_until_height(3, 80_000),
        "no progress after the partition healed"
    );
    s.check_agreement().unwrap();
    all_registered(&s, 2, &[0, 1, 2, 3]);
}

#[test]
fn byzantine_equivocator_never_breaks_agreement() {
    for seed in 1..=8 {
        // Validator 1 leads height 1 and equivocates as leader and as voter.
        let cfg = SimConfig {
            seed,
            byzantine: vec![1],
            ..Default::default()
        };
        let mut s = sim(4, 2, cfg);
        assert!(s.run_until_height(4, 80_000), "seed {seed}: no progress");
        s.check_agreement().unwrap();
        all_registered(&s, 2, &[0, 2, 3]);
        let caught = s.honest().any(|r| {
            r.evidence
                .iter()
                .any(|e| e.a.validator == s.replicas[1].node.id())
        });
        assert!(caught, "seed {seed}: equivocation went unrecorded");
        assert!(
            s.honest().all(|r| r
                .evidence
                .iter()
                .all(|e| e.a.validator == s.replicas[1].node.id())),
            "an honest validator was accused"
        );
    }
}

#[test]
fn seven_validators_tolerate_two_byzantine() {
    for seed in 1..=4 {
        let cfg = SimConfig {
            seed,
            byzantine: vec![1, 4],
            ..Default::default()
        };
        let mut s = sim(7, 2, cfg);
        assert!(s.run_until_height(4, 120_000), "seed {seed}: no progress");
        s.check_agreement().unwrap();
        all_registered(&s, 2, &[0, 2, 3, 5, 6]);
    }
}

#[test]
fn safety_holds_under_heavy_asynchrony() {
    // Delays far beyond the timeouts: liveness is not expected, safety is.
    for seed in 1..=6 {
        let cfg = SimConfig {
            seed,
            min_delay: 1,
            max_delay: 1_500,
            byzantine: vec![2],
            ..Default::default()
        };
        let mut s = sim(4, 1, cfg);
        s.run_until(40_000);
        s.check_agreement().unwrap();
    }
}

/// The lock rule, driven message by message. A validator that precommitted
/// block A must refuse a conflicting block B in a later round, unless it sees
/// n−f prevotes for B in a round after its lock. This is the property that
/// stops two different blocks being committed at one height.
#[test]
fn locked_validator_refuses_conflicting_block_until_newer_polka() {
    use verify_chain::bft::{Behavior, Msg, Out, Proposal, Replica, Step, Timeouts};
    use verify_chain::consensus::{Vote, VoteKind, NIL};

    let mut net = Network::with_validators(4);
    let txs = workload(&mut net, 1);
    let chain_id = net.genesis.chain_id();
    let mut nodes = std::mem::take(&mut net.nodes);
    let key = |i: usize| demo_key(&validator_name(i));
    // Leaders at height 1: round 0 is validator 1, round 1 is validator 2.
    let block_a = nodes[1].propose_at(0, txs).0;
    let block_b = nodes[2].propose_at(1, vec![]).0;
    let (a, b) = (block_a.header.hash(), block_b.header.hash());
    assert_ne!(a, b);

    let mut rep = Replica::new(0, nodes.remove(0), Behavior::Honest, Timeouts::default());
    let my_votes = |outs: &[Out], round: u32, kind: VoteKind| -> Vec<[u8; 32]> {
        outs.iter()
            .filter_map(|o| match o {
                Out::Broadcast(Msg::Vote(v)) if v.round == round && v.kind == kind => Some(v.block),
                _ => None,
            })
            .collect()
    };

    rep.start();
    let outs = rep.on_message(
        1,
        Msg::Proposal(Box::new(Proposal::new(&key(1), 1, 0, None, block_a))),
    );
    assert_eq!(
        my_votes(&outs, 0, VoteKind::Prevote),
        vec![a],
        "prevotes the valid proposal"
    );
    let mut outs = vec![];
    for i in [1, 2] {
        outs.extend(rep.on_message(
            i,
            Msg::Vote(Vote::new(&key(i), chain_id, 1, 0, VoteKind::Prevote, a)),
        ));
    }
    assert_eq!(
        my_votes(&outs, 0, VoteKind::Precommit),
        vec![a],
        "n−f prevotes: lock on A and precommit it"
    );

    // A does not gather n−f precommits; the round times out.
    for i in [1, 2] {
        rep.on_message(
            i,
            Msg::Vote(Vote::new(&key(i), chain_id, 1, 0, VoteKind::Precommit, NIL)),
        );
    }
    rep.on_timeout(1, 0, Step::Precommit);
    assert_eq!(rep.round(), 1);

    // Round 1 leader proposes a different, perfectly valid block B.
    let outs = rep.on_message(
        2,
        Msg::Proposal(Box::new(Proposal::new(&key(2), 1, 1, None, block_b))),
    );
    assert_eq!(
        my_votes(&outs, 1, VoteKind::Prevote),
        vec![NIL],
        "locked on A: must not prevote B"
    );

    // n−f prevotes for B in round 1, later than the lock: now B may be precommitted.
    let mut outs = vec![];
    for i in [1, 2, 3] {
        outs.extend(rep.on_message(
            i,
            Msg::Vote(Vote::new(&key(i), chain_id, 1, 1, VoteKind::Prevote, b)),
        ));
    }
    assert_eq!(
        my_votes(&outs, 1, VoteKind::Precommit),
        vec![b],
        "a newer polka moves the lock"
    );
}
