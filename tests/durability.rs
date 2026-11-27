//! Crash durability: torn writes are trimmed, and a restored validator never
//! casts a second, conflicting vote in a round it already voted in.

use std::io::Write;
use verify_chain::bft::{Behavior, Durable, Msg, Out, Proposal, Replica, Step, Timeouts};
use verify_chain::codec::{Canonical, Decode};
use verify_chain::consensus::VoteKind;
use verify_chain::node::Node;
use verify_chain::store::Store;
use verify_chain::testkit::*;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("verify-dur-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn torn_final_write_is_trimmed_and_appends_continue() {
    let mut net = Network::new();
    net.bootstrap();
    net.register("PCT-0001", 10);
    let chain = net.nodes[0].chain.clone();
    let dir = tmpdir("torn");
    let store = Store::open(&dir).unwrap();
    for b in &chain[..2] {
        store.append_block(b).unwrap();
    }
    // Power cut halfway through the third append.
    let bytes = chain[2].to_canonical();
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(dir.join("chain.bin"))
        .unwrap();
    f.write_all(&(bytes.len() as u32).to_be_bytes()).unwrap();
    f.write_all(&bytes[..bytes.len() / 2]).unwrap();
    drop(f);

    let loaded = store.load_blocks().unwrap();
    assert_eq!(loaded, chain[..2].to_vec(), "only whole blocks survive");
    store.append_block(&chain[2]).unwrap();
    assert_eq!(
        store.load_blocks().unwrap(),
        chain,
        "appending after the trim yields a clean file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn restored_validator_does_not_vote_twice() {
    let mut net = Network::with_validators(4);
    let txs = net.bootstrap_txs();
    let genesis = net.genesis.clone();
    let mk = || {
        Node::new(
            &validator_name(0),
            demo_key(&validator_name(0)),
            genesis.clone(),
        )
    };
    let leader = Node::new(
        &validator_name(1),
        demo_key(&validator_name(1)),
        genesis.clone(),
    );
    let block = leader.propose_at(0, txs).0;

    // Validator 0 prevotes the proposal, then the process dies.
    let mut rep = Replica::new(0, mk(), Behavior::Honest, Timeouts::default());
    rep.start();
    rep.on_message(
        1,
        Msg::Proposal(Box::new(Proposal::new(
            &demo_key(&validator_name(1)),
            1,
            0,
            None,
            block,
        ))),
    );
    let saved = rep.durable();
    assert_eq!(saved.step, Step::Prevote);
    let on_disk = saved.to_canonical();
    drop(rep);

    // Restart from the saved record.
    let d = Durable::from_canonical(&on_disk).unwrap();
    assert_eq!(d, saved);
    let mut back = Replica::new(0, mk(), Behavior::Honest, Timeouts::default());
    assert!(back.restore(d));
    let outs = back.recover();
    // The propose timeout from before the crash fires late. A fresh replica
    // would prevote nil here, contradicting its earlier prevote.
    let late = back.on_timeout(1, 0, Step::Propose);
    let prevotes: Vec<_> = outs
        .iter()
        .chain(late.iter())
        .filter_map(|o| match o {
            Out::Broadcast(Msg::Vote(v)) if v.kind == VoteKind::Prevote => Some(v.block),
            _ => None,
        })
        .collect();
    assert_eq!(
        prevotes,
        vec![saved.own_votes[0].block],
        "only the original prevote is ever sent"
    );
}

#[test]
fn state_for_an_older_height_is_ignored() {
    let net = Network::with_validators(4);
    let genesis = net.genesis.clone();
    let rep = Replica::new(
        0,
        Node::new("v0", demo_key(&validator_name(0)), genesis.clone()),
        Behavior::Honest,
        Timeouts::default(),
    );
    let mut d = rep.durable();
    d.height = 7;
    let mut fresh = Replica::new(
        0,
        Node::new("v0", demo_key(&validator_name(0)), genesis),
        Behavior::Honest,
        Timeouts::default(),
    );
    assert!(!fresh.restore(d));
}
