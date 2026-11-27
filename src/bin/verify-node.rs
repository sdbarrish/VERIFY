//! A VERIFY validator as an operating-system process, talking to its peers
//! over TCP through the authenticated, quantum-safe transport.
//!
//! ```text
//! verify-node run --index <i> --peers <addr0,addr1,...> --data <dir>
//!                 [--txs <file>] [--block-interval-ms <ms>]
//! verify-node make-demo-txs --validators <n> --out <file>
//! ```
//!
//! `--peers` lists every validator's listen address in validator order; this
//! node listens on its own entry. Validator keys are the deterministic demo
//! keys: suitable for simulation only, never for a real election (SR-08).
//!
//! Output, one line per event, for operators and tests:
//! `COMMIT height=<h> round=<r> txs=<n> hash=<hex>`.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use verify_chain::bft::{Behavior, Msg, Out, Replica, Step, Timeouts};
use verify_chain::codec::{Canonical, Dec, Decode, Enc};
use verify_chain::crypto::{hex, HybridKeypair, HybridPublicKey};
use verify_chain::node::Node;
use verify_chain::store::Store;
use verify_chain::testkit::{demo_key, validator_name, Network};
use verify_chain::transport;
use verify_chain::tx::Transaction;

const PEER_QUEUE: usize = 8_192;
const STALL_RESYNC: Duration = Duration::from_secs(3);

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn need(args: &[String], name: &str) -> String {
    arg(args, name).unwrap_or_else(|| {
        eprintln!("missing {name}");
        std::process::exit(2)
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("run") => run(&args),
        Some("make-demo-txs") => make_demo_txs(&args),
        _ => {
            eprintln!("usage: verify-node run --index <i> --peers <a0,a1,...> --data <dir> [--txs <file>] [--block-interval-ms <ms>]");
            eprintln!("       verify-node make-demo-txs --validators <n> --out <file>");
            std::process::exit(2);
        }
    }
}

/// Policy, commencement and two batch registrations for an n-validator demo chain.
fn make_demo_txs(args: &[String]) {
    let n: usize = need(args, "--validators")
        .parse()
        .expect("--validators is a number");
    let mut net = Network::with_validators(n);
    let mut txs = net.bootstrap_txs();
    txs.push(net.register_tx("PCT-0001", 110_000));
    txs.push(net.register_tx("PCT-0002", 2_000));
    let mut e = Enc::new();
    e.list(&txs);
    std::fs::write(need(args, "--out"), e.finish()).expect("write txs");
}

fn load_txs(path: &str) -> Vec<Transaction> {
    let b = std::fs::read(path).expect("read --txs file");
    let mut d = Dec::new(&b);
    let txs = d.list(1 << 16).expect("decode transactions");
    d.finish().expect("trailing bytes in --txs file");
    txs
}

enum Event {
    Msg(usize, Msg),
}

/// Keep one outbound authenticated connection to `peer`, reconnecting forever.
fn spawn_dialer(
    addr: String,
    key: Arc<HybridKeypair>,
    chain_id: [u8; 32],
    peer: HybridPublicKey,
) -> SyncSender<Vec<u8>> {
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(PEER_QUEUE);
    std::thread::spawn(move || loop {
        let sock = addr.to_socket_addrs().ok().and_then(|mut a| a.next());
        let stream =
            sock.and_then(|a| TcpStream::connect_timeout(&a, Duration::from_millis(500)).ok());
        let Some(stream) = stream else {
            std::thread::sleep(Duration::from_millis(200));
            continue;
        };
        let mut ch = match transport::connect(stream, &key, chain_id, &peer) {
            Ok(ch) => ch,
            Err(e) => {
                eprintln!("handshake with {addr} failed: {e}");
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        loop {
            match rx.recv() {
                Ok(bytes) => {
                    if ch.writer.send(&bytes).is_err() {
                        break; // reconnect; this message is lost, peers re-sync
                    }
                }
                Err(_) => return,
            }
        }
    });
    tx
}

fn run(args: &[String]) {
    let index: usize = need(args, "--index").parse().expect("--index is a number");
    let peers: Vec<String> = need(args, "--peers")
        .split(',')
        .map(str::to_string)
        .collect();
    let n = peers.len();
    let data = PathBuf::from(need(args, "--data"));
    let interval: u64 = arg(args, "--block-interval-ms")
        .map(|s| s.parse().expect("number"))
        .unwrap_or(500);
    assert!(index < n, "--index out of range");

    let genesis = Network::with_validators(n).genesis;
    let chain_id = genesis.chain_id();
    let validators = genesis.validators.clone();
    let name = validator_name(index);
    let key = Arc::new(demo_key(&name));
    let store = Store::open(&data).expect("open data directory");

    // Rebuild the chain from disk, re-verifying every block.
    let mut node = Node::new(&name, demo_key(&name), genesis);
    for b in store.load_blocks().expect("read chain") {
        if let Err(e) = node.commit(&b) {
            eprintln!(
                "stored block {} failed verification: {e}; stopping replay there",
                b.header.height
            );
            break;
        }
    }
    let mut persisted = node.chain.len();
    let timeouts = Timeouts {
        base: 1_000,
        per_round: 500,
        commit: interval,
    };
    let mut rep = Replica::new(index, node, Behavior::Honest, timeouts);
    if let Some(p) = arg(args, "--txs") {
        rep.mempool = load_txs(&p);
    }
    println!(
        "START index={index} name={name} height={} chain={}",
        rep.height(),
        hex(&chain_id[..8])
    );

    let (etx, erx) = mpsc::channel::<Event>();

    // Inbound: accept, authenticate, read frames.
    let listener = TcpListener::bind(&peers[index]).expect("bind listen address");
    {
        let (key, validators) = (key.clone(), validators.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (key, validators, etx) = (key.clone(), validators.clone(), etx.clone());
                std::thread::spawn(move || {
                    let mut ch = match transport::accept(stream, &key, chain_id, &validators) {
                        Ok(ch) => ch,
                        Err(e) => {
                            eprintln!("rejected inbound connection: {e}");
                            return;
                        }
                    };
                    let from = validators
                        .iter()
                        .position(|k| *k == ch.peer)
                        .expect("accepted peer is a validator");
                    while let Ok(b) = ch.reader.recv() {
                        match Msg::from_canonical(&b) {
                            Ok(m) => {
                                if etx.send(Event::Msg(from, m)).is_err() {
                                    return;
                                }
                            }
                            Err(e) => {
                                eprintln!("malformed message from validator {from}: {e}");
                                return;
                            }
                        }
                    }
                });
            }
        });
    }

    // Outbound: one dialer per peer.
    let outq: Vec<Option<SyncSender<Vec<u8>>>> = (0..n)
        .map(|j| {
            (j != index).then(|| {
                spawn_dialer(
                    peers[j].clone(),
                    key.clone(),
                    chain_id,
                    validators[j].clone(),
                )
            })
        })
        .collect();

    let mut timers: BinaryHeap<Reverse<(Instant, u64, u32, u8)>> = BinaryHeap::new();
    let step_of = |t: u8| match t {
        0 => Step::Commit,
        1 => Step::Propose,
        2 => Step::Prevote,
        _ => Step::Precommit,
    };
    let tag_of = |s: Step| match s {
        Step::Commit => 0u8,
        Step::Propose => 1,
        Step::Prevote => 2,
        Step::Precommit => 3,
    };

    let mut outs = match store.load_durable().map(|d| rep.restore(d)) {
        Some(true) => {
            println!("RESTORED height={} round={}", rep.height(), rep.round());
            rep.recover()
        }
        _ => {
            let mut o = rep.start();
            o.push(Out::Broadcast(Msg::SyncRequest {
                from_height: rep.height(),
            }));
            o
        }
    };
    let mut last_durable = None;
    let (mut last_height, mut last_progress, mut last_sync) =
        (rep.height(), Instant::now(), Instant::now());

    loop {
        // 1. Persist first: new blocks, then consensus state (write-ahead).
        for b in &rep.node.chain[persisted..] {
            store.append_block(b).expect("persist block");
            let round = b.qc.as_ref().map_or(0, |q| q.votes[0].round);
            println!(
                "COMMIT height={} round={round} txs={} hash={}",
                b.header.height,
                b.txs.len(),
                hex(&b.header.hash())
            );
        }
        persisted = rep.node.chain.len();
        let d = rep.durable();
        if last_durable.as_ref() != Some(&d) {
            store.save_durable(&d).expect("persist consensus state");
            last_durable = Some(d);
        }
        // 2. Then let messages out.
        for o in outs.drain(..) {
            match o {
                Out::Broadcast(m) => {
                    let bytes = m.to_canonical();
                    for q in outq.iter().flatten() {
                        if let Err(TrySendError::Full(_)) = q.try_send(bytes.clone()) {
                            eprintln!("peer queue full; dropping a message");
                        }
                    }
                }
                Out::Send(j, m) => {
                    if let Some(Some(q)) = outq.get(j) {
                        let _ = q.try_send(m.to_canonical());
                    }
                }
                Out::Timer {
                    delay,
                    height,
                    round,
                    step,
                } => {
                    timers.push(Reverse((
                        Instant::now() + Duration::from_millis(delay),
                        height,
                        round,
                        tag_of(step),
                    )));
                }
            }
        }
        // 3. Wait for the next message or timer.
        let wait = timers
            .peek()
            .map_or(Duration::from_millis(500), |Reverse((t, ..))| {
                t.saturating_duration_since(Instant::now())
            });
        match erx.recv_timeout(wait.min(Duration::from_millis(500))) {
            Ok(Event::Msg(from, m)) => outs.extend(rep.on_message(from, m)),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        while timers
            .peek()
            .is_some_and(|Reverse((t, ..))| *t <= Instant::now())
        {
            let Reverse((_, h, r, s)) = timers.pop().expect("peeked");
            outs.extend(rep.on_timeout(h, r, step_of(s)));
        }
        // 4. Stalled? Ask peers for anything we missed (lost messages, restarts).
        if rep.height() != last_height {
            last_height = rep.height();
            last_progress = Instant::now();
        } else if last_progress.elapsed() > STALL_RESYNC && last_sync.elapsed() > STALL_RESYNC {
            last_sync = Instant::now();
            outs.push(Out::Broadcast(Msg::SyncRequest {
                from_height: rep.height(),
            }));
        }
    }
}
