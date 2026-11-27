//! AT-26 over real transport: validator processes on localhost, connected by
//! the authenticated post-quantum transport, crashed with SIGKILL and
//! restarted from disk.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use verify_chain::node::audit;
use verify_chain::store::read_chain_file;
use verify_chain::testkit::Network;

const BIN: &str = env!("CARGO_BIN_EXE_verify-node");

struct Cluster {
    dir: PathBuf,
    peers: String,
    txs: PathBuf,
    procs: Vec<Option<Child>>,
}

impl Cluster {
    fn new(tag: &str, n: usize) -> Self {
        let dir = std::env::temp_dir().join(format!("verify-net-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Reserve distinct free ports.
        let socks: Vec<TcpListener> = (0..n)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let peers = socks
            .iter()
            .map(|s| s.local_addr().unwrap().to_string())
            .collect::<Vec<_>>()
            .join(",");
        drop(socks);
        let txs = dir.join("txs.bin");
        let ok = Command::new(BIN)
            .args(["make-demo-txs", "--validators", &n.to_string(), "--out"])
            .arg(&txs)
            .status()
            .unwrap();
        assert!(ok.success());
        Self {
            dir,
            peers,
            txs,
            procs: (0..n).map(|_| None).collect(),
        }
    }

    fn start(&mut self, i: usize) {
        let child = Command::new(BIN)
            .args([
                "run",
                "--index",
                &i.to_string(),
                "--peers",
                &self.peers,
                "--block-interval-ms",
                "200",
                "--data",
            ])
            .arg(self.dir.join(format!("n{i}")))
            .arg("--txs")
            .arg(&self.txs)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.procs[i] = Some(child);
    }

    /// SIGKILL: no shutdown handler runs, exactly like a power cut.
    fn crash(&mut self, i: usize) {
        if let Some(mut c) = self.procs[i].take() {
            c.kill().unwrap();
            c.wait().unwrap();
        }
    }

    fn height(&self, i: usize) -> usize {
        read_chain_file(&self.dir.join(format!("n{i}")).join("chain.bin"))
            .map(|(b, _)| b.len())
            .unwrap_or(0)
    }

    fn wait(&self, who: &[usize], height: usize, limit: Duration) -> bool {
        let t = Instant::now();
        while t.elapsed() < limit {
            if who.iter().all(|&i| self.height(i) >= height) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    fn chain(&self, i: usize) -> Vec<verify_chain::consensus::Block> {
        read_chain_file(&self.dir.join(format!("n{i}")).join("chain.bin"))
            .unwrap()
            .0
    }

    /// All stored chains agree on every common height, and the longest audits clean.
    fn check(&self, n: usize) {
        let chains: Vec<_> = (0..n).map(|i| self.chain(i)).collect();
        for a in &chains {
            for b in &chains {
                for (x, y) in a.iter().zip(b) {
                    assert_eq!(
                        x.header.hash(),
                        y.header.hash(),
                        "fork at height {}",
                        x.header.height
                    );
                }
            }
        }
        let longest = chains.iter().max_by_key(|c| c.len()).unwrap();
        let genesis = Network::with_validators(n).genesis;
        let r = audit(&genesis, longest).expect("stored chain audits clean");
        assert!(r.transactions >= 4, "demo transactions were committed");
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        for i in 0..self.procs.len() {
            self.crash(i);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn validators_survive_crash_and_restart_from_disk() {
    let mut c = Cluster::new("crash", 4);
    for i in 0..4 {
        c.start(i);
    }
    assert!(
        c.wait(&[0, 1, 2, 3], 3, Duration::from_secs(60)),
        "cluster did not start committing"
    );

    c.crash(1);
    let at_crash = c.height(0);
    assert!(
        c.wait(&[0, 2, 3], at_crash + 6, Duration::from_secs(60)),
        "no progress with one validator down"
    );

    c.start(1);
    let target = c.height(0) + 3;
    assert!(
        c.wait(&[1], target, Duration::from_secs(60)),
        "restarted validator did not catch up"
    );
    for i in 0..4 {
        c.crash(i);
    }
    c.check(4);
}

#[test]
fn no_quorum_means_no_commits_until_one_returns() {
    let mut c = Cluster::new("quorum", 4);
    c.start(0);
    c.start(1);
    std::thread::sleep(Duration::from_secs(4));
    assert_eq!(
        c.height(0) + c.height(1),
        0,
        "two of four committed without a quorum"
    );
    c.start(2);
    assert!(
        c.wait(&[0, 1, 2], 3, Duration::from_secs(60)),
        "no progress once quorum returned"
    );
    for i in 0..4 {
        c.crash(i);
    }
    c.check(4);
}
