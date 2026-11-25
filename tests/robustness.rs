//! §6.4 hardening: strict decoding of untrusted bytes and tamper evidence for
//! exported chains. Randomized but deterministic (fixed-seed generator), so
//! failures are reproducible.

use verify_chain::codec::{Canonical, Decode};
use verify_chain::consensus::Block;
use verify_chain::node::{audit, export_chain, import_chain};
use verify_chain::testkit::*;
use verify_chain::tx::{Payload, Reconciliation, Transaction};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn sample_chain() -> Network {
    let mut net = Network::new();
    net.bootstrap();
    net.register("PCT-0001", 110_000);
    for (from, to, who) in HAPPY_PATH {
        let tx = net.transfer_tx("PCT-0001", from, to, who, true);
        net.submit_one(tx).unwrap();
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
    net.submit_one(tx).unwrap();
    net
}

#[test]
fn export_round_trips_exactly_and_audits() {
    let net = sample_chain();
    let bytes = export_chain(&net.genesis, &net.nodes[0].chain);
    let (g, chain) = import_chain(&bytes).unwrap();
    assert_eq!(g.chain_id(), net.genesis.chain_id());
    assert_eq!(chain, net.nodes[0].chain);
    assert_eq!(
        export_chain(&g, &chain),
        bytes,
        "canonical: re-encoding reproduces the file byte for byte"
    );
    assert!(audit(&g, &chain).is_ok());
    for b in &chain {
        assert_eq!(Block::from_canonical(&b.to_canonical()).unwrap(), *b);
        for t in &b.txs {
            assert_eq!(Transaction::from_canonical(&t.to_canonical()).unwrap(), *t);
        }
    }
}

#[test]
fn every_truncation_and_extension_is_rejected() {
    let net = sample_chain();
    let bytes = export_chain(&net.genesis, &net.nodes[0].chain);
    let mut rng = Rng(0x5EED_0001);
    for _ in 0..300 {
        let cut = rng.below(bytes.len());
        assert!(
            import_chain(&bytes[..cut]).is_err(),
            "truncation at {cut} accepted"
        );
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(import_chain(&longer).is_err(), "trailing byte accepted");
}

#[test]
fn random_bytes_never_panic_the_decoders() {
    let mut rng = Rng(0x5EED_0002);
    for _ in 0..20_000 {
        let len = rng.below(512);
        let buf: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let _ = import_chain(&buf);
        let _ = Block::from_canonical(&buf);
        let _ = Transaction::from_canonical(&buf);
        let _ = verify_chain::envelope::Envelope::from_canonical(&buf);
    }
    // Hostile length prefixes must not trigger huge allocations.
    let mut huge = vec![0xFF; 8];
    huge.extend_from_slice(&[0u8; 64]);
    assert!(Block::from_canonical(&huge).is_err());
}

/// Flip one random bit anywhere in a certified export: it must either fail to
/// decode or fail the audit. Every byte is covered by a hash or signature.
#[test]
fn any_single_bit_flip_is_detected() {
    let net = sample_chain();
    let bytes = export_chain(&net.genesis, &net.nodes[0].chain);
    let mut rng = Rng(0x5EED_0003);
    for i in 0..48 {
        let mut m = bytes.clone();
        let pos = rng.below(m.len());
        m[pos] ^= 1 << rng.below(8);
        let verdict = import_chain(&m)
            .map_err(|e| e.to_string())
            .and_then(|(g, c)| audit(&g, &c));
        assert!(verdict.is_err(), "flip #{i} at byte {pos} went undetected");
    }
}
