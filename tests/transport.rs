//! Validator transport: mutual authentication, quantum-safe key exchange and
//! frame integrity. Every attack here must fail closed.

use std::net::{TcpListener, TcpStream};
use std::thread;
use verify_chain::crypto::HybridKeypair;
use verify_chain::testkit::{demo_key, validator_name, Network};
use verify_chain::transport::{accept, connect, Channel, TransportError};

fn validators() -> Vec<verify_chain::crypto::HybridPublicKey> {
    Network::with_validators(4).genesis.validators
}

/// Run `accept` as validator `server` on a fresh port; dial with `client_key`
/// expecting validator `expect`.
fn pair(
    server: usize,
    client_key: HybridKeypair,
    expect: usize,
    server_chain: [u8; 32],
    client_chain: [u8; 32],
) -> (
    Result<Channel, TransportError>,
    Result<Channel, TransportError>,
) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let vs = validators();
    let h = thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        accept(s, &demo_key(&validator_name(server)), server_chain, &vs)
    });
    let c = connect(
        TcpStream::connect(addr).unwrap(),
        &client_key,
        client_chain,
        &validators()[expect],
    );
    (c, h.join().unwrap())
}

fn chain() -> [u8; 32] {
    Network::with_validators(4).genesis.chain_id()
}

#[test]
fn validators_establish_an_encrypted_channel_both_ways() {
    let (c, s) = pair(1, demo_key(&validator_name(0)), 1, chain(), chain());
    let (mut c, mut s) = (c.unwrap(), s.unwrap());
    assert_eq!(c.peer, validators()[1]);
    assert_eq!(s.peer, validators()[0]);
    c.writer.send(b"prevote").unwrap();
    s.writer.send(b"precommit").unwrap();
    assert_eq!(s.reader.recv().unwrap(), b"prevote");
    assert_eq!(c.reader.recv().unwrap(), b"precommit");
    // Many frames: counters stay in step.
    for i in 0..100u32 {
        c.writer.send(&i.to_be_bytes()).unwrap();
        assert_eq!(s.reader.recv().unwrap(), i.to_be_bytes());
    }
}

#[test]
fn outsider_cannot_join() {
    let (c, s) = pair(1, HybridKeypair::generate(), 1, chain(), chain());
    assert!(matches!(s, Err(TransportError::UnknownPeer)));
    assert!(c.is_err());
}

#[test]
fn dialler_detects_the_wrong_validator() {
    // We meant to reach validator 2, but validator 1 answers.
    let (c, _) = pair(1, demo_key(&validator_name(0)), 2, chain(), chain());
    assert!(matches!(c, Err(TransportError::WrongPeer)));
}

#[test]
fn different_chain_is_refused() {
    let (c, s) = pair(1, demo_key(&validator_name(0)), 1, chain(), [9u8; 32]);
    assert!(matches!(s, Err(TransportError::Protocol(_))));
    assert!(c.is_err());
}

#[test]
fn tampered_replayed_and_reordered_frames_are_rejected() {
    // Tampering.
    let (c, s) = pair(1, demo_key(&validator_name(0)), 1, chain(), chain());
    let (mut c, mut s) = (c.unwrap(), s.unwrap());
    let mut f = c.writer.seal(b"vote for block A");
    f[3] ^= 1;
    c.writer.send_sealed(&f).unwrap();
    assert!(matches!(
        s.reader.recv(),
        Err(TransportError::Authentication)
    ));

    // Replay.
    let (c, s) = pair(1, demo_key(&validator_name(0)), 1, chain(), chain());
    let (mut c, mut s) = (c.unwrap(), s.unwrap());
    let f = c.writer.seal(b"vote");
    c.writer.send_sealed(&f).unwrap();
    c.writer.send_sealed(&f).unwrap();
    assert_eq!(s.reader.recv().unwrap(), b"vote");
    assert!(matches!(
        s.reader.recv(),
        Err(TransportError::Authentication)
    ));

    // Reordering.
    let (c, s) = pair(1, demo_key(&validator_name(0)), 1, chain(), chain());
    let (mut c, mut s) = (c.unwrap(), s.unwrap());
    let f1 = c.writer.seal(b"first");
    let f2 = c.writer.seal(b"second");
    c.writer.send_sealed(&f2).unwrap();
    c.writer.send_sealed(&f1).unwrap();
    assert!(matches!(
        s.reader.recv(),
        Err(TransportError::Authentication)
    ));
}
