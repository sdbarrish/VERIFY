//! §6.1 confidential payloads: hybrid X25519 + ML-KEM-768 sealed envelopes.

use verify_chain::codec::{Canonical, Decode};
use verify_chain::envelope::{Envelope, EnvelopeError, KemKeypair};
use verify_chain::testkit::demo_key;

const DEST: &str = "state-division-of-elections";

#[test]
fn round_trip_and_addressing() {
    let sender = demo_key("county-soe");
    let rcpt = KemKeypair::generate();
    let env = Envelope::seal(&sender, rcpt.public(), DEST, b"scanner image bytes").unwrap();
    assert_eq!(
        env.open(&rcpt, sender.public(), DEST).unwrap(),
        b"scanner image bytes"
    );

    assert_eq!(
        env.open(&KemKeypair::generate(), sender.public(), DEST),
        Err(EnvelopeError::WrongRecipient)
    );
    assert_eq!(
        env.open(&rcpt, sender.public(), "somewhere-else"),
        Err(EnvelopeError::WrongDestination)
    );
    assert_eq!(
        env.open(&rcpt, demo_key("state-doe").public(), DEST),
        Err(EnvelopeError::WrongSender)
    );

    // Fresh randomness every time: identical plaintexts are unlinkable.
    let again = Envelope::seal(&sender, rcpt.public(), DEST, b"scanner image bytes").unwrap();
    assert_ne!(env.ciphertext, again.ciphertext);
    assert_ne!(env.digest(), again.digest());
}

#[test]
fn any_modification_is_detected() {
    let sender = demo_key("county-soe");
    let rcpt = KemKeypair::generate();
    let env = Envelope::seal(&sender, rcpt.public(), DEST, b"evidence").unwrap();

    let mut c = env.clone();
    c.ciphertext[0] ^= 1;
    assert_eq!(
        c.open(&rcpt, sender.public(), DEST),
        Err(EnvelopeError::BadSignature)
    );

    let mut c = env.clone();
    c.mlkem_ciphertext[10] ^= 1;
    assert_eq!(
        c.open(&rcpt, sender.public(), DEST),
        Err(EnvelopeError::BadSignature)
    );

    // Redirecting an envelope breaks the sender's signature over the destination.
    let mut c = env.clone();
    c.destination = "attacker".into();
    assert_eq!(
        c.open(&rcpt, sender.public(), "attacker"),
        Err(EnvelopeError::BadSignature)
    );

    let mut c = env;
    c.kem_suite = 0x0001;
    assert_eq!(
        c.open(&rcpt, sender.public(), DEST),
        Err(EnvelopeError::UnsupportedVersion)
    );
}

#[test]
fn envelope_encoding_round_trips() {
    let sender = demo_key("county-soe");
    let rcpt = KemKeypair::generate();
    let env = Envelope::seal(&sender, rcpt.public(), DEST, b"x").unwrap();
    let bytes = env.to_canonical();
    let back = Envelope::from_canonical(&bytes).unwrap();
    assert_eq!(back, env);
    assert_eq!(back.open(&rcpt, sender.public(), DEST).unwrap(), b"x");
    assert!(Envelope::from_canonical(&bytes[..bytes.len() - 1]).is_err());
}
