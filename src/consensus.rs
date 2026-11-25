//! Permissioned BFT finality (white paper §6.3).
//!
//! n = 3f+1 validators tolerate f Byzantine ones. A block is final only with a
//! quorum certificate: hybrid post-quantum signatures from n−f distinct
//! validators, each of which re-executed the block and got the same state root.
//! Two quorums always overlap in at least one honest validator, so two
//! conflicting blocks at the same height cannot both become final unless more
//! than f validators sign both, which is itself provable misbehaviour
//! ([`EquivocationEvidence`]).
//!
//! This module holds the safety core: blocks, two-phase votes (prevote and
//! precommit), certificates and equivocation evidence. The round-based
//! protocol that drives them, with locking, timeouts and view change, is in
//! [`crate::bft`].

use crate::codec::{Canonical, Enc};
use crate::crypto::{
    hash, short, verify, Hash, HybridKeypair, HybridPublicKey, HybridSignature, KeyId,
};
use crate::merkle;
use crate::tx::Transaction;
use std::collections::BTreeSet;

pub const MAX_TXS_PER_BLOCK: usize = 1_024;
const VOTE_DOMAIN: &str = "VERIFY/vote/v1";
const PROPOSAL_DOMAIN: &str = "VERIFY/proposal/v1";

#[derive(Debug, Clone)]
pub struct ValidatorSet {
    pub keys: Vec<HybridPublicKey>,
}

impl ValidatorSet {
    pub fn n(&self) -> usize {
        self.keys.len()
    }
    pub fn f(&self) -> usize {
        (self.n() - 1) / 3
    }
    pub fn quorum(&self) -> usize {
        self.n() - self.f()
    }
    pub fn get(&self, id: &KeyId) -> Option<&HybridPublicKey> {
        self.keys.iter().find(|k| &k.id() == id)
    }
    /// Deterministic round-robin leader schedule.
    pub fn leader(&self, height: u64, round: u32) -> KeyId {
        // Modular arithmetic first: hostile heights or rounds must not overflow.
        let n = self.n() as u64;
        let i = ((height % n + round as u64 % n) % n) as usize;
        self.keys[i].id()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub chain_id: Hash,
    pub height: u64,
    pub round: u32,
    pub prev: Hash,
    pub tx_root: Hash,
    pub tx_count: u32,
    pub state_root: Hash,
    pub proposer: KeyId,
}

impl Canonical for BlockHeader {
    fn encode(&self, e: &mut Enc) {
        e.hash(&self.chain_id)
            .u64(self.height)
            .u32(self.round)
            .hash(&self.prev);
        e.hash(&self.tx_root)
            .u32(self.tx_count)
            .hash(&self.state_root)
            .hash(&self.proposer);
    }
}

impl BlockHeader {
    pub fn hash(&self) -> Hash {
        hash("VERIFY/block/v1", &self.to_canonical())
    }
}

/// The two voting phases. The phase is inside the signed bytes, so a prevote
/// can never be replayed as a precommit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VoteKind {
    Prevote,
    Precommit,
}

impl VoteKind {
    fn tag(self) -> u8 {
        match self {
            VoteKind::Prevote => 1,
            VoteKind::Precommit => 2,
        }
    }
}

/// The "nil" vote target: no block in this round. All-zero cannot collide
/// with a SHA3-256 block hash in practice.
pub const NIL: Hash = [0u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    pub chain_id: Hash,
    pub height: u64,
    pub round: u32,
    pub kind: VoteKind,
    pub block: Hash,
    pub validator: KeyId,
    pub signature: HybridSignature,
}

fn vote_message(chain_id: &Hash, height: u64, round: u32, kind: VoteKind, block: &Hash) -> Vec<u8> {
    let mut e = Enc::new();
    e.hash(chain_id)
        .u64(height)
        .u32(round)
        .u8(kind.tag())
        .hash(block);
    e.finish()
}

impl Vote {
    pub fn new(
        key: &HybridKeypair,
        chain_id: Hash,
        height: u64,
        round: u32,
        kind: VoteKind,
        block: Hash,
    ) -> Self {
        Vote {
            chain_id,
            height,
            round,
            kind,
            block,
            validator: key.id(),
            signature: key.sign(
                VOTE_DOMAIN,
                &vote_message(&chain_id, height, round, kind, &block),
            ),
        }
    }

    /// A precommit for this header in the header's own round.
    pub fn sign(key: &HybridKeypair, h: &BlockHeader) -> Self {
        Self::new(
            key,
            h.chain_id,
            h.height,
            h.round,
            VoteKind::Precommit,
            h.hash(),
        )
    }

    pub fn verify(&self, vs: &ValidatorSet) -> bool {
        match vs.get(&self.validator) {
            Some(pk) => verify(
                pk,
                VOTE_DOMAIN,
                &vote_message(
                    &self.chain_id,
                    self.height,
                    self.round,
                    self.kind,
                    &self.block,
                ),
                &self.signature,
            )
            .is_ok(),
            None => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumCertificate {
    pub votes: Vec<Vote>,
}

impl QuorumCertificate {
    /// Valid iff at least n−f distinct validators precommitted exactly this
    /// header, all in the same round. The round may be later than the one the
    /// block was first proposed in, when a locked block is re-proposed.
    pub fn verify(&self, h: &BlockHeader, vs: &ValidatorSet) -> Result<(), String> {
        let want = h.hash();
        let round = self
            .votes
            .first()
            .map(|v| v.round)
            .ok_or("empty certificate")?;
        if round < h.round {
            return Err("certificate round precedes the block's proposal round".into());
        }
        let mut signers = BTreeSet::new();
        for v in &self.votes {
            if v.chain_id != h.chain_id
                || v.height != h.height
                || v.round != round
                || v.kind != VoteKind::Precommit
                || v.block != want
            {
                return Err(format!(
                    "vote from {} is for a different block",
                    short(&v.validator)
                ));
            }
            if !v.verify(vs) {
                return Err(format!(
                    "invalid vote signature from {}",
                    short(&v.validator)
                ));
            }
            if !signers.insert(v.validator) {
                return Err("duplicate vote in certificate".into());
            }
        }
        if signers.len() < vs.quorum() {
            return Err(format!(
                "{} votes, quorum is {}",
                signers.len(),
                vs.quorum()
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Transaction>,
    pub proposer_signature: HybridSignature,
    pub qc: Option<QuorumCertificate>,
}

impl Block {
    /// Leaves commit to the full signed transaction, approvals included, so
    /// the signature set is covered by the block hash and the quorum certificate.
    pub fn tx_root(txs: &[Transaction]) -> Hash {
        let leaves: Vec<Hash> = txs
            .iter()
            .map(|t| merkle::leaf_hash(&t.to_canonical()))
            .collect();
        merkle::root(&leaves)
    }

    pub fn sign_proposal(key: &HybridKeypair, header: &BlockHeader) -> HybridSignature {
        key.sign(PROPOSAL_DOMAIN, &header.hash())
    }

    pub fn verify_proposal(&self, vs: &ValidatorSet) -> Result<(), String> {
        if self.txs.len() > MAX_TXS_PER_BLOCK || self.txs.len() != self.header.tx_count as usize {
            return Err("transaction count mismatch or over limit".into());
        }
        if Self::tx_root(&self.txs) != self.header.tx_root {
            return Err("transaction Merkle root mismatch".into());
        }
        if self.header.proposer != vs.leader(self.header.height, self.header.round) {
            return Err("proposer is not the scheduled leader".into());
        }
        let pk = vs
            .get(&self.header.proposer)
            .ok_or("proposer is not a validator")?;
        verify(
            pk,
            PROPOSAL_DOMAIN,
            &self.header.hash(),
            &self.proposer_signature,
        )
        .map_err(|e| format!("proposer signature: {e}"))
    }
}

/// Two valid votes by one validator for different blocks at the same height and
/// round. Anyone can verify it offline; it is grounds for removing the validator.
#[derive(Debug, Clone)]
pub struct EquivocationEvidence {
    pub a: Vote,
    pub b: Vote,
}

impl EquivocationEvidence {
    pub fn check(a: &Vote, b: &Vote, vs: &ValidatorSet) -> Option<Self> {
        let conflicting = a.validator == b.validator
            && a.chain_id == b.chain_id
            && a.height == b.height
            && a.round == b.round
            && a.kind == b.kind
            && a.block != b.block;
        (conflicting && a.verify(vs) && b.verify(vs)).then(|| Self {
            a: a.clone(),
            b: b.clone(),
        })
    }
}

use crate::codec::{derr, Dec, Decode, DecodeError};

impl Canonical for Vote {
    fn encode(&self, e: &mut Enc) {
        e.hash(&self.chain_id)
            .u64(self.height)
            .u32(self.round)
            .u8(self.kind.tag())
            .hash(&self.block)
            .hash(&self.validator);
        self.signature.encode(e);
    }
}

impl Canonical for QuorumCertificate {
    fn encode(&self, e: &mut Enc) {
        e.list(&self.votes);
    }
}

impl Canonical for Block {
    fn encode(&self, e: &mut Enc) {
        self.header.encode(e);
        e.list(&self.txs);
        self.proposer_signature.encode(e);
        match &self.qc {
            None => {
                e.u8(0);
            }
            Some(qc) => {
                e.u8(1);
                qc.encode(e);
            }
        }
    }
}

/// Upper bound on validators (and so votes per certificate).
pub const MAX_VALIDATORS: usize = 256;

impl Decode for BlockHeader {
    fn decode(d: &mut Dec<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            chain_id: d.hash()?,
            height: d.u64()?,
            round: d.u32()?,
            prev: d.hash()?,
            tx_root: d.hash()?,
            tx_count: d.u32()?,
            state_root: d.hash()?,
            proposer: d.hash()?,
        })
    }
}

impl Decode for Vote {
    fn decode(d: &mut Dec<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            chain_id: d.hash()?,
            height: d.u64()?,
            round: d.u32()?,
            kind: match d.u8()? {
                1 => VoteKind::Prevote,
                2 => VoteKind::Precommit,
                t => return derr(format!("unknown vote kind {t}")),
            },
            block: d.hash()?,
            validator: d.hash()?,
            signature: HybridSignature::decode(d)?,
        })
    }
}

impl Decode for Block {
    fn decode(d: &mut Dec<'_>) -> Result<Self, DecodeError> {
        let header = BlockHeader::decode(d)?;
        let txs = d.list(MAX_TXS_PER_BLOCK)?;
        let proposer_signature = HybridSignature::decode(d)?;
        let qc = match d.u8()? {
            0 => None,
            1 => Some(QuorumCertificate {
                votes: d.list(MAX_VALIDATORS)?,
            }),
            t => return derr(format!("bad certificate tag {t}")),
        };
        Ok(Self {
            header,
            txs,
            proposer_signature,
            qc,
        })
    }
}
