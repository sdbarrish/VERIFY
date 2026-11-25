//! A validator node and an independent auditor.

use crate::consensus::{
    Block, BlockHeader, QuorumCertificate, ValidatorSet, Vote, MAX_TXS_PER_BLOCK,
};
use crate::crypto::{hash, Hash, HybridKeypair};
use crate::state::{Genesis, LedgerState, Outcome, Reject};
use crate::tx::Transaction;

pub fn genesis_hash(g: &Genesis) -> Hash {
    hash("VERIFY/genesis-block/v1", &g.chain_id())
}

/// Result of executing a block's transactions against a state.
pub struct Execution {
    pub state: LedgerState,
    pub outcomes: Vec<Outcome>,
}

/// Execute all transactions; any rejection invalidates the whole block.
pub fn execute(
    state: &LedgerState,
    txs: &[Transaction],
    height: u64,
) -> Result<Execution, (usize, Reject)> {
    let mut s = state.clone();
    let mut outcomes = Vec::with_capacity(txs.len());
    for (i, tx) in txs.iter().enumerate() {
        outcomes.push(s.apply(tx, height).map_err(|e| (i, e))?);
    }
    Ok(Execution { state: s, outcomes })
}

pub struct Node {
    pub name: String,
    key: HybridKeypair,
    pub genesis: Genesis,
    pub validators: ValidatorSet,
    pub chain: Vec<Block>,
    pub state: LedgerState,
}

impl Node {
    pub fn new(name: &str, key: HybridKeypair, genesis: Genesis) -> Self {
        genesis.validate().expect("invalid genesis");
        let validators = ValidatorSet {
            keys: genesis.validators.clone(),
        };
        let state = LedgerState::new(&genesis);
        Self {
            name: name.into(),
            key,
            genesis,
            validators,
            chain: vec![],
            state,
        }
    }

    pub fn id(&self) -> Hash {
        self.key.id()
    }

    pub fn tip(&self) -> Hash {
        self.chain
            .last()
            .map(|b| b.header.hash())
            .unwrap_or_else(|| genesis_hash(&self.genesis))
    }

    pub fn next_height(&self) -> u64 {
        self.chain.len() as u64 + 1
    }

    pub(crate) fn key(&self) -> &HybridKeypair {
        &self.key
    }

    /// Leader: drop invalid transactions (reporting why) and propose the rest.
    pub fn propose(&self, candidates: Vec<Transaction>) -> (Block, Vec<(Transaction, Reject)>) {
        self.propose_at(0, candidates)
    }

    /// Propose for a given round (the proposer must be that round's leader).
    pub fn propose_at(
        &self,
        round: u32,
        candidates: Vec<Transaction>,
    ) -> (Block, Vec<(Transaction, Reject)>) {
        let height = self.next_height();
        let mut s = self.state.clone();
        let (mut txs, mut rejected) = (vec![], vec![]);
        for tx in candidates.into_iter().take(MAX_TXS_PER_BLOCK) {
            match s.apply(&tx, height) {
                Ok(_) => txs.push(tx),
                Err(e) => rejected.push((tx, e)),
            }
        }
        let header = BlockHeader {
            chain_id: self.genesis.chain_id(),
            height,
            round,
            prev: self.tip(),
            tx_root: Block::tx_root(&txs),
            tx_count: txs.len() as u32,
            state_root: s.root(),
            proposer: self.id(),
        };
        let proposer_signature = Block::sign_proposal(&self.key, &header);
        (
            Block {
                header,
                txs,
                proposer_signature,
                qc: None,
            },
            rejected,
        )
    }

    /// Follower: independently re-execute the proposal; vote only if every check passes.
    pub fn validate_and_vote(&self, block: &Block) -> Result<Vote, String> {
        self.validate_block(block)?;
        Ok(Vote::sign(&self.key, &block.header))
    }

    /// Every check a validator makes before voting for a proposed block.
    pub fn validate_block(&self, block: &Block) -> Result<(), String> {
        let h = &block.header;
        if h.chain_id != self.genesis.chain_id()
            || h.height != self.next_height()
            || h.prev != self.tip()
        {
            return Err("block does not extend this node's tip".into());
        }
        block.verify_proposal(&self.validators)?;
        let exec = execute(&self.state, &block.txs, h.height)
            .map_err(|(i, e)| format!("tx {i} rejected: {e}"))?;
        if exec.state.root() != h.state_root {
            return Err(
                "state root mismatch: proposer's claimed result differs from re-execution".into(),
            );
        }
        Ok(())
    }

    /// Every check `commit` performs, without changing anything.
    pub fn check_commit(&self, block: &Block) -> Result<Execution, String> {
        let qc = block.qc.as_ref().ok_or("block has no quorum certificate")?;
        qc.verify(&block.header, &self.validators)?;
        if block.header.prev != self.tip() || block.header.height != self.next_height() {
            return Err("block does not extend tip".into());
        }
        block.verify_proposal(&self.validators)?;
        let exec = execute(&self.state, &block.txs, block.header.height)
            .map_err(|(i, e)| format!("tx {i}: {e}"))?;
        if exec.state.root() != block.header.state_root {
            return Err("state root mismatch".into());
        }
        Ok(exec)
    }

    /// Append a block once it carries a valid quorum certificate.
    pub fn commit(&mut self, block: &Block) -> Result<Vec<Outcome>, String> {
        let exec = self.check_commit(block)?;
        self.state = exec.state;
        self.chain.push(block.clone());
        Ok(exec.outcomes)
    }
}

/// Assemble a certificate from votes (any order, any source).
pub fn certify(mut block: Block, votes: Vec<Vote>) -> Block {
    block.qc = Some(QuorumCertificate { votes });
    block
}

#[derive(Debug)]
pub struct AuditReport {
    pub blocks: usize,
    pub transactions: usize,
    pub exceptions: Vec<(u64, String)>,
    pub final_state_root: Hash,
}

/// Independent verifier (§6.3, §6.5). Holds no keys and trusts no node: from
/// the genesis alone it re-checks every link, certificate, Merkle root and
/// state transition, so deletion, reordering, rollback or edits are detected.
pub fn audit(genesis: &Genesis, chain: &[Block]) -> Result<AuditReport, String> {
    genesis.validate()?;
    let vs = ValidatorSet {
        keys: genesis.validators.clone(),
    };
    let mut state = LedgerState::new(genesis);
    let mut prev = genesis_hash(genesis);
    let mut report = AuditReport {
        blocks: 0,
        transactions: 0,
        exceptions: vec![],
        final_state_root: state.root(),
    };
    for (i, b) in chain.iter().enumerate() {
        let h = &b.header;
        let at = |m: String| format!("block {}: {m}", i + 1);
        if h.chain_id != genesis.chain_id() || h.height != i as u64 + 1 {
            return Err(at("wrong chain or height (gap, reorder or splice)".into()));
        }
        if h.prev != prev {
            return Err(at("hash link broken (history edited or removed)".into()));
        }
        b.verify_proposal(&vs).map_err(at)?;
        b.qc.as_ref()
            .ok_or_else(|| at("missing quorum certificate".into()))?
            .verify(h, &vs)
            .map_err(at)?;
        let exec = execute(&state, &b.txs, h.height)
            .map_err(|(t, e)| at(format!("tx {t} invalid: {e}")))?;
        if exec.state.root() != h.state_root {
            return Err(at("state root mismatch".into()));
        }
        for o in &exec.outcomes {
            if let Outcome::Exception(m) = o {
                report.exceptions.push((h.height, m.clone()));
            }
        }
        state = exec.state;
        prev = h.hash();
        report.blocks += 1;
        report.transactions += b.txs.len();
    }
    report.final_state_root = state.root();
    Ok(report)
}

const EXPORT_MAGIC: &str = "VERIFY-CHAIN-EXPORT/v1";
/// Upper bound on blocks in one export file.
pub const MAX_EXPORT_BLOCKS: usize = 1 << 24;

/// Self-contained, independently verifiable export (§6.3, §6.5): the genesis
/// plus every certified block, in canonical encoding. Anyone holding the
/// published chain id can check it with `verify-audit` and no other trust.
pub fn export_chain(genesis: &Genesis, chain: &[Block]) -> Vec<u8> {
    use crate::codec::{Canonical, Enc};
    let mut e = Enc::new();
    e.str(EXPORT_MAGIC);
    genesis.encode(&mut e);
    e.list(chain);
    e.finish()
}

pub fn import_chain(bytes: &[u8]) -> Result<(Genesis, Vec<Block>), crate::codec::DecodeError> {
    use crate::codec::{derr, Dec, Decode};
    let mut d = Dec::new(bytes);
    if d.str()? != EXPORT_MAGIC {
        return derr("not a VERIFY chain export");
    }
    let genesis = Genesis::decode(&mut d)?;
    let blocks = d.list(MAX_EXPORT_BLOCKS)?;
    d.finish()?;
    Ok((genesis, blocks))
}
