//! Round-based BFT consensus with locking and view change (white paper §6.3,
//! requirement SR-18), plus a deterministic simulated network to test it.
//!
//! The protocol follows the published Tendermint algorithm (Buchman, Kwon and
//! Milosevic, "The latest gossip on BFT consensus", 2018). Each height runs
//! rounds. Each round has a proposal, a prevote and a precommit phase.
//!
//! * **Safety.** A validator that precommits a block *locks* on it. It will
//!   prevote a different block only after seeing n−f prevotes for that block in
//!   a later round. Two quorums of n−f overlap in at least one honest
//!   validator, so two different blocks can never both gather n−f precommits
//!   at one height, whatever the timing, while at most f validators are Byzantine.
//! * **Liveness.** Timeouts grow with each round, and the leader rotates. After
//!   the network stabilises, some round has an honest leader and enough time,
//!   and every honest validator commits.
//! * **Catch-up.** A validator that was offline asks its peers for committed
//!   blocks and checks each certificate itself before applying it.
//!
//! Nothing here trusts the network. Every proposal and vote is hybrid-signed
//! and checked, and a node that receives two conflicting signed votes from one
//! validator keeps them as [`EquivocationEvidence`].
//!
//! The simulated network is in-process and deterministic, so failures
//! reproduce from a seed. A real deployment replaces it with authenticated
//! transport. The replica logic does not change.

use crate::codec::Enc;
use crate::consensus::{Block, EquivocationEvidence, QuorumCertificate, Vote, VoteKind, NIL};
use crate::crypto::{verify, Hash, HybridKeypair, HybridSignature, KeyId};
use crate::node::Node;
use crate::tx::Transaction;
use std::collections::{BTreeMap, BTreeSet};

const ROUND_PROPOSAL_DOMAIN: &str = "VERIFY/round-proposal/v1";
/// Cap on buffered messages for future heights, against flooding.
const MAX_FUTURE: usize = 4_096;
/// Most committed blocks sent in reply to one sync request.
const MAX_SYNC_BATCH: usize = 64;
/// Latest rounds of the current height re-sent in reply to a sync request.
const SYNC_ROUNDS: u32 = 4;

/// A leader's proposal for one round. `pol_round` is set when the leader
/// re-proposes a block that already gathered n−f prevotes in that round.
#[derive(Debug, Clone)]
pub struct Proposal {
    pub height: u64,
    pub round: u32,
    pub pol_round: Option<u32>,
    pub block: Block,
    pub signature: HybridSignature,
}

impl Proposal {
    fn message(
        chain_id: &Hash,
        height: u64,
        round: u32,
        pol: Option<u32>,
        block: &Hash,
    ) -> Vec<u8> {
        let mut e = Enc::new();
        e.hash(chain_id).u64(height).u32(round);
        match pol {
            None => e.u8(0),
            Some(r) => e.u8(1).u32(r),
        };
        e.hash(block);
        e.finish()
    }

    pub fn new(
        key: &HybridKeypair,
        height: u64,
        round: u32,
        pol_round: Option<u32>,
        block: Block,
    ) -> Self {
        let msg = Self::message(
            &block.header.chain_id,
            height,
            round,
            pol_round,
            &block.header.hash(),
        );
        let signature = key.sign(ROUND_PROPOSAL_DOMAIN, &msg);
        Self {
            height,
            round,
            pol_round,
            block,
            signature,
        }
    }

    /// Signed by the scheduled leader of (height, round), and for this height.
    pub fn verify(&self, node: &Node) -> bool {
        let leader = node.validators.leader(self.height, self.round);
        let Some(pk) = node.validators.get(&leader) else {
            return false;
        };
        let h = &self.block.header;
        h.height == self.height
            && self.pol_round.is_none_or(|p| p < self.round)
            && verify(
                pk,
                ROUND_PROPOSAL_DOMAIN,
                &Self::message(
                    &h.chain_id,
                    self.height,
                    self.round,
                    self.pol_round,
                    &h.hash(),
                ),
                &self.signature,
            )
            .is_ok()
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    Proposal(Box<Proposal>),
    Vote(Vote),
    /// A committed block with its certificate (decision announcement and catch-up).
    Commit(Box<Block>),
    /// "Send me committed blocks from this height on."
    SyncRequest {
        from_height: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    Propose,
    Prevote,
    Precommit,
}

/// What a replica asks the network to do.
#[derive(Debug, Clone)]
pub enum Out {
    Broadcast(Msg),
    Send(usize, Msg),
    Timer {
        delay: u64,
        height: u64,
        round: u32,
        step: Step,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    Honest,
    /// Byzantine: as leader, sends different blocks to different peers; as
    /// voter, prevotes and precommits every proposal it sees.
    Equivocate,
}

/// Timeout schedule in simulated time units: grows linearly with the round.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub base: u64,
    pub per_round: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            base: 300,
            per_round: 150,
        }
    }
}

pub struct Replica {
    pub index: usize,
    pub node: Node,
    pub behavior: Behavior,
    pub mempool: Vec<Transaction>,
    pub evidence: Vec<EquivocationEvidence>,
    timeouts: Timeouts,
    round: u32,
    step: Step,
    locked: Option<(u32, Hash)>,
    valid: Option<(u32, Hash)>,
    blocks: BTreeMap<Hash, Block>,
    validity: BTreeMap<Hash, bool>,
    proposals: BTreeMap<u32, (Hash, Option<u32>)>,
    proposal_msgs: BTreeMap<u32, Proposal>,
    votes: BTreeMap<(u32, VoteKind), BTreeMap<KeyId, Vote>>,
    fired: BTreeSet<(u32, u8)>,
    future: Vec<(usize, Msg)>,
    pending_commits: BTreeMap<u64, Block>,
    sync_asked: BTreeSet<(usize, u64)>,
    out: Vec<Out>,
}

// "First time" rule identifiers, per round.
const FIRE_PREVOTE_TIMER: u8 = 1;
const FIRE_LOCK: u8 = 2;
const FIRE_PRECOMMIT_TIMER: u8 = 3;

impl Replica {
    pub fn new(index: usize, node: Node, behavior: Behavior, timeouts: Timeouts) -> Self {
        Self {
            index,
            node,
            behavior,
            mempool: vec![],
            evidence: vec![],
            timeouts,
            round: 0,
            step: Step::Propose,
            locked: None,
            valid: None,
            blocks: BTreeMap::new(),
            validity: BTreeMap::new(),
            proposals: BTreeMap::new(),
            proposal_msgs: BTreeMap::new(),
            votes: BTreeMap::new(),
            fired: BTreeSet::new(),
            future: vec![],
            pending_commits: BTreeMap::new(),
            sync_asked: BTreeSet::new(),
            out: vec![],
        }
    }

    pub fn height(&self) -> u64 {
        self.node.next_height()
    }

    pub fn round(&self) -> u32 {
        self.round
    }

    fn quorum(&self) -> usize {
        self.node.validators.quorum()
    }

    fn take_out(&mut self) -> Vec<Out> {
        std::mem::take(&mut self.out)
    }

    /// Begin (or, after a restart, resume) consensus at the current height.
    pub fn start(&mut self) -> Vec<Out> {
        self.start_round(self.round);
        self.take_out()
    }

    /// Back online after a crash. Consensus state is durable: the replica
    /// resumes at the round and step it had reached, never re-entering an
    /// earlier step (which could make an honest node vote twice). It re-sends
    /// its own votes for the round and asks peers for anything it missed.
    pub fn recover(&mut self) -> Vec<Out> {
        self.out.push(Out::Broadcast(Msg::SyncRequest {
            from_height: self.height(),
        }));
        let me = self.node.id();
        let mine: Vec<Vote> = self
            .votes
            .range((self.round, VoteKind::Prevote)..=(self.round, VoteKind::Precommit))
            .filter_map(|(_, m)| m.get(&me).cloned())
            .collect();
        for v in mine {
            self.out.push(Out::Broadcast(Msg::Vote(v)));
        }
        self.timer(self.step);
        self.progress();
        self.take_out()
    }

    pub fn on_timeout(&mut self, height: u64, round: u32, step: Step) -> Vec<Out> {
        if height == self.height() && round == self.round {
            match step {
                Step::Propose if self.step == Step::Propose => {
                    self.cast(VoteKind::Prevote, NIL);
                    self.step = Step::Prevote;
                }
                Step::Prevote if self.step == Step::Prevote => {
                    self.cast(VoteKind::Precommit, NIL);
                    self.step = Step::Precommit;
                }
                Step::Precommit => self.start_round(round + 1),
                _ => {}
            }
            self.progress();
        }
        self.take_out()
    }

    pub fn on_message(&mut self, from: usize, msg: Msg) -> Vec<Out> {
        self.handle(from, msg);
        self.progress();
        self.take_out()
    }

    fn handle(&mut self, from: usize, msg: Msg) {
        let h = self.height();
        match msg {
            Msg::SyncRequest { from_height } => {
                let start = from_height.saturating_sub(1) as usize;
                for b in self.node.chain.iter().skip(start).take(MAX_SYNC_BATCH) {
                    self.out
                        .push(Out::Send(from, Msg::Commit(Box::new(b.clone()))));
                }
                // Re-gossip this height's consensus messages: the peer may have
                // missed them while offline. All are signed, so relaying is safe.
                let since = self.round.saturating_sub(SYNC_ROUNDS - 1);
                for p in self
                    .proposal_msgs
                    .range(since..)
                    .map(|(_, p)| p.clone())
                    .collect::<Vec<_>>()
                {
                    self.out.push(Out::Send(from, Msg::Proposal(Box::new(p))));
                }
                let votes: Vec<Vote> = self
                    .votes
                    .range((since, VoteKind::Prevote)..)
                    .flat_map(|(_, m)| m.values().cloned())
                    .collect();
                for v in votes {
                    self.out.push(Out::Send(from, Msg::Vote(v)));
                }
            }
            Msg::Commit(b) => {
                let bh = b.header.height;
                if bh == h {
                    if self.node.check_commit(&b).is_ok() {
                        self.finalize(*b);
                    }
                } else if bh > h && self.pending_commits.len() < MAX_SYNC_BATCH {
                    self.pending_commits.insert(bh, *b);
                    self.ask_sync(from);
                }
            }
            Msg::Proposal(p) => {
                if p.height > h {
                    self.defer(from, Msg::Proposal(p));
                } else if p.height == h && p.verify(&self.node) {
                    let bh = p.block.header.hash();
                    self.blocks.entry(bh).or_insert_with(|| p.block.clone());
                    self.proposals.entry(p.round).or_insert((bh, p.pol_round));
                    self.proposal_msgs
                        .entry(p.round)
                        .or_insert_with(|| (*p).clone());
                    if self.behavior == Behavior::Equivocate {
                        // Vote both for the block and against it, to everyone.
                        for t in [bh, NIL] {
                            self.cast_at(p.round, VoteKind::Prevote, t);
                            self.cast_at(p.round, VoteKind::Precommit, t);
                        }
                    }
                }
            }
            Msg::Vote(v) => {
                if v.height > h {
                    self.defer(from, Msg::Vote(v));
                } else if v.height == h
                    && v.chain_id == self.node.genesis.chain_id()
                    && v.verify(&self.node.validators)
                {
                    self.record_vote(v);
                }
            }
        }
    }

    fn defer(&mut self, from: usize, msg: Msg) {
        if self.future.len() < MAX_FUTURE {
            self.future.push((from, msg));
        }
        self.ask_sync(from);
    }

    fn ask_sync(&mut self, peer: usize) {
        let h = self.height();
        if self.sync_asked.insert((peer, h)) {
            self.out
                .push(Out::Send(peer, Msg::SyncRequest { from_height: h }));
        }
    }

    fn record_vote(&mut self, v: Vote) {
        let slot = self.votes.entry((v.round, v.kind)).or_default();
        match slot.get(&v.validator) {
            None => {
                slot.insert(v.validator, v);
            }
            Some(prev) if prev.block != v.block => {
                if let Some(ev) = EquivocationEvidence::check(prev, &v, &self.node.validators) {
                    if !self.evidence.iter().any(|e| {
                        e.a.validator == ev.a.validator
                            && e.a.height == ev.a.height
                            && e.a.round == ev.a.round
                            && e.a.kind == ev.a.kind
                    }) {
                        self.evidence.push(ev);
                    }
                }
            }
            Some(_) => {}
        }
    }

    fn cast(&mut self, kind: VoteKind, block: Hash) {
        self.cast_at(self.round, kind, block);
    }

    fn cast_at(&mut self, round: u32, kind: VoteKind, block: Hash) {
        let n = &self.node;
        let v = Vote::new(
            n.key(),
            n.genesis.chain_id(),
            n.next_height(),
            round,
            kind,
            block,
        );
        self.record_vote(v.clone());
        self.out.push(Out::Broadcast(Msg::Vote(v)));
    }

    fn count(&self, round: u32, kind: VoteKind, block: &Hash) -> usize {
        self.votes
            .get(&(round, kind))
            .map_or(0, |m| m.values().filter(|v| &v.block == block).count())
    }

    fn total(&self, round: u32, kind: VoteKind) -> usize {
        self.votes.get(&(round, kind)).map_or(0, |m| m.len())
    }

    fn is_valid(&mut self, bh: &Hash) -> bool {
        if let Some(v) = self.validity.get(bh) {
            return *v;
        }
        let ok = self
            .blocks
            .get(bh)
            .is_some_and(|b| self.node.validate_block(b).is_ok());
        self.validity.insert(*bh, ok);
        ok
    }

    fn timer(&mut self, step: Step) {
        let delay = self.timeouts.base + self.timeouts.per_round * self.round as u64;
        self.out.push(Out::Timer {
            delay,
            height: self.height(),
            round: self.round,
            step,
        });
    }

    fn start_round(&mut self, round: u32) {
        self.round = round;
        self.step = Step::Propose;
        let h = self.height();
        let me = self.node.id();
        if self.node.validators.leader(h, round) == me {
            let (block, pol) = match self.valid {
                Some((vr, vh)) if self.blocks.contains_key(&vh) => {
                    (self.blocks[&vh].clone(), Some(vr))
                }
                _ => {
                    let (b, rejected) = self.node.propose_at(round, self.mempool.clone());
                    let drop: BTreeSet<Hash> = rejected.iter().map(|(t, _)| t.id()).collect();
                    self.mempool.retain(|t| !drop.contains(&t.id()));
                    (b, None)
                }
            };
            if self.behavior == Behavior::Equivocate {
                // Different, individually valid blocks to different halves of the network.
                let (alt, _) = self.node.propose_at(round, vec![]);
                let n = self.node.validators.n();
                for peer in 0..n {
                    let b = if peer % 2 == 0 {
                        block.clone()
                    } else {
                        alt.clone()
                    };
                    let p = Proposal::new(self.node.key(), h, round, pol, b);
                    if peer == self.index {
                        self.handle(peer, Msg::Proposal(Box::new(p)));
                    } else {
                        self.out.push(Out::Send(peer, Msg::Proposal(Box::new(p))));
                    }
                }
            } else {
                let p = Proposal::new(self.node.key(), h, round, pol, block);
                self.handle(self.index, Msg::Proposal(Box::new(p.clone())));
                self.out.push(Out::Broadcast(Msg::Proposal(Box::new(p))));
            }
        }
        self.timer(Step::Propose);
    }

    /// Apply every protocol rule whose condition now holds, until none does.
    fn progress(&mut self) {
        loop {
            let before = (self.height(), self.round, self.step, self.fired.len());
            self.step_once();
            if before == (self.height(), self.round, self.step, self.fired.len()) {
                break;
            }
        }
    }

    fn step_once(&mut self) {
        let r = self.round;
        let q = self.quorum();

        // Decision: any round's proposal with n−f precommits commits the block.
        let decided = self.proposals.iter().find_map(|(&rr, &(bh, _))| {
            (self.count(rr, VoteKind::Precommit, &bh) >= q).then_some((rr, bh))
        });
        if let Some((rr, bh)) = decided {
            if self.is_valid(&bh) {
                let votes: Vec<Vote> = self.votes[&(rr, VoteKind::Precommit)]
                    .values()
                    .filter(|v| v.block == bh)
                    .take(q)
                    .cloned()
                    .collect();
                let mut block = self.blocks[&bh].clone();
                block.qc = Some(QuorumCertificate { votes });
                self.out
                    .push(Out::Broadcast(Msg::Commit(Box::new(block.clone()))));
                self.finalize(block);
                return;
            }
        }

        // Proposal phase: prevote the proposal if it is valid and compatible with our lock.
        if self.step == Step::Propose {
            if let Some(&(bh, pol)) = self.proposals.get(&r) {
                let target = match pol {
                    None => {
                        let ok = self.is_valid(&bh) && self.locked.is_none_or(|(_, lh)| lh == bh);
                        Some(if ok { bh } else { NIL })
                    }
                    Some(vr) if vr < r && self.count(vr, VoteKind::Prevote, &bh) >= q => {
                        let ok = self.is_valid(&bh)
                            && self.locked.is_none_or(|(lr, lh)| lr <= vr || lh == bh);
                        Some(if ok { bh } else { NIL })
                    }
                    _ => None,
                };
                if let Some(t) = target {
                    self.cast(VoteKind::Prevote, t);
                    self.step = Step::Prevote;
                }
            }
        }

        if self.step == Step::Prevote
            && self.total(r, VoteKind::Prevote) >= q
            && self.fired.insert((r, FIRE_PREVOTE_TIMER))
        {
            self.timer(Step::Prevote);
        }

        // n−f prevotes for a valid proposal: lock and precommit it.
        if self.step >= Step::Prevote {
            if let Some(&(bh, _)) = self.proposals.get(&r) {
                if self.count(r, VoteKind::Prevote, &bh) >= q
                    && self.is_valid(&bh)
                    && self.fired.insert((r, FIRE_LOCK))
                {
                    if self.step == Step::Prevote {
                        self.locked = Some((r, bh));
                        self.cast(VoteKind::Precommit, bh);
                        self.step = Step::Precommit;
                    }
                    self.valid = Some((r, bh));
                }
            }
        }

        if self.step == Step::Prevote && self.count(r, VoteKind::Prevote, &NIL) >= q {
            self.cast(VoteKind::Precommit, NIL);
            self.step = Step::Precommit;
        }

        if self.total(r, VoteKind::Precommit) >= q && self.fired.insert((r, FIRE_PRECOMMIT_TIMER)) {
            self.timer(Step::Precommit);
        }

        // f+1 validators already in a later round: at least one is honest, so skip ahead.
        let f1 = self.node.validators.f() + 1;
        let mut later: BTreeMap<u32, BTreeSet<KeyId>> = BTreeMap::new();
        for ((rr, _), m) in self.votes.range((r + 1, VoteKind::Prevote)..) {
            later.entry(*rr).or_default().extend(m.keys().copied());
        }
        if let Some((&rr, _)) = later.iter().find(|(_, s)| s.len() >= f1) {
            self.start_round(rr);
        }
    }

    fn finalize(&mut self, block: Block) {
        if self.node.commit(&block).is_err() {
            return;
        }
        let committed: BTreeSet<Hash> = block.txs.iter().map(|t| t.id()).collect();
        self.mempool.retain(|t| !committed.contains(&t.id()));
        self.round = 0;
        self.locked = None;
        self.valid = None;
        self.blocks.clear();
        self.validity.clear();
        self.proposals.clear();
        self.proposal_msgs.clear();
        self.votes.clear();
        self.fired.clear();
        let h = self.height();
        self.pending_commits.retain(|k, _| *k >= h);
        if let Some(next) = self.pending_commits.remove(&h) {
            if self.node.check_commit(&next).is_ok() {
                self.finalize(next);
                return;
            }
        }
        self.start_round(0);
        let replay: Vec<(usize, Msg)> = std::mem::take(&mut self.future);
        for (from, m) in replay {
            self.handle(from, m);
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic simulated network
// ---------------------------------------------------------------------------

/// A network split: nodes in different groups cannot talk until `until`;
/// messages between them are held and delivered after the split heals.
#[derive(Debug, Clone)]
pub struct Partition {
    pub groups: Vec<Vec<usize>>,
    pub from: u64,
    pub until: u64,
}

#[derive(Debug, Clone)]
pub struct Outage {
    pub node: usize,
    pub from: u64,
    /// `None` = never recovers.
    pub until: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct SimConfig {
    pub seed: u64,
    pub min_delay: u64,
    pub max_delay: u64,
    pub outages: Vec<Outage>,
    pub partitions: Vec<Partition>,
    pub byzantine: Vec<usize>,
    pub timeouts: Timeouts,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            seed: 1,
            min_delay: 5,
            max_delay: 60,
            outages: vec![],
            partitions: vec![],
            byzantine: vec![],
            timeouts: Timeouts::default(),
        }
    }
}

enum Event {
    Deliver {
        from: usize,
        to: usize,
        msg: Msg,
    },
    Timeout {
        node: usize,
        height: u64,
        round: u32,
        step: Step,
    },
    Recover {
        node: usize,
    },
}

pub struct SimNet {
    pub replicas: Vec<Replica>,
    pub now: u64,
    pub delivered: u64,
    cfg: SimConfig,
    queue: BTreeMap<(u64, u64), Event>,
    seq: u64,
    rng: u64,
}

impl SimNet {
    /// `nodes` in validator order; each becomes a replica.
    pub fn new(nodes: Vec<Node>, cfg: SimConfig) -> Self {
        let replicas = nodes
            .into_iter()
            .enumerate()
            .map(|(i, n)| {
                let b = if cfg.byzantine.contains(&i) {
                    Behavior::Equivocate
                } else {
                    Behavior::Honest
                };
                Replica::new(i, n, b, cfg.timeouts)
            })
            .collect();
        let rng = cfg.seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut net = Self {
            replicas,
            now: 0,
            delivered: 0,
            cfg,
            queue: BTreeMap::new(),
            seq: 0,
            rng,
        };
        for o in net.cfg.outages.clone() {
            if let Some(t) = o.until {
                net.push(t, Event::Recover { node: o.node });
            }
        }
        for i in 0..net.replicas.len() {
            if net.up(i, 0) {
                let outs = net.replicas[i].start();
                net.dispatch(i, outs);
            }
        }
        net
    }

    fn rand(&mut self) -> u64 {
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        self.rng.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn push(&mut self, at: u64, e: Event) {
        self.seq += 1;
        self.queue.insert((at, self.seq), e);
    }

    pub fn up(&self, node: usize, t: u64) -> bool {
        !self
            .cfg
            .outages
            .iter()
            .any(|o| o.node == node && t >= o.from && o.until.is_none_or(|u| t < u))
    }

    fn split_until(&self, a: usize, b: usize, t: u64) -> Option<u64> {
        self.cfg
            .partitions
            .iter()
            .filter(|p| t >= p.from && t < p.until)
            .filter(|p| {
                let g = |x: usize| p.groups.iter().position(|grp| grp.contains(&x));
                g(a) != g(b)
            })
            .map(|p| p.until)
            .max()
    }

    /// Add a transaction to every validator's mempool (gossip is assumed).
    pub fn submit(&mut self, tx: Transaction) {
        for r in &mut self.replicas {
            r.mempool.push(tx.clone());
        }
    }

    fn send(&mut self, from: usize, to: usize, msg: Msg) {
        let span = self.cfg.max_delay - self.cfg.min_delay + 1;
        let delay = self.cfg.min_delay + self.rand() % span;
        let at = match self.split_until(from, to, self.now) {
            Some(heal) => heal + delay,
            None => self.now + delay,
        };
        self.push(at, Event::Deliver { from, to, msg });
    }

    fn dispatch(&mut self, from: usize, outs: Vec<Out>) {
        for o in outs {
            match o {
                Out::Broadcast(m) => {
                    for to in 0..self.replicas.len() {
                        if to != from {
                            self.send(from, to, m.clone());
                        }
                    }
                }
                Out::Send(to, m) => {
                    if to != from && to < self.replicas.len() {
                        self.send(from, to, m);
                    }
                }
                Out::Timer {
                    delay,
                    height,
                    round,
                    step,
                } => {
                    self.push(
                        self.now + delay,
                        Event::Timeout {
                            node: from,
                            height,
                            round,
                            step,
                        },
                    );
                }
            }
        }
    }

    /// Process one event. Returns false when nothing is left.
    pub fn step(&mut self) -> bool {
        let Some(((at, _), e)) = self.queue.pop_first() else {
            return false;
        };
        self.now = at;
        match e {
            Event::Deliver { from, to, msg } => {
                if self.up(to, at) {
                    self.delivered += 1;
                    let outs = self.replicas[to].on_message(from, msg);
                    self.dispatch(to, outs);
                }
            }
            Event::Timeout {
                node,
                height,
                round,
                step,
            } => {
                if self.up(node, at) {
                    let outs = self.replicas[node].on_timeout(height, round, step);
                    self.dispatch(node, outs);
                }
            }
            Event::Recover { node } => {
                let outs = self.replicas[node].recover();
                self.dispatch(node, outs);
            }
        }
        true
    }

    pub fn honest(&self) -> impl Iterator<Item = &Replica> {
        self.replicas
            .iter()
            .filter(|r| r.behavior == Behavior::Honest)
    }

    /// Run until every honest replica that is up has committed `height`
    /// blocks, or until `deadline`. Returns whether the target was reached.
    pub fn run_until_height(&mut self, height: usize, deadline: u64) -> bool {
        loop {
            let now = self.now;
            let done = self
                .replicas
                .iter()
                .enumerate()
                .filter(|(i, r)| r.behavior == Behavior::Honest && self.up(*i, now))
                .all(|(_, r)| r.node.chain.len() >= height);
            if done {
                return true;
            }
            if self.now > deadline || !self.step() {
                return false;
            }
        }
    }

    pub fn run_until(&mut self, deadline: u64) {
        while self
            .queue
            .first_key_value()
            .is_some_and(|((t, _), _)| *t <= deadline)
        {
            self.step();
        }
        self.now = self.now.max(deadline);
    }

    /// Safety: honest chains never diverge; one is always a prefix of another.
    pub fn check_agreement(&self) -> Result<(), String> {
        let chains: Vec<&Vec<Block>> = self.honest().map(|r| &r.node.chain).collect();
        for a in &chains {
            for b in &chains {
                for (x, y) in a.iter().zip(b.iter()) {
                    if x.header.hash() != y.header.hash() {
                        return Err(format!(
                            "honest validators disagree at height {}",
                            x.header.height
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn min_honest_height(&self) -> usize {
        self.honest().map(|r| r.node.chain.len()).min().unwrap_or(0)
    }
}
