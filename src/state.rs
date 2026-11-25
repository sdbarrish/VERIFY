//! CORE: the deterministic state machine every validator runs independently.
//!
//! Given the same genesis and the same ordered transactions, every honest
//! node computes the same state root. Validation is pure rule evaluation over
//! signed data; nothing in this path is a heuristic, a model or a score.

use crate::codec::{Canonical, Enc};
use crate::crypto::{hash, short, Hash, HybridPublicKey, KeyId};
use crate::policy::{ApprovalRule, Policy, Principal, PrincipalClass};
use crate::tx::{Payload, Reconciliation, Transaction, MAX_APPROVALS, MAX_TTL, PROTOCOL_VERSION};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Network constitution. Its hash is the chain id, which every transaction and vote binds.
#[derive(Debug, Clone)]
pub struct Genesis {
    pub network: String,
    pub validators: Vec<HybridPublicKey>,
    /// Jurisdictional root keys that authorize policy (§6.2 key separation).
    pub root_authorities: Vec<HybridPublicKey>,
    pub root_threshold: u8,
}

impl Canonical for Genesis {
    fn encode(&self, e: &mut Enc) {
        e.str(&self.network)
            .list(&self.validators)
            .list(&self.root_authorities)
            .u8(self.root_threshold);
    }
}

impl Genesis {
    pub fn chain_id(&self) -> Hash {
        hash("VERIFY/chain-id/v1", &self.to_canonical())
    }

    pub fn validate(&self) -> Result<(), String> {
        let n = self.validators.len();
        if n < 4 {
            return Err("BFT needs n >= 3f+1 with f >= 1, i.e. at least 4 validators".into());
        }
        let vids: BTreeSet<KeyId> = self.validators.iter().map(|k| k.id()).collect();
        let rids: BTreeSet<KeyId> = self.root_authorities.iter().map(|k| k.id()).collect();
        if vids.len() != n || rids.len() != self.root_authorities.len() {
            return Err("duplicate keys in genesis".into());
        }
        if !vids.is_disjoint(&rids) {
            return Err("validator keys and root keys must be separate".into());
        }
        if self.root_threshold < 2 || self.root_threshold as usize > rids.len() {
            return Err("root threshold must be at least 2 and achievable".into());
        }
        Ok(())
    }

    pub fn reserved_keys(&self) -> BTreeSet<KeyId> {
        self.validators
            .iter()
            .chain(&self.root_authorities)
            .map(|k| k.id())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    Malformed(String),
    WrongChain,
    Expired,
    Replay,
    UnknownSigner(String),
    BadSignature(String),
    /// A key registered as analytics/AI tried to act on the live election (§8.4).
    AiIsolation(String),
    InsufficientApprovals(String),
    Unauthorized(String),
    PolicyViolation(String),
    ConfigurationLocked,
    PredecessorMismatch,
    Quarantined(String),
    ConflictOfInterest(String),
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reject::Malformed(m) => write!(f, "malformed: {m}"),
            Reject::WrongChain => write!(
                f,
                "transaction bound to a different chain or protocol version"
            ),
            Reject::Expired => write!(f, "expired or over-long validity window"),
            Reject::Replay => write!(f, "replayed or stale nonce"),
            Reject::UnknownSigner(m) => write!(f, "unknown signer: {m}"),
            Reject::BadSignature(m) => write!(f, "bad signature: {m}"),
            Reject::AiIsolation(m) => write!(f, "AI isolation invariant: {m}"),
            Reject::InsufficientApprovals(m) => write!(f, "insufficient approvals: {m}"),
            Reject::Unauthorized(m) => write!(f, "unauthorized: {m}"),
            Reject::PolicyViolation(m) => write!(f, "policy violation: {m}"),
            Reject::ConfigurationLocked => write!(f, "election configuration is locked"),
            Reject::PredecessorMismatch => {
                write!(f, "predecessor does not match the batch's latest record")
            }
            Reject::Quarantined(m) => write!(f, "batch is quarantined: {m}"),
            Reject::ConflictOfInterest(m) => write!(f, "conflict of interest: {m}"),
        }
    }
}

/// Accepted, possibly with an observed exception. An exception quarantines the
/// batch; it is a finding to investigate, not a determination of misconduct (§1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    Exception(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub tx: Hash,
    pub kind: String,
    pub signers: Vec<KeyId>,
}

impl Canonical for HistoryEntry {
    fn encode(&self, e: &mut Enc) {
        e.hash(&self.tx).str(&self.kind).list(&self.signers);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub jurisdiction: String,
    pub election: String,
    pub ballot_style: String,
    pub quantity: u64,
    pub inventory_commitment: Hash,
    pub seal_commitment: Hash,
    pub state: String,
    pub quarantined: bool,
    pub reconciliation: Option<Reconciliation>,
    pub exceptions: Vec<String>,
    pub history: Vec<HistoryEntry>,
}

impl Batch {
    pub fn last_tx(&self) -> Hash {
        self.history
            .last()
            .expect("batch has a registration record")
            .tx
    }
}

impl Canonical for Batch {
    fn encode(&self, e: &mut Enc) {
        e.str(&self.jurisdiction)
            .str(&self.election)
            .str(&self.ballot_style)
            .u64(self.quantity);
        e.hash(&self.inventory_commitment)
            .hash(&self.seal_commitment)
            .str(&self.state)
            .bool(self.quarantined);
        match &self.reconciliation {
            None => {
                e.u8(0);
            }
            Some(r) => {
                e.u8(1);
                r.encode(e);
            }
        }
        e.list(&self.exceptions).list(&self.history);
    }
}

#[derive(Debug, Clone)]
pub struct LedgerState {
    chain_id: Hash,
    roots: BTreeMap<KeyId, HybridPublicKey>,
    root_threshold: u8,
    reserved: BTreeSet<KeyId>,
    pub policies: BTreeMap<String, Policy>,
    pub locked: BTreeSet<String>,
    pub batches: BTreeMap<String, Batch>,
    pub nonces: BTreeMap<KeyId, u64>,
}

const MAX_TEXT: usize = 256;

impl LedgerState {
    pub fn new(genesis: &Genesis) -> Self {
        Self {
            chain_id: genesis.chain_id(),
            roots: genesis
                .root_authorities
                .iter()
                .map(|k| (k.id(), k.clone()))
                .collect(),
            root_threshold: genesis.root_threshold,
            reserved: genesis.reserved_keys(),
            policies: BTreeMap::new(),
            locked: BTreeSet::new(),
            batches: BTreeMap::new(),
            nonces: BTreeMap::new(),
        }
    }

    /// Commitment to the complete state; validators sign blocks that carry it.
    pub fn root(&self) -> Hash {
        let mut e = Enc::new();
        e.hash(&self.chain_id);
        e.u32(self.policies.len() as u32);
        for (j, p) in &self.policies {
            e.str(j).hash(&p.hash());
        }
        e.u32(self.locked.len() as u32);
        for j in &self.locked {
            e.str(j);
        }
        e.u32(self.batches.len() as u32);
        for (id, b) in &self.batches {
            e.str(id);
            b.encode(&mut e);
        }
        e.u32(self.nonces.len() as u32);
        for (k, n) in &self.nonces {
            e.hash(k).u64(*n);
        }
        hash("VERIFY/state-root/v1", &e.finish())
    }

    /// Validate and apply one transaction at `height`. On error the state is unchanged.
    pub fn apply(&mut self, tx: &Transaction, height: u64) -> Result<Outcome, Reject> {
        let b = &tx.body;
        if b.protocol_version != PROTOCOL_VERSION || b.chain_id != self.chain_id {
            return Err(Reject::WrongChain);
        }
        for s in [&b.election, &b.jurisdiction] {
            if s.is_empty() || s.len() > MAX_TEXT {
                return Err(Reject::Malformed(
                    "election and jurisdiction are required".into(),
                ));
            }
        }
        if height > b.expiry_height || b.expiry_height > height.saturating_add(MAX_TTL) {
            return Err(Reject::Expired);
        }
        if self
            .nonces
            .get(&b.origin)
            .is_some_and(|last| b.nonce <= *last)
        {
            return Err(Reject::Replay);
        }
        if tx.approvals.is_empty() || tx.approvals.len() > MAX_APPROVALS {
            return Err(Reject::Malformed("approval count out of bounds".into()));
        }
        let signer_ids: BTreeSet<KeyId> = tx.approvals.iter().map(|a| a.signer).collect();
        if signer_ids.len() != tx.approvals.len() {
            return Err(Reject::Malformed("duplicate approver".into()));
        }
        if !signer_ids.contains(&b.origin) {
            return Err(Reject::Malformed(
                "origin did not approve its own transaction".into(),
            ));
        }

        // CORE invariant (§8.4): an AI/analytics key never acts on a live election,
        // whatever any policy says and whichever jurisdiction it is registered in.
        for id in &signer_ids {
            if let Some(p) = self.ai_principal(id) {
                return Err(Reject::AiIsolation(format!(
                    "{} is registered as analytics/AI and cannot sign",
                    p.name
                )));
            }
        }

        let outcome = match &b.payload {
            Payload::ActivatePolicy(p) => {
                self.check_root_quorum(tx)?;
                self.activate_policy(p, &b.jurisdiction)?;
                Outcome::Applied
            }
            Payload::CommenceElection => {
                self.check_root_quorum(tx)?;
                if !self.policies.contains_key(&b.jurisdiction) {
                    return Err(Reject::PolicyViolation(
                        "no active policy for jurisdiction".into(),
                    ));
                }
                if !self.locked.insert(b.jurisdiction.clone()) {
                    return Err(Reject::ConfigurationLocked);
                }
                Outcome::Applied
            }
            _ => self.apply_batch_tx(tx)?,
        };
        self.nonces.insert(b.origin, b.nonce);
        Ok(outcome)
    }

    fn ai_principal(&self, id: &KeyId) -> Option<&Principal> {
        self.policies
            .values()
            .flat_map(|p| p.principals.iter())
            .find(|p| p.class == PrincipalClass::AnalyticsAi && &p.key.id() == id)
    }

    fn check_root_quorum(&self, tx: &Transaction) -> Result<(), Reject> {
        for a in &tx.approvals {
            let pk = self.roots.get(&a.signer).ok_or_else(|| {
                Reject::UnknownSigner(format!("{} is not a root authority", short(&a.signer)))
            })?;
            if !tx.verify_approval(a, pk) {
                return Err(Reject::BadSignature(short(&a.signer)));
            }
        }
        if tx.approvals.len() < self.root_threshold as usize {
            return Err(Reject::InsufficientApprovals(format!(
                "{} of {} root authorities",
                tx.approvals.len(),
                self.root_threshold
            )));
        }
        Ok(())
    }

    fn activate_policy(&mut self, p: &Policy, jurisdiction: &str) -> Result<(), Reject> {
        if p.jurisdiction != jurisdiction {
            return Err(Reject::Malformed(
                "policy jurisdiction differs from transaction scope".into(),
            ));
        }
        if self.locked.contains(jurisdiction) {
            return Err(Reject::ConfigurationLocked);
        }
        let current = self.policies.get(jurisdiction);
        let (want_pred, want_ver) = match current {
            None => (None, 1),
            Some(c) => (Some(c.hash()), c.version + 1),
        };
        if p.predecessor != want_pred || p.version != want_ver {
            return Err(Reject::PolicyViolation(
                "policy must reference the current version as predecessor".into(),
            ));
        }
        p.validate(&self.reserved).map_err(|e| {
            if e.starts_with("AI isolation") {
                Reject::AiIsolation(e)
            } else {
                Reject::PolicyViolation(e)
            }
        })?;
        self.policies.insert(jurisdiction.to_string(), p.clone());
        Ok(())
    }

    /// Resolve and verify every approver against the jurisdiction's policy.
    fn resolve_signers<'a>(
        policy: &'a Policy,
        tx: &Transaction,
    ) -> Result<Vec<&'a Principal>, Reject> {
        tx.approvals
            .iter()
            .map(|a| {
                let p = policy
                    .principal(&a.signer)
                    .ok_or_else(|| Reject::UnknownSigner(short(&a.signer)))?;
                if !tx.verify_approval(a, &p.key) {
                    return Err(Reject::BadSignature(p.name.clone()));
                }
                Ok(p)
            })
            .collect()
    }

    fn check_rule(rule: &ApprovalRule, signers: &[&Principal], what: &str) -> Result<(), Reject> {
        let mut roles = BTreeSet::new();
        for s in signers {
            match &s.role {
                Some(r) if rule.eligible_roles.contains(r) => {
                    roles.insert(r.as_str());
                }
                _ => {
                    return Err(Reject::Unauthorized(format!(
                        "{} is not eligible to approve {what}",
                        s.name
                    )))
                }
            }
        }
        if signers.len() < rule.threshold as usize || roles.len() < rule.min_distinct_roles as usize
        {
            return Err(Reject::InsufficientApprovals(format!(
                "{what} needs {} approvers across {} roles, got {} across {}",
                rule.threshold,
                rule.min_distinct_roles,
                signers.len(),
                roles.len()
            )));
        }
        Ok(())
    }

    fn apply_batch_tx(&mut self, tx: &Transaction) -> Result<Outcome, Reject> {
        let b = &tx.body;
        let policy = self
            .policies
            .get(&b.jurisdiction)
            .ok_or_else(|| Reject::PolicyViolation("no active policy for jurisdiction".into()))?;
        if !self.locked.contains(&b.jurisdiction) {
            return Err(Reject::PolicyViolation(
                "election has not commenced; configuration is not locked".into(),
            ));
        }
        let signers = Self::resolve_signers(policy, tx)?;
        let signer_ids: Vec<KeyId> = tx.approvals.iter().map(|a| a.signer).collect();
        let entry = HistoryEntry {
            tx: tx.id(),
            kind: b.payload.kind().into(),
            signers: signer_ids,
        };

        if let Payload::RegisterBatch {
            batch_id,
            ballot_style,
            quantity,
            inventory_commitment,
            seal_commitment,
        } = &b.payload
        {
            if batch_id.is_empty()
                || batch_id.len() > MAX_TEXT
                || ballot_style.len() > MAX_TEXT
                || *quantity == 0
            {
                return Err(Reject::Malformed("invalid batch registration".into()));
            }
            if b.predecessor.is_some() {
                return Err(Reject::PredecessorMismatch);
            }
            if self.batches.contains_key(batch_id) {
                return Err(Reject::PolicyViolation(format!(
                    "batch {batch_id} already registered"
                )));
            }
            Self::check_rule(&policy.registration, &signers, "batch registration")?;
            let batch = Batch {
                jurisdiction: b.jurisdiction.clone(),
                election: b.election.clone(),
                ballot_style: ballot_style.clone(),
                quantity: *quantity,
                inventory_commitment: *inventory_commitment,
                seal_commitment: *seal_commitment,
                state: policy.initial_state.clone(),
                quarantined: false,
                reconciliation: None,
                exceptions: vec![],
                history: vec![entry],
            };
            self.batches.insert(batch_id.clone(), batch);
            return Ok(Outcome::Applied);
        }

        let batch_id = match &b.payload {
            Payload::CustodyTransfer { batch_id, .. }
            | Payload::Reconcile { batch_id, .. }
            | Payload::EmergencyCorrection { batch_id, .. } => batch_id,
            _ => unreachable!("non-batch payloads handled by caller"),
        };
        let batch = self
            .batches
            .get(batch_id)
            .ok_or_else(|| Reject::PolicyViolation(format!("unknown batch {batch_id}")))?;
        if batch.jurisdiction != b.jurisdiction || batch.election != b.election {
            return Err(Reject::Unauthorized(
                "batch belongs to a different jurisdiction or election".into(),
            ));
        }
        if b.predecessor != Some(batch.last_tx()) {
            return Err(Reject::PredecessorMismatch);
        }

        let mut next = batch.clone();
        let outcome = match &b.payload {
            Payload::CustodyTransfer {
                from,
                to,
                seal_intact,
                ..
            } => {
                if batch.quarantined {
                    return Err(Reject::Quarantined(
                        batch.exceptions.last().cloned().unwrap_or_default(),
                    ));
                }
                if from != &batch.state {
                    return Err(Reject::PolicyViolation(format!(
                        "batch is in {}, not {from}",
                        batch.state
                    )));
                }
                let t = policy.transition(from, to).ok_or_else(|| {
                    Reject::PolicyViolation(format!("transition {from} -> {to} not permitted"))
                })?;
                Self::check_rule(&t.rule, &signers, &format!("{from} -> {to}"))?;
                next.state = to.clone();
                if *seal_intact {
                    Outcome::Applied
                } else {
                    let msg = format!("seal reported broken on {from} -> {to}");
                    next.quarantined = true;
                    next.exceptions.push(msg.clone());
                    Outcome::Exception(msg)
                }
            }
            Payload::Reconcile { report, .. } => {
                if batch.quarantined {
                    return Err(Reject::Quarantined(
                        batch.exceptions.last().cloned().unwrap_or_default(),
                    ));
                }
                Self::check_rule(&policy.reconciliation, &signers, "reconciliation")?;
                next.reconciliation = Some(*report);
                let mut problems = vec![];
                if report.supplied != batch.quantity {
                    problems.push(format!(
                        "reported supply {} differs from registered {}",
                        report.supplied, batch.quantity
                    ));
                }
                if let Some(d) = report.discrepancy() {
                    problems.push(format!("unexplained discrepancy of {d} ballots"));
                }
                if problems.is_empty() {
                    Outcome::Applied
                } else {
                    let msg = problems.join("; ");
                    next.quarantined = true;
                    next.exceptions.push(msg.clone());
                    Outcome::Exception(msg)
                }
            }
            Payload::EmergencyCorrection {
                original_tx,
                corrected_state,
                reason,
                legal_authority,
                ..
            } => {
                if reason.is_empty()
                    || legal_authority.is_empty()
                    || reason.len() > MAX_TEXT
                    || legal_authority.len() > MAX_TEXT
                {
                    return Err(Reject::Malformed(
                        "correction needs a reason and legal authority".into(),
                    ));
                }
                if !policy.states.contains(corrected_state) {
                    return Err(Reject::PolicyViolation(format!(
                        "{corrected_state} is not a declared state"
                    )));
                }
                let original = batch
                    .history
                    .iter()
                    .find(|h| &h.tx == original_tx)
                    .ok_or_else(|| {
                        Reject::PolicyViolation(
                            "original transaction is not in this batch's history".into(),
                        )
                    })?;
                // Each required role covered by a distinct principal, nobody else.
                let required = &policy.emergency.required_roles;
                let covered: BTreeSet<&String> = signers
                    .iter()
                    .filter_map(|s| s.role.as_ref())
                    .filter(|r| required.contains(r))
                    .collect();
                if signers.len() != required.len() || covered.len() != required.len() {
                    return Err(Reject::InsufficientApprovals(format!("emergency correction requires exactly one approver for each of {required:?}")));
                }
                for s in &signers {
                    if original.signers.contains(&s.key.id()) {
                        return Err(Reject::ConflictOfInterest(format!(
                            "{} approved the transaction being corrected",
                            s.name
                        )));
                    }
                }
                next.state = corrected_state.clone();
                next.quarantined = false;
                Outcome::Applied
            }
            _ => unreachable!(),
        };
        next.history.push(entry);
        self.batches.insert(batch_id.clone(), next);
        Ok(outcome)
    }
}

impl crate::codec::Decode for Genesis {
    fn decode(d: &mut crate::codec::Dec<'_>) -> Result<Self, crate::codec::DecodeError> {
        Ok(Self {
            network: d.str()?,
            validators: d.list(crate::consensus::MAX_VALIDATORS)?,
            root_authorities: d.list(crate::codec::SMALL_LIST)?,
            root_threshold: d.u8()?,
        })
    }
}
