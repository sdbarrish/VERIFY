//! Transactions (white paper §6.1). No transaction type has a field for a
//! voter identity or a vote selection, so neither can reach the ledger.

use crate::codec::{Canonical, Enc};
use crate::crypto::{hash, verify, Hash, HybridKeypair, HybridSignature, KeyId};
use crate::policy::Policy;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_APPROVALS: usize = 16;
/// Longest a transaction may stay valid, in blocks.
pub const MAX_TTL: u64 = 1_000;

/// Ballot accounting for one batch (§4.2). Supplied plus additional receipts
/// must equal the sum of mutually exclusive dispositions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Reconciliation {
    pub supplied: u64,
    pub additional_receipts: u64,
    pub cast: u64,
    pub spoiled: u64,
    pub issued_unreturned: u64,
    pub provisional: u64,
    pub unused: u64,
    pub other: u64,
}

impl Reconciliation {
    /// Signed difference between what came in and what is accounted for.
    pub fn discrepancy(&self) -> Option<i128> {
        let inflow = self.supplied as i128 + self.additional_receipts as i128;
        let out = [self.cast, self.spoiled, self.issued_unreturned, self.provisional, self.unused, self.other]
            .iter()
            .map(|v| *v as i128)
            .sum::<i128>();
        (inflow != out).then_some(inflow - out)
    }
}

impl Canonical for Reconciliation {
    fn encode(&self, e: &mut Enc) {
        e.u64(self.supplied).u64(self.additional_receipts).u64(self.cast).u64(self.spoiled);
        e.u64(self.issued_unreturned).u64(self.provisional).u64(self.unused).u64(self.other);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// New or replacement policy version; needs the root-authority threshold.
    ActivatePolicy(Policy),
    /// Locks the jurisdiction's configuration for the election (§2.3).
    CommenceElection,
    RegisterBatch { batch_id: String, ballot_style: String, quantity: u64, inventory_commitment: Hash, seal_commitment: Hash },
    CustodyTransfer { batch_id: String, from: String, to: String, seal_intact: bool, evidence_commitment: Hash },
    Reconcile { batch_id: String, report: Reconciliation },
    /// IEOA correction (§4.3). Appends; never rewrites history.
    EmergencyCorrection { batch_id: String, original_tx: Hash, corrected_state: String, reason: String, legal_authority: String, evidence_commitment: Hash },
}

impl Canonical for Payload {
    fn encode(&self, e: &mut Enc) {
        match self {
            Payload::ActivatePolicy(p) => {
                e.u8(1);
                p.encode(e);
            }
            Payload::CommenceElection => {
                e.u8(2);
            }
            Payload::RegisterBatch { batch_id, ballot_style, quantity, inventory_commitment, seal_commitment } => {
                e.u8(3).str(batch_id).str(ballot_style).u64(*quantity).hash(inventory_commitment).hash(seal_commitment);
            }
            Payload::CustodyTransfer { batch_id, from, to, seal_intact, evidence_commitment } => {
                e.u8(4).str(batch_id).str(from).str(to).bool(*seal_intact).hash(evidence_commitment);
            }
            Payload::Reconcile { batch_id, report } => {
                e.u8(5).str(batch_id);
                report.encode(e);
            }
            Payload::EmergencyCorrection { batch_id, original_tx, corrected_state, reason, legal_authority, evidence_commitment } => {
                e.u8(6).str(batch_id).hash(original_tx).str(corrected_state).str(reason).str(legal_authority).hash(evidence_commitment);
            }
        }
    }
}

impl Payload {
    pub fn kind(&self) -> &'static str {
        match self {
            Payload::ActivatePolicy(_) => "ActivatePolicy",
            Payload::CommenceElection => "CommenceElection",
            Payload::RegisterBatch { .. } => "RegisterBatch",
            Payload::CustodyTransfer { .. } => "CustodyTransfer",
            Payload::Reconcile { .. } => "Reconcile",
            Payload::EmergencyCorrection { .. } => "EmergencyCorrection",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxBody {
    pub protocol_version: u16,
    pub chain_id: Hash,
    pub election: String,
    pub jurisdiction: String,
    pub origin: KeyId,
    /// Must be strictly greater than the origin's previous nonce (replay protection).
    pub nonce: u64,
    pub expiry_height: u64,
    /// For batch transactions: the batch's previous transaction (§6.1 predecessor).
    pub predecessor: Option<Hash>,
    pub payload: Payload,
}

impl Canonical for TxBody {
    fn encode(&self, e: &mut Enc) {
        e.u16(self.protocol_version).hash(&self.chain_id).str(&self.election).str(&self.jurisdiction);
        e.hash(&self.origin).u64(self.nonce).u64(self.expiry_height).opt_hash(&self.predecessor);
        self.payload.encode(e);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub signer: KeyId,
    pub signature: HybridSignature,
}

impl Canonical for Approval {
    fn encode(&self, e: &mut Enc) {
        e.hash(&self.signer);
        self.signature.encode(e);
    }
}

pub const TX_APPROVAL_DOMAIN: &str = "VERIFY/tx-approval/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub body: TxBody,
    pub approvals: Vec<Approval>,
}

impl Canonical for Transaction {
    fn encode(&self, e: &mut Enc) {
        self.body.encode(e);
        e.list(&self.approvals);
    }
}

impl Transaction {
    pub fn new(body: TxBody) -> Self {
        Self { body, approvals: vec![] }
    }

    /// The transaction id commits to the body only, so every approver signs the same thing.
    pub fn id(&self) -> Hash {
        hash("VERIFY/tx/v1", &self.body.to_canonical())
    }

    pub fn approve(mut self, key: &HybridKeypair) -> Self {
        let id = self.id();
        self.approvals.push(Approval { signer: key.id(), signature: key.sign(TX_APPROVAL_DOMAIN, &id) });
        self
    }

    pub fn verify_approval(&self, a: &Approval, pk: &crate::crypto::HybridPublicKey) -> bool {
        pk.id() == a.signer && verify(pk, TX_APPROVAL_DOMAIN, &self.id(), &a.signature).is_ok()
    }
}
