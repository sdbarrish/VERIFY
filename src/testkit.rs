//! In-process network harness for the simulator and acceptance tests.
//!
//! Keys are derived from public seeds so runs are reproducible. That is for
//! simulation only; real keys come from a documented ceremony in an HSM (§6.2).

use crate::consensus::Vote;
use crate::crypto::{hash, CommitmentOpening, Hash, HybridKeypair, KeyId};
use crate::node::{certify, Node};
use crate::policy::{ApprovalRule, EmergencyRule, Policy, Principal, PrincipalClass, Transition};
use crate::state::{Genesis, Outcome, Reject};
use crate::tx::{Payload, Transaction, TxBody, PROTOCOL_VERSION};
use std::collections::BTreeMap;

pub const ELECTION: &str = "2026-GENERAL";
pub const JURISDICTION: &str = "US-FL-EXAMPLE-COUNTY";

pub fn demo_key(name: &str) -> HybridKeypair {
    HybridKeypair::from_seed(&hash(
        "VERIFY/demo-seed/not-for-production",
        name.as_bytes(),
    ))
}

pub const STATES: [&str; 9] = [
    "Produced",
    "WarehouseSealed",
    "OutboundTransit",
    "AtPollingPlace",
    "Closed",
    "ReturnTransit",
    "SecureStorage",
    "Canvassed",
    "Archived",
];

/// (name, class, role)
pub const PEOPLE: &[(&str, PrincipalClass, Option<&str>)] = &[
    (
        "warehouse-1",
        PrincipalClass::Custodian,
        Some("warehouse_custodian"),
    ),
    (
        "warehouse-2",
        PrincipalClass::Custodian,
        Some("warehouse_custodian"),
    ),
    (
        "warehouse-3",
        PrincipalClass::Custodian,
        Some("warehouse_custodian"),
    ),
    (
        "transport-1",
        PrincipalClass::Custodian,
        Some("transport_officer"),
    ),
    (
        "transport-2",
        PrincipalClass::Custodian,
        Some("transport_officer"),
    ),
    (
        "clerk-1",
        PrincipalClass::ElectionOfficial,
        Some("poll_clerk"),
    ),
    (
        "clerk-2",
        PrincipalClass::ElectionOfficial,
        Some("poll_clerk"),
    ),
    (
        "clerk-3",
        PrincipalClass::ElectionOfficial,
        Some("poll_clerk"),
    ),
    ("witness-1", PrincipalClass::Witness, Some("poll_witness")),
    (
        "canvass-1",
        PrincipalClass::ElectionOfficial,
        Some("canvassing_board"),
    ),
    (
        "canvass-2",
        PrincipalClass::ElectionOfficial,
        Some("canvassing_board"),
    ),
    (
        "canvass-3",
        PrincipalClass::ElectionOfficial,
        Some("canvassing_board"),
    ),
    (
        "canvass-4",
        PrincipalClass::ElectionOfficial,
        Some("canvassing_board"),
    ),
    (
        "canvass-5",
        PrincipalClass::ElectionOfficial,
        Some("canvassing_board"),
    ),
    (
        "county-soe",
        PrincipalClass::ElectionOfficial,
        Some("county_supervisor"),
    ),
    (
        "state-doe",
        PrincipalClass::ElectionOfficial,
        Some("state_division"),
    ),
    (
        "ieoa-external",
        PrincipalClass::IndependentAuthority,
        Some("independent_authority"),
    ),
    ("insights-ai", PrincipalClass::AnalyticsAi, None),
];

fn t(from: &str, to: &str, roles: &[&str], m: u8, distinct: u8) -> Transition {
    Transition {
        from: from.into(),
        to: to.into(),
        rule: ApprovalRule::new(roles, m, distinct),
    }
}

/// Illustrative thresholds from white paper §4.2 (2-of-3, 3-of-4, 3-of-5).
pub fn reference_policy() -> Policy {
    Policy {
        jurisdiction: JURISDICTION.into(),
        version: 1,
        legal_basis: "Illustrative county custody procedure (simulation)".into(),
        predecessor: None,
        principals: PEOPLE
            .iter()
            .map(|(n, c, r)| Principal {
                name: n.to_string(),
                key: demo_key(n).public().clone(),
                class: *c,
                role: r.map(String::from),
            })
            .collect(),
        states: STATES.iter().map(|s| s.to_string()).collect(),
        initial_state: "Produced".into(),
        transitions: vec![
            t(
                "Produced",
                "WarehouseSealed",
                &["warehouse_custodian"],
                2,
                1,
            ),
            t(
                "WarehouseSealed",
                "OutboundTransit",
                &["warehouse_custodian", "transport_officer"],
                2,
                2,
            ),
            t(
                "OutboundTransit",
                "AtPollingPlace",
                &["poll_clerk", "poll_witness", "transport_officer"],
                3,
                2,
            ),
            t(
                "AtPollingPlace",
                "Closed",
                &["poll_clerk", "poll_witness"],
                3,
                2,
            ),
            t(
                "Closed",
                "ReturnTransit",
                &["poll_clerk", "transport_officer"],
                2,
                2,
            ),
            t(
                "ReturnTransit",
                "SecureStorage",
                &["warehouse_custodian", "transport_officer"],
                3,
                2,
            ),
            t("SecureStorage", "Canvassed", &["canvassing_board"], 3, 1),
            t(
                "Canvassed",
                "Archived",
                &["warehouse_custodian", "canvassing_board"],
                3,
                2,
            ),
        ],
        registration: ApprovalRule::new(&["warehouse_custodian"], 2, 1),
        reconciliation: ApprovalRule::new(&["canvassing_board"], 3, 1),
        emergency: EmergencyRule {
            required_roles: vec![
                "county_supervisor".into(),
                "state_division".into(),
                "independent_authority".into(),
            ],
        },
    }
}

pub struct Network {
    pub genesis: Genesis,
    pub nodes: Vec<Node>,
    nonces: BTreeMap<KeyId, u64>,
}

pub const VALIDATORS: [&str; 4] = [
    "validator-tallahassee",
    "validator-orlando",
    "validator-miami",
    "validator-independent",
];
pub const ROOTS: [&str; 3] = ["root-county", "root-state", "root-independent"];

/// Everything a submitted block produced.
pub struct Round {
    pub outcomes: Vec<Outcome>,
    pub rejected: Vec<(Transaction, Reject)>,
}

impl Network {
    pub fn new() -> Self {
        let genesis = Genesis {
            network: "VERIFY-SIM".into(),
            validators: VALIDATORS
                .iter()
                .map(|v| demo_key(v).public().clone())
                .collect(),
            root_authorities: ROOTS.iter().map(|r| demo_key(r).public().clone()).collect(),
            root_threshold: 2,
        };
        let nodes = VALIDATORS
            .iter()
            .map(|v| Node::new(v, demo_key(v), genesis.clone()))
            .collect();
        Self {
            genesis,
            nodes,
            nonces: BTreeMap::new(),
        }
    }

    pub fn height(&self) -> u64 {
        self.nodes[0].next_height()
    }

    /// Unsigned transaction from `origin` with a fresh nonce.
    pub fn body(
        &mut self,
        origin: &str,
        payload: Payload,
        predecessor: Option<Hash>,
    ) -> Transaction {
        let id = demo_key(origin).id();
        let nonce = self.nonces.entry(id).and_modify(|n| *n += 1).or_insert(1);
        Transaction::new(TxBody {
            protocol_version: PROTOCOL_VERSION,
            chain_id: self.genesis.chain_id(),
            election: ELECTION.into(),
            jurisdiction: JURISDICTION.into(),
            origin: id,
            nonce: *nonce,
            expiry_height: self.height() + 100,
            predecessor,
            payload,
        })
    }

    /// Build a transaction whose first approver is the origin.
    pub fn tx(
        &mut self,
        approvers: &[&str],
        payload: Payload,
        predecessor: Option<Hash>,
    ) -> Transaction {
        let mut tx = self.body(approvers[0], payload, predecessor);
        for a in approvers {
            tx = tx.approve(&demo_key(a));
        }
        tx
    }

    pub fn batch_tip(&self, batch: &str) -> Hash {
        self.nodes[0].state.batches[batch].last_tx()
    }

    /// One consensus round: scheduled leader proposes, every validator
    /// re-executes and votes, the certificate is assembled, everyone commits.
    pub fn submit(&mut self, txs: Vec<Transaction>) -> Round {
        let leader_id = self.nodes[0].validators.leader(self.height(), 0);
        let leader = self
            .nodes
            .iter()
            .find(|n| n.id() == leader_id)
            .expect("leader is a node");
        let (block, rejected) = leader.propose(txs);
        let votes: Vec<Vote> = self
            .nodes
            .iter()
            .map(|n| {
                n.validate_and_vote(&block)
                    .expect("honest validators agree")
            })
            .collect();
        let block = certify(block, votes);
        let mut outcomes = vec![];
        for n in &mut self.nodes {
            outcomes = n.commit(&block).expect("commit");
        }
        Round { outcomes, rejected }
    }

    /// Submit a single transaction and return its outcome or rejection.
    pub fn submit_one(&mut self, tx: Transaction) -> Result<Outcome, Reject> {
        let mut r = self.submit(vec![tx]);
        match r.rejected.pop() {
            Some((_, e)) => Err(e),
            None => Ok(r.outcomes.pop().expect("one outcome")),
        }
    }

    /// Activate the reference policy and lock the configuration.
    pub fn bootstrap(&mut self) {
        let p = self.tx(
            &["root-county", "root-state"],
            Payload::ActivatePolicy(reference_policy()),
            None,
        );
        self.submit_one(p).expect("policy activates");
        let c = self.tx(
            &["root-county", "root-independent"],
            Payload::CommenceElection,
            None,
        );
        self.submit_one(c).expect("election commences");
    }

    pub fn register(
        &mut self,
        batch: &str,
        quantity: u64,
    ) -> (CommitmentOpening, CommitmentOpening) {
        let inventory =
            CommitmentOpening::new(format!("{batch}:serials 000001-{quantity:06}").as_bytes());
        let seal = CommitmentOpening::new(format!("{batch}:seal SEAL-4471902").as_bytes());
        let tx = self.tx(
            &["warehouse-1", "warehouse-2"],
            Payload::RegisterBatch {
                batch_id: batch.into(),
                ballot_style: "BS-07".into(),
                quantity,
                inventory_commitment: inventory.commitment(),
                seal_commitment: seal.commitment(),
            },
            None,
        );
        self.submit_one(tx).expect("batch registers");
        (inventory, seal)
    }

    pub fn transfer_tx(
        &mut self,
        batch: &str,
        from: &str,
        to: &str,
        approvers: &[&str],
        seal_intact: bool,
    ) -> Transaction {
        let evidence = CommitmentOpening::new(
            format!("{batch}:{from}->{to}:signed acknowledgment").as_bytes(),
        );
        let pred = self.batch_tip(batch);
        self.tx(
            approvers,
            Payload::CustodyTransfer {
                batch_id: batch.into(),
                from: from.into(),
                to: to.into(),
                seal_intact,
                evidence_commitment: evidence.commitment(),
            },
            Some(pred),
        )
    }
}

impl Default for Network {
    fn default() -> Self {
        Self::new()
    }
}

/// The custody walk from production to secure storage, with valid approvers.
pub const HAPPY_PATH: &[(&str, &str, &[&str])] = &[
    (
        "Produced",
        "WarehouseSealed",
        &["warehouse-1", "warehouse-2"],
    ),
    (
        "WarehouseSealed",
        "OutboundTransit",
        &["warehouse-3", "transport-1"],
    ),
    (
        "OutboundTransit",
        "AtPollingPlace",
        &["clerk-1", "clerk-2", "transport-1"],
    ),
    (
        "AtPollingPlace",
        "Closed",
        &["clerk-1", "clerk-3", "witness-1"],
    ),
    ("Closed", "ReturnTransit", &["clerk-2", "transport-2"]),
    (
        "ReturnTransit",
        "SecureStorage",
        &["warehouse-1", "warehouse-3", "transport-2"],
    ),
];
