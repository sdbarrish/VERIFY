//! Jurisdictional policy objects (white paper Volume II) and the CORE
//! invariants that no policy can override.

use crate::codec::{Canonical, Enc};
use crate::crypto::{hash, Hash, HybridPublicKey, KeyId};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_NAME_LEN: usize = 128;
pub const MAX_PRINCIPALS: usize = 512;
pub const MAX_STATES: usize = 64;
pub const MAX_TRANSITIONS: usize = 256;

/// What kind of actor holds a key. The class is part of the signed policy, so
/// it cannot be changed without a new authorized policy version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrincipalClass {
    ElectionOfficial,
    Custodian,
    Witness,
    /// Not an employee, contractor, volunteer or participant of the jurisdiction (§4.3).
    IndependentAuthority,
    /// An AI or analytics system. It may receive certified, sanitized exports
    /// downstream, but it can never hold a role, sign, approve or validate (§8.4).
    AnalyticsAi,
}

impl PrincipalClass {
    fn tag(self) -> u8 {
        match self {
            PrincipalClass::ElectionOfficial => 1,
            PrincipalClass::Custodian => 2,
            PrincipalClass::Witness => 3,
            PrincipalClass::IndependentAuthority => 4,
            PrincipalClass::AnalyticsAi => 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub name: String,
    pub key: HybridPublicKey,
    pub class: PrincipalClass,
    /// At most one role per key, so independence can be counted honestly.
    pub role: Option<String>,
}

impl Canonical for Principal {
    fn encode(&self, e: &mut Enc) {
        e.str(&self.name).u8(self.class.tag());
        self.key.encode(e);
        match &self.role {
            None => e.u8(0),
            Some(r) => e.u8(1).str(r),
        };
    }
}

/// Who must approve an action (§4.2). Every approver must hold an eligible role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRule {
    pub eligible_roles: Vec<String>,
    /// m in m-of-n: distinct eligible principals required.
    pub threshold: u8,
    /// Minimum number of distinct roles among the approvers.
    pub min_distinct_roles: u8,
}

impl Canonical for ApprovalRule {
    fn encode(&self, e: &mut Enc) {
        e.list(&self.eligible_roles)
            .u8(self.threshold)
            .u8(self.min_distinct_roles);
    }
}

impl ApprovalRule {
    pub fn new(roles: &[&str], threshold: u8, min_distinct_roles: u8) -> Self {
        Self {
            eligible_roles: roles.iter().map(|r| r.to_string()).collect(),
            threshold,
            min_distinct_roles,
        }
    }

    fn validate(&self, what: &str, role_holders: &BTreeMap<&str, usize>) -> Result<(), String> {
        if self.threshold == 0 || self.min_distinct_roles == 0 {
            return Err(format!("{what} must require at least one approver"));
        }
        let pool: usize = self
            .eligible_roles
            .iter()
            .map(|r| role_holders.get(r.as_str()).copied().unwrap_or(0))
            .sum();
        let distinct: BTreeSet<&String> = self.eligible_roles.iter().collect();
        if pool < self.threshold as usize || distinct.len() < self.min_distinct_roles as usize {
            return Err(format!(
                "{what}: threshold cannot be met by eligible principals"
            ));
        }
        Ok(())
    }
}

/// A permitted custody transition and who must approve it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub from: String,
    pub to: String,
    pub rule: ApprovalRule,
}

impl Canonical for Transition {
    fn encode(&self, e: &mut Enc) {
        e.str(&self.from).str(&self.to);
        self.rule.encode(e);
    }
}

/// Independent Emergency Override Authority (§4.3): one distinct approver per role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyRule {
    pub required_roles: Vec<String>,
}

impl Canonical for EmergencyRule {
    fn encode(&self, e: &mut Enc) {
        e.list(&self.required_roles);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub jurisdiction: String,
    pub version: u32,
    pub legal_basis: String,
    pub predecessor: Option<Hash>,
    pub principals: Vec<Principal>,
    pub states: Vec<String>,
    pub initial_state: String,
    pub transitions: Vec<Transition>,
    pub registration: ApprovalRule,
    pub reconciliation: ApprovalRule,
    pub emergency: EmergencyRule,
}

impl Canonical for Policy {
    fn encode(&self, e: &mut Enc) {
        e.str(&self.jurisdiction)
            .u32(self.version)
            .str(&self.legal_basis)
            .opt_hash(&self.predecessor);
        e.list(&self.principals)
            .list(&self.states)
            .str(&self.initial_state)
            .list(&self.transitions);
        self.registration.encode(e);
        self.reconciliation.encode(e);
        self.emergency.encode(e);
    }
}

impl Policy {
    pub fn hash(&self) -> Hash {
        hash("VERIFY/policy/v1", &self.to_canonical())
    }

    pub fn principal(&self, id: &KeyId) -> Option<&Principal> {
        self.principals.iter().find(|p| &p.key.id() == id)
    }

    pub fn transition(&self, from: &str, to: &str) -> Option<&Transition> {
        self.transitions
            .iter()
            .find(|t| t.from == from && t.to == to)
    }

    /// Structural checks plus CORE invariants. `reserved_keys` are validator and
    /// root keys, which must never double as election-operation keys (§6.2).
    pub fn validate(&self, reserved_keys: &BTreeSet<KeyId>) -> Result<(), String> {
        let name_ok = |s: &str| !s.is_empty() && s.len() <= MAX_NAME_LEN;
        if !name_ok(&self.jurisdiction) || !name_ok(&self.legal_basis) {
            return Err("jurisdiction and legal basis are required".into());
        }
        if self.principals.len() > MAX_PRINCIPALS
            || self.states.len() > MAX_STATES
            || self.transitions.len() > MAX_TRANSITIONS
        {
            return Err("policy exceeds size bounds".into());
        }
        let states: BTreeSet<&str> = self.states.iter().map(String::as_str).collect();
        if states.len() != self.states.len() || !self.states.iter().all(|s| name_ok(s)) {
            return Err("custody states must be unique, non-empty names".into());
        }
        if !states.contains(self.initial_state.as_str()) {
            return Err("initial state is not a declared custody state".into());
        }

        let mut ids = BTreeSet::new();
        let mut role_holders: BTreeMap<&str, usize> = BTreeMap::new();
        for p in &self.principals {
            if !name_ok(&p.name) {
                return Err("principal name required".into());
            }
            let id = p.key.id();
            if !ids.insert(id) {
                return Err(format!("duplicate key for principal {}", p.name));
            }
            if reserved_keys.contains(&id) {
                return Err(format!(
                    "principal {} reuses a validator or root key",
                    p.name
                ));
            }
            // CORE invariant: AI isolation. Not configurable by policy.
            if p.class == PrincipalClass::AnalyticsAi && p.role.is_some() {
                return Err(format!(
                    "AI isolation: analytics/AI principal {} cannot hold a role",
                    p.name
                ));
            }
            if let Some(r) = &p.role {
                *role_holders.entry(r.as_str()).or_default() += 1;
            }
        }

        let mut seen = BTreeSet::new();
        for t in &self.transitions {
            if !states.contains(t.from.as_str())
                || !states.contains(t.to.as_str())
                || t.from == t.to
            {
                return Err(format!(
                    "transition {} -> {} references undeclared states",
                    t.from, t.to
                ));
            }
            if !seen.insert((t.from.as_str(), t.to.as_str())) {
                return Err(format!("duplicate transition {} -> {}", t.from, t.to));
            }
            t.rule
                .validate(&format!("transition {} -> {}", t.from, t.to), &role_holders)?;
        }
        self.registration
            .validate("batch registration", &role_holders)?;
        self.reconciliation
            .validate("reconciliation", &role_holders)?;

        // CORE invariant: emergency correction needs >= 2 distinct roles,
        // one of them held by an independent authority.
        let er = &self.emergency.required_roles;
        let distinct: BTreeSet<&String> = er.iter().collect();
        if distinct.len() < 2 || distinct.len() != er.len() {
            return Err("emergency rule needs at least two distinct roles".into());
        }
        for r in er {
            if !role_holders.contains_key(r.as_str()) {
                return Err(format!("emergency role {r} has no holder"));
            }
        }
        let has_independent = self.principals.iter().any(|p| {
            p.class == PrincipalClass::IndependentAuthority
                && p.role.as_ref().is_some_and(|r| er.contains(r))
        });
        if !has_independent {
            return Err("emergency rule must include an independent authority".into());
        }
        Ok(())
    }
}

use crate::codec::{derr, Dec, Decode, DecodeError, SMALL_LIST};

impl Decode for Principal {
    fn decode(d: &mut Dec<'_>) -> Result<Self, DecodeError> {
        let name = d.str()?;
        let class = match d.u8()? {
            1 => PrincipalClass::ElectionOfficial,
            2 => PrincipalClass::Custodian,
            3 => PrincipalClass::Witness,
            4 => PrincipalClass::IndependentAuthority,
            5 => PrincipalClass::AnalyticsAi,
            t => return derr(format!("unknown principal class {t}")),
        };
        let key = HybridPublicKey::decode(d)?;
        let role = match d.u8()? {
            0 => None,
            1 => Some(d.str()?),
            t => return derr(format!("bad role tag {t}")),
        };
        Ok(Self {
            name,
            key,
            class,
            role,
        })
    }
}

impl Decode for ApprovalRule {
    fn decode(d: &mut Dec<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            eligible_roles: d.list(SMALL_LIST)?,
            threshold: d.u8()?,
            min_distinct_roles: d.u8()?,
        })
    }
}

impl Decode for Transition {
    fn decode(d: &mut Dec<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            from: d.str()?,
            to: d.str()?,
            rule: ApprovalRule::decode(d)?,
        })
    }
}

impl Decode for EmergencyRule {
    fn decode(d: &mut Dec<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            required_roles: d.list(SMALL_LIST)?,
        })
    }
}

impl Decode for Policy {
    fn decode(d: &mut Dec<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            jurisdiction: d.str()?,
            version: d.u32()?,
            legal_basis: d.str()?,
            predecessor: d.opt_hash()?,
            principals: d.list(MAX_PRINCIPALS)?,
            states: d.list(MAX_STATES)?,
            initial_state: d.str()?,
            transitions: d.list(MAX_TRANSITIONS)?,
            registration: ApprovalRule::decode(d)?,
            reconciliation: ApprovalRule::decode(d)?,
            emergency: EmergencyRule::decode(d)?,
        })
    }
}
