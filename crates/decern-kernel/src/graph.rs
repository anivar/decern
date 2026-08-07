// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Authority graph directory + load-time attenuation validation.
//!
//! The kernel refuses to load a graph that violates attenuation-by-construction:
//! a delegated principal must sit strictly inside its delegator's authority
//! (same tenant, expiry no later, scopes a subset, no cycles), and every
//! resource owner must exist inside the resource's own tenant. Enforcing this
//! at load time means the policy layer can assume the graph is well-formed —
//! and the proofs certify what the policies then guarantee.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
pub struct PrincipalRec {
    pub id: String,
    pub kind: String,
    pub tenant: String,
    pub expiry: i64,
    pub scopes: BTreeSet<String>,
    pub delegator: Option<String>,
    /// CIAM v3: the customer org this identity belongs to (optional).
    pub org: Option<String>,
    /// CIAM v3: RBAC labels; a delegate's roles must be a subset of its
    /// delegator's, enforced at load like scopes.
    pub roles: BTreeSet<String>,
    /// Data-residency clearances; a delegate's must be a subset of its
    /// delegator's, enforced at load like roles/scopes.
    pub jurisdictions: BTreeSet<String>,
    /// Whether this principal is directly revoked (authored). Effective
    /// revocation also propagates from revoked ancestors, computed at load.
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceRec {
    pub id: String,
    pub owner: String,
    pub tenant: String,
    /// CIAM v3: the customer org that owns this resource (optional).
    pub org: Option<String>,
    /// CIAM v3: data sensitivity label, e.g. "pii" (optional).
    pub sensitivity: Option<String>,
    /// Data-residency label, e.g. "EU" (optional); gates by principal clearance.
    pub residency: Option<String>,
    /// ReBAC viewers — principals explicitly granted read without ownership/delegation.
    /// Load-validated: each must exist and share the resource's tenant.
    pub viewers: BTreeSet<String>,
}

/// Tenant id reserved for the unattributed ledger shard (`__system__`).
/// A real directory tenant with this name would co-mingle with that shard;
/// [`Directory::validate`] refuses it at load so every consumer fails closed,
/// not only `decern-serve`.
pub const RESERVED_TENANT: &str = "__system__";

/// CIAM v3: a customer organization — a tenancy anchor with an optional
/// sub-organization parent edge (a hierarchy inside one isolation tenant).
#[derive(Debug, Clone, Serialize)]
pub struct OrgRec {
    pub id: String,
    pub tenant: String,
    pub parent: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Directory {
    pub principals: BTreeMap<String, PrincipalRec>,
    pub resources: BTreeMap<String, ResourceRec>,
    /// CIAM v3: customer organizations, keyed by id.
    pub orgs: BTreeMap<String, OrgRec>,
}

fn attr_str(attrs: &serde_json::Map<String, Value>, name: &str) -> Option<String> {
    attrs.get(name)?.as_str().map(str::to_owned)
}

/// A Set<String> attribute (e.g. scopes, roles). Absent => empty set.
fn attr_set(attrs: &serde_json::Map<String, Value>, name: &str) -> BTreeSet<String> {
    attrs
        .get(name)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default()
}

/// Extract a Set of entity references (e.g. resource.viewers). Absent => empty.
/// Both Cedar encodings accepted per element; malformed / wrong-type → Err.
fn attr_entity_set(
    attrs: &serde_json::Map<String, Value>,
    name: &str,
    expected_type: &str,
) -> Result<BTreeSet<String>, String> {
    let Some(v) = attrs.get(name) else {
        return Ok(BTreeSet::new());
    };
    let Some(arr) = v.as_array() else {
        return Err(format!("{name}: expected array of entity refs"));
    };
    let mut out = BTreeSet::new();
    for (i, elem) in arr.iter().enumerate() {
        let fake = {
            let mut m = serde_json::Map::new();
            m.insert(name.to_owned(), elem.clone());
            m
        };
        match attr_entity_ref(&fake, name, expected_type)? {
            Some(id) => {
                out.insert(id);
            }
            None => {
                return Err(format!("{name}[{i}]: missing entity ref"));
            }
        }
    }
    Ok(out)
}

/// Extract an entity reference attribute. Cedar accepts TWO encodings —
/// the explicit escape `{"__entity": {"type": T, "id": I}}` and the implicit
/// `{"type": T, "id": I}` — and the validator must see exactly what Cedar
/// sees, or an edge written in the other form bypasses attenuation checks.
/// Returns Ok(None) if absent, Err if present but malformed (fail-closed).
fn attr_entity_ref(
    attrs: &serde_json::Map<String, Value>,
    name: &str,
    expected_type: &str,
) -> Result<Option<String>, String> {
    let Some(v) = attrs.get(name) else {
        return Ok(None);
    };
    let inner = v.get("__entity").unwrap_or(v);
    let ty = inner.get("type").and_then(Value::as_str);
    let id = inner.get("id").and_then(Value::as_str);
    match (ty, id) {
        (Some(t), Some(i)) if t == expected_type => Ok(Some(i.to_owned())),
        (Some(t), Some(_)) => Err(format!(
            "{name}: entity ref has type {t}, expected {expected_type}"
        )),
        _ => Err(format!(
            "{name}: unparseable entity reference (need type+id, explicit or implicit form)"
        )),
    }
}

/// Walk a self-referential chain from `start`, following `next_of` at each node and
/// resolving the successor via `lookup`; return the id at which the chain first REVISITS a
/// node — the entry point of a cycle — or `None` if it terminates or hits a missing link
/// (a missing link is reported separately). Shared by the delegation-chain and org-parent
/// cycle checks in [`Directory::validate`] so both detect a cycle by exactly one walk.
/// Security-critical: part of the load-time trusted base under the SMT proofs.
fn first_cycle_id<'a, N>(
    start: &'a N,
    id_of: impl Fn(&N) -> &str,
    next_of: impl Fn(&N) -> Option<&str>,
    lookup: impl Fn(&str) -> Option<&'a N>,
) -> Option<String> {
    let mut seen = BTreeSet::new();
    seen.insert(id_of(start).to_owned());
    let mut cur = start;
    while let Some(next_id) = next_of(cur) {
        if !seen.insert(next_id.to_owned()) {
            return Some(next_id.to_owned());
        }
        // A missing link is already reported elsewhere; stop the walk.
        cur = lookup(next_id)?;
    }
    None
}

impl Directory {
    /// Parse the Cedar entities-JSON array into a typed directory.
    /// Shape errors are reported as violations, not panics.
    pub fn parse(entities: &Value) -> Result<Self, Vec<String>> {
        let mut dir = Directory::default();
        let mut violations = Vec::new();

        let Some(list) = entities.as_array() else {
            return Err(vec!["entities must be a JSON array".into()]);
        };

        for (i, e) in list.iter().enumerate() {
            let ty = e
                .get("uid")
                .and_then(|u| u.get("type"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let id = e
                .get("uid")
                .and_then(|u| u.get("id"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if ty.is_empty() || id.is_empty() {
                violations.push(format!("entity #{i}: missing uid type/id"));
                continue;
            }
            let attrs = match e.get("attrs").and_then(Value::as_object) {
                Some(a) => a,
                None => {
                    violations.push(format!("{ty}::{id}: missing attrs object"));
                    continue;
                }
            };

            match ty {
                "Principal" => {
                    let scopes = attr_set(attrs, "scopes");
                    let roles = attr_set(attrs, "roles");
                    let jurisdictions = attr_set(attrs, "jurisdictions");
                    let delegator = match attr_entity_ref(attrs, "delegator", "Principal") {
                        Ok(d) => d,
                        Err(e) => {
                            violations.push(format!("Principal::{id}: {e}"));
                            continue;
                        }
                    };
                    let org = match attr_entity_ref(attrs, "org", "Organization") {
                        Ok(o) => o,
                        Err(e) => {
                            violations.push(format!("Principal::{id}: {e}"));
                            continue;
                        }
                    };
                    let rec = PrincipalRec {
                        id: id.to_owned(),
                        kind: attr_str(attrs, "kind").unwrap_or_default(),
                        tenant: attr_str(attrs, "tenant").unwrap_or_default(),
                        expiry: attrs.get("expiry").and_then(Value::as_i64).unwrap_or(-1),
                        scopes,
                        delegator,
                        org,
                        roles,
                        jurisdictions,
                        revoked: attrs
                            .get("revoked")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    };
                    if rec.tenant.is_empty() {
                        violations.push(format!("Principal::{id}: missing tenant"));
                    }
                    if rec.expiry < 0 {
                        violations.push(format!("Principal::{id}: missing or negative expiry"));
                    }
                    if dir.principals.insert(id.to_owned(), rec).is_some() {
                        violations.push(format!(
                            "Principal::{id}: duplicate uid (validator and engine could disagree on attrs)"
                        ));
                    }
                }
                "Resource" => {
                    let owner = match attr_entity_ref(attrs, "owner", "Principal") {
                        Ok(o) => o.unwrap_or_default(),
                        Err(e) => {
                            violations.push(format!("Resource::{id}: {e}"));
                            continue;
                        }
                    };
                    let org = match attr_entity_ref(attrs, "org", "Organization") {
                        Ok(o) => o,
                        Err(e) => {
                            violations.push(format!("Resource::{id}: {e}"));
                            continue;
                        }
                    };
                    let viewers = match attr_entity_set(attrs, "viewers", "Principal") {
                        Ok(v) => v,
                        Err(e) => {
                            violations.push(format!("Resource::{id}: {e}"));
                            continue;
                        }
                    };
                    let rec = ResourceRec {
                        id: id.to_owned(),
                        owner,
                        tenant: attr_str(attrs, "tenant").unwrap_or_default(),
                        org,
                        sensitivity: attr_str(attrs, "sensitivity"),
                        residency: attr_str(attrs, "residency"),
                        viewers,
                    };
                    if rec.owner.is_empty() {
                        violations.push(format!("Resource::{id}: missing owner"));
                    }
                    if rec.tenant.is_empty() {
                        violations.push(format!("Resource::{id}: missing tenant"));
                    }
                    if dir.resources.insert(id.to_owned(), rec).is_some() {
                        violations.push(format!(
                            "Resource::{id}: duplicate uid (validator and engine could disagree on attrs)"
                        ));
                    }
                }
                "Organization" => {
                    let parent = match attr_entity_ref(attrs, "parent", "Organization") {
                        Ok(p) => p,
                        Err(e) => {
                            violations.push(format!("Organization::{id}: {e}"));
                            continue;
                        }
                    };
                    let rec = OrgRec {
                        id: id.to_owned(),
                        tenant: attr_str(attrs, "tenant").unwrap_or_default(),
                        parent,
                    };
                    if rec.tenant.is_empty() {
                        violations.push(format!("Organization::{id}: missing tenant"));
                    }
                    if dir.orgs.insert(id.to_owned(), rec).is_some() {
                        violations.push(format!(
                            "Organization::{id}: duplicate uid (validator and engine could disagree on attrs)"
                        ));
                    }
                }
                other => {
                    violations.push(format!("unknown entity type {other}::{id}"));
                }
            }
        }

        if violations.is_empty() {
            Ok(dir)
        } else {
            Err(violations)
        }
    }

    /// The transitive delegator chain of a principal — its authority ancestors,
    /// nearest first. Cycle-safe (validation rejects cycles; this guards anyway).
    /// A delegate may reach any ancestor's resources; the load-time attenuation
    /// rules guarantee the delegate's authority is a subset of each ancestor's.
    pub fn ancestors_of(&self, id: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        seen.insert(id.to_owned());
        let mut cur = self.principals.get(id);
        while let Some(p) = cur {
            match &p.delegator {
                Some(d) if seen.insert(d.clone()) => {
                    out.push(d.clone());
                    cur = self.principals.get(d);
                }
                _ => break,
            }
        }
        out
    }

    /// The transitive delegates of a principal — every principal delegating FROM it,
    /// nearest first. This is the blast radius: revoke `id` and exactly these lose
    /// authority with it, so an operator can see the cost of a revocation before
    /// paying it. The mirror of [`ancestors_of`](Self::ancestors_of), which walks up.
    ///
    /// Breadth-first, so the result reads outward from `id` one delegation hop at a
    /// time — the order an operator reasons in ("who did this principal grant to, and
    /// who did they grant to"). Within a level, ordering follows the directory's own
    /// (sorted) principal order, so the answer is deterministic.
    ///
    /// The delegation graph points upward (a principal names its delegator), so the
    /// downward direction has to be inverted. That inversion is built once per call
    /// rather than rescanning every principal per node: the naive form is quadratic
    /// in directory size, and this is on an operator's interactive path.
    ///
    /// Never leaves the starting principal's tenant. Load-time validation already
    /// forbids a cross-tenant delegation edge, so this filter is defence in depth
    /// rather than the only thing standing between tenants — a traversal that
    /// silently spanned tenants would leak one tenant's shape to another.
    ///
    /// Cycle-safe: `validate` rejects cycles at load, and the visited set means a
    /// cycle that somehow reached here terminates instead of hanging. Every principal
    /// is visited at most once, so the walk is bounded by the directory already in
    /// memory and needs no separate depth or size cap.
    pub fn descendants_of(&self, id: &str) -> Vec<String> {
        let Some(root) = self.principals.get(id) else {
            return Vec::new();
        };
        let root_tenant = &root.tenant;

        // Invert the graph once: delegator -> everyone delegating from it.
        let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (child_id, child) in &self.principals {
            if child.tenant != *root_tenant {
                continue;
            }
            if let Some(delegator) = child.delegator.as_deref() {
                children
                    .entry(delegator)
                    .or_default()
                    .push(child_id.as_str());
            }
        }

        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        seen.insert(id);

        let mut queue = VecDeque::new();
        queue.push_back(id);
        while let Some(cur) = queue.pop_front() {
            for &child in children.get(cur).into_iter().flatten() {
                if seen.insert(child) {
                    out.push(child.to_owned());
                    queue.push_back(child);
                }
            }
        }
        out
    }

    /// Whether `id` names a principal this directory recognizes. Thin wrapper
    /// over the (already public) `principals` map — added for call-site clarity
    /// where the distinction that matters is "known principal" vs "a caller the
    /// directory doesn't recognize at all". Used to derive the accountable-owner:
    /// an unknown subject has NO sponsor, which is a different fact than a known
    /// self-sponsored root (both of which `ancestors_of` returns empty for).
    pub fn contains(&self, id: &str) -> bool {
        self.principals.contains_key(id)
    }

    /// Attenuation-by-construction rules. Empty result = graph is well-formed.
    pub fn validate(&self) -> Vec<String> {
        let mut v = Vec::new();

        for p in self.principals.values() {
            let Some(del_id) = &p.delegator else { continue };

            let Some(d) = self.principals.get(del_id) else {
                v.push(format!(
                    "Principal::{}: delegator {del_id} does not exist",
                    p.id
                ));
                continue;
            };
            if d.tenant != p.tenant {
                v.push(format!(
                    "Principal::{}: cross-tenant delegation ({} -> {})",
                    p.id, p.tenant, d.tenant
                ));
            }
            if p.expiry > d.expiry {
                v.push(format!(
                    "Principal::{}: expiry {} outlives delegator {} expiry {}",
                    p.id, p.expiry, d.id, d.expiry
                ));
            }
            if !p.scopes.is_subset(&d.scopes) {
                let excess: Vec<_> = p.scopes.difference(&d.scopes).cloned().collect();
                v.push(format!(
                    "Principal::{}: scopes exceed delegator {} (excess: {})",
                    p.id,
                    d.id,
                    excess.join(", ")
                ));
            }
            // CIAM: a delegate's roles cannot exceed its delegator's either.
            if !p.roles.is_subset(&d.roles) {
                let excess: Vec<_> = p.roles.difference(&d.roles).cloned().collect();
                v.push(format!(
                    "Principal::{}: roles exceed delegator {} (excess: {})",
                    p.id,
                    d.id,
                    excess.join(", ")
                ));
            }
            // Residency: a delegate can only be cleared for jurisdictions its
            // delegator is cleared for (attenuation-by-construction).
            if !p.jurisdictions.is_subset(&d.jurisdictions) {
                let excess: Vec<_> = p
                    .jurisdictions
                    .difference(&d.jurisdictions)
                    .cloned()
                    .collect();
                v.push(format!(
                    "Principal::{}: jurisdictions exceed delegator {} (excess: {})",
                    p.id,
                    d.id,
                    excess.join(", ")
                ));
            }
        }

        // Delegation chains must be cycle-free.
        for p in self.principals.values() {
            if let Some(via) = first_cycle_id(
                p,
                |n| &n.id,
                |n| n.delegator.as_deref(),
                |id| self.principals.get(id),
            ) {
                v.push(format!("Principal::{}: delegation cycle via {via}", p.id));
            }
        }

        for r in self.resources.values() {
            match self.principals.get(&r.owner) {
                None => v.push(format!(
                    "Resource::{}: owner {} does not exist",
                    r.id, r.owner
                )),
                Some(o) if o.tenant != r.tenant => v.push(format!(
                    "Resource::{}: owner {} is in tenant {} but resource is in tenant {}",
                    r.id, o.id, o.tenant, r.tenant
                )),
                Some(_) => {}
            }
            // ReBAC viewers: each must exist and share the resource's tenant —
            // a cross-tenant viewer edge would otherwise only be caught at
            // decision time by F-tenant, after the graph had already loaded.
            for viewer_id in &r.viewers {
                match self.principals.get(viewer_id) {
                    None => v.push(format!(
                        "Resource::{}: viewer {viewer_id} does not exist",
                        r.id
                    )),
                    Some(p) if p.tenant != r.tenant => v.push(format!(
                        "Resource::{}: viewer {viewer_id} is in tenant {} but resource is in tenant {}",
                        r.id, p.tenant, r.tenant
                    )),
                    Some(_) => {}
                }
            }
        }

        // Reserved tenant: never a real isolation domain (collides with the
        // unattributed ledger shard name).
        for p in self.principals.values() {
            if p.tenant == RESERVED_TENANT {
                v.push(format!(
                    "Principal::{}: tenant {RESERVED_TENANT:?} is reserved",
                    p.id
                ));
            }
        }
        for r in self.resources.values() {
            if r.tenant == RESERVED_TENANT {
                v.push(format!(
                    "Resource::{}: tenant {RESERVED_TENANT:?} is reserved",
                    r.id
                ));
            }
        }
        for o in self.orgs.values() {
            if o.tenant == RESERVED_TENANT {
                v.push(format!(
                    "Organization::{}: tenant {RESERVED_TENANT:?} is reserved",
                    o.id
                ));
            }
        }

        // ============================ CIAM: orgs ==============================

        // Org hierarchy: a sub-org's parent must exist, share the org's tenant,
        // and the parent chain must be cycle-free.
        for o in self.orgs.values() {
            if let Some(parent_id) = &o.parent {
                match self.orgs.get(parent_id) {
                    None => v.push(format!(
                        "Organization::{}: parent {parent_id} does not exist",
                        o.id
                    )),
                    Some(p) if p.tenant != o.tenant => v.push(format!(
                        "Organization::{}: cross-tenant parent ({} -> {})",
                        o.id, o.tenant, p.tenant
                    )),
                    Some(_) => {}
                }
            }
        }
        for o in self.orgs.values() {
            if let Some(via) = first_cycle_id(
                o,
                |n| &n.id,
                |n| n.parent.as_deref(),
                |id| self.orgs.get(id),
            ) {
                v.push(format!("Organization::{}: hierarchy cycle via {via}", o.id));
            }
        }

        // Org membership: a principal's org must exist and live in the
        // principal's own isolation tenant (an org cannot span tenants).
        for p in self.principals.values() {
            let Some(org_id) = &p.org else { continue };
            match self.orgs.get(org_id) {
                None => v.push(format!("Principal::{}: org {org_id} does not exist", p.id)),
                Some(o) if o.tenant != p.tenant => v.push(format!(
                    "Principal::{}: org {} is in tenant {} but principal is in tenant {}",
                    p.id, o.id, o.tenant, p.tenant
                )),
                Some(_) => {}
            }
        }

        // Resource org: must exist, share the resource's tenant, and — when the
        // owner also declares an org — match the owner's org (a resource belongs
        // to the org that owns it).
        for r in self.resources.values() {
            let Some(org_id) = &r.org else { continue };
            match self.orgs.get(org_id) {
                None => v.push(format!("Resource::{}: org {org_id} does not exist", r.id)),
                Some(o) if o.tenant != r.tenant => v.push(format!(
                    "Resource::{}: org {} is in tenant {} but resource is in tenant {}",
                    r.id, o.id, o.tenant, r.tenant
                )),
                Some(_) => {}
            }
            if let Some(owner) = self.principals.get(&r.owner)
                && let Some(owner_org) = &owner.org
                && owner_org != org_id
            {
                v.push(format!(
                    "Resource::{}: org {org_id} differs from owner {}'s org {owner_org}",
                    r.id, owner.id
                ));
            }
        }

        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn principal(
        id: &str,
        tenant: &str,
        expiry: i64,
        scopes: &[&str],
        delegator: Option<&str>,
    ) -> Value {
        let mut attrs = json!({
            "kind": "Agent", "tenant": tenant, "expiry": expiry,
            "scopes": scopes,
        });
        if let Some(d) = delegator {
            attrs["delegator"] = json!({"__entity": {"type": "Principal", "id": d}});
        }
        json!({"uid": {"type": "Principal", "id": id}, "attrs": attrs, "parents": []})
    }

    #[test]
    fn valid_delegation_passes() {
        let ents = json!([
            principal("corp", "A", 1000, &["read", "move_money"], None),
            principal("agent", "A", 500, &["read"], Some("corp")),
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(dir.validate().is_empty());
    }

    #[test]
    fn expiry_outliving_delegator_rejected() {
        let ents = json!([
            principal("corp", "A", 100, &["read"], None),
            principal("agent", "A", 500, &["read"], Some("corp")),
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(dir.validate().iter().any(|v| v.contains("outlives")));
    }

    #[test]
    fn scope_escalation_rejected() {
        let ents = json!([
            principal("corp", "A", 1000, &["read"], None),
            principal("agent", "A", 500, &["read", "move_money"], Some("corp")),
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(dir.validate().iter().any(|v| v.contains("exceed")));
    }

    #[test]
    fn cross_tenant_delegation_rejected() {
        let ents = json!([
            principal("corp", "A", 1000, &["read"], None),
            principal("agent", "B", 500, &["read"], Some("corp")),
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(dir.validate().iter().any(|v| v.contains("cross-tenant")));
    }

    #[test]
    fn delegation_cycle_rejected() {
        let ents = json!([
            principal("a", "A", 1000, &["read"], Some("b")),
            principal("b", "A", 1000, &["read"], Some("a")),
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(dir.validate().iter().any(|v| v.contains("cycle")));
    }

    #[test]
    fn ancestors_of_is_the_full_transitive_chain() {
        // The `attenuation-edge` proof reasons over `principal.ancestors`, which cvc5
        // treats as an opaque flat set — the TRANSITIVE closure that fills it is this
        // trusted-base walk, so re-derive it here against hand-checked ground truth.
        // Well-attenuated 4-hop chain a <- b <- c <- d plus a branch e off b.
        let ents = json!([
            principal("a", "A", 1000, &["read"], None),
            principal("b", "A", 900, &["read"], Some("a")),
            principal("c", "A", 800, &["read"], Some("b")),
            principal("d", "A", 700, &["read"], Some("c")),
            principal("e", "A", 850, &["read"], Some("b")),
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(dir.validate().is_empty(), "chain must be well-formed");

        // Nearest-first, complete to the root — the whole authority chain, not one hop.
        assert_eq!(dir.ancestors_of("d"), vec!["c", "b", "a"]);
        assert_eq!(dir.ancestors_of("c"), vec!["b", "a"]);
        assert_eq!(dir.ancestors_of("b"), vec!["a"]);
        assert!(dir.ancestors_of("a").is_empty(), "root has no delegator");
        // The branch is independent of the deeper chain.
        assert_eq!(dir.ancestors_of("e"), vec!["b", "a"]);
        // Unknown principal → empty (never panics).
        assert!(dir.ancestors_of("nope").is_empty());
    }

    #[test]
    fn contains_distinguishes_known_from_unknown_principals() {
        let ents = json!([
            principal("a", "A", 1000, &["read"], None),
            principal("b", "A", 900, &["read"], Some("a")),
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(dir.contains("a"), "root principal is known");
        assert!(dir.contains("b"), "delegate is known");
        assert!(
            !dir.contains("nope"),
            "a caller not in the directory is unknown"
        );
    }

    #[test]
    fn ancestors_of_terminates_on_a_cycle() {
        // Validation rejects cycles, but `ancestors_of` still runs on the parsed graph
        // (e.g. before validate), so the walker must be cycle-safe on its own — an
        // unguarded walk would loop forever and hang the load path.
        let ents = json!([
            principal("a", "A", 1000, &["read"], Some("b")),
            principal("b", "A", 1000, &["read"], Some("a")),
        ]);
        let dir = Directory::parse(&ents).unwrap();
        // Each id appears at most once; the walk stops when it revisits a seen node.
        let anc = dir.ancestors_of("a");
        assert_eq!(
            anc,
            vec!["b"],
            "one hop then the cycle-guard stops the walk"
        );
        assert_eq!(dir.ancestors_of("b"), vec!["a"]);
    }

    #[test]
    fn implicit_entity_ref_form_cannot_bypass_validation() {
        // Cedar accepts {"type","id"} without the __entity escape; the
        // validator must see that edge too — this was a confirmed bypass.
        let ents = json!([
            principal("corp", "A", 1000, &["read"], None),
            {"uid": {"type": "Principal", "id": "sneaky"},
             "attrs": {"kind": "Agent", "tenant": "A", "expiry": 999999,
                       "scopes": ["read", "move_money"],
                       "delegator": {"type": "Principal", "id": "corp"}},
             "parents": []}
        ]);
        let dir = Directory::parse(&ents).unwrap();
        let v = dir.validate();
        assert!(v.iter().any(|x| x.contains("outlives")), "{v:?}");
        assert!(v.iter().any(|x| x.contains("exceed")), "{v:?}");
    }

    #[test]
    fn malformed_entity_ref_is_a_violation_not_ignored() {
        let ents = json!([
            {"uid": {"type": "Principal", "id": "p"},
             "attrs": {"kind": "Agent", "tenant": "A", "expiry": 10,
                       "scopes": [], "delegator": {"__entity": {"id": "corp"}}},
             "parents": []}
        ]);
        let err = Directory::parse(&ents).unwrap_err();
        assert!(
            err.iter()
                .any(|x| x.contains("unparseable entity reference")),
            "{err:?}"
        );
    }

    #[test]
    fn wrong_type_entity_ref_is_a_violation() {
        let ents = json!([
            {"uid": {"type": "Principal", "id": "p"},
             "attrs": {"kind": "Agent", "tenant": "A", "expiry": 10, "scopes": [],
                       "delegator": {"__entity": {"type": "Resource", "id": "claim1"}}},
             "parents": []}
        ]);
        let err = Directory::parse(&ents).unwrap_err();
        assert!(
            err.iter().any(|x| x.contains("expected Principal")),
            "{err:?}"
        );
    }

    #[test]
    fn valid_org_graph_passes() {
        let ents = json!([
            {"uid":{"type":"Organization","id":"acme"},"attrs":{"tenant":"acme"},"parents":[]},
            {"uid":{"type":"Organization","id":"eu"},"attrs":{"tenant":"acme",
                "parent":{"__entity":{"type":"Organization","id":"acme"}}},"parents":[]},
            {"uid":{"type":"Principal","id":"alice"},"attrs":{"kind":"Human","tenant":"acme",
                "expiry":1000,"scopes":["pii:read"],"roles":["customer"],
                "org":{"__entity":{"type":"Organization","id":"acme"}}},"parents":[]},
            {"uid":{"type":"Principal","id":"ag"},"attrs":{"kind":"Agent","tenant":"acme",
                "expiry":500,"scopes":["pii:read"],"roles":["customer"],
                "org":{"__entity":{"type":"Organization","id":"acme"}},
                "delegator":{"__entity":{"type":"Principal","id":"alice"}}},"parents":[]},
            {"uid":{"type":"Resource","id":"prof"},"attrs":{
                "owner":{"__entity":{"type":"Principal","id":"alice"}},"tenant":"acme",
                "org":{"__entity":{"type":"Organization","id":"acme"}},"sensitivity":"pii"},"parents":[]}
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(dir.validate().is_empty(), "{:?}", dir.validate());
    }

    #[test]
    fn role_escalation_rejected() {
        let ents = json!([
            {"uid":{"type":"Principal","id":"alice"},"attrs":{"kind":"Human","tenant":"acme",
                "expiry":1000,"scopes":["pii:read"],"roles":["customer"]},"parents":[]},
            {"uid":{"type":"Principal","id":"ag"},"attrs":{"kind":"Agent","tenant":"acme",
                "expiry":500,"scopes":["pii:read"],"roles":["customer","admin"],
                "delegator":{"__entity":{"type":"Principal","id":"alice"}}},"parents":[]}
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(
            dir.validate().iter().any(|v| v.contains("roles exceed")),
            "{:?}",
            dir.validate()
        );
    }

    #[test]
    fn org_cross_tenant_membership_rejected() {
        let ents = json!([
            {"uid":{"type":"Organization","id":"acme"},"attrs":{"tenant":"acme"},"parents":[]},
            {"uid":{"type":"Principal","id":"p"},"attrs":{"kind":"Human","tenant":"other",
                "expiry":1000,"scopes":[],
                "org":{"__entity":{"type":"Organization","id":"acme"}}},"parents":[]}
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(
            dir.validate()
                .iter()
                .any(|v| v.contains("org acme is in tenant")),
            "{:?}",
            dir.validate()
        );
    }

    #[test]
    fn org_hierarchy_cycle_rejected() {
        let ents = json!([
            {"uid":{"type":"Organization","id":"a"},"attrs":{"tenant":"t",
                "parent":{"__entity":{"type":"Organization","id":"b"}}},"parents":[]},
            {"uid":{"type":"Organization","id":"b"},"attrs":{"tenant":"t",
                "parent":{"__entity":{"type":"Organization","id":"a"}}},"parents":[]}
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(
            dir.validate().iter().any(|v| v.contains("hierarchy cycle")),
            "{:?}",
            dir.validate()
        );
    }

    #[test]
    fn missing_owner_rejected() {
        let ents = json!([
            {"uid": {"type": "Resource", "id": "r1"},
             "attrs": {"owner": {"__entity": {"type": "Principal", "id": "ghost"}}, "tenant": "A"},
             "parents": []}
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(dir.validate().iter().any(|v| v.contains("does not exist")));
    }

    #[test]
    fn cross_tenant_viewer_rejected_at_load() {
        let ents = json!([
            principal("corp", "A", 1000, &["read"], None),
            principal("outsider", "B", 1000, &["read"], None),
            {"uid": {"type": "Resource", "id": "doc"},
             "attrs": {
                "owner": {"__entity": {"type": "Principal", "id": "corp"}},
                "tenant": "A",
                "viewers": [{"__entity": {"type": "Principal", "id": "outsider"}}]
             },
             "parents": []}
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(
            dir.validate()
                .iter()
                .any(|v| v.contains("viewer outsider") && v.contains("tenant")),
            "{:?}",
            dir.validate()
        );
    }

    #[test]
    fn unknown_viewer_rejected_at_load() {
        let ents = json!([
            principal("corp", "A", 1000, &["read"], None),
            {"uid": {"type": "Resource", "id": "doc"},
             "attrs": {
                "owner": {"__entity": {"type": "Principal", "id": "corp"}},
                "tenant": "A",
                "viewers": [{"__entity": {"type": "Principal", "id": "ghost"}}]
             },
             "parents": []}
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(
            dir.validate()
                .iter()
                .any(|v| v.contains("viewer ghost") && v.contains("does not exist")),
            "{:?}",
            dir.validate()
        );
    }

    #[test]
    fn reserved_tenant_rejected_at_load() {
        let ents = json!([
            {"uid": {"type": "Principal", "id": "sys"},
             "attrs": {"kind": "Agent", "tenant": RESERVED_TENANT, "expiry": 1000, "scopes": []},
             "parents": []}
        ]);
        let dir = Directory::parse(&ents).unwrap();
        assert!(
            dir.validate().iter().any(|v| v.contains("reserved")),
            "{:?}",
            dir.validate()
        );
    }

    // ===================== proptest: trusted-base closure =====================
    // `ancestors_of` is the transitive walk cvc5 does NOT certify. Generate random
    // delegation forests (and cyclic graphs) and check the production walk against
    // an independent set-closure + nearest-first order discipline.

    /// Set-based closure: follow `delegator` into a set until fixpoint / cycle.
    /// The starting id is never an ancestor of itself (a cycle back to start stops
    /// without inserting it) — matching `ancestors_of`.
    fn reference_ancestor_set(dir: &Directory, id: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut cur = id.to_owned();
        let mut guard = 0usize;
        let limit = dir.principals.len().saturating_add(1);
        while let Some(p) = dir.principals.get(&cur) {
            let Some(d) = &p.delegator else {
                break;
            };
            // Stop before inserting the start (not your own ancestor) or a repeat.
            if d == id || !out.insert(d.clone()) {
                break;
            }
            cur = d.clone();
            guard += 1;
            if guard > limit {
                break;
            }
        }
        out
    }

    fn dir_from_edges(n: usize, parent_of: &[Option<usize>], revoked: &[bool]) -> Directory {
        let mut principals = BTreeMap::new();
        for i in 0..n {
            let id = format!("p{i}");
            let delegator = parent_of.get(i).and_then(|p| p.map(|j| format!("p{j}")));
            principals.insert(
                id.clone(),
                PrincipalRec {
                    id,
                    kind: "Agent".into(),
                    tenant: "T".into(),
                    expiry: 1000 - i as i64,
                    scopes: BTreeSet::from(["read".into()]),
                    delegator,
                    org: None,
                    roles: BTreeSet::new(),
                    jurisdictions: BTreeSet::new(),
                    revoked: revoked.get(i).copied().unwrap_or(false),
                },
            );
        }
        Directory {
            principals,
            resources: BTreeMap::new(),
            orgs: BTreeMap::new(),
        }
    }

    /// Forest: node i's parent is None or in 0..i — acyclic by construction.
    #[test]
    fn prop_ancestors_of_matches_reference_on_random_forests() {
        use proptest::prelude::*;

        // parent_of[i] encoded as u8: 0 = root, else parent = (v-1) % i
        proptest!(|(n in 1usize..16, bits in proptest::collection::vec(any::<u8>(), 1usize..16))| {
            let n = n.min(bits.len()).max(1);
            let mut parent_of = vec![None; n];
            let mut revoked = vec![false; n];
            for (i, &b) in bits.iter().take(n).enumerate() {
                revoked[i] = b & 1 != 0;
                if i == 0 || (b >> 1) & 3 == 0 {
                    parent_of[i] = None;
                } else {
                    parent_of[i] = Some(((b >> 2) as usize) % i);
                }
            }
            let dir = dir_from_edges(n, &parent_of, &revoked);
            for i in 0..n {
                let id = format!("p{i}");
                let got = dir.ancestors_of(&id);
                let as_set: BTreeSet<_> = got.iter().cloned().collect();
                prop_assert_eq!(
                    as_set,
                    reference_ancestor_set(&dir, &id),
                    "{}: set closure mismatch",
                    id
                );
                // Nearest-first: each step is the authored delegator of the previous node.
                let mut prev = id.clone();
                for a in &got {
                    let prev_del = dir
                        .principals
                        .get(&prev)
                        .and_then(|p| p.delegator.clone());
                    prop_assert_eq!(
                        prev_del.as_deref(),
                        Some(a.as_str()),
                        "{}: order break at {} after {}",
                        id,
                        a,
                        prev
                    );
                    prev = a.clone();
                }
            }
        });
    }

    /// Cycles must not hang: every id appears at most once; set agrees with reference.
    #[test]
    fn prop_ancestors_of_terminates_on_random_cycles() {
        use proptest::prelude::*;

        proptest!(|(n in 2usize..12, cycle_shift in 0usize..16)| {
            let mut parent_of = vec![None; n];
            for (i, parent) in parent_of.iter_mut().enumerate() {
                *parent = Some((i + 1 + cycle_shift) % n);
            }
            let dir = dir_from_edges(n, &parent_of, &vec![false; n]);
            for i in 0..n {
                let id = format!("p{i}");
                let got = dir.ancestors_of(&id);
                prop_assert!(got.len() < n, "{}: walk longer than n on a cycle", id);
                let as_set: BTreeSet<_> = got.iter().cloned().collect();
                prop_assert_eq!(as_set.len(), got.len(), "{}: duplicate in walk", id);
                prop_assert_eq!(as_set, reference_ancestor_set(&dir, &id));
            }
        });
    }

    #[test]
    fn descendants_of_returns_transitive_closure_on_chain() {
        // Chain: a <- b <- c <- d. Revoke a, who loses authority? b, c, d.
        let ents = json!([
            principal("a", "A", 1000, &["read"], None),
            principal("b", "A", 900, &["read"], Some("a")),
            principal("c", "A", 800, &["read"], Some("b")),
            principal("d", "A", 700, &["read"], Some("c")),
        ]);
        let dir = Directory::parse(&ents).unwrap();

        assert_eq!(dir.descendants_of("a"), vec!["b", "c", "d"]);
        assert_eq!(dir.descendants_of("b"), vec!["c", "d"]);
        assert_eq!(dir.descendants_of("c"), vec!["d"]);
        assert!(dir.descendants_of("d").is_empty());
    }

    /// A chain cannot tell breadth-first from depth-first — every node has one
    /// child, so both orders agree. This branching tree can: breadth-first returns
    /// the near delegates before the far ones, depth-first dives down one leg first.
    #[test]
    fn descendants_of_is_breadth_first_on_a_branching_tree() {
        // a delegates to b and c; b to d and e; c to f. Revoking a costs all five.
        let ents = json!([
            principal("a", "A", 1000, &["read"], None),
            principal("b", "A", 900, &["read"], Some("a")),
            principal("c", "A", 900, &["read"], Some("a")),
            principal("d", "A", 800, &["read"], Some("b")),
            principal("e", "A", 800, &["read"], Some("b")),
            principal("f", "A", 800, &["read"], Some("c")),
        ]);
        let dir = Directory::parse(&ents).unwrap();

        // Nearest first: both direct delegates, then the next hop out. A
        // depth-first walk would put d and e before c.
        assert_eq!(dir.descendants_of("a"), vec!["b", "c", "d", "e", "f"]);
        assert_eq!(dir.descendants_of("b"), vec!["d", "e"]);
        assert_eq!(dir.descendants_of("c"), vec!["f"]);
    }

    /// The blast radius stops at the tenant boundary. Load-time validation forbids
    /// a cross-tenant delegation edge, so this is defence in depth — but a traversal
    /// that spanned tenants would report one tenant's principals to another.
    #[test]
    fn descendants_of_never_leaves_the_tenant() {
        let mut ents = json!([
            principal("root_a", "A", 1000, &["read"], None),
            principal("child_a", "A", 900, &["read"], Some("root_a")),
            principal("root_b", "B", 1000, &["read"], None),
            principal("child_b", "B", 900, &["read"], Some("root_b")),
        ]);
        // Forge the edge validation would reject: a tenant-B principal claiming a
        // tenant-A delegator. The traversal must not follow it.
        ents.as_array_mut().unwrap()[3]["attrs"]["delegator"] = json!({
            "__entity": { "type": "Principal", "id": "root_a" }
        });
        let dir = Directory::parse(&ents).unwrap();

        assert_eq!(dir.descendants_of("root_a"), vec!["child_a"]);
        assert!(
            !dir.descendants_of("root_a").contains(&"child_b".to_owned()),
            "a forged cross-tenant edge must not widen the blast radius"
        );
        assert!(dir.descendants_of("unknown").is_empty());
    }

    /// A cycle reaching this far means load-time validation was bypassed; the walk
    /// must still terminate rather than hang an operator's revocation preview.
    #[test]
    fn descendants_of_terminates_on_a_cycle() {
        let mut ents = json!([
            principal("a", "A", 1000, &["read"], None),
            principal("b", "A", 900, &["read"], Some("a")),
            principal("c", "A", 800, &["read"], Some("b")),
        ]);
        // Close the loop: a delegates from c, which validate() would reject.
        ents.as_array_mut().unwrap()[0]["attrs"]["delegator"] = json!({
            "__entity": { "type": "Principal", "id": "c" }
        });
        let dir = Directory::parse(&ents).unwrap();

        let out = dir.descendants_of("a");
        assert_eq!(out, vec!["b", "c"], "each principal is visited once");
    }
}
