// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
#![forbid(unsafe_code)]
//! decern-kernel — the deterministic decision core.
//!
//! `check()` is a pure function of (principal, authority graph, policy,
//! context). There is no clock, no randomness, and no I/O at decision time;
//! time enters only as `context.now`. Every failure path resolves to Deny
//! (fail-closed) with the cause reported, never to a panic.

pub mod graph;

use std::path::Path;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, PolicySet,
    Request, Schema, ValidationMode, Validator,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub use graph::{Directory, RESERVED_TENANT};

/// The authority model: schema + policies + entity graph. Pure data —
/// adding principals, tenants or resources never touches code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Model {
    pub schema: String,
    pub policies: String,
    pub entities: Value,
}

impl Model {
    pub fn from_dir(dir: &Path) -> Result<Self, KernelError> {
        let read = |name: &str| {
            std::fs::read_to_string(dir.join(name))
                .map_err(|e| KernelError::Io(format!("{}: {e}", dir.join(name).display())))
        };
        let entities: Value = serde_json::from_str(&read("entities.json")?)
            .map_err(|e| KernelError::Entities(e.to_string()))?;
        Ok(Model {
            schema: read("authority.cedarschema")?,
            policies: read("authority.cedar")?,
            entities,
        })
    }

    /// The built-in demo model (finance: corp delegates to agents across tenants).
    pub fn builtin() -> Self {
        let entities: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/model/entities.json"
        )))
        .unwrap_or(Value::Null); // include_str is compile-time constant; parse cannot fail in practice
        Model {
            schema: include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/model/authority.cedarschema"
            ))
            .to_owned(),
            policies: include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/model/authority.cedar"
            ))
            .to_owned(),
            entities,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("model I/O error: {0}")]
    Io(String),
    #[error("schema error: {0}")]
    Schema(String),
    #[error("policy parse error: {0}")]
    Policy(String),
    #[error("policies are not well-typed against the schema:\n{0}")]
    Validation(String),
    #[error("entities error: {0}")]
    Entities(String),
    #[error("authority graph rejected (attenuation violations):\n{0}")]
    Graph(String),
}

/// A subject/resource reference, AuthZEN-shaped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityRef {
    #[serde(rename = "type")]
    pub ty: String,
    pub id: String,
}

/// The kernel's decision. `reasons` names the determining policies on Allow;
/// `errors` carries evaluation diagnostics (e.g. unknown principal) — which
/// always accompany a Deny, never an Allow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResponse {
    pub decision: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

impl CheckResponse {
    fn deny(reason: String) -> Self {
        CheckResponse {
            decision: false,
            reasons: Vec::new(),
            errors: vec![reason],
        }
    }
}

pub struct Kernel {
    schema: Schema,
    policies: PolicySet,
    entities: Entities,
    directory: Directory,
    authorizer: Authorizer,
}

impl Kernel {
    /// Build a kernel from a model. Fail-closed: schema must parse, policies
    /// must be well-typed against it, entities must conform, and the graph
    /// must pass attenuation validation — or nothing loads.
    pub fn new(model: &Model) -> Result<Self, KernelError> {
        let (schema, _warnings) = Schema::from_cedarschema_str(&model.schema)
            .map_err(|e| KernelError::Schema(e.to_string()))?;

        let policies =
            PolicySet::from_str(&model.policies).map_err(|e| KernelError::Policy(e.to_string()))?;

        // Honor `@id("...")` annotations as policy ids. Without this a decision's
        // `reasons` name policies by position — `policy9` — which shifts when a policy
        // is added and tells a reader of the record nothing. A model that annotates
        // gets named reasons; one that does not keeps the positional ids it had.
        let policies = {
            let mut named = PolicySet::new();
            for p in policies.policies() {
                let p = match p.annotation("id") {
                    Some(id) => p.new_id(id.parse().map_err(|_| {
                        // PolicyId::from_str is infallible in cedar 4; kept for the type.
                        KernelError::Policy(format!("invalid @id annotation on {}", p.id()))
                    })?),
                    None => p.clone(),
                };
                let id = p.id().clone();
                named.add(p).map_err(|e| {
                    KernelError::Policy(format!("duplicate policy @id {id:?}: {e}"))
                })?;
            }
            named
        };

        let validation = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        if !validation.validation_passed() {
            let errs: Vec<String> = validation
                .validation_errors()
                .map(|e| e.to_string())
                .collect();
            return Err(KernelError::Validation(errs.join("\n")));
        }

        // Parse + validate the authority graph BEFORE building Cedar entities:
        // attenuation must hold, and we derive each principal's transitive
        // `ancestors` set from the (now acyclic, attenuated) delegation chain.
        let directory =
            Directory::parse(&model.entities).map_err(|v| KernelError::Graph(v.join("\n")))?;
        let violations = directory.validate();
        if !violations.is_empty() {
            return Err(KernelError::Graph(violations.join("\n")));
        }

        let augmented = inject_derived(&model.entities, &directory);
        let entities = Entities::from_json_value(augmented, Some(&schema))
            .map_err(|e| KernelError::Entities(e.to_string()))?;

        Ok(Kernel {
            schema,
            policies,
            entities,
            directory,
            authorizer: Authorizer::new(),
        })
    }

    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    /// The deterministic decision. `context` must be a JSON object and must
    /// carry `now` (the kernel never reads a clock). Any malformed input
    /// resolves to Deny with the cause in `errors`.
    pub fn check(
        &self,
        subject: &EntityRef,
        action: &str,
        resource: &EntityRef,
        context: &Value,
    ) -> CheckResponse {
        let principal = match uid(&subject.ty, &subject.id) {
            Ok(u) => u,
            Err(e) => return CheckResponse::deny(format!("bad subject: {e}")),
        };
        let action_uid = match uid("Action", action) {
            Ok(u) => u,
            Err(e) => return CheckResponse::deny(format!("bad action: {e}")),
        };
        let resource_uid = match uid(&resource.ty, &resource.id) {
            Ok(u) => u,
            Err(e) => return CheckResponse::deny(format!("bad resource: {e}")),
        };

        if !context.is_object() {
            return CheckResponse::deny("context must be a JSON object".into());
        }
        // Time is epoch seconds, injected. Anything else — absent, negative,
        // fractional, or beyond Long range — is a malformed clock: Deny.
        match context.get("now") {
            None => {
                return CheckResponse::deny(
                    "context.now is required (the kernel never reads a clock)".into(),
                );
            }
            Some(v) => match v.as_u64() {
                Some(n) if n <= i64::MAX as u64 => {}
                _ => {
                    return CheckResponse::deny(format!(
                        "context.now must be a non-negative integer within Long range (epoch seconds), got {v}"
                    ));
                }
            },
        }

        let ctx = match Context::from_json_value(context.clone(), Some((&self.schema, &action_uid)))
        {
            Ok(c) => c,
            Err(e) => return CheckResponse::deny(format!("bad context: {e}")),
        };

        let request =
            match Request::new(principal, action_uid, resource_uid, ctx, Some(&self.schema)) {
                Ok(r) => r,
                Err(e) => return CheckResponse::deny(format!("bad request: {e}")),
            };

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &self.entities);

        CheckResponse {
            decision: response.decision() == Decision::Allow,
            reasons: response
                .diagnostics()
                .reason()
                .map(|p| p.to_string())
                .collect(),
            errors: response
                .diagnostics()
                .errors()
                .map(|e| e.to_string())
                .collect(),
        }
    }

    /// AuthZEN subject search: which principals get Allow for (action, resource)?
    pub fn search_subjects(
        &self,
        action: &str,
        resource: &EntityRef,
        context: &Value,
    ) -> Vec<EntityRef> {
        self.directory
            .principals
            .keys()
            .filter(|id| {
                self.check(
                    &EntityRef {
                        ty: "Principal".into(),
                        id: (*id).clone(),
                    },
                    action,
                    resource,
                    context,
                )
                .decision
            })
            .map(|id| EntityRef {
                ty: "Principal".into(),
                id: id.clone(),
            })
            .collect()
    }

    /// AuthZEN resource search: which resources does (subject, action) reach?
    pub fn search_resources(
        &self,
        subject: &EntityRef,
        action: &str,
        context: &Value,
    ) -> Vec<EntityRef> {
        self.directory
            .resources
            .keys()
            .filter(|id| {
                self.check(
                    subject,
                    action,
                    &EntityRef {
                        ty: "Resource".into(),
                        id: (*id).clone(),
                    },
                    context,
                )
                .decision
            })
            .map(|id| EntityRef {
                ty: "Resource".into(),
                id: id.clone(),
            })
            .collect()
    }
}

/// Inject the derived attributes into every Principal entity, computed from the
/// validated delegation chain — the single source of truth being the authored
/// `delegator` edges:
///   * `ancestors` — the transitive delegator set, so the policy layer can grant
///     a delegate access to any authority ancestor's resource without walking
///     chains at decision time (which Cedar cannot do, nor the SMT prover certify).
///   * `revoked` — effective revocation: the principal's own `revoked` flag OR
///     that of any ancestor, so revoking upstream kills the whole subtree.
fn inject_derived(entities: &Value, dir: &Directory) -> Value {
    let revoked_of = |id: &str| dir.principals.get(id).map(|p| p.revoked).unwrap_or(false);
    let mut list = entities.as_array().cloned().unwrap_or_default();
    for e in list.iter_mut() {
        let is_principal = e
            .get("uid")
            .and_then(|u| u.get("type"))
            .and_then(Value::as_str)
            == Some("Principal");
        if !is_principal {
            continue;
        }
        let id = e
            .get("uid")
            .and_then(|u| u.get("id"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let ancestors = dir.ancestors_of(&id);
        let effective_revoked = revoked_of(&id) || ancestors.iter().any(|a| revoked_of(a));
        let refs: Vec<Value> = ancestors
            .into_iter()
            .map(|a| json!({ "__entity": { "type": "Principal", "id": a } }))
            .collect();
        if let Some(attrs) = e.get_mut("attrs").and_then(Value::as_object_mut) {
            attrs.insert("ancestors".to_owned(), Value::Array(refs));
            attrs.insert("revoked".to_owned(), Value::Bool(effective_revoked));
        }
    }
    Value::Array(list)
}

/// Build an EntityUid without string interpolation, so hostile ids
/// (quotes, backslashes) cannot inject into the uid grammar.
fn uid(ty: &str, id: &str) -> Result<EntityUid, String> {
    let tn = EntityTypeName::from_str(ty).map_err(|e| e.to_string())?;
    let eid = EntityId::from_str(id).map_err(|e| e.to_string())?;
    Ok(EntityUid::from_type_name_and_id(tn, eid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn kernel() -> Kernel {
        Kernel::new(&Model::builtin()).expect("builtin model must load")
    }

    fn sub(id: &str) -> EntityRef {
        EntityRef {
            ty: "Principal".into(),
            id: id.into(),
        }
    }

    fn res(id: &str) -> EntityRef {
        EntityRef {
            ty: "Resource".into(),
            id: id.into(),
        }
    }

    #[test]
    fn delegated_read_in_window_allows() {
        let r = kernel().check(&sub("agent1"), "Read", &res("claim1"), &json!({"now": 100}));
        assert!(r.decision, "{r:?}");
        assert!(!r.reasons.is_empty());
    }

    #[test]
    fn money_without_approval_denies() {
        let r = kernel().check(
            &sub("agent1"),
            "MoveMoney",
            &res("claim1"),
            &json!({"now": 100}),
        );
        assert!(!r.decision);
    }

    #[test]
    fn money_with_approval_allows() {
        let r = kernel().check(
            &sub("agent1"),
            "MoveMoney",
            &res("claim1"),
            &json!({"now": 100, "human_approved": true}),
        );
        assert!(r.decision, "{r:?}");
    }

    #[test]
    fn money_with_approval_but_no_scope_denies() {
        // agent2 was attenuated to read-only at delegation time
        let r = kernel().check(
            &sub("agent2"),
            "MoveMoney",
            &res("claim1"),
            &json!({"now": 100, "human_approved": true}),
        );
        assert!(!r.decision);
    }

    #[test]
    fn cross_tenant_denies() {
        let r = kernel().check(&sub("agent1"), "Read", &res("claimB"), &json!({"now": 100}));
        assert!(!r.decision);
    }

    #[test]
    fn decayed_authority_denies() {
        let r = kernel().check(&sub("agent1"), "Read", &res("claim1"), &json!({"now": 500}));
        assert!(!r.decision);
    }

    #[test]
    fn unknown_principal_denies_with_error() {
        let r = kernel().check(&sub("ghost"), "Read", &res("claim1"), &json!({"now": 100}));
        assert!(!r.decision);
    }

    #[test]
    fn missing_now_denies() {
        let r = kernel().check(&sub("agent1"), "Read", &res("claim1"), &json!({}));
        assert!(!r.decision);
        assert!(r.errors.iter().any(|e| e.contains("now")));
    }

    #[test]
    fn hostile_id_cannot_inject() {
        let r = kernel().check(
            &sub("x\" || principal == Principal::\"corp"),
            "Read",
            &res("claim1"),
            &json!({"now": 100}),
        );
        assert!(!r.decision);
    }

    #[test]
    fn graph_with_scope_escalation_refuses_to_load() {
        let mut model = Model::builtin();
        // grant agent2 a scope its delegator corp does not have
        let ents = model.entities.as_array_mut().unwrap();
        for e in ents.iter_mut() {
            if e["uid"]["id"] == "agent2" {
                e["attrs"]["scopes"] = json!(["read", "root_everything"]);
            }
        }
        let err = Kernel::new(&model).err().expect("must refuse");
        assert!(matches!(err, KernelError::Graph(_)), "{err}");
    }

    /// An `@id` annotation names the policy, so a decision's reasons say what decided
    /// it rather than a position that shifts when a policy is added. The builtin model
    /// annotates every policy; a model without annotations keeps positional ids.
    #[test]
    fn the_builtin_model_names_its_policies_in_reasons() {
        let k = kernel();
        let allow = k.check(&sub("corp"), "Read", &res("claim1"), &json!({"now": 100}));
        assert!(allow.decision);
        assert!(
            allow.reasons.contains(&"P-read".to_owned()),
            "{:?}",
            allow.reasons
        );
        let deny = k.check(
            &sub("corp"),
            "MoveMoney",
            &res("claim1"),
            &json!({"now": 100}),
        );
        assert!(!deny.decision);
        assert!(
            deny.reasons.contains(&"F-money".to_owned()),
            "{:?}",
            deny.reasons
        );
    }

    #[test]
    fn duplicate_id_annotations_refuse_to_load() {
        let mut model = Model::builtin();
        model.policies = format!(
            "@id(\"dup\")\npermit (principal, action, resource) when {{ false }};\n\
             @id(\"dup\")\npermit (principal, action, resource) when {{ false }};\n{}",
            model.policies
        );
        let err = Kernel::new(&model).err().expect("must refuse");
        assert!(matches!(err, KernelError::Policy(_)), "{err}");
    }

    #[test]
    fn subject_search_finds_expected() {
        let k = kernel();
        let subs = k.search_subjects("Read", &res("claim1"), &json!({"now": 100}));
        let ids: Vec<_> = subs.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"corp"));
        assert!(ids.contains(&"agent1"));
        assert!(ids.contains(&"agent2"));
        assert!(!ids.contains(&"corpB"));
        assert!(!ids.contains(&"machine1")); // machine1 has no edge to claim1
    }

    // ============================ CIAM v3 ================================

    fn profile() -> EntityRef {
        res("alice_profile") // owned by alice, tenant acme, sensitivity pii
    }

    #[test]
    fn customer_reads_own_pii_without_consent() {
        // Self-access: alice owns her profile, so the consent gate does not apply.
        let r = kernel().check(&sub("alice"), "AccessPII", &profile(), &json!({"now": 100}));
        assert!(r.decision, "{r:?}");
    }

    #[test]
    fn agent_on_behalf_reads_pii_without_consent_denies() {
        // acme_agent acts on behalf of alice but has no consent in context.
        let r = kernel().check(
            &sub("acme_agent"),
            "AccessPII",
            &profile(),
            &json!({"now": 100}),
        );
        assert!(
            !r.decision,
            "OBO PII access must be denied without consent: {r:?}"
        );
    }

    #[test]
    fn agent_on_behalf_reads_pii_with_consent_allows() {
        let r = kernel().check(
            &sub("acme_agent"),
            "AccessPII",
            &profile(),
            &json!({"now": 100, "consent": true}),
        );
        assert!(
            r.decision,
            "OBO PII access must be allowed with consent: {r:?}"
        );
    }

    #[test]
    fn consent_false_still_denies() {
        let r = kernel().check(
            &sub("acme_agent"),
            "AccessPII",
            &profile(),
            &json!({"now": 100, "consent": false}),
        );
        assert!(!r.decision, "explicit consent:false must deny: {r:?}");
    }

    #[test]
    fn multi_hop_delegate_reaches_root_resource() {
        // corp -> mid -> leaf (a 2-hop agent chain). The leaf must reach corp's
        // resource (owner is an authority ancestor), but not an unrelated one.
        let ents = json!([
            {"uid":{"type":"Principal","id":"corp"},"attrs":{"kind":"Human","tenant":"T","expiry":1000000000,"scopes":["read"]},"parents":[]},
            {"uid":{"type":"Principal","id":"mid"},"attrs":{"kind":"Agent","tenant":"T","expiry":1000000000,"scopes":["read"],"delegator":{"__entity":{"type":"Principal","id":"corp"}}},"parents":[]},
            {"uid":{"type":"Principal","id":"leaf"},"attrs":{"kind":"Agent","tenant":"T","expiry":1000000000,"scopes":["read"],"delegator":{"__entity":{"type":"Principal","id":"mid"}}},"parents":[]},
            {"uid":{"type":"Principal","id":"other"},"attrs":{"kind":"Human","tenant":"T","expiry":1000000000,"scopes":["read"]},"parents":[]},
            {"uid":{"type":"Resource","id":"corp_res"},"attrs":{"owner":{"__entity":{"type":"Principal","id":"corp"}},"tenant":"T"},"parents":[]},
            {"uid":{"type":"Resource","id":"other_res"},"attrs":{"owner":{"__entity":{"type":"Principal","id":"other"}},"tenant":"T"},"parents":[]}
        ]);
        let model = Model {
            entities: ents,
            ..Model::builtin()
        };
        let k = Kernel::new(&model).expect("2-hop model must load");
        // leaf reaches corp's resource through the transitive chain.
        assert!(
            k.check(&sub("leaf"), "Read", &res("corp_res"), &json!({"now": 100}))
                .decision
        );
        // but not a resource owned by a non-ancestor in the same tenant.
        assert!(
            !k.check(
                &sub("leaf"),
                "Read",
                &res("other_res"),
                &json!({"now": 100})
            )
            .decision
        );
    }

    #[test]
    fn rebac_viewer_reads_but_stays_bounded_by_the_forbids() {
        // `viewer` is neither owner nor delegate of corp's resource, but is
        // granted the viewer relation. It may Read — yet the grant cannot
        // expose PII without consent or bypass the scope gate. Cross-tenant
        // viewer edges are refused at load (see `cross_tenant_viewer_rejected_at_load`).
        let ents = json!([
            {"uid":{"type":"Principal","id":"corp"},"attrs":{"kind":"Human","tenant":"T","expiry":1000000000,"scopes":["read"]},"parents":[]},
            {"uid":{"type":"Principal","id":"viewer"},"attrs":{"kind":"Agent","tenant":"T","expiry":1000000000,"scopes":["read"]},"parents":[]},
            {"uid":{"type":"Principal","id":"noscope"},"attrs":{"kind":"Agent","tenant":"T","expiry":1000000000,"scopes":[]},"parents":[]},
            {"uid":{"type":"Principal","id":"outsider"},"attrs":{"kind":"Agent","tenant":"OTHER","expiry":1000000000,"scopes":["read"]},"parents":[]},
            {"uid":{"type":"Resource","id":"doc"},"attrs":{"owner":{"__entity":{"type":"Principal","id":"corp"}},"tenant":"T","viewers":[{"__entity":{"type":"Principal","id":"viewer"}},{"__entity":{"type":"Principal","id":"noscope"}}]},"parents":[]},
            {"uid":{"type":"Resource","id":"secret"},"attrs":{"owner":{"__entity":{"type":"Principal","id":"corp"}},"tenant":"T","sensitivity":"pii","viewers":[{"__entity":{"type":"Principal","id":"viewer"}}]},"parents":[]}
        ]);
        let k = Kernel::new(&Model {
            entities: ents,
            ..Model::builtin()
        })
        .expect("loads");
        let now = json!({"now": 100});
        // the viewer relation grants read to a non-owner, non-delegate.
        assert!(
            k.check(&sub("viewer"), "Read", &res("doc"), &now).decision,
            "granted viewer reads"
        );
        // ...but a viewer without the read scope is still denied (scope-gate).
        assert!(
            !k.check(&sub("noscope"), "Read", &res("doc"), &now).decision,
            "scope gate still binds"
        );
        // ...and a principal in another tenant (no edge) is denied.
        assert!(
            !k.check(&sub("outsider"), "Read", &res("doc"), &now)
                .decision,
            "tenant isolation still binds"
        );
        // ...and a viewer of a PII doc without consent is denied (consent forbid).
        assert!(
            !k.check(&sub("viewer"), "Read", &res("secret"), &now)
                .decision,
            "consent gate still binds"
        );
        assert!(
            k.check(
                &sub("viewer"),
                "Read",
                &res("secret"),
                &json!({"now":100,"consent":true})
            )
            .decision,
            "with consent, reads"
        );
    }

    #[test]
    fn residency_gate_binds_by_clearance_even_for_the_owner() {
        // Data labeled with a residency jurisdiction is readable only by a
        // principal cleared for it — the gate is on the DATA, so it binds even
        // the resource's own owner.
        let ents = json!([
            {"uid":{"type":"Principal","id":"acme_eu"},"attrs":{"kind":"Human","tenant":"T","expiry":1000000000,"scopes":["read"],"jurisdictions":["EU"]},"parents":[]},
            {"uid":{"type":"Principal","id":"acme_us"},"attrs":{"kind":"Human","tenant":"T","expiry":1000000000,"scopes":["read"],"jurisdictions":["US"]},"parents":[]},
            {"uid":{"type":"Resource","id":"eu_doc"},"attrs":{"owner":{"__entity":{"type":"Principal","id":"acme_eu"}},"tenant":"T","residency":"EU"},"parents":[]},
            {"uid":{"type":"Resource","id":"eu_doc_us_owner"},"attrs":{"owner":{"__entity":{"type":"Principal","id":"acme_us"}},"tenant":"T","residency":"EU"},"parents":[]}
        ]);
        let k = Kernel::new(&Model {
            entities: ents,
            ..Model::builtin()
        })
        .expect("loads");
        let now = json!({"now": 100});
        assert!(
            k.check(&sub("acme_eu"), "Read", &res("eu_doc"), &now)
                .decision,
            "EU-cleared owner reads EU data"
        );
        assert!(
            !k.check(&sub("acme_us"), "Read", &res("eu_doc_us_owner"), &now)
                .decision,
            "US-only clearance denied EU-resident data, even as owner"
        );
    }

    #[test]
    fn role_gate_binds_by_role_even_for_the_owner() {
        // R5 F2 — roles-at-decision. A resource that REQUIRES a role is accessible only
        // to a principal whose `roles` includes it. The gate is on the DATA (F-role), so
        // it binds even the resource's own owner — exactly like the residency and consent
        // gates — and is certified by the `role-gate` invariant.
        let ents = json!([
            {"uid":{"type":"Principal","id":"mgr"},"attrs":{"kind":"Human","tenant":"T","expiry":1000000000,"scopes":["read"],"roles":["manager"]},"parents":[]},
            {"uid":{"type":"Principal","id":"staff"},"attrs":{"kind":"Human","tenant":"T","expiry":1000000000,"scopes":["read"],"roles":["staff"]},"parents":[]},
            {"uid":{"type":"Resource","id":"mgr_doc"},"attrs":{"owner":{"__entity":{"type":"Principal","id":"mgr"}},"tenant":"T","required_role":"manager"},"parents":[]},
            {"uid":{"type":"Resource","id":"mgr_doc_staff_owner"},"attrs":{"owner":{"__entity":{"type":"Principal","id":"staff"}},"tenant":"T","required_role":"manager"},"parents":[]}
        ]);
        let k = Kernel::new(&Model {
            entities: ents,
            ..Model::builtin()
        })
        .expect("loads");
        let now = json!({"now": 100});
        assert!(
            k.check(&sub("mgr"), "Read", &res("mgr_doc"), &now).decision,
            "a role-holder reads role-gated data it owns"
        );
        assert!(
            !k.check(&sub("staff"), "Read", &res("mgr_doc_staff_owner"), &now)
                .decision,
            "a principal lacking the required role is denied — even as the owner"
        );
    }

    #[test]
    fn delegate_cannot_exceed_delegator_jurisdictions() {
        // Attenuation-by-construction: a delegate cleared beyond its delegator
        // is rejected at load, so a residency clearance can't be widened by
        // delegating through a broader agent.
        let ents = json!([
            {"uid":{"type":"Principal","id":"eu_corp"},"attrs":{"kind":"Human","tenant":"T","expiry":1000000000,"scopes":["read"],"jurisdictions":["EU"]},"parents":[]},
            {"uid":{"type":"Principal","id":"agent"},"attrs":{"kind":"Agent","tenant":"T","expiry":1000000000,"scopes":["read"],"jurisdictions":["EU","US"],"delegator":{"__entity":{"type":"Principal","id":"eu_corp"}}},"parents":[]}
        ]);
        let err = Kernel::new(&Model {
            entities: ents,
            ..Model::builtin()
        })
        .err()
        .expect("should reject over-broad jurisdictions")
        .to_string();
        assert!(err.contains("jurisdictions exceed"), "got: {err}");
    }

    #[test]
    fn revoking_upstream_kills_the_whole_chain() {
        // corp -> mid -> leaf; revoke `mid`, and both mid and leaf die, while
        // corp (above the revocation) still works.
        let ents = json!([
            {"uid":{"type":"Principal","id":"corp"},"attrs":{"kind":"Human","tenant":"T","expiry":1000000000,"scopes":["read"]},"parents":[]},
            {"uid":{"type":"Principal","id":"mid"},"attrs":{"kind":"Agent","tenant":"T","expiry":1000000000,"scopes":["read"],"revoked":true,"delegator":{"__entity":{"type":"Principal","id":"corp"}}},"parents":[]},
            {"uid":{"type":"Principal","id":"leaf"},"attrs":{"kind":"Agent","tenant":"T","expiry":1000000000,"scopes":["read"],"delegator":{"__entity":{"type":"Principal","id":"mid"}}},"parents":[]},
            {"uid":{"type":"Resource","id":"corp_res"},"attrs":{"owner":{"__entity":{"type":"Principal","id":"corp"}},"tenant":"T"},"parents":[]}
        ]);
        let k = Kernel::new(&Model {
            entities: ents,
            ..Model::builtin()
        })
        .expect("loads");
        let now = json!({"now": 100});
        assert!(
            k.check(&sub("corp"), "Read", &res("corp_res"), &now)
                .decision,
            "corp above revocation still works"
        );
        assert!(
            !k.check(&sub("mid"), "Read", &res("corp_res"), &now)
                .decision,
            "revoked mid denied"
        );
        assert!(
            !k.check(&sub("leaf"), "Read", &res("corp_res"), &now)
                .decision,
            "leaf under revoked mid denied"
        );
    }

    #[test]
    fn inject_derived_propagates_effective_revocation() {
        // The `revocation-gate` proof reasons over the FLAT `principal.revoked` boolean.
        // The effective-revocation propagation that sets it true when an upstream
        // delegator is revoked is THIS trusted-base derivation — cvc5 cannot certify it,
        // so re-derive it independently and assert `inject_derived` agrees. `top` is
        // authored-revoked; `mid`/`leaf` inherit it; `solo`/`other` are a clean chain.
        let ents = json!([
            {"uid":{"type":"Principal","id":"top"},"attrs":{"kind":"Human","tenant":"T","expiry":1000,"scopes":["read"],"revoked":true},"parents":[]},
            {"uid":{"type":"Principal","id":"mid"},"attrs":{"kind":"Agent","tenant":"T","expiry":900,"scopes":["read"],"delegator":{"__entity":{"type":"Principal","id":"top"}}},"parents":[]},
            {"uid":{"type":"Principal","id":"leaf"},"attrs":{"kind":"Agent","tenant":"T","expiry":800,"scopes":["read"],"delegator":{"__entity":{"type":"Principal","id":"mid"}}},"parents":[]},
            {"uid":{"type":"Principal","id":"solo"},"attrs":{"kind":"Human","tenant":"T","expiry":1000,"scopes":["read"]},"parents":[]},
            {"uid":{"type":"Principal","id":"other"},"attrs":{"kind":"Agent","tenant":"T","expiry":900,"scopes":["read"],"delegator":{"__entity":{"type":"Principal","id":"solo"}}},"parents":[]}
        ]);
        let dir = Directory::parse(&ents).unwrap();
        let augmented = inject_derived(&ents, &dir);

        // Independent re-derivation: effective = authored-revoked OR any ancestor is.
        let authored = |id: &str| dir.principals.get(id).map(|p| p.revoked).unwrap_or(false);
        let expected_revoked =
            |id: &str| authored(id) || dir.ancestors_of(id).iter().any(|a| authored(a));
        let expected = [
            ("top", true),
            ("mid", true),
            ("leaf", true),
            ("solo", false),
            ("other", false),
        ];

        for e in augmented.as_array().expect("array") {
            let id = e["uid"]["id"].as_str().unwrap();
            let want = expected_revoked(id);
            // sanity: the hand table matches the independent walk
            let table = expected.iter().find(|(k, _)| *k == id).unwrap().1;
            assert_eq!(want, table, "{id}: table vs walk disagree");
            // the real assertion: inject_derived wrote the same effective flag...
            assert_eq!(
                e["attrs"]["revoked"].as_bool().unwrap(),
                want,
                "{id}: injected `revoked` must match the trusted-base propagation"
            );
            // ...and the injected `ancestors` set equals the closure walk.
            let got: Vec<String> = e["attrs"]["ancestors"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|r| r["__entity"]["id"].as_str().unwrap().to_owned())
                        .collect()
                })
                .unwrap_or_default();
            assert_eq!(got, dir.ancestors_of(id), "{id}: injected ancestors set");
        }
    }

    /// proptest: random forests → `inject_derived` effective `revoked` and `ancestors`
    /// match an independent re-derivation (the trusted base under revocation-gate /
    /// attenuation-edge).
    #[test]
    fn prop_inject_derived_matches_independent_derivation() {
        use proptest::prelude::*;
        use std::collections::BTreeSet;

        proptest!(|(n in 1usize..12, bits in proptest::collection::vec(any::<u8>(), 1usize..16))| {
            let n = n.min(bits.len()).max(1);
            let mut ents = Vec::new();
            for (i, &b) in bits.iter().take(n).enumerate() {
                let revoked = b & 1 != 0;
                let mut attrs = serde_json::json!({
                    "kind": "Agent",
                    "tenant": "T",
                    "expiry": 1000 - i as i64,
                    "scopes": ["read"],
                    "revoked": revoked,
                });
                if i > 0 && (b >> 1) & 3 != 0 {
                    let parent = ((b >> 2) as usize) % i;
                    attrs["delegator"] = serde_json::json!({
                        "__entity": {"type": "Principal", "id": format!("p{parent}")}
                    });
                }
                ents.push(serde_json::json!({
                    "uid": {"type": "Principal", "id": format!("p{i}")},
                    "attrs": attrs,
                    "parents": []
                }));
            }
            let entities = serde_json::Value::Array(ents);
            let dir = Directory::parse(&entities).expect("parse forest");
            let augmented = inject_derived(&entities, &dir);

            let authored = |id: &str| dir.principals.get(id).map(|p| p.revoked).unwrap_or(false);
            for e in augmented.as_array().expect("array") {
                let id = e["uid"]["id"].as_str().unwrap();
                let want_revoked =
                    authored(id) || dir.ancestors_of(id).iter().any(|a| authored(a));
                prop_assert_eq!(
                    e["attrs"]["revoked"].as_bool().unwrap(),
                    want_revoked,
                    "{}: effective revoked",
                    id
                );
                let got: BTreeSet<String> = e["attrs"]["ancestors"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|r| r["__entity"]["id"].as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                let want: BTreeSet<String> = dir.ancestors_of(id).into_iter().collect();
                prop_assert_eq!(got, want, "{}: injected ancestors", id);
            }
        });
    }

    #[test]
    fn cross_tenant_pii_denies_even_with_consent() {
        // agent1 lives in tenant A; alice_profile is in tenant acme. Tenant
        // isolation is absolute — consent cannot bridge it.
        let r = kernel().check(
            &sub("agent1"),
            "AccessPII",
            &profile(),
            &json!({"now": 100, "consent": true}),
        );
        assert!(!r.decision, "cross-tenant PII access must deny: {r:?}");
    }

    // The consent gate is DATA-scoped: it must hold on the plain Read verb too,
    // not just AccessPII. acme_agent holds the "read" scope, so without a
    // data-scoped gate it could read alice's PII via Read with no consent.
    #[test]
    fn agent_reads_pii_via_read_verb_without_consent_denies() {
        let r = kernel().check(&sub("acme_agent"), "Read", &profile(), &json!({"now": 100}));
        assert!(
            !r.decision,
            "Read of PII on behalf of a customer must deny without consent: {r:?}"
        );
    }

    #[test]
    fn agent_reads_pii_via_read_verb_with_consent_allows() {
        let r = kernel().check(
            &sub("acme_agent"),
            "Read",
            &profile(),
            &json!({"now": 100, "consent": true}),
        );
        assert!(r.decision, "Read of PII with consent must allow: {r:?}");
    }

    #[test]
    fn customer_reads_own_pii_via_read_verb_without_consent() {
        // Self-access is exempt regardless of verb: alice owns her profile.
        let r = kernel().check(&sub("alice"), "Read", &profile(), &json!({"now": 100}));
        assert!(r.decision, "self Read of own PII needs no consent: {r:?}");
    }

    #[test]
    fn non_pii_read_unaffected_by_consent_gate() {
        // The finance demo's claim1 has no sensitivity label — the data-scoped
        // gate must not touch it (agent1 reads claim1 on behalf of corp).
        let r = kernel().check(&sub("agent1"), "Read", &res("claim1"), &json!({"now": 100}));
        assert!(r.decision, "non-PII delegated read must still allow: {r:?}");
    }
}
