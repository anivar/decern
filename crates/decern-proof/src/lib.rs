// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
#![forbid(unsafe_code)]
//! decern-proof — the formal proof suite.
//!
//! Each invariant is proved over the ENTIRE symbolic input space (not a finite
//! sample) using Cedar's Lean-verified symbolic compiler (`cedar-policy-symcc`)
//! → SMT (cvc5). Proof method: policy subsumption `policies ⟹ guard`, where
//! the guard admits exactly the states the invariant permits. A failed proof
//! yields a concrete, replayable counterexample request. The suite reads the
//! SAME model the kernel enforces — what is proven is what runs.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use cedar_policy::{PolicySet, Schema};
use cedar_policy_symcc::{CedarSymCompiler, CompiledPolicySet, solver::LocalSolver};
use decern_kernel::Model;

/// An invariant, stated as a guard policy set: the invariant holds iff every
/// request the model allows is also allowed by the guard.
#[derive(Debug, Clone)]
pub struct Invariant {
    pub name: &'static str,
    pub statement: &'static str,
    pub guard: &'static str,
    /// Restrict to these actions' request environments (None = all actions).
    pub only_actions: Option<&'static [&'static str]>,
}

/// The invariant suite. Each `statement` is calibrated to exactly what cvc5
/// discharges over the Cedar entities — no more. Two invariants (`attenuation-edge`,
/// `revocation-gate`) reason over attributes (`principal.ancestors`, `principal.revoked`)
/// that decern-kernel `inject_derived` computes from the transitive delegation chain BEFORE
/// the prover runs; cvc5 sees them as flat, opaque values and proves membership / the
/// boolean, not the closure that produced them. That closure is trusted base — covered
/// instead by the decern-kernel re-derivation unit tests (dedicated example-based tests
/// that re-derive the closure against hand-written ground truth; NOT property/proptest-
/// generated, and NOT exhaustive). The statements name this split
/// so "PROVEN" never claims more than the machine actually checks.
pub fn suite() -> Vec<Invariant> {
    vec![
        Invariant {
            name: "money-gate",
            statement: "MoveMoney is never allowed without explicit human approval",
            guard: r#"permit(principal, action == Action::"MoveMoney", resource)
                      when { context has human_approved && context.human_approved == true };"#,
            only_actions: Some(&["MoveMoney"]),
        },
        Invariant {
            name: "isolation",
            statement: "no allow ever crosses a tenant boundary",
            guard: r#"permit(principal, action, resource)
                      when { principal.tenant == resource.tenant };"#,
            only_actions: None,
        },
        Invariant {
            name: "decay",
            statement: "no allow once context.now > principal.expiry",
            guard: r#"permit(principal, action, resource)
                      when { context.now <= principal.expiry };"#,
            only_actions: None,
        },
        Invariant {
            // cvc5 discharges the FLAT check: allow ⟹ owner==principal ∨ owner ∈
            // principal.ancestors ∨ principal ∈ resource.viewers. It treats `ancestors`
            // as an opaque set attribute — it does NOT certify that the set is the true
            // transitive delegation closure. That closure is walked by trusted-base Rust
            // (decern-kernel `ancestors_of`/`inject_derived`) and re-derived in the unit
            // test `ancestors_of_is_the_full_transitive_chain`. Keep the statement to
            // exactly what the prover proves.
            name: "attenuation-edge",
            statement: "no allow without ownership, a delegation ancestor, or an explicit relation edge — cvc5 proves flat `principal.ancestors` membership; the transitive closure that fills `ancestors` is trusted base",
            guard: r#"permit(principal, action, resource)
                      when { resource.owner == principal ||
                             principal.ancestors.contains(resource.owner) ||
                             (resource has viewers && resource.viewers.contains(principal)) };"#,
            only_actions: None,
        },
        Invariant {
            // Deliberately bounded, not universal: the guard names exactly the
            // three actions it has a scope convention for. `only_actions` keeps
            // the proof itself scoped to that same set, so a schema that adds
            // other actions (e.g. MCP: McpCallTool/McpReadResource/McpGetPrompt/
            // McpSample/McpElicit/McpRoots) neither refutes this invariant nor is
            // silently claimed as covered by it — those actions are simply
            // outside what "PROVEN" means here until someone adds them a scope
            // name and a permit line. Previously `only_actions` was unset here,
            // which made the guard implicitly deny (and thus refute) every
            // action outside this trio — a false "scope-gate is broken" signal
            // for any operator who extends the action set, not a real gap.
            name: "scope-gate",
            statement: "no action among {Read, MoveMoney, AccessPII} is allowed without its scope in principal.scopes — bounded to these three; any other action (e.g. an operator-added MCP action) is outside this invariant until it gets its own scope-name convention and a guard entry here",
            guard: r#"permit(principal, action == Action::"Read", resource)
                      when { principal.scopes.contains("read") };
                      permit(principal, action == Action::"MoveMoney", resource)
                      when { principal.scopes.contains("move_money") };
                      permit(principal, action == Action::"AccessPII", resource)
                      when { principal.scopes.contains("pii:read") };"#,
            only_actions: Some(&["Read", "MoveMoney", "AccessPII"]),
        },
        Invariant {
            // cvc5 discharges allow ⟹ principal.revoked == false over the FLAT boolean.
            // The propagation that sets `revoked` true when a transitive delegator is
            // revoked (effective revocation) is trusted-base Rust (decern-kernel
            // `inject_derived`), re-derived in the unit test
            // `inject_derived_propagates_effective_revocation`. The statement claims only
            // the flat check the prover certifies.
            name: "revocation-gate",
            statement: "a principal whose effective `revoked` flag is set is never allowed anything — cvc5 proves allow⟹`revoked==false`; propagation of `revoked` from a revoked ancestor is trusted base",
            guard: r#"permit(principal, action, resource)
                      when { principal.revoked == false };"#,
            only_actions: None,
        },
        Invariant {
            name: "residency-gate",
            statement: "accessing a residency-labeled resource is never allowed (via any action) unless the principal is cleared for that jurisdiction",
            guard: r#"permit(principal, action, resource)
                      when { !(resource has residency) ||
                             (resource has residency && principal has jurisdictions &&
                              principal.jurisdictions.contains(resource.residency)) };"#,
            only_actions: None,
        },
        Invariant {
            name: "role-gate",
            statement: "accessing a role-required resource is never allowed (via any action) unless the principal holds that role",
            guard: r#"permit(principal, action, resource)
                      when { !(resource has required_role) ||
                             (resource has required_role && principal has roles &&
                              principal.roles.contains(resource.required_role)) };"#,
            only_actions: None,
        },
        Invariant {
            name: "consent-gate",
            statement: "accessing a pii-labeled resource the principal does not own is never allowed (via any action) without explicit consent",
            guard: r#"permit(principal, action, resource)
                      when { !(resource has sensitivity && resource.sensitivity == "pii") ||
                             resource.owner == principal ||
                             (context has consent && context.consent == true) };"#,
            only_actions: None,
        },
    ]
}

#[derive(Debug, Clone)]
pub struct ProofOutcome {
    pub name: String,
    pub statement: String,
    pub proven: bool,
    pub envs_checked: usize,
    pub counterexample: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("model error: {0}")]
    Model(String),
    #[error("guard policy error: {0}")]
    Guard(String),
    #[error("solver error (is cvc5 installed / CVC5 set?): {0}")]
    Solver(String),
    #[error("prove_all exceeded its {0}s bound — cvc5 may be hung or the model too large")]
    Timeout(u64),
}

/// The default bound for [`prove_all`]: without it, a pathological model or a
/// hung cvc5 process could tie up a prove-request worker indefinitely.
/// Operator-overridable — see `decern serve --cvc5-timeout-secs`.
pub const DEFAULT_PROVE_TIMEOUT_SECS: u64 = 120;

/// Prove every invariant in the suite against `model`, bounded by `timeout`.
/// `cvc5_path` overrides the CVC5 env var / PATH lookup.
///
/// On timeout the proving future is dropped and this call returns promptly, so
/// the caller's worker is freed — but the underlying cvc5 subprocess is NOT
/// force-killed: `cedar-policy-symcc`'s `LocalSolver` spawns it without
/// `kill_on_drop` and does not expose the child handle. The orphaned process
/// keeps running until it exits or is reaped. The bound is on the worker, not
/// the OS subprocess.
pub async fn prove_all(
    model: &Model,
    cvc5_path: Option<&Path>,
    timeout: Duration,
) -> Result<Vec<ProofOutcome>, ProofError> {
    match tokio::time::timeout(timeout, prove_all_inner(model, cvc5_path)).await {
        Ok(result) => result,
        Err(_) => Err(ProofError::Timeout(timeout.as_secs())),
    }
}

/// Build a cvc5-backed solver, honoring an explicit `cvc5_path` override without
/// mutating the process environment (which is `unsafe` under this crate's
/// `forbid(unsafe_code)`). Mirrors `LocalSolver::cvc5()`'s invocation exactly
/// (`--lang smt --tlimit=60000`) so an explicit path proves identically to the
/// PATH / `CVC5`-env default.
fn build_solver(cvc5_path: Option<&Path>) -> Result<LocalSolver, ProofError> {
    match cvc5_path {
        Some(p) => LocalSolver::from_command(tokio::process::Command::new(p).args([
            "--lang",
            "smt",
            "--tlimit=60000",
        ])),
        None => LocalSolver::cvc5(),
    }
    .map_err(|e| ProofError::Solver(e.to_string()))
}

async fn prove_all_inner(
    model: &Model,
    cvc5_path: Option<&Path>,
) -> Result<Vec<ProofOutcome>, ProofError> {
    let (schema, _warnings) = Schema::from_cedarschema_str(&model.schema)
        .map_err(|e| ProofError::Model(e.to_string()))?;
    let policies =
        PolicySet::from_str(&model.policies).map_err(|e| ProofError::Model(e.to_string()))?;

    let solver = build_solver(cvc5_path)?;
    let mut compiler =
        CedarSymCompiler::new(solver).map_err(|e| ProofError::Solver(e.to_string()))?;

    let mut outcomes = Vec::new();
    for inv in suite() {
        outcomes.push(prove_invariant_compiled(&mut compiler, &schema, &policies, &inv).await?);
    }
    Ok(outcomes)
}

/// Prove one invariant against already-parsed `schema`/`policies` on an existing
/// `compiler`. This is the shared per-invariant core: [`prove_all`] loops it over the
/// whole suite with a SINGLE solver (so the suite still spawns one cvc5, as its doc
/// describes), and [`prove_invariant`] calls it once.
async fn prove_invariant_compiled(
    compiler: &mut CedarSymCompiler<LocalSolver>,
    schema: &Schema,
    policies: &PolicySet,
    inv: &Invariant,
) -> Result<ProofOutcome, ProofError> {
    let guard = PolicySet::from_str(inv.guard).map_err(|e| ProofError::Guard(e.to_string()))?;

    let mut proven = true;
    let mut envs_checked = 0usize;
    let mut counterexample = None;

    for env in schema.request_envs() {
        if let Some(actions) = inv.only_actions {
            let env_action = env.action().to_string();
            if !actions
                .iter()
                .any(|a| env_action == format!("Action::\"{a}\""))
            {
                continue;
            }
        }
        let p = CompiledPolicySet::compile(policies, &env, schema)
            .map_err(|e| ProofError::Model(format!("compile policies: {e}")))?;
        let g = CompiledPolicySet::compile(&guard, &env, schema)
            .map_err(|e| ProofError::Guard(format!("compile guard [{}]: {e}", inv.name)))?;
        envs_checked += 1;

        let holds = compiler
            .check_implies_opt(&p, &g)
            .await
            .map_err(|e| ProofError::Solver(e.to_string()))?;

        if !holds {
            proven = false;
            let cex = compiler
                .check_implies_with_counterexample_opt(&p, &g)
                .await
                .map_err(|e| ProofError::Solver(e.to_string()))?;
            counterexample = cex.map(|env| format!("{}", env.request));
            break;
        }
    }

    // A proof over zero request environments is vacuous, not a proof:
    // an only_actions typo or schema drift must fail loudly.
    if envs_checked == 0 {
        proven = false;
        counterexample = Some(format!(
            "invariant matched no request environments (only_actions={:?}) — schema/action drift?",
            inv.only_actions
        ));
    }

    Ok(ProofOutcome {
        name: inv.name.to_owned(),
        statement: inv.statement.to_owned(),
        proven,
        envs_checked,
        counterexample,
    })
}

/// Prove a SINGLE named invariant against `model`, bounded by `timeout`. Unlike
/// [`prove_all`], this builds its own schema, policies, and solver, so it is not on
/// the suite's shared-solver path — it exists for targeted checks such as the
/// per-invariant negative-control tests. `cvc5_path` overrides the CVC5 env var / PATH.
pub async fn prove_invariant(
    model: &Model,
    inv: &Invariant,
    cvc5_path: Option<&Path>,
    timeout: Duration,
) -> Result<ProofOutcome, ProofError> {
    match tokio::time::timeout(timeout, async {
        let (schema, _warnings) = Schema::from_cedarschema_str(&model.schema)
            .map_err(|e| ProofError::Model(e.to_string()))?;
        let policies =
            PolicySet::from_str(&model.policies).map_err(|e| ProofError::Model(e.to_string()))?;
        let solver = build_solver(cvc5_path)?;
        let mut compiler =
            CedarSymCompiler::new(solver).map_err(|e| ProofError::Solver(e.to_string()))?;
        prove_invariant_compiled(&mut compiler, &schema, &policies, inv).await
    })
    .await
    {
        Ok(r) => r,
        Err(_) => Err(ProofError::Timeout(timeout.as_secs())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full SMT run — needs cvc5 on PATH or CVC5 set. Run via `just prove-test`.
    #[tokio::test]
    #[ignore = "requires cvc5"]
    async fn builtin_model_proves_all_invariants() {
        let outcomes = prove_all(
            &Model::builtin(),
            None,
            Duration::from_secs(DEFAULT_PROVE_TIMEOUT_SECS),
        )
        .await
        .unwrap();
        for o in &outcomes {
            assert!(o.proven, "{} REFUTED: {:?}", o.name, o.counterexample);
        }
        assert_eq!(outcomes.len(), 9);
    }

    /// The negative control: strip the invariant layer AND loosen a permit —
    /// the prover must catch the hole with a counterexample. This test proves
    /// the prover can actually fail.
    #[tokio::test]
    #[ignore = "requires cvc5"]
    async fn broken_model_is_refuted() {
        let mut model = Model::builtin();
        model.policies = r#"
            permit (principal, action == Action::"MoveMoney", resource)
            when { context.now <= principal.expiry };
        "#
        .to_owned();
        let outcomes = prove_all(
            &model,
            None,
            Duration::from_secs(DEFAULT_PROVE_TIMEOUT_SECS),
        )
        .await
        .unwrap();
        let money = outcomes.iter().find(|o| o.name == "money-gate").unwrap();
        assert!(
            !money.proven,
            "money-gate must be refuted for the broken model"
        );
        assert!(money.counterexample.is_some());
    }

    /// Regression: scope-gate is deliberately bounded to
    /// {Read, MoveMoney, AccessPII} via `only_actions`, not left unbounded. Before
    /// the fix, `only_actions` was unset, so ANY action a schema added — even one
    /// decern-proof has no scope-name convention for, like an MCP action — was
    /// enumerated by scope-gate too, found no matching permit in its guard, and
    /// REFUTED: a false "scope-gate is broken" signal for an operator extending
    /// the action set, not a real coverage gap.
    ///
    /// (a) proves the shipped, bounded scope-gate still PROVES on a model with an
    /// added MCP action, checking exactly the 3 request envs it claims to cover.
    /// (b) is the control: it re-runs the SAME guard text UNBOUNDED, the way
    /// pre-fix code did, directly via the SymCC primitives (not by touching
    /// `suite()`) — this must refute, or (a) isn't proving anything a broken
    /// scope-gate couldn't also pass.
    #[tokio::test]
    #[ignore = "requires cvc5"]
    async fn scope_gate_is_bounded_not_broken_by_an_added_mcp_action() {
        let mut model = Model::builtin();
        model.schema.push_str(
            r#"
action McpCallTool appliesTo {
  principal: [Principal],
  resource: [Resource],
  context: { now: Long }
};
"#,
        );
        model.policies.push_str(
            r#"
permit (
  principal,
  action == Action::"McpCallTool",
  resource
) when {
  principal.tenant == resource.tenant &&
  context.now <= principal.expiry &&
  principal.scopes.contains("read") &&
  (resource.owner == principal || principal.ancestors.contains(resource.owner))
};
"#,
        );

        let outcomes = prove_all(
            &model,
            None,
            Duration::from_secs(DEFAULT_PROVE_TIMEOUT_SECS),
        )
        .await
        .unwrap();
        let scope_gate = outcomes.iter().find(|o| o.name == "scope-gate").unwrap();
        assert!(
            scope_gate.proven,
            "scope-gate must stay PROVEN when a schema adds an action outside its \
             bound: {:?}",
            scope_gate.counterexample
        );
        assert_eq!(
            scope_gate.envs_checked, 3,
            "scope-gate must stay bounded to exactly {{Read, MoveMoney, AccessPII}} \
             — it must not silently start covering (or refuting on) McpCallTool"
        );

        let (schema, _) = Schema::from_cedarschema_str(&model.schema).unwrap();
        let policies = PolicySet::from_str(&model.policies).unwrap();
        let guard_text = suite()
            .into_iter()
            .find(|i| i.name == "scope-gate")
            .unwrap()
            .guard;
        let guard = PolicySet::from_str(guard_text).unwrap();
        let solver = LocalSolver::cvc5().unwrap();
        let mut compiler = CedarSymCompiler::new(solver).unwrap();
        let mcp_env = schema
            .request_envs()
            .find(|e| e.action().to_string() == "Action::\"McpCallTool\"")
            .expect("McpCallTool must be a request environment in the extended schema");
        let p = CompiledPolicySet::compile(&policies, &mcp_env, &schema).unwrap();
        let g = CompiledPolicySet::compile(&guard, &mcp_env, &schema).unwrap();
        let holds = compiler.check_implies_opt(&p, &g).await.unwrap();
        assert!(
            !holds,
            "control failed: the OLD unbounded check should refute for McpCallTool \
             (scope-gate's guard has no permit line for it) — if this holds, the \
             test's premise that pre-fix code really did refute is wrong"
        );
    }

    #[tokio::test]
    #[ignore = "requires cvc5"]
    async fn prove_all_times_out_instead_of_hanging() {
        let err = prove_all(&Model::builtin(), None, Duration::from_micros(1))
            .await
            .unwrap_err();
        assert!(
            matches!(err, ProofError::Timeout(_)),
            "expected ProofError::Timeout, got {err:?}"
        );
    }

    // ===================== per-invariant negative controls =====================
    // A green suite is only meaningful if each invariant is LOAD-BEARING: it must
    // REFUTE if its protection were removed. Each control mutates the SHIPPED policy
    // text (`authority.cedar`) so ONE invariant's guard is gone, then proves that
    // invariant refutes with a real counterexample. Mutating the shipped text (not a
    // synthetic model) is what ties the control to decern's actual enforcement: delete
    // F-money from the model and this catches it.

    /// (invariant, [(needle, replacement)]) — the mutation per invariant, shared by the
    /// single-invariant controls and the exactly-one-refutes matrix so both mutate
    /// identically. money/isolation/decay carry BOTH a `forbid` backstop and a
    /// business-permit conjunct (defense in depth): neutralize only one and the invariant
    /// stays PROVEN, so both are removed. The other four gates are forbid-only.
    type Mutation = (&'static str, Vec<(&'static str, &'static str)>);
    fn negative_control_mutations() -> Vec<Mutation> {
        vec![
            (
                "money-gate",
                vec![(
                    "context has human_approved && context.human_approved == true",
                    "true",
                )],
            ),
            (
                "isolation",
                vec![
                    ("principal.tenant != resource.tenant", "false"),
                    ("principal.tenant == resource.tenant", "true"),
                ],
            ),
            (
                "decay",
                vec![
                    ("context.now > principal.expiry", "false"),
                    ("context.now <= principal.expiry", "true"),
                ],
            ),
            (
                "attenuation-edge",
                vec![(
                    "(resource.owner == principal || principal.ancestors.contains(resource.owner))",
                    "true",
                )],
            ),
            (
                "scope-gate",
                vec![
                    (r#"principal.scopes.contains("read")"#, "true"),
                    (r#"principal.scopes.contains("move_money")"#, "true"),
                    (r#"principal.scopes.contains("pii:read")"#, "true"),
                ],
            ),
            // Structurally pinned to F-revoked's whole guard so a stray comment
            // mentioning `principal.revoked` can never be the thing we neutralize.
            (
                "revocation-gate",
                vec![("when { principal.revoked }", "when { false }")],
            ),
            (
                "residency-gate",
                vec![(
                    "!(principal has jurisdictions && principal.jurisdictions.contains(resource.residency))",
                    "false",
                )],
            ),
            (
                "role-gate",
                vec![(
                    "!(principal has roles && principal.roles.contains(resource.required_role))",
                    "false",
                )],
            ),
            (
                "consent-gate",
                vec![(r#"resource.sensitivity == "pii""#, "false")],
            ),
        ]
    }

    /// Builtin model with `inv_name`'s protection stripped from the shipped policy text.
    /// A missing needle means `authority.cedar` was reworded — fail loudly telling the
    /// maintainer to RE-DERIVE this control, so a policy edit never reads as "test broken".
    fn mutated_model(inv_name: &str) -> Model {
        let edits = negative_control_mutations()
            .into_iter()
            .find(|(n, _)| *n == inv_name)
            .unwrap_or_else(|| panic!("no negative-control mutation defined for {inv_name}"))
            .1;
        let mut model = Model::builtin();
        for (needle, repl) in edits {
            assert!(
                model.policies.contains(needle),
                "negative control [{inv_name}]: policy changed — re-derive this negative \
                 control. Expected needle absent from authority.cedar: {needle:?}"
            );
            model.policies = model.policies.replace(needle, repl);
        }
        model
    }

    /// A load-bearing invariant must REFUTE — with a real, non-vacuous counterexample —
    /// once its protection is removed from the shipped model.
    async fn assert_refutes_when_unguarded(inv_name: &str) {
        let model = mutated_model(inv_name);
        let inv = suite().into_iter().find(|i| i.name == inv_name).unwrap();
        let o = prove_invariant(
            &model,
            &inv,
            None,
            Duration::from_secs(DEFAULT_PROVE_TIMEOUT_SECS),
        )
        .await
        .unwrap();
        assert!(
            !o.proven,
            "{inv_name} must REFUTE once unguarded, but it PROVED"
        );
        // Not vacuous: the drift branch also sets proven=false + Some(cex), so
        // `envs_checked > 0` is what proves cvc5 actually found the hole.
        assert!(
            o.envs_checked > 0,
            "{inv_name}: zero request envs checked — vacuous, not a real refutation"
        );
        assert!(
            o.counterexample.is_some(),
            "{inv_name}: refuted without a counterexample"
        );
    }

    #[tokio::test]
    #[ignore = "requires cvc5"]
    async fn negative_control_money_gate_refutes_when_unguarded() {
        assert_refutes_when_unguarded("money-gate").await;
    }

    #[tokio::test]
    #[ignore = "requires cvc5"]
    async fn negative_control_isolation_refutes_when_unguarded() {
        assert_refutes_when_unguarded("isolation").await;
    }

    #[tokio::test]
    #[ignore = "requires cvc5"]
    async fn negative_control_decay_refutes_when_unguarded() {
        assert_refutes_when_unguarded("decay").await;
    }

    #[tokio::test]
    #[ignore = "requires cvc5"]
    async fn negative_control_attenuation_edge_refutes_when_unguarded() {
        assert_refutes_when_unguarded("attenuation-edge").await;
    }

    #[tokio::test]
    #[ignore = "requires cvc5"]
    async fn negative_control_scope_gate_refutes_when_unguarded() {
        assert_refutes_when_unguarded("scope-gate").await;
    }

    #[tokio::test]
    #[ignore = "requires cvc5"]
    async fn negative_control_revocation_gate_refutes_when_unguarded() {
        assert_refutes_when_unguarded("revocation-gate").await;
    }

    #[tokio::test]
    #[ignore = "requires cvc5"]
    async fn negative_control_residency_gate_refutes_when_unguarded() {
        assert_refutes_when_unguarded("residency-gate").await;
    }

    #[tokio::test]
    #[ignore = "requires cvc5"]
    async fn negative_control_role_gate_refutes_when_unguarded() {
        assert_refutes_when_unguarded("role-gate").await;
    }

    #[tokio::test]
    #[ignore = "requires cvc5"]
    async fn negative_control_consent_gate_refutes_when_unguarded() {
        assert_refutes_when_unguarded("consent-gate").await;
    }

    /// Cross-refutation is CHECKED, not assumed: each mutation must refute its OWN
    /// invariant and leave all eight others PROVEN. A sloppy mutation that also tripped
    /// an unrelated invariant would let a single-target control pass for the wrong reason
    /// — this proves every mutation is surgical.
    #[tokio::test]
    #[ignore = "requires cvc5"]
    async fn negative_controls_each_refute_exactly_one_invariant() {
        for (target, _) in negative_control_mutations() {
            let model = mutated_model(target);
            let outcomes = prove_all(
                &model,
                None,
                Duration::from_secs(DEFAULT_PROVE_TIMEOUT_SECS),
            )
            .await
            .unwrap();
            for o in &outcomes {
                if o.name == target {
                    assert!(!o.proven, "{target}: its own invariant must refute");
                    assert!(o.envs_checked > 0, "{target}: vacuous refutation (0 envs)");
                    assert!(
                        o.counterexample.is_some(),
                        "{target}: refuted without a counterexample"
                    );
                } else {
                    assert!(
                        o.proven,
                        "{target} mutation must NOT refute {} (cross-refutation) — cex: {:?}",
                        o.name, o.counterexample
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod doc_sync {
    // The README states the invariant COUNT. Keep it honest against the
    // machine-checked reality: if the proof suite grows or shrinks, this test fails
    // until the README is updated, so the count is pinned by a test rather than by
    // memory.
    #[test]
    fn readme_states_the_real_invariant_count() {
        let needle = format!("{} invariants", super::suite().len());
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md");
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("reading README.md for the invariant-count doc guard: {e}"));
        assert!(
            text.contains(&needle),
            "README.md must state the real invariant count (\"{needle}\"); update it when the proof suite changes"
        );
    }
}
