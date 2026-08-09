// decern authority model — policies v2
// Cedar is default-deny: no matching permit => Deny.
// Two layers:
//   BUSINESS LAYER (permits)  — who may do what, under the standard conditions.
//   INVARIANT LAYER (forbids) — backstops that survive any future permit:
//     Cedar `forbid` overrides `permit`, so a permit added later without the
//     decay/tenant/approval guards is STILL bounded by them. `decern prove`
//     certifies this structurally, unbounded, via SMT.

// ============================ BUSINESS LAYER ================================

// P-read: owner or delegated principal may Read, in-tenant, in-window, in-scope.
@id("P-read")
permit (
  principal,
  action == Action::"Read",
  resource
) when {
  principal.tenant == resource.tenant &&
  context.now <= principal.expiry &&
  principal.scopes.contains("read") &&
  (resource.owner == principal || principal.ancestors.contains(resource.owner))
};

// P-move: as above, plus the explicit, fail-closed human approval gate.
@id("P-move")
permit (
  principal,
  action == Action::"MoveMoney",
  resource
) when {
  principal.tenant == resource.tenant &&
  context has human_approved && context.human_approved == true &&
  context.now <= principal.expiry &&
  principal.scopes.contains("move_money") &&
  (resource.owner == principal || principal.ancestors.contains(resource.owner))
};

// P-pii: CIAM read of a customer's protected data. Same owner-or-delegate
// edge and window/scope conditions; the consent backstop (F-consent) then
// requires the customer's consent whenever the accessor is not the owner.
@id("P-pii")
permit (
  principal,
  action == Action::"AccessPII",
  resource
) when {
  principal.tenant == resource.tenant &&
  context.now <= principal.expiry &&
  principal.scopes.contains("pii:read") &&
  (resource.owner == principal || principal.ancestors.contains(resource.owner))
};

// P-rebac: ReBAC / Zanzibar visibility. A principal explicitly listed as a
// viewer of a resource may Read it, even without an ownership or delegation
// edge — this is the Trust-graph "who may see what". It is an ADDITIONAL permit
// only: it still requires the read scope and stays in-tenant / in-window, and
// every forbid below (tenant, decay, revocation, consent) overrides it. So a
// relation tuple can never cross a tenant, expose PII without consent, act past
// expiry, or survive revocation. `decern prove` certifies those bounds unbounded.
@id("P-rebac")
permit (
  principal,
  action == Action::"Read",
  resource
) when {
  principal.tenant == resource.tenant &&
  context.now <= principal.expiry &&
  principal.scopes.contains("read") &&
  resource has viewers && resource.viewers.contains(principal)
};

// ============================ INVARIANT LAYER ===============================

// F-revoked: a revoked principal (directly, or via a revoked authority
// ancestor — the kernel propagates it down the chain) is denied everything.
// This is the kill-switch: revoke upstream, and the whole delegation subtree
// fails its next decision.
@id("F-revoked")
forbid (principal, action, resource)
when { principal.revoked };

// F-residency: DATA-scoped data-residency backstop. Accessing a resource
// labeled with a `residency` jurisdiction is always forbidden unless the
// principal is cleared for that jurisdiction — via ANY action, so no verb
// bypasses it. Like consent, the protection attaches to the DATA, and the
// clearance set is attenuated by construction (a delegate's ⊆ its delegator's).
@id("F-residency")
forbid (principal, action, resource)
when {
  resource has residency &&
  !(principal has jurisdictions && principal.jurisdictions.contains(resource.residency))
};

// F-role: DATA-scoped RBAC backstop. Accessing a resource that REQUIRES a role is
// always forbidden unless the principal's `roles` includes it — via ANY action, so no
// verb bypasses it. Like F-residency/F-consent the protection attaches to the DATA, and
// the role set is attenuated by construction (a delegate's roles ⊆ its delegator's,
// enforced at load), so a delegate can never present a role its delegator lacked. This
// forbid survives any future permit, and `decern prove` certifies it (role-gate invariant).
@id("F-role")
forbid (principal, action, resource)
when {
  resource has required_role &&
  !(principal has roles && principal.roles.contains(resource.required_role))
};

// F-tenant: nothing ever crosses a tenant boundary.
@id("F-tenant")
forbid (principal, action, resource)
when { principal.tenant != resource.tenant };

// F-decay: nothing is allowed past the principal's expiry.
@id("F-decay")
forbid (principal, action, resource)
when { context.now > principal.expiry };

// F-money: MoveMoney without explicit human approval is always forbidden.
@id("F-money")
forbid (principal, action == Action::"MoveMoney", resource)
unless { context has human_approved && context.human_approved == true };

// F-consent: CIAM keystone, DATA-scoped. Accessing PII-labeled data the
// accessor does NOT own (an agent acting on behalf of a customer) is always
// forbidden without that customer's explicit consent — via ANY action, so the
// verb chosen (Read, AccessPII, …) cannot bypass it. Self-access (owner ==
// principal) is exempt. Like F-money, this forbid survives any future permit,
// and `decern prove` certifies it. The protection attaches to the data.
@id("F-consent")
forbid (principal, action, resource)
when {
  resource has sensitivity && resource.sensitivity == "pii" &&
  resource.owner != principal
}
unless { context has consent && context.consent == true };
