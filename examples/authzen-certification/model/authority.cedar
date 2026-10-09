// decern AuthZEN certification model — policies.
//
// The fixture of the Authorization API 1.0 certification scenario
// (openid/authzen, certification/authorization-api-1_0-scenario.md, "Required Fixture"),
// expressed in decern's vocabulary. The invariant layer below is the built-in model's,
// verbatim, so `decern prove --model examples/authzen-certification/model` proves the
// same nine statements over this model. The permits are the fixture's rules 1–4:
// alice owns both records and may read, write and delete them; bob is a viewer of
// record-1 and may read it, and nothing else.

// ============================ BUSINESS LAYER ================================

@id("P-read")
permit (
  principal,
  action == Action::"read",
  resource
) when {
  principal.tenant == resource.tenant &&
  context.now <= principal.expiry &&
  principal.scopes.contains("read") &&
  (resource.owner == principal ||
   principal.ancestors.contains(resource.owner) ||
   (resource has viewers && resource.viewers.contains(principal)))
};

@id("P-write")
permit (
  principal,
  action == Action::"write",
  resource
) when {
  principal.tenant == resource.tenant &&
  context.now <= principal.expiry &&
  principal.scopes.contains("write") &&
  (resource.owner == principal || principal.ancestors.contains(resource.owner))
};

@id("P-delete")
permit (
  principal,
  action == Action::"delete",
  resource
) when {
  principal.tenant == resource.tenant &&
  context.now <= principal.expiry &&
  principal.scopes.contains("delete") &&
  (resource.owner == principal || principal.ancestors.contains(resource.owner))
};

// ============================ INVARIANT LAYER ===============================
// Verbatim from the built-in model. A permit added above cannot escape these.

@id("F-revoked")
forbid (principal, action, resource)
when { principal.revoked };

@id("F-residency")
forbid (principal, action, resource)
when {
  resource has residency &&
  !(principal has jurisdictions && principal.jurisdictions.contains(resource.residency))
};

@id("F-role")
forbid (principal, action, resource)
when {
  resource has required_role &&
  !(principal has roles && principal.roles.contains(resource.required_role))
};

@id("F-tenant")
forbid (principal, action, resource)
when { principal.tenant != resource.tenant };

@id("F-decay")
forbid (principal, action, resource)
when { context.now > principal.expiry };

@id("F-money")
forbid (principal, action == Action::"MoveMoney", resource)
unless { context has human_approved && context.human_approved == true };

@id("F-consent")
forbid (principal, action, resource)
when {
  resource has sensitivity && resource.sensitivity == "pii" &&
  resource.owner != principal
}
unless { context has consent && context.consent == true };
