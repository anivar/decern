// decern AuthZEN certification model — policies.
//
// The fixture of the Authorization API 1.0 certification scenario
// (openid/authzen, certification/authorization-api-1_0-scenario.md, "Required Fixture"),
// expressed in decern's vocabulary. The invariant layer below is the built-in model's,
// verbatim, so `decern prove --model examples/authzen-certification/model` proves the
// same nine statements over this model. The permits are the fixture's rules 1–8: alice
// owns both records and may read, write and (softly) delete them; bob is a viewer of both
// and may read them; nobody writes an archived record, except a viewer the PEP describes
// as an admin. Request properties are read from `context.subject`, `context.resource` and
// `context.action`, where the schema declares them. Every permit keeps to an edge the
// authority graph records — ownership, a delegation ancestor, or a viewer relation — which
// is what the attenuation-edge proof holds over this model too.

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

// Rules 2, 4 and 5: an owner writes, unless the PEP describes the record as archived.
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
} unless {
  context has resource && context.resource has status && context.resource.status == "archived"
};

// Rule 6: a viewer the PEP describes as an admin writes an archived record.
@id("P-write-archived-as-admin")
permit (
  principal,
  action == Action::"write",
  resource
) when {
  principal.tenant == resource.tenant &&
  context.now <= principal.expiry &&
  principal.scopes.contains("write") &&
  resource has viewers && resource.viewers.contains(principal) &&
  context has subject && context.subject has role && context.subject.role == "admin" &&
  context has resource && context.resource has status && context.resource.status == "archived"
};

// Rules 7 and 8: an owner deletes softly; a hard delete is denied.
@id("P-delete")
permit (
  principal,
  action == Action::"delete",
  resource
) when {
  principal.tenant == resource.tenant &&
  context.now <= principal.expiry &&
  principal.scopes.contains("delete") &&
  (resource.owner == principal || principal.ancestors.contains(resource.owner)) &&
  context has action && context.action has soft && context.action.soft == true
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
