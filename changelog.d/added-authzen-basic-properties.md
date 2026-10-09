- **AuthZEN Basic Properties.** What a PEP says about a party — `subject.properties`,
  `resource.properties`, `action.properties` — reaches the policies as `context.subject`,
  `context.resource` and `context.action`, where the action's schema declares it; the rest is
  dropped before evaluation, at every level, and never recorded. Only a caller bound as a PEP
  (`--pep`, a bearer caller, `--trust-proxy`) may describe a party; a workload bound to itself
  gets `403 caller_mismatch`, and those three context keys are reserved so there is no second
  way in. The certification scenario's Basic Properties tests (rules 5–8) run against
  `examples/authzen-certification/model`. Authored by @anivar.
