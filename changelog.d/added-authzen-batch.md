- **AuthZEN Access Evaluations.** `POST /access/v1/evaluations` decides several evaluations in
  one exchange (AuthZEN 1.0 §7): top-level `subject`, `action`, `resource` and `context` are
  defaults an item replaces whole; `options.evaluations_semantic` picks `execute_all`,
  `deny_on_first_deny` or `permit_on_first_permit`; answers come back in request order. Every
  evaluated item is admitted, decided and recorded as a single evaluation is, before the batch
  is served — as one durable step on the single-file ledger; an item that is not an evaluation,
  or that this server refuses, is `decision: false` with `context.error` `{status, code,
  message}` and, having decided nothing, is not recorded. Without items the endpoint is the
  single evaluation. At most 1000 items. Discovery advertises `access_evaluations_endpoint`.
  The certification scenario's Batch Core and Batch Properties tests run against
  `examples/authzen-certification/model`. Authored by @anivar.
