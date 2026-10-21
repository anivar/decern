- **A caller bound to itself may not name another party as the decision subject.**
  `context.decision_subject` is the handle the open subject-side audit route is keyed by, and a
  workload posture caller could name any handle, so a record it asserted attached to another
  party's audit view with nothing to tell planted from genuine. The handle now binds as
  `subject.id` does: a workload not listed in `--pep` may name only itself, which the record then
  drops as redundant, and any other handle is `403 caller_mismatch` before anything is evaluated or
  recorded, on the single evaluation, on every batch item, defaults included, and on the searches.
  Bearer and `--trust-proxy` callers are unchanged, as they are for `subject.id`. Authored by
  @anivar.
