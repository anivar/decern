- **A direct test for the `asserted_by` context strip.** `mission_entry` already stripped
  a caller-supplied `context.asserted_by` before recording, but no test called it with
  one — there is no live path through `mission_approve`/`mission_terminate` today that
  reaches it. `mission_entry_strips_a_context_supplied_asserted_by` calls the function
  directly to prove the defense-in-depth fires, so a future change that makes the path
  reachable does not silently lose the guarantee.
