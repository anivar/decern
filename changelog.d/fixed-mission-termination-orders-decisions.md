- **No Allow under a Mission is recorded after the Mission's termination.** A decision bound to a
  live Mission, then recorded after the Mission was terminated through the same host, was recorded
  and served as the Allow it was evaluated as. The decision is now settled under the ledger's lock
  just before its record lands: one whose Mission was terminated is recorded and answered as a Deny
  with that reason. A Mission terminated at or past its expiry now keeps its termination on record
  for the 30 days a termination is kept past its expiry, rather than being pruned at once, so the
  rule holds then too and `GET /mission/v1/{s256}` reports it terminated. In a `deny_on_first_deny`
  or `permit_on_first_permit` batch each item is recorded before the next is evaluated and the
  semantic follows the decision as recorded, so an item settled to a Deny stops the first and does
  not end the second; `execute_all` records the whole batch as one step on the single-file ledger,
  where the two short-circuit modes record, and sync, one item per step. The order holds on one
  host; under a Postgres store each host has its own Mission registry. Authored by @anivar.
