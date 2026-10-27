- **No Allow under a Mission is recorded after the Mission's termination.** A decision bound
  to a live Mission, then recorded after the Mission was terminated through the same host, was
  recorded and served as the Allow it was evaluated as. The decision is now settled under the
  ledger's lock just before its record lands: one whose Mission was terminated is recorded and
  answered as a Deny with that reason. A Mission terminated at or past its expiry now keeps its
  termination on record for the 30 days a termination is kept past its expiry, rather than
  being pruned at once, so the rule holds then too and `GET /mission/v1/{s256}` reports it
  terminated. In a batch the semantic is
  applied to each decision as evaluated, and an item settled to a Deny at the record is still
  answered as one. The order holds on one host; under a Postgres store each host has its own
  Mission registry.
  Authored by @anivar.
