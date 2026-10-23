- **A retired ledger key may not sign after its successor.** Verification refuses a record whose
  key had already been followed by another key in the same log, where it accepted a record under
  any key in the ring at any position. A record is attributed to the key its signature verifies
  under, so removing its `kid` does not get past the rule. `decern verify`, `decern-serve` at
  startup and the library apply it; `decern-serve` refuses to start on a `--key` another key has
  already followed, and the library refuses to open a ledger with one or to rotate back to one, so
  `Ledger::rotate` now returns a `Result`. `verify_evidence_bundle` checks each record under the
  key its `kid` names and applies the rule within the bundle's span, where it accepted a record
  under any pinned key. The rule holds within one log: across a single-file or segmented ledger,
  and shard by shard in a sharded store, where a retired key can still sign a shard its successor
  has not signed. It covers records only: a tree head is checked against the keys given, whichever
  of them signed it, and records removed from the end of a log show only against a tree head kept
  where the operator cannot reach. A ledger `decern-serve` signed with one key is unaffected. A
  shard that replicas extended under different keys at once now fails even with every key given:
  that happens to a store that replicas of a release before 0.6.0 extended without `--key`, and to
  one that 0.6.0 replicas started together on an empty store under different keys. A library
  caller that rotated back to an earlier key wrote a ledger this refuses. Authored by @anivar.
