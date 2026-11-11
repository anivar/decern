- **A head store's cursor carries the keys that signed its shard.** `HeadCursor` gains `signers:
  Option<ShardSigners>`, so code that builds a `HeadCursor` adds the field; `None` is what a store
  that does not keep them returns. `LedgerHeadStore` gains `with_shard_head`, `has_failed` and
  `is_stalled`, each with a default, so an existing implementation compiles. `LedgerError` gains
  `KeySuperseded`. Added beside them: `Ledger::prefix`, `read_verified_with_keys`,
  `merkle_leaves_with_keys`, `verify_sharded_dir_with_keys`, `ShardedLedger::append_revised`,
  `Directory::revoked` and `decern_identity::mission::HUMAN_KIND`. Authored by @anivar.
