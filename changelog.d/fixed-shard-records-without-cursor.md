- **A shard file holding records but no head cursor is refused.** The file head store listed a shard
  only when its cursor was set, so a shard file whose cursor had been removed was neither verified
  at boot nor counted as history: a second key could extend it, and the next append started the
  chain again at sequence 0 beside the old records. Such a file is now refused wherever it is read,
  by `decern-serve` at boot before anything is written and by `decern verify --sharded`, as an
  altered store. Authored by @anivar.
