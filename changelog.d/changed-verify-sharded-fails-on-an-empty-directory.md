- **`decern verify --sharded` fails on a directory that holds no shard.** It printed `no shards
  found` and exited 0, so a wrong path, or a store with no record yet, passed a check whose exit
  code is read as "verified". It now exits non-zero and says nothing was verified. A script that
  verifies a store before its first decision fails until the store holds one. Authored by
  @anivar.
