- **A ledger is extended only by the key that signed it.** `--sharded` without `--key` is refused:
  the shared head store was signed under a fresh ephemeral key on every restart, so each replica's
  records verified under a different key and `/pubkey` only ever named the latest. At boot every
  shard is verified under the key `--key` holds, chain and every signature, one signature check per
  record, as a single-file open already was; a record another key signed refuses the boot, naming
  both key ids where the record names its key. The check runs at boot only: a store with no shards
  boots under any key, so two replicas started at once on an empty store under different keys both
  boot and the store then verifies under neither; start the first replica alone, or give every
  replica the same key before any starts. A shard another replica creates later is checked at the
  next restart. A single-file ledger with records already refused a different key; the refusal now
  names both key ids, and an ephemeral key, or a `--key` file that does not exist, is refused before
  anything is written. An empty ledger file is a new ledger. The startup line marks an ephemeral key
  `(ephemeral)`. Where a Postgres head store already holds shards, a `--key` file that does not
  exist is still created before the refusal. Authored by @anivar.
