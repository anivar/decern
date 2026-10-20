- **A ledger is extended only by the key that signed it.** `--sharded` without `--key` is refused:
  the shared head store was signed under a fresh ephemeral key on every restart, so each
  replica's records verified under a different key and `/pubkey` only ever named the latest. At
  boot each shard's last record must have been signed by the key `--key` holds; a different key
  is refused naming both key ids. A single-file ledger already refused a different key; the
  refusal now names both key ids, and an ephemeral key, or a `--key` file that does not exist, is
  refused before anything is written where the ledger already exists. The startup line marks an
  ephemeral key `(ephemeral)`. Where a Postgres head store already holds shards, a `--key` file
  that does not exist is still created before the refusal. Authored by @anivar.
