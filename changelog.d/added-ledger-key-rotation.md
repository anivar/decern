- **The ledger signing key can be rotated without starting a new ledger.** `decern-serve
  --retired-key <HEX>`, repeatable, names by its public key a key the deployment rotated away
  from, and `--key` then names a key file made beforehand. Restarted on the new key with the old
  one retired, the server extends the ledger and every record still verifies. `GET /pubkey` keeps
  `kid`, the key signing now, and adds `keys`: the retired keys in the order given, then `kid`.
  `decern verify` and `decern explain` take `--pubkey` once per key, and `decern verify --ledger`
  with `--pubkey` prints each signing key with the record it started at. A sharded deployment
  rotates every replica together: a replica still on the old key refuses to record into a shard
  the new key has signed and answers `503` until it is restarted on the new key; `/healthz` does
  not report it. The same check makes two replicas started together on an empty store under
  different keys each answer `503` for a shard the other wrote first, where both recorded into it
  before. Authored by @anivar.
