- **The ledger stops recording after a write fails part-way.** When a write failed (a full
  disk, for example), that request was answered `503`, but the next appends went into the file
  behind the partial record. Decisions were served with `200` into a ledger that no longer
  verified, and the server then refused to start. Now, once a write fails after bytes may have
  reached the file, the ledger refuses every append until it is reopened, so each later decision
  is a `503` until a restart, and the restart trims the partial record. The sharded ledger
  writes through its head store, a different path this change does not touch. Authored by @anivar.
