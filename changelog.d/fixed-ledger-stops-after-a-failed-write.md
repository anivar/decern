- **The ledger stops recording after a write error.** When a write failed (a full disk, for
  example), that request was answered `503`, but the next appends went into the file behind the
  partial record. Decisions were served with `200` into a ledger that no longer verified, and
  the server then refused to start. Now a write, flush or sync error on the single-file ledger
  makes it refuse every append until it is reopened, so each later decision is a `503`, and
  `/healthz` answers `503` so a liveness probe restarts the server. The restart trims an
  unterminated record; a record written in full before its sync failed is kept, though its
  request was answered `503`. The sharded ledger writes through its head store, a different
  path this change does not touch. Authored by @anivar.
