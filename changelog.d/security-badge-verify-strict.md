- **Agent Badge verification uses `verify_strict`.** The path that admits a principal
  into the authority graph now rejects small-order keys and non-canonical signatures,
  matching the ledger and the caller postures. A badge that only passed the cofactorless
  equation is refused. Authored by @anivar.
