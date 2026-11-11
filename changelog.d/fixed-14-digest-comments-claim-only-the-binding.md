- **The parameter digest's documentation claims the binding, not the execution.** It binds a record
  to the arguments decided, so whoever holds the arguments an execution used can tell whether they
  are the ones on record. The comments said the digest "closes the TOCTOU gap between authorized and
  executed", which the ledger cannot see; a PEP that acts on other arguments is caught only by that
  comparison. Authored by @anivar.
