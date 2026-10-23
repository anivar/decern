- **The README, the website and the Postgres store README say what `--sharded` needs.** Each now
  states that `--sharded` requires `--key` and that `decern verify --sharded` audits a directory
  store only, since a Postgres head store has no `decern verify` path; both READMEs also state
  that a store whose records a key it was not given signed refuses to start, and the README's
  Known-limitations entry on the file head store says when the ledger key is checked, and its
  pointer to the release's known limits no longer lists items from an older release. The website
  drops its version badge, so it carries no version string and no release step has to move one.
  Authored by @anivar.
