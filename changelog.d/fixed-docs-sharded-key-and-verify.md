- **The README, the website and the Postgres store README say what `--sharded` needs.** Each
  now states that `--sharded` requires `--key`, that a store whose records another key signed
  refuses to start, and that `decern verify --sharded` audits a directory store only, since a
  Postgres head store has no `decern verify` path; the README's Known-limitations entry on the
  file head store carries the boot-only key check, and its pointer to the release's known limits
  no longer lists items from an older release. Authored by @anivar.
