- **A ledger path that names the key file is refused, and a new key file is synced to disk.**
  `decern-serve --ledger k --key k` booted and truncated the key to nothing: the ledger trims an
  unterminated last line, and a key file has none, so the process went on signing with a key no
  longer on disk. The boot now refuses a `--ledger` or `--missions` that names the key file, by
  any spelling of its path or a link to it, and compares `--missions` with `--ledger` the same
  way. The ledger refuses to truncate an unterminated last line that does not begin a record, so
  a file that is not a ledger is never cut. A key file created at boot is synced, with its
  directory, before anything is signed with it. Authored by @anivar.
