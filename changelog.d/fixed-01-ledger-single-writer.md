- **A second process can no longer fork the single-file ledger.** Two `decern-serve` processes
  pointed at one `--ledger` file both served decisions, each chaining from the same record, so
  the ledger stopped verifying and the next start refused it. Opening a single-file ledger for
  writing now takes an exclusive lock before anything reads the log, and a second writer is
  refused at startup. On Unix the lock is on the ledger file itself, so it holds through any
  path, symbolic or hard link, or mount; on Windows it is a `<ledger>.lock` file beside the
  ledger's canonical path, which a hard link to the ledger, or a link made before the ledger
  existed, does not share. On a network filesystem the lock holds only where the filesystem
  honours it. Readers such as `decern verify` take no lock. A deployment that runs a second
  replica on the same file, or starts the new process before the old one exits, is now refused
  rather than forked. On Unix a child process started while a ledger is open shares its lock
  until it starts its own program, so an open in that moment is refused as a second writer.
  `Ledger::open_anchored` now refuses a ledger whose file is gone when its
  anchor counts a record, as it refuses a truncation; it started a new ledger.
  Authored by @anivar.
