- **Docs corrected where they overstated or named what is not there.** The README no longer
  calls the sharded ledger's file head store Unix-only: its lock is `flock` on Unix and
  `LockFileEx` on Windows, and on Windows its files are not written owner-only and a rename is
  not synced to its directory. `DEPENDENCIES.md` gives the pins the build uses,
  `cedar-policy =4.13.0` and `cedar-policy-symcc =0.7.0`. The 0.4.0 known limits said the AAuth
  posture followed draft `-10`, which that release had moved past; they name its replay limit
  instead. `decern-proof` no longer points at a `decern serve` flag that does not exist, and
  says what bounds a cvc5 left running by a timeout: cvc5's own 60-second `--tlimit`. The JCS
  module states that `-0` and `0` canonicalize and digest alike, where RFC 8785 erratum 7920
  asks a parser to refuse `-0`. Authored by @anivar.
