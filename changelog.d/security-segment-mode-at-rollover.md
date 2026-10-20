- **A segment created at rollover is owner-only.** A segmented ledger (`Ledger::open_segmented`)
  created each new segment with the process's default mode, `0644` under the common umask, so
  the records it collected were readable by group and other until the next rollover sealed it
  or the ledger was reopened. Every segment is now created `0600` on Unix; the next rollover
  still seals it `0400`, and a reopen tightens an active segment created before this change,
  as it already did. The manifest beside the segments, which names them with their sequence
  ranges and open times and holds no records, keeps the default mode. Only a segmented ledger
  creates segments: `decern-serve` never opens one (a single file, or a head store under
  `--sharded`), and `decern verify` and `decern explain` read a segmented directory without
  writing to it, so neither was affected. On
  Windows the ledger's files are not written owner-only. Authored by @anivar.
