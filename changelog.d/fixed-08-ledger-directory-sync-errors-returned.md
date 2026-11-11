- **A failed directory sync is the anchor's or the manifest's error, never an `Ok`.** On Unix the
  directory open and the sync return their error, so a crash cannot take back an anchor or a
  rollover the caller was told had landed. Both writes discarded that result. A segment rollover
  that fails after its manifest landed stops the ledger, as a half-written record does, until it is
  reopened; one that fails before it is retried on the next append, as before. On a target that is
  not Unix, the Windows build, the directory sync is skipped, as it is for the store's files.
  Authored by @anivar.
