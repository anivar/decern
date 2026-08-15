- **The ledger signing key is no longer written world-readable.** `decern-serve --key`
  created the seed file with `std::fs::write`, which uses the process umask — commonly
  `0644`. That key signs every record and every tree head, so a readable copy on a shared
  host was enough to forge history that verifies. The server now routes through
  `decern-crypto`'s existing key discipline: created at `0600`, never overwritten, and a
  key that is group- or other-readable is refused rather than loaded silently, so a file
  opened up by a later `chmod` fails closed. The seed is zeroized on both paths. Existing
  key files keep working unchanged, provided their permissions are not open. Authored by
  @anivar.
