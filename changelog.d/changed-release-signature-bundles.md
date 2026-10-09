- **Release assets are signed as Sigstore bundles.** Each binary and `SHA256SUMS` now ships
  with a `<file>.sigstore.json` carrying the signature, the signing certificate and the
  transparency-log entry, written by cosign 3, in place of the `.sig` and `.pem` pair earlier
  releases carried. `SECURITY.md` shows the `cosign verify-blob --bundle` command and the
  identity to check against; older releases verify as before. Authored by @anivar.
