- **Docs name all five caller postures, and the release steps as they run.** The README,
  `ARCHITECTURE.md`, the CLI reference, both diagrams and the website described four postures;
  they now include AAuth, and the README's known limits say the AAuth posture does not yet meet
  draft-hardt-oauth-aauth-protocol-11. `SECURITY.md` says the proofs cover the Cedar model's
  symbolic input space, where it said the entire input space. `RELEASES.md` says which version
  fields each publish workflow checks and which none does, lists the crates.io workflow, says
  the SBOMs are not signed, and points to `SECURITY.md` for verifying a release's Sigstore
  bundles. `scripts/changelog.sh
  --preview` exits 0 when the last fragment ends in a newline, where it exited 1. Authored by
  @anivar.
