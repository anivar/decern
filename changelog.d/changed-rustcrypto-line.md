- **The RustCrypto line moves together: ed25519-dalek 3.0, p256 0.14, sha2 0.11, getrandom 0.4
  and, through them, signature 3.0.** Nothing a caller sees changes: key, signature and digest
  formats are the same bytes, the test suite (which signs with fixed keys) passes unchanged, and
  the proofs are unaffected. ed25519-dalek, p256, sha2 and signature now resolve to one version
  each where the tree carried two; getrandom still has the older versions `ring` and
  `rand_core` pin beside it. Authored by @anivar.
