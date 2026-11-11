- **The ES256 verification path builds on patched constant-time crates.** `crypto-bigint` moves
  to 0.7.8 and `ctutils` to 0.4.5, for timing variability in operations meant to be constant-time
  ([RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387)) and non-constant-time mask
  generation ([RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385)). Both arrive
  through `p256`, which `decern-serve` uses only to verify ES256 SPIFFE JWT-SVIDs, a public-key
  operation; nothing in decern holds a P-256 private key. Authored by @anivar.
