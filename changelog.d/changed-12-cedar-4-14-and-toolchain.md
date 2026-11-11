- **The kernel decides with Cedar 4.14.0, and the proofs compile through `cedar-policy-symcc`
  0.8.0.** Both are exact pins and move together; 0.6.0 pinned 4.13.0 and 0.7.0. A crate that
  depends on a decern library and on `cedar-policy` must name `=4.14.0`. A build from source needs
  Rust 1.99, the toolchain `rust-toolchain.toml` pins, where 0.6.0 pinned 1.97. Authored by @anivar.
