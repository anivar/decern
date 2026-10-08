- **The kernel and the proof harness move to cedar-policy 4.13.0 and cedar-policy-symcc 0.7.0.**
  The nine invariants and the negative controls prove unchanged on the built-in model. The
  `rustls` the optional `decern-store-postgres` crate pulls in moves to 0.23.45, which closes
  RUSTSEC-2026-0285; the default build carries no TLS stack and was never affected. Authored by
  @anivar.
