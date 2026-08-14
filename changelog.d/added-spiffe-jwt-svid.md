- **`decern-serve` can establish its caller from a SPIFFE JWT-SVID.**
  `--spiffe-trust-domain TRUST_DOMAIN=PATH` (repeatable) and `--spiffe-audience` make the
  deciding and mission-lifecycle routes require a JWT-SVID, presented as a `Bearer`
  credential per JWT-SVID §5.2 and verified against a JWK Set pinned at startup. Trust
  domains are matched exactly, so a domain that merely shares a prefix cannot present as a
  configured one; the bundle is filtered to `use: jwt-svid` keys and refused at boot if it
  carries none, an entry without a `kid`, or a key this build cannot verify with. Bundles
  are configured, never fetched, so this adds no TLS stack and no reliance on a SPIFFE
  control plane being reachable. **`ES256` only** — `RS*`/`PS*` would require a crate
  carrying an unpatched key-recovery advisory, so a SPIRE deployment issuing RSA SVIDs is
  not interoperable, which the docs state rather than soften. A verified `spiffe://…`
  identity is recorded as the caller and never minted into the authority graph: what a
  decision may be *about* is unchanged. `examples/spiffe/` runs the whole posture with no
  SPIRE daemon. Authored by @anivar.
- **The four caller postures are now one clap group.** Naming two at once is a startup
  failure rather than a matrix of `conflicts_with` pairs that has to grow with each
  posture. Authored by @anivar.
- **A SPIFFE caller is a workload, and binds to itself.** Like a signed-request agent, a
  verified `spiffe://…` identity may only name itself as AuthZEN `subject`, mission
  `approver`, stored approver on terminate, and directory principal, unless it is listed
  in `--pep`. A mismatch is `403 caller_mismatch`. Without this the second posture would
  have reopened the escalation the first one closed. Authored by @anivar.
