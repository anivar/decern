- **`decern-serve` can require proof of possession on every request, not just a bearer
  token.** `--signed-agent-key` (repeatable, `ID=HEX`) and `--signed-audience` make the
  deciding and mission-lifecycle routes require an RFC 9421 HTTP Message Signature over
  `@method`, `@authority`, `@path` and `signature-key`, bound to an RFC 7800 `cnf.jwk`
  claim matching a key configured here for the claimed agent identifier. Unlike bearer
  validation, a leaked token alone is not enough here: it must also be signed, per
  request, by the key it is bound to. Verification is against configured keys only —
  no live key discovery, no outbound HTTP client — and an agent identifier with no
  configured key is refused before any cryptography runs. Conflicts with
  `--bearer-issuer`/`--trust-proxy`; one posture is required to start. Authored by
  @anivar.
