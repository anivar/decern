- **`decern-serve` can establish its caller from an AAuth agent token.** `--aauth-provider
  ISS=PATH` (repeatable) and `--aauth-audience` make the deciding and mission-lifecycle routes
  require an `aa-agent+jwt` presented per `draft-hardt-oauth-aauth-protocol` in
  `Signature-Key: sig=jwt; jwt="…"`, with the request signed under RFC 9421 by the key the
  token's RFC 7800 `cnf` confirms. This serves the draft's **identity-based access** mode,
  where the resource applies its own policy to a verified agent identity; the PS-asserted and
  federated modes need a Person Server, which decern does not implement. Two profile decisions
  are stated rather than implied. Providers are **pinned, never discovered** — the draft says
  to fetch the issuer's JWKS, and this deployment instead checks that `dwk` names that document
  and selects from a key set configured at startup, which the draft contemplates where it notes
  a resource pre-caching provider keys does not need the fetch; an agent from a provider this
  deployment was never told about is refused. And **`content-digest` is required on a bodied
  request**, which the draft's example component list does not carry: every AuthZEN evaluation
  is a POST, and RFC 9421 §1.4 assigns component requirements to the profile, so an agent that
  does not sign the digest is refused rather than allowing one captured signature to authorize
  any body at that path. `EdDSA` only. Unlike the signed-request posture, the agent token's own
  signature is verified against its provider's key, because here the token is the provider's
  assertion about which key the agent holds. A verified agent is a **workload** and may name
  only itself unless listed in `--pep`. `jti` is required and shape-checked but not used for
  replay detection — there is no nonce cache — and `parent_agent` is shape-checked and never
  reaches the kernel. Authored by @anivar.
