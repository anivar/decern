- **The AAuth posture verifies draft-hardt-oauth-aauth-protocol-11's signature profile.** An
  agent token's header must name `alg: Ed25519`; the polymorphic `EdDSA` that 0.6 required is
  refused, so an agent built to that shape is refused until it moves. Every key carries a
  fully-specified `alg` consistent with `kty` and `crv`: the key `cnf` confirms is refused
  without one. An `--aauth-provider` key set keeps only the members that name one, carry a
  `kid` and have no `use` other than `sig`, skips the rest, and is refused at startup if none
  is left or two share a `kid`. The token is the `Signature-Key` member under the label the
  signature carries, read as a structured-field dictionary, where it was the member `sig`
  beside a signature labelled `sig1`; a second `jwt`-scheme member is refused. The signature
  must cover the required components in any order and may cover further header fields; an
  `alg` parameter is not read, `nonce` and `tag` are refused, and `expires` is honoured.
  `created` may be up to 60 seconds either side of the server's clock, and an agent token's
  `iat` up to 60 seconds ahead, where both were limited to 5 seconds ahead; further ahead is
  answered with `Signature-Error: error=clock_skew`. Still not met: no other refusal carries a
  `Signature-Error` code, so an agent that leaves `content-digest` off a request with a body,
  which this deployment requires, learns why only from the response body, and that body is not
  problem details; ES256 is not verified. The signed-request posture accepts and refuses what
  it did; its refusal for a missing `Content-Digest` now reads "request carries no
  Content-Digest" where it named POST. Authored by @anivar.
