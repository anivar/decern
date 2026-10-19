- **Signature headers are parsed as structured fields.** `Signature-Input` and `Signature` were
  matched against one fixed string shape; the signed-request and AAuth postures now parse them
  as RFC 8941 structured fields and build the RFC 9421 signature base the way the RFC defines it.
  What a signer can notice: `@method` is signed as sent, case included (RFC 9421 §2.2.1),
  where it was uppercased first, so a signature over `POST` no longer covers a request sent as
  `post`. Every line of a signature header is read, joined with `", "` (§2.1), where only the
  first was. The `@signature-params` line is serialized from the parsed input (§3.2 step 7)
  rather than copied, so a signer that signs the serialization §2.3 defines verifies whatever
  optional whitespace its `Signature-Input` carries. `@authority` is host and optional port,
  from an absolute-form request target when there is one and from a single `Host` otherwise,
  where it was always `Host` as sent; a missing or repeated `Host` is refused. A `Host`,
  `Signature-Key`, `Signature-Input`, `Signature` or `Content-Digest` value that is not visible
  ASCII is refused as malformed rather than read as absent, so a GET carrying such a
  `Content-Digest`, once not checked, is refused. Parsing follows RFC 8941 rather than the old
  string shape: a token `keyid`, `created=+1` and a trailing `;` are refused, and a `Signature`
  whose base64 lacks its padding is accepted (RFC 9651 §4.2.7). The profile is otherwise
  unchanged: one signature labelled `sig1`, exactly its covered components in order, `created`
  and `keyid` only, Ed25519 only. The AAuth posture still does not meet
  draft-hardt-oauth-aauth-protocol-11; the standards registry lists where. Authored by @anivar.
