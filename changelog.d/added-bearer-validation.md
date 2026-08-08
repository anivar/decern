- **`decern-serve` can validate the access token itself.** `--bearer-issuer`,
  `--bearer-audience` and `--bearer-issuer-key` (repeatable) make the deciding and
  mission-lifecycle routes require an RFC 9068 `at+jwt` bearer token: EdDSA over an
  operator-configured key, issuer matched exactly, audience containing this server per
  RFC 8707 §2, all required claims present. `--bearer-scope` (repeatable) additionally
  requires scopes, refusing a verified token without them as `403 insufficient_scope`.
  Absent or invalid tokens get `401`; every refusal carries an RFC 6750 challenge.
  Verification is signature-checking against configured keys, never fetching, so the
  default build still carries no TLS stack. The subject-side routes — the anchor, the
  disclosure, `/audit/v1/subject` — stay open by intent, and the disclosure now reports
  how callers are established. Authored by @anivar.
