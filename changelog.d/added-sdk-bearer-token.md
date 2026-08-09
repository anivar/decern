- **Every SDK client can send a bearer token.** An optional token on the Go, Python and
  TypeScript clients, sent as `Authorization: Bearer` on every request when set and
  absent entirely when not — for a deployment that requires access tokens on the
  evaluation endpoint. The client carries a token the application already holds;
  acquiring one stays the issuer's business. Authored by @anivar.
