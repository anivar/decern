- **Signed POST requests now cover the body.** `--signed-agent-key` requires
  `Content-Digest` (RFC 9530, `sha-256` only) as a fifth covered component on POST,
  verified against the bytes the handler will see. A captured signature over one JSON
  body cannot authorize a different one at the same path. GET is unchanged: it has no
  body to cover. Verbatim replay of the same path and body is still accepted within
  the freshness window — there is no nonce cache. Authored by @anivar.
