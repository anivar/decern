- **The ledger is no longer world-readable.** It was created at the process umask —
  commonly `0644` — while the signing key and the mission registry beside it are `0600`,
  which made the audit log the readable one of the three. It holds decision subjects and
  the pseudonymous handles the subject-side audit route is keyed by. Now `0600` on
  creation, and an existing ledger is tightened when it is next opened rather than left
  readable forever. Sealed segments go from `0444` to `0400` for the same reason. Unlike
  the signing key, a group- or other-readable ledger is tightened rather than refused:
  failing an existing deployment's next append would be worse than fixing it in place.
  Authored by @anivar.
- **The Envoy `ext_authz` snippet no longer forwards a client-supplied subject header.**
  `allowed_headers` forwards whatever is on the request, so the documented config passed a
  client's own `x-forwarded-subject` straight to the adapter — the exact bypass the README
  warns about, in the README. The NGINX example overwrites the header and the Traefik one
  sets `trustForwardHeader: false`; the Envoy one now strips it and says why filter
  ordering has to be checked. Authored by @anivar.
