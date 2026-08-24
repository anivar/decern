- **The ext_authz adapter refuses a duplicated forwarded header instead of choosing one.**
  `HeaderMap::get` returns the first copy and ignores the rest, so a gateway that appended
  its own header rather than replacing a client-supplied one had the adapter authorize
  whichever copy arrived first — a client's `x-forwarded-method: Read` ahead of the gateway's
  `Write` is exactly the fail-open the adapter exists to prevent. Subject, method and URI are
  all checked now, and a duplicate is refused `403` before the PDP is consulted, so nothing is
  evaluated and nothing is recorded. Identical copies are refused too: the adapter cannot tell
  which copy the gateway set, so agreement between them is not evidence that the client did
  not supply one. A deployment whose gateway appends rather than replaces these headers will
  start seeing refusals, which is the misconfiguration becoming visible rather than a new
  restriction. Authored by @shaurya703, reported by @anivar.
