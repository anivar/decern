- **Two claims narrowed to what the code checks.** `decern prove` states `money-gate` as
  "MoveMoney is never allowed unless the context carries human_approved = true" and
  `consent-gate` as "… unless the context carries consent = true", where they said "explicit
  human approval" and "explicit consent". The solver checks a context flag. The server sets
  `human_approved` only from a Mission covering `MoveMoney`, and `approve` does not check that
  the approver is human or someone other than the agent; the enforcement point sets
  `consent`. The proofs are unchanged. Bearer validation is described as RFC 9068's checks for
  `EdDSA` tokens: RFC 9068 §2.1 requires a conforming resource server to support RS256, which
  this does not, and the standards registry now says so. Authored by @anivar.
