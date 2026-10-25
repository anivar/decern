- **A signed request's record names no issuer.** Under `--signed-agent-key`, `asserted_by.iss`
  held the bound token's `iss` claim, which nothing verified: the token is covered by the
  request signature, never checked against an issuer key, so the value was the agent's own
  claim. Records made under this posture now omit `iss`, and `decern explain` says no issuer was
  verified. Records already written keep theirs, and the other postures record the issuer whose
  signature they checked, as before. `decern verify` and `decern explain` from 0.6.0 or earlier
  cannot parse a record without `iss` and report it as tampered, so a ledger written under this
  posture is verified with this release or later. In `decern-ledger`, `AssertedBy::iss` is now
  an `Option<String>`.
  Authored by @anivar.
