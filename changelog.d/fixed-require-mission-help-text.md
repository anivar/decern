- **`--require-mission` no longer promises server-derived consent.** Its help text said
  client-supplied `human_approved` and `consent` are "derived server-side from the verified
  Mission". Only `human_approved` is, and only for `MoveMoney`; `consent` is stripped and
  never put back, because a Mission is an approver's grant and not the resource owner's
  consent. An operator who turned the flag on *to make consent server-derived* got
  fail-closed on-behalf-of PII access and a contract that was not true. The flag's behaviour
  is unchanged — the text now describes it. Authored by @anivar.
