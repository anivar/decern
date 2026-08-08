- **`decern-serve` refuses to start unless the caller posture is named.** Either the bearer
  flags establish callers here, or `--trust-proxy` states that something in front already
  authenticates them — the proxy deployment every earlier version assumed, now a choice the
  operator writes down. A bind with neither used to warn; a warning is what a startup script
  discards, so it is now a refusal, and the quickstart passes `--trust-proxy` explicitly.
  A standing token whose `typ` is `at+jwt` is also now refused: an access token proves the
  right to call this server, not standing as the party a decision was about.
  Authored by @anivar.
