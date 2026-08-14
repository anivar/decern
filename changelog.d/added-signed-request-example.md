- **A runnable walkthrough for sender-constrained callers.**
  `examples/signed-request/` serves the proven builtin model to a caller that must prove
  possession of a configured key on every request, and shows the property a bearer
  credential cannot give: the *same* token, byte-identical and unexpired, is refused when
  the RFC 9421 signature comes from a different key. Also covers refusal for signature
  age alone, refusal when a valid signature is replayed against a different path, the
  deployment disclosing its own caller posture, and the ledger naming the caller the
  server verified via `asserted_by`. Runs in CI. Authored by @anivar.
