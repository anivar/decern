- **The record says who asserted the request.** Under bearer validation a decision
  carries `asserted_by` — the token's subject, client and issuer, exactly as the server
  verified them — so a hardened deployment's log reads "the gateway asked about alice",
  not only "alice". Absent under `--trust-proxy`: an assertion the server did not verify
  itself does not belong on a permanent record. Never a decision input, and
  `decern explain` prints it. Authored by @anivar.
