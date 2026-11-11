- **The Python and TypeScript clients allow only on the JSON boolean `true`.** They read the
  answer's `decision` by truthiness, so a response whose `decision` was the string `"false"`, a
  number or any other non-empty value came back as `allowed`. All three clients now raise an error
  when `decision` is absent or is not a boolean; the Go client, which already refused a wrong type,
  no longer reads an absent or `null` decision as a deny. A conformant decision point always sends a
  boolean, so nothing changes against `decern-serve`.
- **The Python client no longer follows a redirect.** `urllib` re-sends the request headers to the
  redirect target, the bearer token among them. A `3xx` answer is now an error carrying its status
  code. The TypeScript and Go clients still follow redirects with their runtime's defaults, which
  this change did not examine.
- **Each client refuses a success body over 1 MiB**, where the error body was already capped at 64
  KiB and the success body was read whole. Authored by @anivar.
