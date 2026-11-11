- **The Python and TypeScript clients allow only on the JSON boolean `true`.** They read the
  answer's `decision` by truthiness, so a response whose `decision` was the string `"false"`, a
  number or any other non-empty value came back as `allowed`. All three clients now raise an error
  when `decision` is absent or is not a boolean; the Go client, which already refused a wrong type,
  no longer reads an absent or `null` decision as a deny. A conformant decision point always sends a
  boolean, so nothing changes against `decern-serve`. An answer with no `decision`, which each
  client read as a deny, is now an error too. Authored by @anivar.
