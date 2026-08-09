- **The subject-audit projection no longer parses the log under the append lock.** It
  held the same mutex every decision needs while deserializing every record and deriving
  every proof — a way to slow the server's ability to decide. The lock is now held twice,
  briefly: once to copy raw bytes out, once to sign the head; parsing, matching and
  proving happen unlocked, and only matched records are parsed in full.
  Authored by @anivar.
