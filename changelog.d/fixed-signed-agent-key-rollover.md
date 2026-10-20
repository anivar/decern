- **A second `--signed-agent-key` for the same agent adds a key instead of replacing it.** The
  flag's help, `docs/CLI.md` and the signed-request module all said a key rollover is a second
  entry for the same id with the old one still accepted, but the second entry silently replaced
  the first, so an agent mid-rollover was refused under its old key. Both keys now verify until
  the old one is dropped from the command line: the bound token's `cnf.jwk` must name one of the
  agent's configured keys, and the request signature must verify under that key. The same key
  given twice for one id is refused at startup. Authored by @anivar.
