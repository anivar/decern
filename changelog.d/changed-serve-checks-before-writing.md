- **`decern-serve` checks every flag before it writes anything.** A boot refused for a bad
  `--public-url`, a malformed `--standing-issuer-key`, an unknown `--authzen-type-alias` model type,
  a port already taken or an unsupported `--sharded` target used to leave the key, the ledger and
  the Mission registry behind; it now leaves nothing, so a failed deployment can be retried as it
  stands. `--missions` naming a directory, the shard directory, the ledger file, a path under a file
  or a file that is not JSON, and `--ledger` or `--key` under a directory that does not exist, are
  refused before anything is written; `--ledger` there used to be refused after the key was created,
  and a `--missions` parent directory that does not exist is still created when the registry opens,
  as before. A registry file that is JSON of another shape is refused only when opened, after the
  key and the ledger exist, and leaves its lock file; a failure opening the ledger or the head store
  itself can still leave the key. `--sharded` matches its scheme regardless of case, so
  `POSTGRES://…` reaches the Postgres store instead of becoming a directory named after the URL with
  the password printed in the startup line; any other scheme is refused, and no message repeats the
  URL. `--signed-audience`, `--spiffe-audience` and `--aauth-audience` given without their posture
  are refused instead of ignored. The startup line names the address actually bound. Authored by
  @anivar.
