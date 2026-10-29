- **A Postgres-sharded start says that its Mission registry is this host's.** `decern-serve
  --sharded postgres://…` starts only with `--missions-per-host`, which says that the Mission
  registry is a file on this host alone: a Mission approved or terminated here is unknown to, or
  still live on, every other host. The flag is the deployment's word, which the server cannot check,
  that a Mission's requests and its termination go to the host that holds it; given with a
  single-file or directory ledger it is refused, since the flag would be ignored. The option table
  said so; a deployment could miss a row, not a refusal. Authored by @anivar.
