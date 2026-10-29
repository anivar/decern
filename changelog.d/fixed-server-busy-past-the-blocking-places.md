- **A request past 512 being decided or recorded is answered `503` at once.** A request runs its
  decision, search or record on a blocking thread, and past the pool's 512 threads it waited in the
  pool's queue, each answered `503` only at the 30-second deadline, so a database that stopped
  answering under `--sharded postgres://…` collected one waiting request after another.
  `decern-serve` now hands out 512 places, one per blocking thread; every request that touches
  durable state, a Mission status read included, takes one, and a request that finds them taken is
  answered `503`, `server_busy`, at once; a request that ran out of time keeps its place until its
  work ends. The Postgres head store also bounds its own queue, at 1,024 sections, which
  `decern-serve`'s places keep it from reaching. `/healthz` still answers `ok`: the store has not
  failed, the database is not keeping up. Authored by @anivar.
