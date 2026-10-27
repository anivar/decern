- **A Postgres head store answers a database error with a `503` instead of hanging.**
  Under `--sharded postgres://…`, a database error before a shard was read, such as the
  connection a database restart closes, left the store's one connection and the request each
  waiting on the other for good. That decision and every later one waited, and `decern-serve` did
  not stop on `SIGTERM`. Such an error is now answered at once with `503`, the store goes on
  to the next request, and the server stops when asked. The store does not reconnect: after the
  database restarts, every decision is refused with `503` until `decern-serve` is restarted. The
  first decision to find the connection closed turns `/healthz` to `503`, so a liveness probe
  restarts the server; a replica that serves no decision meanwhile answers `ok` until one does.
  A database that stops answering without closing the connection, behind a network partition for
  example, still holds the store until TCP gives up: each decision meanwhile is answered `503` at
  the 30-second request deadline, `/healthz` answers `ok`, and `SIGTERM` waits.
  Authored by @anivar.
