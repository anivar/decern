- **A Postgres head store refuses a URL to another host that does not require TLS.** The URL went to
  the client as given, and the client's default, `sslmode=prefer`, carries on in plaintext when it
  is told the server has no TLS, which anyone in the network path can say. A `--sharded
  postgres://…` URL, or one given to `PostgresLedgerHeadStore::new`, that names a host other than
  this one must now carry `sslmode=require`: without it the server refuses to start, before it
  connects. A Unix socket, `localhost` and loopback addresses are left alone, judged by `hostaddr`
  when the URL gives one; a name that only resolves to this host counts as another host. Add
  `sslmode=require` to the URL of a deployment that crosses hosts. Authored by @anivar.
