- **At most 512 requests are decided, searched, recorded, audited or read as a Mission at once.**
  Each such request runs on a blocking thread and takes one of 512 places; a request that finds them
  taken is answered `503`, `server_busy`, at once, and a request that ran out of time keeps its
  place until its work ends. The Postgres head store also bounds its own queue, at 1,024 sections,
  which the places keep it from reaching. `/healthz` answers `ok` while the places are full, unless
  the store behind them has failed or stalled. Authored by @anivar.
