- **A Postgres head store bounds its waits.** A start fails after 30 seconds without a ready
  database, where it waited with no deadline, serving nothing and handling no signal; a section
  waits at most 10 seconds for any lock, its shard's first, so a host paused mid-section costs
  each other host `503`s on that shard and, its store serving one section at a time, a wait of up
  to 10 seconds for the sections queued behind, not a hang until it resumes. The store still sets
  no statement timeout, which a stalled server could not deliver, does not reconnect, and leaves
  the connection's TCP parameters to the URL. Authored by @anivar.
