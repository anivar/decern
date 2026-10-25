- **An anonymous caller can no longer stall every decision through the tree head.**
  `GET /anchor/v1/tree-head` re-read and re-hashed the whole ledger while holding the lock every
  append needs, on a thread that serves requests: at 150,000 records, twelve anonymous clients
  polling it held a decision for 8 seconds on average. It now notes the record count under the
  lock, reads and hashes that prefix on a blocking thread without it, takes the lock again only
  to sign, and recomputes at most once a second, serving the last head in between; under the
  same load a decision took 5 ms. `/audit/v1/subject` reads the log the same way, one
  projection at a time, since each holds the whole log in memory; the rest wait within the
  30-second request deadline. Decisions, batches and Mission approvals and terminations run on
  blocking threads too, so a slow fsync no longer holds a thread other requests need, and the
  request deadline covers them: a decision whose append has not finished by then is answered
  `503`, and the append still lands.
  Authored by @anivar.
