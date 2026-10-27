- **A sharded append no longer reads the shard's history.** Under `--sharded`, each append read
  and parsed every record of the tenant's shard under its lock, so an append cost more the longer
  the shard: on the file store, 12.3 ms per append at 1,000 records and 26.1 ms at 5,000 on one
  machine. An append now reads the shard's head alone. The head carries the keys that have signed
  the shard, which the key-rotation guard checks. On the file store a shard is a small head,
  rewritten atomically, and an append-only log; on Postgres the head row alone is read. On the
  same machine an append on the file store costs about 12.5 ms at 1,000, 5,000 and 10,000
  records; the in-memory store takes 17 µs, so nearly all of it is the file store's disk writes.
  A record edited so it no longer parses as JSON is no longer refused by the next append to its
  shard; the next boot's check of every shard and `decern verify --sharded` find it, as they find
  any edit to a record.
  A file store written by an earlier release is read as it is, and each shard is converted at its
  next append. Every shard this release creates carries, from before its first record, a marker
  an earlier release cannot read, and every shard it converts gets one as the conversion
  completes. An earlier release's `decern-serve` and `decern verify` refuse a store holding a
  marked shard rather than read the shard as empty, so stop every replica before upgrading; there
  is no way back to the earlier release. Should an earlier release still write to a converted
  shard, this release refuses that shard rather than overwrite what it wrote.
  A Postgres store gains a nullable `signers` column. The first boot of this release adds it,
  which needs the role that owns `decern_ledger_head`, and gives up after 5 seconds behind
  another session holding the table, naming the statement to run; later boots only check for it.
  An earlier release still writing to the store leaves the column behind, and the next append then
  reads the history instead of trusting it.
  Authored by @anivar.
