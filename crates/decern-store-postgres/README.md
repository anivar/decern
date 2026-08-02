<!-- SPDX-License-Identifier: Apache-2.0 -->
# decern-store-postgres

An **optional** Postgres backend for decern's `LedgerHeadStore` — the one that
works across **multiple hosts**.

decern's default ledger-head stores are sovereign and database-free:
`MemoryLedgerHeadStore` (in-process) and `FileLedgerHeadStore` (single-host,
multi-process, `flock`-held). Both stop at one machine. This crate is a third
backend behind the same trait, for hosted, horizontally-scaled deployments where
more than one `decern-serve` replica must safely extend the **same** tenant hash
chain (and gate the same cumulative money-budget) without forking it.

## How the exclusive, cross-host critical section works

`with_shard(shard, f)` runs, on a dedicated background thread that owns the
connection:

```
BEGIN;
SELECT pg_advisory_xact_lock($hash_of_shard);   -- txn-scoped, cross-host EXCLUSIVE lock
-- read this shard's cursor + full record history, hand them to f
-- f decides what (if anything) to append
INSERT the new record; upsert the new head cursor;   -- only if f returned Some(...)
COMMIT;                                          -- releases the advisory lock
```

The advisory lock is **held across the whole read-then-decide-then-write critical
section**, not just the final write — the same guarantee `FileLedgerHeadStore`'s
`flock` gives on one host, now across hosts. A second host calling `with_shard`
on the same shard blocks inside `pg_advisory_xact_lock` until the first commits,
so the chain can't fork and a read-then-append critical section can't double-read
the same total.

## The sync-client-in-async design (why the dedicated thread)

The trait is synchronous, so this crate uses the **sync** `postgres` crate. A
sync `postgres::Client` owns an internal current-thread tokio runtime, and both
its creation (`block_on`) and its `Drop` **panic** if run inside another tokio
runtime — which `decern-serve` (`#[tokio::main]`) always is. So the `Client` is
created, used, and dropped entirely on **one dedicated OS thread** that has no
ambient runtime. `with_shard` round-trips the work to that thread: the actor
holds the transaction open and ships the shard's state to the caller; the caller
runs `f` locally (it isn't `Send`) and ships back the decision; the actor
commits or rolls back. See the crate-level docs for the full rationale and the
one deliberate behavior divergence (a `(shard, seq)` primary key that rejects a
duplicate seq instead of trusting the caller).

## The compiled-C-FFI exception

decern's **core libraries and its `decern`/`decern-serve` binaries are pure Rust
with zero compiled-C-FFI dependencies** — the default build pulls no TLS stack.
This crate is the **single documented exception**: multi-host Postgres needs TLS,
and every TLS provider links compiled C/assembly. The exception is isolated —
the binaries do **not** depend on this crate (verify with
`cargo tree -p decern-cli` / `cargo tree -p decern-server`: no `rustls`, `ring`,
`aws-lc`, `openssl`, `postgres`, or `tokio-postgres`). We use `rustls` with the
pure-`ring` provider (default features off), not `aws-lc-rs` (which needs a
`cmake` toolchain), keeping the exception a single, audit-scoped stack with an
explicit crypto provider (no process-global provider is installed).

## Testing

Tests read `DECERN_TEST_POSTGRES_URL`; when it is unset every DB test **skips**,
so `cargo test --workspace` (and `scripts/verify.sh`) stay green with no
database. Set it to run against a real Postgres:

```
DECERN_TEST_POSTGRES_URL=postgres://user@127.0.0.1:5432/db?sslmode=disable \
  cargo test -p decern-store-postgres
```

The `store-postgres` GitHub workflow runs these against a Postgres service
container as a **non-required** check.
