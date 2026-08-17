// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
#![forbid(unsafe_code)]
//! decern-store-postgres — the **multi-host** [`LedgerHeadStore`] backend.
//!
//! decern's default ledger-head stores are sovereign and database-free:
//! `decern_store::MemoryLedgerHeadStore` (in-process) and
//! `decern_store::FileLedgerHeadStore` (single-host, multi-process, `flock`-held).
//! Both stop at ONE machine. This crate is the third backend behind the SAME
//! trait: a Postgres store where the shard critical section is held across
//! **every replica/host** via a transaction-scoped advisory lock, so more than
//! one `decern-server` host can safely extend the same tenant hash chain (and
//! gate the cumulative money-budget) without forking it.
//!
//! # The TLS exception (deliberate, isolated, documented)
//!
//! decern's core libraries and its `decern`/`decern-serve` binaries pull no TLS
//! stack, no OpenSSL and no `cmake` — not zero compiled native code, since `psm`
//! (via `cedar-policy` → `stacker`) compiles a small assembly routine in every
//! build. This crate is the ONE documented exception for TLS: multi-host Postgres
//! needs it, and TLS providers link compiled C/assembly. The exception is contained
//! here — the binaries do NOT depend on this crate. We use `rustls`
//! with the `ring` provider (not `aws-lc-rs`, which needs a `cmake` toolchain),
//! keeping the exception a single, audit-scoped stack. See this crate's README.
//!
//! # The sync-client-in-async pitfall (the whole reason for the actor thread)
//!
//! The trait methods are synchronous, so this backend uses the **sync**
//! `postgres` crate. A sync `postgres::Client` owns an internal current-thread
//! tokio runtime: `Client::connect` does `block_on`, and `Client`'s `Drop` also
//! drives that runtime. Both **panic** ("cannot start a runtime from within a
//! runtime") if they run inside another tokio runtime — and `decern-server` is
//! `#[tokio::main]`, so this store is used from async context. The tempting
//! shape (connect in `new`, then `thread::spawn` to use it) compiles and passes
//! every unit test, then panics only under the server.
//!
//! The fix: a **dedicated-thread actor**. One background OS thread owns the
//! `Client` for its whole lifetime — the client is created there, every query
//! runs there, and it is dropped there when the loop ends. That thread has no
//! ambient tokio runtime, so `block_on` is always legal. The runtime's own
//! executor threads are never blocked on Postgres I/O either.
//!
//! # Why not just ship the closure to the actor thread
//!
//! The critical-section callback is `&mut ShardCriticalSection<'_>` — an
//! `FnMut` that is neither `Send` nor `'static`, so it cannot cross a thread
//! boundary. Instead the actor holds the transaction open and the work
//! **round-trips**: the actor `BEGIN`s, takes the advisory lock, reads the
//! shard's cursor+records, and ships them to the caller thread; the caller runs
//! `f` locally and ships back what to write; the actor commits (or rolls back).
//! The advisory lock is held across the entire round trip — exactly the
//! held-lock semantics the trait requires, not a bare compare-and-swap.
//!
//! # The advisory-lock CAS transaction (`with_shard`, on the actor thread)
//!
//! ```text
//! BEGIN;
//! SELECT pg_advisory_xact_lock($key);   -- $key = a stable 64-bit hash of shard;
//!                                       --   txn-scoped, cross-host EXCLUSIVE lock
//! SELECT next_seq, last_hash FROM decern_ledger_head   WHERE shard = $s;      -- cursor
//! SELECT seq, record         FROM decern_ledger_record WHERE shard = $s ORDER BY seq;
//! -- (records + cursor shipped to caller; caller runs f; ships decision back)
//! -- if f returned Some((new_cursor, record_json)):
//!   INSERT INTO decern_ledger_record (shard, seq, record) VALUES ($s, $new_cursor.next_seq - 1, $record_json);
//!   INSERT INTO decern_ledger_head (shard, next_seq, last_hash) VALUES ($s, $new_cursor.next_seq, $new_cursor.last_hash)
//!     ON CONFLICT (shard) DO UPDATE SET next_seq = EXCLUDED.next_seq, last_hash = EXCLUDED.last_hash;
//! COMMIT;                               -- releases the advisory lock
//! -- if f returned None: COMMIT with nothing written (still releases the lock)
//! -- if f returned Err / a DB error occurred: ROLLBACK (RAII on the Transaction), no write
//! ```
//!
//! Two hosts calling `with_shard` on the same shard genuinely serialize: the
//! second blocks inside `pg_advisory_xact_lock` (in the database, across
//! connections) until the first `COMMIT`s. So the hash chain cannot fork and a
//! read-total-then-append critical section cannot both-read-the-same-total.
//!
//! # Schema
//!
//! Two tables, created idempotently by [`PostgresLedgerHeadStore::new`] under a
//! session advisory lock (so two hosts booting at once cannot race the DDL into
//! a duplicate-object error):
//!
//! - `decern_ledger_record (shard TEXT, seq BIGINT, record TEXT, PRIMARY KEY (shard, seq))`
//! - `decern_ledger_head   (shard TEXT PRIMARY KEY, next_seq BIGINT, last_hash TEXT)`
//!
//! **One deliberate behavior divergence from the Memory/File backends:** the
//! `(shard, seq)` primary key REJECTS a duplicate seq. Those backends trust the
//! caller and blindly push whatever seq the returned cursor implies; here a
//! caller bug that reuses a seq surfaces as a clean rolled-back [`StoreError`]
//! instead of silently corrupting the chain. For a chain-integrity backend that
//! stricter check is a feature, not a regression — but it IS a difference, noted
//! here and in the crate report.
//!
//! One more scope note: a shard id is stored in a Postgres `TEXT` column, which
//! cannot hold a NUL byte, whereas the File backend hex-encodes and could. Shard
//! ids in decern are tenant ids (UTF-8 identifiers), so this is a non-issue in
//! practice; `list_shards` orders with `COLLATE "C"` so the sort is byte order on
//! every server locale, matching the Memory/File backends exactly.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, SyncSender, channel, sync_channel};
use std::thread::{self, JoinHandle};

use decern_store::{
    HeadCursor, LedgerHeadStore, ShardCriticalSection, ShardWrite, StoreError, StoredRecord,
};
use postgres::{Client, Transaction};
use tokio_postgres_rustls::MakeRustlsConnect;

/// Fixed advisory-lock key guarding the idempotent `CREATE TABLE` DDL. Any
/// constant works; it only needs to be the same on every host so concurrent
/// boots serialize their schema creation. `pg_advisory_lock` is session-scoped
/// and released explicitly after the DDL.
const SCHEMA_LOCK_KEY: i64 = 0x6465_6365_726e_0001; // "dece","rn",1

/// The shard state the actor reads under the lock and ships to the caller: the
/// current cursor (`None` = genesis) plus the full record history in seq order.
type ShardState = (Option<HeadCursor>, Vec<StoredRecord>);

/// A unit of work handed to the actor thread that owns the `postgres::Client`.
enum Job {
    /// Run one shard critical section. The actor opens the transaction, takes the
    /// advisory lock, reads state, and hands it to the caller over `loaded`; the
    /// caller runs `f` and returns what to write over `decision`; the actor
    /// commits/rolls back and reports the outcome over `done`.
    WithShard {
        shard: String,
        loaded: SyncSender<Result<ShardState, StoreError>>,
        decision: Receiver<Result<ShardWrite, StoreError>>,
        done: SyncSender<Result<(), StoreError>>,
    },
    ListShards {
        resp: SyncSender<Result<Vec<String>, StoreError>>,
    },
    /// End the loop so the `Client` is dropped on this (non-async) thread.
    Shutdown,
}

/// Multi-host [`LedgerHeadStore`] backed by Postgres. Cheap to clone-free share
/// behind an `Arc<dyn LedgerHeadStore>`; all state lives on the actor thread.
pub struct PostgresLedgerHeadStore {
    jobs: Sender<Job>,
    handle: Option<JoinHandle<()>>,
}

impl PostgresLedgerHeadStore {
    /// Connect to `url` (a libpq/`postgres://…` connection string) and ensure the
    /// schema. Spawns the actor thread FIRST and connects ON it, so the sync
    /// client is never created inside a caller's tokio runtime (see the crate
    /// docs). Returns `Err` — never panics — on a bad URL, an unreachable
    /// server, or a schema failure.
    pub fn new(url: &str) -> Result<Self, StoreError> {
        let url = url.to_owned();
        let (ready_tx, ready_rx) = sync_channel::<Result<(), StoreError>>(0);
        let (job_tx, job_rx) = channel::<Job>();
        let handle = thread::Builder::new()
            .name("decern-pg-ledger-head".into())
            .spawn(move || actor_main(&url, &ready_tx, &job_rx))
            .map_err(|e| StoreError::Io {
                path: "<pg actor thread>".into(),
                err: e.to_string(),
            })?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(PostgresLedgerHeadStore {
                jobs: job_tx,
                handle: Some(handle),
            }),
            Ok(Err(e)) => {
                let _ = handle.join();
                Err(e)
            }
            Err(_) => {
                let _ = handle.join();
                Err(StoreError::Invalid(
                    "postgres ledger-head actor exited during startup".into(),
                ))
            }
        }
    }
}

impl Drop for PostgresLedgerHeadStore {
    fn drop(&mut self) {
        // Tell the actor to end its loop, then join so the `Client` is fully
        // dropped on the actor thread (never in a tokio runtime) before we return.
        let _ = self.jobs.send(Job::Shutdown);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl LedgerHeadStore for PostgresLedgerHeadStore {
    fn with_shard(&self, shard: &str, f: &mut ShardCriticalSection<'_>) -> Result<(), StoreError> {
        // Rendezvous channels (capacity 0): each hop blocks until the other side
        // is ready, keeping the actor's held transaction in lockstep with `f`.
        let (loaded_tx, loaded_rx) = sync_channel(0);
        let (decision_tx, decision_rx) = sync_channel(0);
        let (done_tx, done_rx) = sync_channel(0);
        self.jobs
            .send(Job::WithShard {
                shard: shard.to_owned(),
                loaded: loaded_tx,
                decision: decision_rx,
                done: done_tx,
            })
            .map_err(|_| actor_gone())?;

        // The actor has BEGUN, taken the advisory lock, and read the shard.
        let (cursor, records) = match loaded_rx.recv() {
            Ok(state) => state?,
            Err(_) => return Err(actor_gone()),
        };

        // Run the caller's critical section on THIS thread (it is not `Send`).
        // Exactly once — the sharded ledger's callback panics if invoked twice.
        let decision = f(cursor.as_ref(), &records);

        // Ship the decision back (Ok(write) commits, Err rolls back). If the
        // actor is gone the send fails; we surface that via the `done` recv below.
        let _ = decision_tx.send(decision);

        match done_rx.recv() {
            Ok(outcome) => outcome,
            Err(_) => Err(actor_gone()),
        }
    }

    fn list_shards(&self) -> Result<Vec<String>, StoreError> {
        let (resp_tx, resp_rx) = sync_channel(0);
        self.jobs
            .send(Job::ListShards { resp: resp_tx })
            .map_err(|_| actor_gone())?;
        resp_rx.recv().map_err(|_| actor_gone())?
    }
}

// ============================ actor thread ============================

fn actor_main(url: &str, ready: &SyncSender<Result<(), StoreError>>, jobs: &Receiver<Job>) {
    let tls = match build_tls() {
        Ok(t) => t,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    // Created HERE, on the actor thread — never inside a caller's tokio runtime.
    let mut client = match Client::connect(url, tls) {
        Ok(c) => c,
        Err(e) => {
            let _ = ready.send(Err(db(&e)));
            return;
        }
    };
    if let Err(e) = ensure_schema(&mut client) {
        let _ = ready.send(Err(e));
        return;
    }
    if ready.send(Ok(())).is_err() {
        return; // creator gave up; client drops here, on this thread.
    }

    while let Ok(job) = jobs.recv() {
        match job {
            Job::WithShard {
                shard,
                loaded,
                decision,
                done,
            } => {
                // A single call's failure never kills the actor: the transaction
                // rolls back via RAII and the loop continues with the next job.
                let outcome = run_with_shard(&mut client, &shard, &loaded, &decision);
                let _ = done.send(outcome);
            }
            Job::ListShards { resp } => {
                let _ = resp.send(list_shards_impl(&mut client));
            }
            Job::Shutdown => break,
        }
    }
    // `client` dropped here, on the actor thread. Its internal runtime teardown
    // is legal because this thread has no ambient tokio runtime.
}

/// The held-advisory-lock critical section, run entirely on the actor thread.
fn run_with_shard(
    client: &mut Client,
    shard: &str,
    loaded: &SyncSender<Result<ShardState, StoreError>>,
    decision: &Receiver<Result<ShardWrite, StoreError>>,
) -> Result<(), StoreError> {
    // `Transaction` rolls back on drop unless `commit()` is called, so every
    // early return below aborts cleanly with no write.
    let mut tx = client.transaction().map_err(|e| db(&e))?;
    // Transaction-scoped, cross-host EXCLUSIVE lock on this shard. Blocks (in the
    // database, across connections) until any other host's section commits.
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&advisory_key(shard)])
        .map_err(|e| db(&e))?;

    let cursor = read_head(&mut tx, shard)?;
    let records = read_records(&mut tx, shard)?;

    // Hand the fresh state to the caller thread and wait for its decision.
    if loaded.send(Ok((cursor, records))).is_err() {
        return Err(StoreError::Invalid(
            "caller disconnected before running the critical section".into(),
        ));
    }
    let write = match decision.recv() {
        Ok(Ok(w)) => w,
        // `f` returned Err — abort with no write (matches the File backend).
        Ok(Err(e)) => return Err(e),
        // Caller thread dropped (e.g. it panicked). Abort; the loop survives.
        Err(_) => {
            return Err(StoreError::Invalid(
                "critical section aborted before returning a decision".into(),
            ));
        }
    };

    if let Some((new_cursor, record_json)) = write {
        // The record's seq is the new cursor's next_seq minus one — identical to
        // the Memory and File backends. The `(shard, seq)` PK rejects a duplicate.
        let seq = to_i64(new_cursor.next_seq.saturating_sub(1))?;
        tx.execute(
            "INSERT INTO decern_ledger_record (shard, seq, record) VALUES ($1, $2, $3)",
            &[&shard, &seq, &record_json],
        )
        .map_err(|e| db(&e))?;
        tx.execute(
            "INSERT INTO decern_ledger_head (shard, next_seq, last_hash) VALUES ($1, $2, $3) \
             ON CONFLICT (shard) DO UPDATE SET next_seq = EXCLUDED.next_seq, last_hash = EXCLUDED.last_hash",
            &[&shard, &to_i64(new_cursor.next_seq)?, &new_cursor.last_hash],
        )
        .map_err(|e| db(&e))?;
    }
    // COMMIT even on a `None` write: it releases the advisory lock cleanly.
    tx.commit().map_err(|e| db(&e))
}

fn read_head(tx: &mut Transaction<'_>, shard: &str) -> Result<Option<HeadCursor>, StoreError> {
    let row = tx
        .query_opt(
            "SELECT next_seq, last_hash FROM decern_ledger_head WHERE shard = $1",
            &[&shard],
        )
        .map_err(|e| db(&e))?;
    row.map(|r| {
        Ok(HeadCursor {
            next_seq: from_i64(r.get::<_, i64>(0))?,
            last_hash: r.get::<_, String>(1),
        })
    })
    .transpose()
}

fn read_records(tx: &mut Transaction<'_>, shard: &str) -> Result<Vec<StoredRecord>, StoreError> {
    let rows = tx
        .query(
            "SELECT seq, record FROM decern_ledger_record WHERE shard = $1 ORDER BY seq",
            &[&shard],
        )
        .map_err(|e| db(&e))?;
    rows.iter()
        .map(|r| {
            Ok(StoredRecord {
                seq: from_i64(r.get::<_, i64>(0))?,
                record_json: r.get::<_, String>(1),
            })
        })
        .collect()
}

/// `list_shards` reads the HEAD table (a row exists only after a real commit),
/// matching the Memory/File backends' `cursor.is_some()` filter exactly — and it
/// is a primary-key scan, not a `DISTINCT` over the whole record table.
///
/// `COLLATE "C"` is load-bearing, not incidental: the Memory backend iterates a
/// `BTreeMap` and the File backend calls `Vec::sort`, both **byte-lexicographic**.
/// A bare `ORDER BY shard` sorts in the database's `lc_collate` order, where
/// under a locale like `en_US.UTF-8` punctuation is variable-weighted and shard
/// ids such as `a/b` or `tenant:with:colons` can order differently. The trait
/// promises the SAME order on every replica so order-sensitive cross-tenant
/// aggregates converge — which only holds if this matches the other backends' byte
/// order regardless of the server's locale. `COLLATE "C"`
/// forces byte order.
fn list_shards_impl(client: &mut Client) -> Result<Vec<String>, StoreError> {
    let rows = client
        .query(
            "SELECT shard FROM decern_ledger_head ORDER BY shard COLLATE \"C\"",
            &[],
        )
        .map_err(|e| db(&e))?;
    Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
}

/// Idempotent schema creation under a SESSION advisory lock, so two hosts booting
/// simultaneously serialize the DDL and cannot race `CREATE TABLE IF NOT EXISTS`
/// into a duplicate-object error (SQLSTATE 23505/42P07).
fn ensure_schema(client: &mut Client) -> Result<(), StoreError> {
    client
        .execute("SELECT pg_advisory_lock($1)", &[&SCHEMA_LOCK_KEY])
        .map_err(|e| db(&e))?;
    let ddl = client.batch_execute(
        "CREATE TABLE IF NOT EXISTS decern_ledger_record (\
             shard  TEXT   NOT NULL, \
             seq    BIGINT NOT NULL, \
             record TEXT   NOT NULL, \
             PRIMARY KEY (shard, seq)); \
         CREATE TABLE IF NOT EXISTS decern_ledger_head (\
             shard     TEXT   PRIMARY KEY, \
             next_seq  BIGINT NOT NULL, \
             last_hash TEXT   NOT NULL);",
    );
    // Release the session lock regardless of the DDL outcome.
    let _ = client.execute("SELECT pg_advisory_unlock($1)", &[&SCHEMA_LOCK_KEY]);
    ddl.map_err(|e| db(&e))
}

// ============================ helpers ============================

/// A stable 64-bit advisory-lock key for `shard` (FNV-1a, no external dep, no
/// dependence on any hasher's default seed). A collision would merely make two
/// unrelated shards serialize against each other occasionally — never a
/// correctness problem, since each still reads and writes only its own rows.
fn advisory_key(shard: &str) -> i64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in shard.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h as i64
}

/// Build the rustls TLS connector with an EXPLICIT `ring` provider. We do NOT
/// use rustls' process-default provider (it panics if none is installed, and a
/// library installing a process-global provider can conflict with the host app),
/// nor `aws-lc-rs` (which needs a `cmake` toolchain). Native OS roots are loaded
/// so a real TLS deployment verifies certificates; a local `sslmode=disable`
/// connection negotiates no TLS and needs no roots at all.
fn build_tls() -> Result<MakeRustlsConnect, StoreError> {
    let provider = rustls::crypto::ring::default_provider();
    let mut roots = rustls::RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(loaded.certs);
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| StoreError::Invalid(format!("rustls provider setup failed: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

fn to_i64(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Invalid(format!("sequence {v} exceeds i64 range")))
}

fn from_i64(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Invalid(format!("stored sequence {v} is negative")))
}

fn db(e: &postgres::Error) -> StoreError {
    StoreError::Io {
        path: "postgres".into(),
        err: e.to_string(),
    }
}

fn actor_gone() -> StoreError {
    StoreError::Invalid("postgres ledger-head actor thread is gone".into())
}

#[cfg(test)]
mod tests;
