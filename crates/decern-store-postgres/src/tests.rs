// SPDX-License-Identifier: Apache-2.0
//! Tests for the Postgres ledger-head store.
//!
//! Every test that needs a live database reads `DECERN_TEST_POSTGRES_URL` and
//! returns early (skips) when it is unset — so `cargo test --workspace` stays
//! green with NO database. The one exception is the connect-off-runtime
//! regression test below, which needs no database at all and MUST run everywhere.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{Bounds, PostgresLedgerHeadStore};
use decern_store::{HeadCursor, LedgerHeadStore, StoreError};

/// A unique-per-test shard id, so tests sharing one database never collide (the
/// tables are shared and cargo runs tests in parallel). Never `TRUNCATE` — that
/// would corrupt a concurrently-running test.
fn uniq(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let thread: String = format!("{:?}", thread::current().id())
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    format!("test_{prefix}_{nanos}_{thread}")
}

/// A cursor that keeps no key spans.
fn cursor_at(next_seq: u64, last_hash: impl Into<String>) -> HeadCursor {
    HeadCursor {
        next_seq,
        last_hash: last_hash.into(),
        signers: None,
    }
}

/// `url` with one more connection parameter.
fn with_param(url: &str, param: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{param}")
}

fn test_url() -> Option<String> {
    std::env::var("DECERN_TEST_POSTGRES_URL").ok()
}

/// Take `shard`'s advisory lock from a second connection, in a transaction held open for
/// `hold_for`, and return once it is held; the thread commits when the time is up.
fn hold_shard_lock(url: &str, shard: &str, hold_for: Duration) -> thread::JoinHandle<()> {
    let key = super::advisory_key(shard);
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let url = url.to_owned();
    let holder = thread::spawn(move || {
        let mut client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        let mut tx = client.transaction().unwrap();
        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&key])
            .unwrap();
        locked_tx.send(()).unwrap();
        thread::sleep(hold_for);
        tx.commit().unwrap();
    });
    locked_rx.recv().unwrap();
    holder
}

/// THE pitfall regression test — needs no database. A sync `postgres::Client` is
/// created via `block_on`, which panics if run inside a tokio runtime. This test
/// runs `new()` from INSIDE a tokio runtime against a dead port: if the connect
/// happened on the caller's (runtime) thread it would PANIC; because the actor
/// thread owns the connect, it instead returns a clean `Err`. A valid URL on a
/// closed port gets past parsing into the real connect path.
#[tokio::test]
async fn connect_from_within_tokio_runtime_returns_err_not_panic() {
    let result =
        PostgresLedgerHeadStore::new("postgres://decern@127.0.0.1:1/decern?sslmode=disable");
    assert!(
        result.is_err(),
        "connecting to a dead port must return Err, not succeed"
    );
}

/// Drop-path regression (DB-gated). Under `decern-serve`'s `#[tokio::main]` the
/// store is BOTH constructed and dropped inside a tokio runtime. The sync
/// `postgres::Client` lives on the actor thread, so dropping the store here must
/// close the channel and join that thread cleanly — never abort with "Cannot
/// drop a runtime in a context where blocking is not allowed". A SIGABRT here
/// fails the whole test binary, as intended.
#[tokio::test]
async fn constructed_used_and_dropped_inside_runtime_does_not_abort() {
    let Some(url) = test_url() else {
        return;
    };
    let shard = uniq("droptest");
    let store = PostgresLedgerHeadStore::new(&url).unwrap();
    // Fully exercise the actor round-trip so the client is live before drop.
    store
        .with_shard(&shard, &mut |_cursor, _records| Ok(None))
        .unwrap();
    drop(store); // the Drop-inside-runtime path — must not abort.
}

#[test]
fn roundtrip_append_advances_cursor_and_persists_across_a_fresh_handle() {
    let Some(url) = test_url() else {
        return;
    };
    let shard = uniq("roundtrip");

    {
        let store = PostgresLedgerHeadStore::new(&url).unwrap();
        // First write sees genesis: no cursor, no records.
        let mut seen = None;
        store
            .with_shard(&shard, &mut |cursor, records| {
                seen = Some((cursor.cloned(), records.len()));
                Ok(Some((cursor_at(1, "h0"), "line-0".into())))
            })
            .unwrap();
        assert_eq!(seen, Some((None, 0)), "first write sees genesis");

        // The append is visible to the next call on the same handle.
        let mut after = None;
        store
            .with_shard(&shard, &mut |cursor, records| {
                after = Some((cursor.cloned(), records.len(), records[0].seq));
                Ok(None)
            })
            .unwrap();
        assert_eq!(after, Some((Some(cursor_at(1, "h0")), 1, 0)));
    }

    // A freshly-opened store (a NEW connection) sees the persisted state.
    let store = PostgresLedgerHeadStore::new(&url).unwrap();
    let mut reopened = None;
    store
        .with_shard(&shard, &mut |cursor, records| {
            reopened = Some((cursor.cloned(), records.to_vec()));
            Ok(None)
        })
        .unwrap();
    let (cursor, records) = reopened.unwrap();
    assert_eq!(cursor, Some(cursor_at(1, "h0")));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].seq, 0);
    assert_eq!(records[0].record_json, "line-0");
    assert!(store.list_shards().unwrap().contains(&shard));
}

#[test]
fn noop_and_error_write_nothing() {
    let Some(url) = test_url() else {
        return;
    };
    let shard = uniq("noop");
    let store = PostgresLedgerHeadStore::new(&url).unwrap();

    // A None decision writes nothing.
    store.with_shard(&shard, &mut |_, _| Ok(None)).unwrap();

    // An Err decision rolls back with no write.
    let err = store.with_shard(&shard, &mut |_, _| {
        Err(StoreError::Invalid("simulated".into()))
    });
    assert!(err.is_err());

    // Neither touched history: no head row, and the next call still sees genesis.
    assert!(!store.list_shards().unwrap().contains(&shard));
    let mut after = None;
    store
        .with_shard(&shard, &mut |c, r| {
            after = Some((c.cloned(), r.len()));
            Ok(None)
        })
        .unwrap();
    assert_eq!(after, Some((None, 0)));
}

#[test]
fn list_shards_is_sorted_and_only_committed() {
    let Some(url) = test_url() else {
        return;
    };
    let store = PostgresLedgerHeadStore::new(&url).unwrap();
    // Two committed shards (ordered so we can check the sort) plus one never-written.
    let base = uniq("list");
    let alpha = format!("{base}-aaa");
    let zeta = format!("{base}-zzz");
    let never = format!("{base}-never");
    for (shard, hash) in [(&zeta, "z1"), (&alpha, "a1")] {
        store
            .with_shard(shard, &mut |_, _| {
                Ok(Some((cursor_at(1, hash), "line".into())))
            })
            .unwrap();
    }
    store.with_shard(&never, &mut |_, _| Ok(None)).unwrap();

    let listed = store.list_shards().unwrap();
    // Globally sorted (assert on our own subset, since the table is shared).
    let mut ours: Vec<&String> = listed.iter().filter(|s| s.starts_with(&base)).collect();
    let expected = vec![&alpha, &zeta];
    ours.sort();
    assert_eq!(ours, expected, "committed shards only, sorted");
    assert!(!listed.contains(&never), "never-written shard is absent");
    // The full list is globally sorted, too.
    let mut sorted = listed.clone();
    sorted.sort();
    assert_eq!(listed, sorted);
}

/// THE crux: two SEPARATE store instances — hence two INDEPENDENT Postgres
/// connections — concurrently drive the read-then-append shape (read count → sleep →
/// append claiming that index) on the SAME shard. The sleep sits INSIDE `f`, on
/// the caller thread, so it is load-bearing here in a way a bare CAS could not
/// cover: it proves the `pg_advisory_xact_lock` is held across the whole
/// actor↔caller round trip, not merely around the SQL. Only a genuinely held
/// cross-connection lock yields gapless seqs with no lost/dup/forked head.
#[test]
fn two_instances_two_connections_serialize_the_critical_section() {
    let Some(url) = test_url() else {
        return;
    };
    // Several iterations, each on a fresh shard, so a subtly-broken lock reliably
    // fails rather than passing by luck once.
    for iteration in 0..5 {
        let shard = uniq(&format!("concurrency-{iteration}"));
        let a = Arc::new(PostgresLedgerHeadStore::new(&url).unwrap());
        let b = Arc::new(PostgresLedgerHeadStore::new(&url).unwrap());

        let mut handles = Vec::new();
        for store in [a.clone(), b.clone()] {
            for _ in 0..8 {
                let store = store.clone();
                let shard = shard.clone();
                handles.push(thread::spawn(move || {
                    store
                        .with_shard(&shard, &mut |cursor, records| {
                            let my_index = records.len();
                            // Widen the race window: a lock that did not span the read
                            // would let two callers observe the same len.
                            thread::sleep(Duration::from_millis(2));
                            let next_seq = cursor.map(|c| c.next_seq).unwrap_or(0) + 1;
                            Ok(Some((
                                cursor_at(next_seq, format!("h{my_index}")),
                                format!("record-{my_index}"),
                            )))
                        })
                        .unwrap();
                }));
            }
        }
        for h in handles {
            h.join().unwrap();
        }

        // Read back from a THIRD fresh connection.
        let c = PostgresLedgerHeadStore::new(&url).unwrap();
        let mut final_records = Vec::new();
        c.with_shard(&shard, &mut |_, records| {
            final_records = records.to_vec();
            Ok(None)
        })
        .unwrap();

        assert_eq!(
            final_records.len(),
            16,
            "no lost updates across two connections"
        );
        let mut seqs: Vec<u64> = final_records.iter().map(|r| r.seq).collect();
        seqs.sort_unstable();
        assert_eq!(
            seqs,
            (0..16).collect::<Vec<u64>>(),
            "strictly monotonic, no gaps, no dups"
        );
        let mut lines: Vec<&str> = final_records
            .iter()
            .map(|r| r.record_json.as_str())
            .collect();
        lines.sort_unstable();
        lines.dedup();
        assert_eq!(lines.len(), 16, "no two callers claimed the same index");
    }
}

/// Parity with the File backend's untrusted-shard-name test: punctuation-heavy
/// and non-ASCII tenant ids must round-trip through `with_shard` AND come back
/// from `list_shards` in the SAME order Rust's byte-lexicographic `sort()` gives.
/// This is the test that pins the `COLLATE "C"` ordering: a bare `ORDER BY shard`
/// on a non-`C` server locale sorts `-`/`/`/`:` differently and this fails.
#[test]
fn weird_shard_ids_round_trip_and_list_in_byte_order() {
    let Some(url) = test_url() else {
        return;
    };
    let store = PostgresLedgerHeadStore::new(&url).unwrap();
    // A shared unique prefix so we can filter our own rows out of the global list.
    let base = uniq("weird");
    let suffixes = [
        "../escape",
        "a/b",
        "/abs/path",
        "..",
        "normal",
        "tenant:with:colons",
        "utf8-Ω-λ",
        // Mixed case is the sharpest collation discriminator: a UCA locale sorts
        // these case-insensitively (a,A,b,B) while byte order (and the Memory/File
        // backends) give A,B,a,b. Without `COLLATE "C"` this list diverges.
        "Zeta",
        "alpha",
        "Beta",
        "gamma",
    ];
    let shards: Vec<String> = suffixes.iter().map(|s| format!("{base}|{s}")).collect();
    for shard in &shards {
        store
            .with_shard(shard, &mut |cursor, records| {
                assert!(cursor.is_none() && records.is_empty(), "fresh shard");
                Ok(Some((cursor_at(1, "h"), "line".into())))
            })
            .unwrap();
    }

    let listed = store.list_shards().unwrap();
    let ours: Vec<String> = listed
        .into_iter()
        .filter(|s| s.starts_with(&base))
        .collect();
    let mut expected = shards.clone();
    expected.sort(); // Rust byte-lexicographic order.
    assert_eq!(
        ours, expected,
        "list_shards must return byte-order, matching the Memory/File backends"
    );
}

/// Run `f` on its own thread and give up after `secs` rather than wait with it. A call left
/// waiting keeps whatever `f` holds, so a store it holds is never dropped (and its actor
/// never joined) while it waits.
fn within<T: Send + 'static>(secs: u64, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(secs)).ok()
}

/// An empty section on `shard`, given up after 30 seconds.
fn section_within(
    store: &Arc<PostgresLedgerHeadStore>,
    shard: &str,
) -> Option<Result<(), StoreError>> {
    let store = Arc::clone(store);
    let shard = shard.to_owned();
    within(30, move || store.with_shard(&shard, &mut |_, _| Ok(None)))
}

/// A shard that fails to load is answered as an error, and the store serves the next shard
/// (DB-gated). The caller waits for the load, so a failure before it has to be answered there:
/// answered anywhere else, the caller and the store's one connection each wait on the other,
/// and every later call waits behind them.
#[test]
fn a_shard_that_fails_to_load_is_an_error_and_the_store_serves_the_next() {
    let Some(url) = test_url() else {
        return;
    };
    let store = Arc::new(PostgresLedgerHeadStore::new(&url).unwrap());
    // A head row the store refuses to read. The test URLs are plaintext, as in CI.
    let broken = uniq("unloadable");
    let mut raw = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    raw.execute(
        "INSERT INTO decern_ledger_head (shard, next_seq, last_hash) VALUES ($1, -1, 'h')",
        &[&broken],
    )
    .unwrap();

    let refused = section_within(&store, &broken);
    // Left behind, the row would make every later boot against this database refuse.
    raw.execute(
        "DELETE FROM decern_ledger_head WHERE shard = $1",
        &[&broken],
    )
    .unwrap();
    let refused = refused.expect("a shard that failed to load left its caller waiting");
    assert!(
        matches!(&refused, Err(StoreError::Invalid(m)) if m.contains("negative")),
        "{refused:?}"
    );
    assert!(
        matches!(section_within(&store, &uniq("next")), Some(Ok(()))),
        "the store did not serve the next shard"
    );
    assert!(
        !store.has_failed(),
        "a shard that failed to load on an open connection failed the store"
    );
}

/// A store whose connection the database closed answers each section as an error rather than
/// waiting (DB-gated). It does not reconnect, so the next section fails too.
#[test]
fn a_store_whose_connection_was_closed_answers_each_section_as_an_error() {
    let Some(url) = test_url() else {
        return;
    };
    // Names the store's own connection, so only it is closed under tests running in parallel.
    let name = uniq("closed");
    let store = Arc::new(
        PostgresLedgerHeadStore::new(&with_param(&url, &format!("application_name={name}")))
            .unwrap(),
    );
    assert!(matches!(
        section_within(&store, &uniq("before")),
        Some(Ok(()))
    ));
    assert!(!store.has_failed());

    let mut raw = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    raw.execute(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = $1",
        &[&name],
    )
    .unwrap();
    let gone = (0..100).any(|_| {
        let left: i64 = raw
            .query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE application_name = $1",
                &[&name],
            )
            .unwrap()
            .get(0);
        left == 0 || {
            thread::sleep(Duration::from_millis(100));
            false
        }
    });
    assert!(gone, "the store's connection was not closed");

    for _ in 0..2 {
        assert!(
            matches!(section_within(&store, &uniq("after")), Some(Err(_))),
            "a section on a closed connection was not answered as an error"
        );
        // Set before the refusal is answered, so a liveness check after it sees it. The code
        // holds that order, not this test: reversed, the flag is still almost always set first.
        assert!(
            store.has_failed(),
            "a closed connection left the store healthy"
        );
    }
}

/// A store whose worker thread has stopped answers every section as an error, so it is failed
/// too (DB-gated): nothing restarts the thread.
#[test]
fn a_store_whose_worker_has_stopped_has_failed() {
    let Some(url) = test_url() else {
        return;
    };
    let store = Arc::new(PostgresLedgerHeadStore::new(&url).unwrap());
    assert!(!store.has_failed());
    store.jobs.send(super::Job::Shutdown).unwrap();
    let stopped = (0..100).any(|_| {
        store
            .handle
            .as_ref()
            .is_some_and(thread::JoinHandle::is_finished)
            || {
                thread::sleep(Duration::from_millis(50));
                false
            }
    });
    assert!(stopped, "the worker did not stop");
    assert!(
        store.has_failed(),
        "a stopped worker left the store healthy"
    );
    assert!(matches!(
        section_within(&store, &uniq("after")),
        Some(Err(_))
    ));
}

/// The cursor's key spans survive the head row, and the head-only section sees the cursor
/// `with_shard` sees and commits as it does (DB-gated).
#[test]
fn key_spans_round_trip_and_the_head_only_section_matches_with_shard() {
    let Some(url) = test_url() else {
        return;
    };
    let shard = uniq("headonly");
    let store = PostgresLedgerHeadStore::new(&url).unwrap();
    let spans = decern_store::ShardSigners {
        through: 1,
        spans: vec![decern_store::KeySpan {
            kid: "k1".into(),
            first_seq: 0,
        }],
    };
    store
        .with_shard_head(&shard, &mut |c| {
            assert!(c.is_none());
            Ok(Some((
                HeadCursor {
                    next_seq: 1,
                    last_hash: "h1".into(),
                    signers: Some(spans.clone()),
                },
                "line-0".into(),
            )))
        })
        .unwrap();
    let mut head_only = None;
    store
        .with_shard_head(&shard, &mut |c| {
            head_only = c.cloned();
            Ok(None)
        })
        .unwrap();
    let mut full = None;
    store
        .with_shard(&shard, &mut |c, records| {
            full = Some((c.cloned(), records.len()));
            Ok(None)
        })
        .unwrap();
    assert_eq!(head_only.as_ref().unwrap().signers, Some(spans));
    assert_eq!(full, Some((head_only, 1)));
}

/// Open a store, given up after `secs`.
/// A section that finds the actor's queue full is refused at once, where it would otherwise
/// wait behind every stalled section (DB-gated). The actor is stalled by another session
/// holding a shard's advisory lock, as a partitioned replica holds it.
#[test]
fn a_full_queue_refuses_a_section_at_once() {
    let Some(url) = test_url() else {
        return;
    };
    let store = Arc::new(PostgresLedgerHeadStore::with_bounds(&url, 1, Bounds::default()).unwrap());
    let stalled = uniq("stalled");
    let mut raw = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut holding = raw.transaction().unwrap();
    holding
        .execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&super::advisory_key(&stalled)],
        )
        .unwrap();

    let section = |shard: String| {
        let store = Arc::clone(&store);
        thread::spawn(move || store.with_shard(&shard, &mut |_, _| Ok(None)))
    };
    // The actor takes this job and waits in the database for the lock.
    let first = section(stalled.clone());
    thread::sleep(Duration::from_millis(300));
    // The queue, one deep, holds this one.
    let second = section(uniq("queued"));
    thread::sleep(Duration::from_millis(300));

    let refused = {
        let store = Arc::clone(&store);
        let shard = uniq("refused");
        within(5, move || store.with_shard(&shard, &mut |_, _| Ok(None)))
    }
    .expect("a section that found the queue full waited behind it");
    assert!(
        matches!(&refused, Err(StoreError::Io { err, .. }) if err.contains("queue is full")),
        "{refused:?}"
    );
    assert!(!store.has_failed(), "a full queue is not a failed store");

    holding.rollback().unwrap();
    assert!(first.join().unwrap().is_ok());
    assert!(second.join().unwrap().is_ok());
}

fn open_within(url: &str, secs: u64) -> Option<Result<(), StoreError>> {
    let url = url.to_owned();
    within(secs, move || PostgresLedgerHeadStore::new(&url).map(drop))
}

/// A boot that finds the `signers` column takes no lock on the head table, so a reader
/// holding the table open, a long query or a dump, does not hold the boot (DB-gated).
#[test]
fn a_boot_that_finds_the_column_waits_on_no_reader() {
    let Some(url) = test_url() else {
        return;
    };
    drop(PostgresLedgerHeadStore::new(&url).unwrap());
    let mut reader = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut open = reader.transaction().unwrap();
    open.query("SELECT 1 FROM decern_ledger_head LIMIT 1", &[])
        .unwrap();
    let booted = open_within(&url, 10);
    open.rollback().unwrap();
    assert!(
        matches!(booted, Some(Ok(()))),
        "a boot waited on a reader of the head table: {booted:?}"
    );
}

/// A boot that has to add the `signers` column gives up behind a reader and says what to
/// run, rather than wait with every append queued behind it; once the reader is gone it
/// adds the column (DB-gated). Run in a schema of its own, through the URL's search path.
#[test]
fn a_boot_that_must_add_the_column_gives_up_behind_a_reader() {
    let Some(url) = test_url() else {
        return;
    };
    let schema = uniq("upgrade");
    let mut raw = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    raw.batch_execute(&format!(
        "CREATE SCHEMA {schema}; \
         CREATE TABLE {schema}.decern_ledger_head (\
             shard TEXT PRIMARY KEY, next_seq BIGINT NOT NULL, last_hash TEXT NOT NULL);"
    ))
    .unwrap();
    let scoped = with_param(&url, &format!("options=-c%20search_path%3D{schema}"));

    let mut reader = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut open = reader.transaction().unwrap();
    open.query(&format!("SELECT 1 FROM {schema}.decern_ledger_head"), &[])
        .unwrap();
    let refused = open_within(&scoped, 30);
    open.rollback().unwrap();
    let added = open_within(&scoped, 30);
    let column: bool = raw
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_schema = $1 AND table_name = 'decern_ledger_head' \
             AND column_name = 'signers')",
            &[&schema],
        )
        .unwrap()
        .get(0);
    raw.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .unwrap();

    assert!(
        matches!(&refused, Some(Err(StoreError::Io { err, .. }))
            if err.contains("ALTER TABLE decern_ledger_head ADD COLUMN signers TEXT")),
        "{refused:?}"
    );
    assert!(matches!(added, Some(Ok(()))), "{added:?}");
    assert!(column, "the boot did not add the column");
}

/// Startup is bounded, with no database: a socket that accepts the connection and never
/// answers, the shape of a stalled server or a proxy with no backend, fails `new` at the
/// deadline instead of holding it. The holder keeps the connection open past the deadline;
/// the actor thread is left in its connect, as a start is, until the process ends.
#[test]
fn a_start_against_a_silent_socket_fails_at_the_deadline() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let holder = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_secs(4));
        drop(stream);
    });
    let url = format!("postgres://decern@127.0.0.1:{port}/decern?sslmode=disable");
    let bounds = Bounds {
        startup: Duration::from_secs(1),
        ..Bounds::default()
    };
    // (the lock wait and the stall bound keep their defaults)
    let started = Instant::now();
    let err = PostgresLedgerHeadStore::with_bounds(&url, 8, bounds)
        .err()
        .expect("a database that never answers fails the start");
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(1) && waited < Duration::from_secs(3),
        "failed at the deadline, not before and not long after: {waited:?}"
    );
    assert!(
        err.to_string().contains("not ready after 1s"),
        "the error names the deadline: {err}"
    );
    holder.join().unwrap();
}

/// A section waits a bounded time for its shard's lock. A second connection holds the lock
/// in an open transaction for three seconds; the store's section, allowed one, fails naming
/// the lock timeout, the store is not failed, and the actor serves the next section once the
/// holder commits. Without the bound the section would succeed after the holder's commit.
#[test]
fn a_section_waits_a_bounded_time_for_its_shard_lock() {
    let Some(url) = test_url() else {
        return;
    };
    let shard = uniq("lockwait");
    let bounds = Bounds {
        lock_wait: Duration::from_secs(1),
        ..Bounds::default()
    };
    let store = PostgresLedgerHeadStore::with_bounds(&url, 8, bounds).unwrap();

    let holder = hold_shard_lock(&url, &shard, Duration::from_secs(3));

    let started = Instant::now();
    let err = store
        .with_shard_head(&shard, &mut |_cursor| Ok(None))
        .expect_err("a held lock fails the section at its wait");
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(1) && waited < Duration::from_secs(3),
        "cancelled at the wait, before the holder commits: {waited:?}"
    );
    assert!(
        err.to_string().contains("lock timeout"),
        "the error names the lock timeout: {err}"
    );
    assert!(
        !store.has_failed(),
        "a cancelled wait is the section's error, not the store's"
    );

    holder.join().unwrap();
    store
        .with_shard_head(&shard, &mut |_cursor| Ok(None))
        .expect("the actor serves the next section");
}

/// A database call that outlives the stall bound reads as a stall, and the mark clears when
/// it returns. A second connection holds the shard's lock for three seconds; the store, with
/// a ten-second lock wait and a one-second stall bound, waits inside its lock call, is
/// stalled at a second and a half, and is not, a stall bound later, once the holder commits
/// and the section lands.
#[test]
fn a_database_call_past_the_stall_bound_reads_as_a_stall_until_it_returns() {
    let Some(url) = test_url() else {
        return;
    };
    let shard = uniq("stall");
    let bounds = Bounds {
        stall_after: Duration::from_secs(1),
        ..Bounds::default()
    };
    let store = Arc::new(PostgresLedgerHeadStore::with_bounds(&url, 8, bounds).unwrap());
    assert!(!store.is_stalled(), "idle is not stalled");

    let holder = hold_shard_lock(&url, &shard, Duration::from_secs(3));

    let waiter = Arc::clone(&store);
    let waiter_shard = shard.clone();
    let section =
        thread::spawn(move || waiter.with_shard_head(&waiter_shard, &mut |_cursor| Ok(None)));
    thread::sleep(Duration::from_millis(1500));
    assert!(
        store.is_stalled(),
        "a lock call running past the stall bound reads as a stall"
    );

    holder.join().unwrap();
    section
        .join()
        .unwrap()
        .expect("the section lands once the holder commits");
    // Past the stall bound again, with no call running: a mark that did not clear would
    // read as a stall here.
    thread::sleep(Duration::from_millis(1500));
    assert!(!store.is_stalled(), "the mark clears when the call returns");
    assert!(!store.has_failed(), "a stall is not a failure");
}

/// The caller's own decision is not timed: a section whose caller takes longer than the stall
/// bound to decide, the lock held and the transaction open meanwhile, does not read as a stall.
#[test]
fn a_slow_caller_does_not_read_as_a_stall() {
    let Some(url) = test_url() else {
        return;
    };
    let shard = uniq("slowcaller");
    let bounds = Bounds {
        stall_after: Duration::from_secs(1),
        ..Bounds::default()
    };
    let store = PostgresLedgerHeadStore::with_bounds(&url, 8, bounds).unwrap();
    let mut stalled_while_deciding = None;
    store
        .with_shard_head(&shard, &mut |_cursor| {
            thread::sleep(Duration::from_millis(1500));
            stalled_while_deciding = Some(store.is_stalled());
            Ok(None)
        })
        .expect("the section lands");
    assert_eq!(
        stalled_while_deciding,
        Some(false),
        "the caller's time is not the database's"
    );
    assert!(!store.is_stalled(), "nothing runs after the section");
}
