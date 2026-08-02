// SPDX-License-Identifier: Apache-2.0
//! Tests for the Postgres ledger-head store.
//!
//! Every test that needs a live database reads `DECERN_TEST_POSTGRES_URL` and
//! returns early (skips) when it is unset — so `cargo test --workspace` stays
//! green with NO database. The one exception is the connect-off-runtime
//! regression test below, which needs no database at all and MUST run everywhere.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::PostgresLedgerHeadStore;
use decern_store::{HeadCursor, LedgerHeadStore, StoreError};

/// A unique-per-test shard id, so tests sharing one database never collide (the
/// tables are shared and cargo runs tests in parallel). Never `TRUNCATE` — that
/// would corrupt a concurrently-running test.
fn uniq(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("test-{prefix}-{nanos}-{:?}", thread::current().id())
}

fn test_url() -> Option<String> {
    std::env::var("DECERN_TEST_POSTGRES_URL").ok()
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
/// fails the whole test binary, which is the point.
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
                Ok(Some((
                    HeadCursor {
                        next_seq: 1,
                        last_hash: "h0".into(),
                    },
                    "line-0".into(),
                )))
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
        assert_eq!(
            after,
            Some((
                Some(HeadCursor {
                    next_seq: 1,
                    last_hash: "h0".into()
                }),
                1,
                0
            ))
        );
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
    assert_eq!(
        cursor,
        Some(HeadCursor {
            next_seq: 1,
            last_hash: "h0".into()
        })
    );
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
                Ok(Some((
                    HeadCursor {
                        next_seq: 1,
                        last_hash: hash.into(),
                    },
                    "line".into(),
                )))
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
                                HeadCursor {
                                    next_seq,
                                    last_hash: format!("h{my_index}"),
                                },
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
                Ok(Some((
                    HeadCursor {
                        next_seq: 1,
                        last_hash: "h".into(),
                    },
                    "line".into(),
                )))
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
