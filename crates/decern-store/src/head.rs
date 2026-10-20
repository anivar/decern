// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The ledger head store: per-shard head cursors and the critical section the
//! sharded ledger appends through.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::StoreError;
use crate::fsio::{atomic_write_json, io, poisoned, with_write_lock};

/// One shard's chain-continuation cursor for the hosted, horizontally-scaled
/// ledger. A "shard" is a tenant's own hash chain (or the reserved
/// `__system__` shard for entries with no resolvable tenant) — the same
/// `(prev_hash) -> hash` chaining `decern_ledger::Ledger` uses on a single node, now
/// keyed so more than one `decern-server` replica can safely extend the SAME chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeadCursor {
    /// The next sequence number this shard will assign.
    pub next_seq: u64,
    /// The current chain head hash — the `prev` every subsequent append chains onto.
    pub last_hash: String,
}

/// One durably-stored record row in a shard's chain — the exact byte-stable
/// JSON line `decern_ledger::Ledger::append` would have written to its file,
/// unchanged, just addressed by `(shard, seq)` instead of a file offset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRecord {
    pub seq: u64,
    pub record_json: String,
}

/// Cross-process-safe, cross-replica critical-section coordination for a
/// sharded, hosted ledger.
///
/// This is NOT a key-value store or a bare compare-and-swap. Two invariants
/// both require the SAME thing — a held, exclusive lock on the shard for the
/// duration of a read-then-write critical section, not just atomicity of the
/// final write:
/// - **Chain integrity**: a hash chain is inherently sequential (entry N's
///   hash covers entry N-1's), so two replicas racing to extend the same
///   shard must never interleave.
/// - **A read-then-decide-then-append gate**: a caller that reads a shard's
///   accumulated state, decides against it, and appends — ALL under one lock, so
///   two concurrent callers can't both read the same pre-append state and both act
///   on it. A bare CAS-on-append (retry-and-re-chain on conflict) fixes chain
///   integrity but NOT this: a losing retry re-chains its hash onto the winner's
///   new cursor without ever re-running the caller's decision, which silently lets
///   both acts through — the exact bug this whole design exists to prevent,
///   reintroduced by a too-narrow fix.
///
/// [`with_shard`](LedgerHeadStore::with_shard) is therefore a held per-shard
/// lock/transaction (`pg_advisory_xact_lock` in the Postgres backend),
/// generalizing the single-process `Mutex<Ledger>` every `AppState.ledger`
/// caller already holds today to work correctly across replicas. Hash+sign is
/// sub-millisecond, so the lock's hold time is short regardless of caller.
///
/// Implemented by a Postgres backend (`decern-store-postgres`), by
/// [`MemoryLedgerHeadStore`] here (fast, dependency-free tests, exercised by
/// `decern-ledger`'s sharded-ledger test suite), and by
/// [`FileLedgerHeadStore`] (a persistent **single-host, multi-process**
/// reference: file-lock-held per-shard critical sections on one machine). The
/// original reasoning still holds and bounds each backend's scope: sharding
/// exists to solve MULTI-*HOST* coordination, which a single sovereign node
/// never needs — the existing single-file `Ledger` is untouched and remains
/// the sovereign default; the File backend adds durable multi-*process*
/// coordination on one host but is NOT multi-host (that stays Postgres).
/// What to write at the end of a [`LedgerHeadStore::with_shard`] critical
/// section: the new cursor plus the exact byte-stable record line, or `None`
/// for a pure read / a decision that appends nothing.
pub type ShardWrite = Option<(HeadCursor, String)>;

/// The critical-section callback `with_shard` runs under the shard's
/// exclusive lock — named as a type alias per clippy's `type_complexity`,
/// not because callers construct it directly (they pass a closure; see
/// [`LedgerHeadStore::with_shard`]'s own doc for the full contract).
pub type ShardCriticalSection<'a> =
    dyn FnMut(Option<&HeadCursor>, &[StoredRecord]) -> Result<ShardWrite, StoreError> + 'a;

pub trait LedgerHeadStore: Send + Sync {
    /// Run `f` with EXCLUSIVE access to `shard`: no other `with_shard` call on
    /// the SAME shard, from any replica, can proceed until this returns. `f`
    /// sees the shard's current cursor (`None` = genesis) and its full record
    /// history (seq order — what `net_spend`-style accumulation scans over),
    /// and returns what to write, if anything:
    /// - `Some((new_cursor, record_json))` — append `record_json` (the exact
    ///   byte-stable line to store), advancing the shard to `new_cursor`.
    /// - `None` — nothing to write (a pure read, or a decision that appends
    ///   nothing, e.g. a request denied before any obligation is recorded).
    ///
    /// `f` returning `Err` aborts with no write (mirrors a `?`-short-circuited
    /// critical section under today's `MutexGuard` — the lock still releases,
    /// nothing is committed). Capture whatever response payload the caller
    /// needs via the closure's environment (a `let mut` in the enclosing
    /// scope) — this trait carries no opinion about what callers return.
    fn with_shard(&self, shard: &str, f: &mut ShardCriticalSection<'_>) -> Result<(), StoreError>;

    /// Every shard with any committed history, sorted for a deterministic
    /// iteration order (callers building a Merkle tree or any other
    /// order-sensitive aggregate over "every tenant" need the SAME order on
    /// every replica). This is the authoritative shard set for an audit sweep —
    /// deliberately the ledger's own committed history, not a scan of some other
    /// live tenant list: a tenant since removed elsewhere can still have committed
    /// ledger history that must not silently drop out of a cross-tenant aggregate.
    fn list_shards(&self) -> Result<Vec<String>, StoreError>;
}

/// One shard's state for [`MemoryLedgerHeadStore`].
#[derive(Default)]
struct MemoryShard {
    cursor: Option<HeadCursor>,
    records: Vec<StoredRecord>,
}

/// Volatile `LedgerHeadStore` — tests only (no persistence, no cross-process
/// coordination; a durable deployment uses [`FileLedgerHeadStore`] for a single
/// host or the Postgres backend for multiple hosts). Each
/// shard gets its own `Mutex`, created lazily, so `with_shard` on DIFFERENT
/// shards never contends — only same-shard callers block on each other,
/// matching the real backend's per-shard-lock semantics (not a single global
/// lock across every tenant, which would misrepresent the production shape in
/// a way that could hide a cross-shard-parallelism regression in a caller).
#[derive(Default)]
pub struct MemoryLedgerHeadStore {
    shards: Mutex<BTreeMap<String, std::sync::Arc<Mutex<MemoryShard>>>>,
}

impl MemoryLedgerHeadStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn shard_lock(&self, shard: &str) -> Result<std::sync::Arc<Mutex<MemoryShard>>, StoreError> {
        let mut shards = self.shards.lock().map_err(poisoned)?;
        Ok(shards
            .entry(shard.to_owned())
            .or_insert_with(|| std::sync::Arc::new(Mutex::new(MemoryShard::default())))
            .clone())
    }
}

impl LedgerHeadStore for MemoryLedgerHeadStore {
    fn with_shard(&self, shard: &str, f: &mut ShardCriticalSection<'_>) -> Result<(), StoreError> {
        let lock = self.shard_lock(shard)?;
        // Held for the whole critical section — the point of the trait.
        let mut state = lock.lock().map_err(poisoned)?;
        if let Some((new_cursor, record_json)) = f(state.cursor.as_ref(), &state.records)? {
            state.records.push(StoredRecord {
                seq: new_cursor.next_seq.saturating_sub(1),
                record_json,
            });
            state.cursor = Some(new_cursor);
        }
        Ok(())
    }

    fn list_shards(&self) -> Result<Vec<String>, StoreError> {
        let shards = self.shards.lock().map_err(poisoned)?;
        // `shard_lock` lazily inserts an empty entry for ANY `with_shard`
        // call, including a pure read on a shard nothing has ever committed
        // to — filter those out so this matches the Postgres backend (which
        // only ever gets a `decern_ledger_head` row on an actual write) and the
        // trait's own "committed history" contract.
        let mut out = Vec::new();
        for (shard, state) in shards.iter() {
            let has_history = state.lock().map_err(poisoned)?.cursor.is_some();
            if has_history {
                out.push(shard.clone());
            }
        }
        // `BTreeMap` keys already iterate sorted, and the filter above
        // preserves that order.
        Ok(out)
    }
}

// ===================== single-host file ledger head store ==================

/// Hex-encode an untrusted shard id into a filesystem-safe stem.
///
/// `shard` is a tenant id and is UNTRUSTED — used raw as a filename it is a
/// path-traversal primitive (`../evil`, `a/b`, an absolute path). Lowercase
/// hex of the UTF-8 bytes maps every possible shard to a stem drawn from
/// `[0-9a-f]` only: no separators, no `..`, no leading dot — so the join can
/// never escape `root`, and the mapping is total and reversible (see
/// [`shard_from_hex`]) for [`FileLedgerHeadStore::list_shards`].
fn shard_to_hex(shard: &str) -> String {
    let mut s = String::with_capacity(shard.len() * 2);
    for b in shard.as_bytes() {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Inverse of [`shard_to_hex`]. Fails closed on any non-hex or odd-length stem
/// rather than skipping it: `list_shards` is the authoritative shard set for a
/// commit-every-tenant audit sweep, so a stem we cannot decode is a real
/// integrity fault (foreign file, corruption), never something to silently drop
/// — that would be exactly the "history drops out of the aggregate" failure the
/// trait doc warns against.
fn shard_from_hex(stem: &str) -> Result<String, StoreError> {
    let bytes = stem.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(StoreError::Invalid(format!(
            "ledger shard file stem {stem:?} is not valid hex (odd length)"
        )));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16);
        let lo = (pair[1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => out.push((h * 16 + l) as u8),
            _ => {
                return Err(StoreError::Invalid(format!(
                    "ledger shard file stem {stem:?} is not valid hex"
                )));
            }
        }
    }
    String::from_utf8(out).map_err(|e| {
        StoreError::Invalid(format!(
            "ledger shard file stem {stem:?} decodes to non-UTF-8: {e}"
        ))
    })
}

/// The persisted state of one shard: its cursor and full record history, in one
/// JSON object per shard file.
#[derive(Default, Serialize, Deserialize)]
struct ShardState {
    cursor: Option<HeadCursor>,
    records: Vec<StoredRecord>,
}

/// **Single-host, multi-process** persistent `LedgerHeadStore` — the durable
/// reference backend for the sharded ledger on ONE machine.
///
/// The whole point is the lock. [`with_shard`](FileLedgerHeadStore::with_shard)
/// holds an **exclusive file lock (`File::lock`) on a per-shard
/// sidecar for the ENTIRE critical section** — acquire → read the shard's
/// cursor+records FRESH from disk → run `f` → durably write → release. That
/// gives cross-process exclusion on one host: two `decern-server` processes (or
/// an operator CLI) each open their OWN lock fd and genuinely mutually exclude,
/// so a hash chain can never fork and a read-total-then-append critical section
/// can never both-read-the-same-total. This is a HELD lock across the read, not
/// a last-writer-wins rename (two writers each read head=N, both write N+1, one
/// silently clobbered → forked ledger — the exact failure this trait prevents).
///
/// **Scope / honesty.** The lock is host-local, so this backend is single-host
/// multi-process. It is NOT a multi-*host* distributed store: a second machine's
/// lock on its own filesystem does not see this one's. Multi-host coordination is
/// `decern-store-postgres`, behind this same trait, which serializes a shard with
/// `pg_advisory_xact_lock`. `File::lock` is `flock` on Unix and `LockFileEx` on
/// Windows; CI exercises the exclusion, between two handles in one process, on
/// Linux only.
///
/// **On-disk layout** (all inside `root`, shard ids hex-encoded — see
/// `shard_to_hex` — so an untrusted tenant id can never traverse out):
/// - `<root>/<hex-shard>.shard` — the shard's `{cursor, records}` as one JSON
///   object, rewritten wholesale on each append via `atomic_write_json`
///   (temp-file + fsync + atomic rename + parent-dir fsync).
/// - `<root>/<hex-shard>.lock` — the stable per-shard advisory-lock sidecar
///   (never renamed, so the lock stays on one inode); its content is unused.
/// - `<root>/<hex-shard>.tmp` — `atomic_write_json`'s transient sibling.
///
/// **Whole-file rewrite is a deliberate choice for a terse reference backend,
/// not an oversight.** An append re-serializes the shard's whole record vector,
/// O(n) per append. The defense is durability integrity: atomic rename is never
/// torn, whereas an in-place `.jsonl` append can leave a half-written final line
/// after a crash. A high-write production deployment uses the Postgres backend
/// (append-a-row, no rewrite); this file backend is sized for a sovereign single
/// host, matching the rest of this crate's File* backends.
pub struct FileLedgerHeadStore {
    root: PathBuf,
}

impl FileLedgerHeadStore {
    /// Create (or reopen) a file ledger head store rooted at `root`, an
    /// existing-or-created directory holding the per-shard files above.
    ///
    /// Signature note: `new(root) -> io::Result<Self>`; the other File*
    /// backends in this crate use `open(path) -> Result<_, StoreError>` — a
    /// deliberate deviation kept to match this backend's specified signature.
    pub fn new(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_owned();
        fs::create_dir_all(&root)?;
        Ok(FileLedgerHeadStore { root })
    }

    /// The `<root>/<hex-shard>.shard` data path. Rejects an empty shard id
    /// (its hex is `""`, giving `<root>/.shard` — a dotfile with no extension
    /// that `list_shards` would miss and `with_extension` would mangle), so the
    /// stem is always a non-empty hex string with a real `.shard` extension.
    fn shard_path(&self, shard: &str) -> Result<PathBuf, StoreError> {
        if shard.is_empty() {
            return Err(StoreError::Invalid(
                "ledger shard id must not be empty".into(),
            ));
        }
        Ok(self.root.join(format!("{}.shard", shard_to_hex(shard))))
    }
}

/// Read a shard's persisted state fresh from disk. A missing file is genesis
/// (empty state); a present-but-unparseable file fails closed.
fn read_shard_state(path: &Path) -> Result<ShardState, StoreError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| StoreError::Serde(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ShardState::default()),
        Err(e) => Err(io(path, e)),
    }
}

impl LedgerHeadStore for FileLedgerHeadStore {
    fn with_shard(&self, shard: &str, f: &mut ShardCriticalSection<'_>) -> Result<(), StoreError> {
        let path = self.shard_path(shard)?;
        // `with_write_lock` opens `<path>.lock` FRESH on every call and holds an
        // exclusive `flock` for the whole closure. Opening the lock fd per call
        // is load-bearing, NOT incidental: `flock` is per-open-file-description,
        // so a cached/re-used fd would re-lock the same OFD immediately and
        // silently destroy same-process exclusion between two store instances —
        // never cache the lock handle in the struct.
        with_write_lock(&path, || {
            // Read FRESH from disk under the lock — never from an in-process
            // cache — so a commit by another process/replica is always seen.
            let mut state = read_shard_state(&path)?;
            if let Some((new_cursor, record_json)) = f(state.cursor.as_ref(), &state.records)? {
                state.records.push(StoredRecord {
                    // Verbatim from MemoryLedgerHeadStore: the record's seq is
                    // the cursor's next_seq minus one.
                    seq: new_cursor.next_seq.saturating_sub(1),
                    record_json,
                });
                state.cursor = Some(new_cursor);
                // Durable before the lock releases: fsync'd temp + atomic rename
                // + parent-dir fsync, so a committed cursor survives a crash.
                atomic_write_json(&path, &state)?;
            }
            Ok(())
        })
    }

    fn list_shards(&self) -> Result<Vec<String>, StoreError> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(io(&self.root, e)),
        };
        for entry in entries {
            let entry = entry.map_err(|e| io(&self.root, e))?;
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            // Only shard DATA files; skip the `.lock`/`.tmp` sidecars.
            let Some(stem) = name.strip_suffix(".shard") else {
                continue;
            };
            // Fail closed on an undecodable stem (see `shard_from_hex`): a shard
            // whose history exists must never silently drop from the audit set.
            let shard = shard_from_hex(stem)?;
            // A `.shard` file exists only after an actual commit (atomic_write is
            // reached solely on a `Some` write), but confirm committed history to
            // exactly mirror the Memory backend's `cursor.is_some()` filter.
            if read_shard_state(&entry.path())?.cursor.is_some() {
                out.push(shard);
            }
        }
        out.sort();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::tmp;

    #[test]
    fn ledger_head_store_genesis_is_none_and_first_write_commits() {
        let s = MemoryLedgerHeadStore::new();
        let mut seen_genesis = None;
        s.with_shard("acme", &mut |cursor, records| {
            seen_genesis = Some((cursor.cloned(), records.len()));
            Ok(Some((
                HeadCursor {
                    next_seq: 1,
                    last_hash: "h0".into(),
                },
                "line-0".into(),
            )))
        })
        .unwrap();
        assert_eq!(seen_genesis, Some((None, 0)));

        // The write landed: a second with_shard now sees it.
        let mut seen_after = None;
        s.with_shard("acme", &mut |cursor, records| {
            seen_after = Some((cursor.cloned(), records.len()));
            Ok(None)
        })
        .unwrap();
        assert_eq!(
            seen_after,
            Some((
                Some(HeadCursor {
                    next_seq: 1,
                    last_hash: "h0".into()
                }),
                1
            ))
        );
    }

    #[test]
    fn ledger_head_store_noop_and_error_write_nothing() {
        let s = MemoryLedgerHeadStore::new();
        // A pure read (Ok(None)) writes nothing.
        s.with_shard("acme", &mut |_, _| Ok(None)).unwrap();
        // An error also writes nothing (mirrors a `?`-short-circuited critical
        // section under a MutexGuard: the lock releases, nothing commits).
        let err = s.with_shard("acme", &mut |_, _| {
            Err(StoreError::Invalid("simulated failure".into()))
        });
        assert!(err.is_err());

        let mut cursor_after = None;
        s.with_shard("acme", &mut |c, r| {
            cursor_after = Some((c.cloned(), r.len()));
            Ok(None)
        })
        .unwrap();
        assert_eq!(cursor_after, Some((None, 0)));
    }

    #[test]
    fn ledger_head_store_shards_are_isolated() {
        let s = MemoryLedgerHeadStore::new();
        for (shard, hash) in [("tenant-a", "a1"), ("tenant-b", "b1")] {
            s.with_shard(shard, &mut |_, _| {
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
        let mut a = None;
        s.with_shard("tenant-a", &mut |c, _| {
            a = c.cloned();
            Ok(None)
        })
        .unwrap();
        assert_eq!(a.unwrap().last_hash, "a1");
        let mut sys = None;
        s.with_shard("__system__", &mut |c, _| {
            sys = Some(c.cloned());
            Ok(None)
        })
        .unwrap();
        assert_eq!(sys, Some(None));
    }

    #[test]
    fn ledger_head_store_list_shards_returns_only_shards_with_committed_history_sorted() {
        let s = MemoryLedgerHeadStore::new();
        for (shard, hash) in [("zeta", "z1"), ("alpha", "a1")] {
            s.with_shard(shard, &mut |_, _| {
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
        // A pure read (no write) on a never-written shard must NOT make it
        // appear as if it had committed history.
        s.with_shard("never-written", &mut |_, _| Ok(None)).unwrap();

        assert_eq!(
            s.list_shards().unwrap(),
            vec!["alpha".to_string(), "zeta".to_string()],
            "must be sorted and must exclude a shard that was only ever read, never written"
        );
    }

    /// The property the whole redesign exists for: `with_shard` on the SAME
    /// shard from concurrent threads must fully serialize the read-then-write
    /// critical section — not just avoid corrupting the final write. This is
    /// exactly a "read accumulated state, decide, append" shape:
    /// each thread reads the current record count, computes "my index" from
    /// it, sleeps (widening the race window a CAS-with-retry would NOT close),
    /// then appends claiming that index. If `with_shard` only serialized the
    /// WRITE (a bare CAS) rather than holding the lock across the read too,
    /// every thread would read the same starting count and produce duplicate/
    /// lost indices — exactly a double-spend past a budget ceiling.
    #[test]
    fn ledger_head_store_with_shard_serializes_the_whole_read_then_write_critical_section() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(MemoryLedgerHeadStore::new());
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let store = store.clone();
                thread::spawn(move || {
                    store
                        .with_shard("contended", &mut |cursor, records| {
                            let my_index = records.len();
                            // Widen the race window: a lock that only protects the
                            // final write (not this read) would let every thread
                            // observe the same `records.len()` here.
                            thread::sleep(std::time::Duration::from_micros(200));
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
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        let mut final_records = Vec::new();
        store
            .with_shard("contended", &mut |_, records| {
                final_records = records.to_vec();
                Ok(None)
            })
            .unwrap();

        // 16 threads, no lost updates, no duplicate indices, no gaps.
        assert_eq!(final_records.len(), 16);
        let mut seqs: Vec<u64> = final_records.iter().map(|r| r.seq).collect();
        seqs.sort_unstable();
        assert_eq!(seqs, (0..16).collect::<Vec<u64>>());
        let mut hashes: Vec<&str> = final_records
            .iter()
            .map(|r| r.record_json.as_str())
            .collect();
        hashes.sort_unstable();
        hashes.dedup();
        assert_eq!(hashes.len(), 16, "no two threads claimed the same index");
    }

    #[test]
    fn ledger_head_store_different_shards_do_not_contend() {
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration, Instant};

        let store = Arc::new(MemoryLedgerHeadStore::new());
        let start = Instant::now();
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let store = store.clone();
                thread::spawn(move || {
                    store
                        .with_shard(&format!("tenant-{i}"), &mut |_, _| {
                            thread::sleep(Duration::from_millis(20));
                            Ok(None)
                        })
                        .unwrap();
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        // 8 DIFFERENT shards each holding 20ms: if they contended on one lock
        // this would take >=160ms; distinct per-shard locks keep it close to
        // 20ms. Generous bound for CI jitter.
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "different shards appear to be contending on a shared lock: {:?}",
            start.elapsed()
        );
    }

    // ===================== FileLedgerHeadStore tests =======================

    fn tmp_dir(name: &str) -> PathBuf {
        let dir = tmp(name);
        std::fs::remove_dir_all(&dir).ok();
        dir
    }

    #[test]
    fn file_ledger_head_store_roundtrips_and_persists_across_a_fresh_handle() {
        let root = tmp_dir("fhs-roundtrip");
        {
            let s = FileLedgerHeadStore::new(&root).unwrap();
            let mut seen = None;
            s.with_shard("acme", &mut |cursor, records| {
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
            s.with_shard("acme", &mut |cursor, records| {
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
        // A freshly-opened store on the SAME root sees the persisted state.
        let s = FileLedgerHeadStore::new(&root).unwrap();
        let mut reopened = None;
        s.with_shard("acme", &mut |cursor, records| {
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
        assert_eq!(s.list_shards().unwrap(), vec!["acme".to_string()]);
    }

    #[test]
    fn file_ledger_head_store_noop_and_error_write_nothing() {
        let root = tmp_dir("fhs-noop");
        let s = FileLedgerHeadStore::new(&root).unwrap();
        s.with_shard("acme", &mut |_, _| Ok(None)).unwrap();
        let err = s.with_shard("acme", &mut |_, _| {
            Err(StoreError::Invalid("simulated".into()))
        });
        assert!(err.is_err());
        // Nothing committed → not a shard with history, no data file.
        assert!(s.list_shards().unwrap().is_empty());
        let mut after = None;
        s.with_shard("acme", &mut |c, r| {
            after = Some((c.cloned(), r.len()));
            Ok(None)
        })
        .unwrap();
        assert_eq!(after, Some((None, 0)));
    }

    #[test]
    fn file_ledger_head_store_list_shards_sorted_and_only_committed() {
        let root = tmp_dir("fhs-list");
        let s = FileLedgerHeadStore::new(&root).unwrap();
        for (shard, hash) in [("zeta", "z1"), ("alpha", "a1")] {
            s.with_shard(shard, &mut |_, _| {
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
        s.with_shard("never-written", &mut |_, _| Ok(None)).unwrap();
        assert_eq!(
            s.list_shards().unwrap(),
            vec!["alpha".to_string(), "zeta".to_string()]
        );
    }

    /// THE crux: two SEPARATE store instances on the SAME root — so each opens
    /// its OWN `flock` fd and cross-fd advisory locking is genuinely exercised
    /// (sharing one instance would not test cross-process exclusion) —
    /// concurrently drive the read-then-append shape (read count → sleep → append
    /// claiming that index) on the SAME shard. A held cross-fd lock is the only
    /// thing that yields no lost/duplicate indices and a gapless seq range.
    #[test]
    fn file_ledger_head_store_two_instances_same_root_fully_serialize_the_critical_section() {
        use std::sync::Arc;
        use std::thread;

        let root = tmp_dir("fhs-concurrency");
        // Run several iterations to make a broken lock reliably fail.
        for _ in 0..8 {
            std::fs::remove_dir_all(&root).ok();
            let a = Arc::new(FileLedgerHeadStore::new(&root).unwrap());
            let b = Arc::new(FileLedgerHeadStore::new(&root).unwrap());

            let mut handles = Vec::new();
            for store in [a.clone(), b.clone()] {
                for _ in 0..8 {
                    let store = store.clone();
                    handles.push(thread::spawn(move || {
                        store
                            .with_shard("contended", &mut |cursor, records| {
                                let my_index = records.len();
                                // Widen the race window: a lock that did not span
                                // the read would let two callers see the same len.
                                thread::sleep(std::time::Duration::from_micros(200));
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

            // Read back from a THIRD fresh handle.
            let c = FileLedgerHeadStore::new(&root).unwrap();
            let mut final_records = Vec::new();
            c.with_shard("contended", &mut |_, records| {
                final_records = records.to_vec();
                Ok(None)
            })
            .unwrap();

            assert_eq!(final_records.len(), 16, "no lost updates across two fds");
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

    #[test]
    fn file_ledger_head_store_different_shards_do_not_block_each_other() {
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration, Instant};

        let root = tmp_dir("fhs-isolation");
        let store = Arc::new(FileLedgerHeadStore::new(&root).unwrap());
        let start = Instant::now();
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let store = store.clone();
                thread::spawn(move || {
                    store
                        .with_shard(&format!("tenant-{i}"), &mut |_, _| {
                            thread::sleep(Duration::from_millis(20));
                            Ok(None)
                        })
                        .unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        // 8 distinct shards, 20ms each: a single shared lock would need >=160ms.
        assert!(
            start.elapsed() < Duration::from_millis(120),
            "different shards appear to contend: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn file_ledger_head_store_untrusted_shard_names_stay_inside_root_and_round_trip() {
        let root = tmp_dir("fhs-pathsafety");
        let s = FileLedgerHeadStore::new(&root).unwrap();
        // Path-traversal-shaped tenant ids must be encoded, not used raw.
        for shard in ["../escape", "a/b", "/abs/path", "..", "normal"] {
            s.with_shard(shard, &mut |_, _| {
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
        // Every shard file materialized INSIDE root (no escape), stem is pure hex.
        let mut on_disk = 0;
        for entry in std::fs::read_dir(&root).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(stem) = name.strip_suffix(".shard") {
                assert!(
                    stem.bytes().all(|b| b.is_ascii_hexdigit()),
                    "shard stem must be pure hex, got {stem:?}"
                );
                on_disk += 1;
            }
            assert!(entry.path().starts_with(&root), "file escaped root: {name}");
        }
        assert_eq!(on_disk, 5);
        // …and they all decode back through list_shards.
        let mut listed = s.list_shards().unwrap();
        listed.sort();
        let mut expected = vec!["../escape", "a/b", "/abs/path", "..", "normal"];
        expected.sort();
        assert_eq!(listed, expected);
    }

    #[test]
    fn file_ledger_head_store_rejects_empty_shard_id() {
        let root = tmp_dir("fhs-empty");
        let s = FileLedgerHeadStore::new(&root).unwrap();
        assert!(s.with_shard("", &mut |_, _| Ok(None)).is_err());
    }

    #[test]
    fn shard_hex_round_trips_arbitrary_bytes() {
        for shard in ["", "acme", "../x", "a/b", "tenant:with:colons", "utf8-Ω-λ"] {
            assert_eq!(shard_from_hex(&shard_to_hex(shard)).unwrap(), shard);
        }
        // Odd-length / non-hex stems fail closed, never silently skipped.
        assert!(shard_from_hex("abc").is_err());
        assert!(shard_from_hex("zz").is_err());
    }
}
