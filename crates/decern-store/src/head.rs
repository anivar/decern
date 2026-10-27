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
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct HeadCursor {
    /// The next sequence number this shard will assign.
    pub next_seq: u64,
    /// The current chain head hash — the `prev` every subsequent append chains onto.
    pub last_hash: String,
    /// The keys that have signed this shard, so an append can check that its key may
    /// follow the last one without reading the shard's history. `None` from a writer that
    /// does not keep them, including every release before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signers: Option<ShardSigners>,
}

/// The keys that have signed a shard, each from the first record it signed, as of
/// `through` records. A reader trusts them only while `through` equals the cursor's
/// `next_seq`: a writer that does not keep them advances the cursor and leaves them behind.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ShardSigners {
    pub through: u64,
    pub spans: Vec<KeySpan>,
}

/// One key's run in a shard: its key id, and the sequence number of the first record of
/// the run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeySpan {
    pub kid: String,
    pub first_seq: u64,
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

/// The critical-section callback [`LedgerHeadStore::with_shard_head`] runs: the shard's
/// cursor alone, under the same exclusive lock.
pub type HeadCriticalSection<'a> =
    dyn FnMut(Option<&HeadCursor>) -> Result<ShardWrite, StoreError> + 'a;

pub trait LedgerHeadStore: Send + Sync {
    /// Run `f` with EXCLUSIVE access to `shard`: no other `with_shard` call on
    /// the SAME shard, from any replica, can proceed until this returns. `f`
    /// sees the shard's current cursor (`None` = genesis) and its full record
    /// history in seq order, for a caller that decides from it, and returns what
    /// to write, if anything:
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

    /// [`with_shard`](LedgerHeadStore::with_shard) for a caller that decides from the
    /// cursor alone, as an append does: the same exclusive lock and the same write, without
    /// the history. A backend overrides it to skip reading the records; the default reads
    /// the history and passes over it.
    fn with_shard_head(
        &self,
        shard: &str,
        f: &mut HeadCriticalSection<'_>,
    ) -> Result<(), StoreError> {
        self.with_shard(shard, &mut |cursor, _records| f(cursor))
    }

    /// Every shard with any committed history, sorted for a deterministic
    /// iteration order (callers building a Merkle tree or any other
    /// order-sensitive aggregate over "every tenant" need the SAME order on
    /// every replica). This is the authoritative shard set for an audit sweep —
    /// deliberately the ledger's own committed history, not a scan of some other
    /// live tenant list: a tenant since removed elsewhere can still have committed
    /// ledger history that must not silently drop out of a cross-tenant aggregate.
    fn list_shards(&self) -> Result<Vec<String>, StoreError>;

    /// Whether the store can serve no section again until the process restarts, so a
    /// liveness check on it restarts the process. A store that recovers in-process, or keeps
    /// no state that can break, never says so.
    fn has_failed(&self) -> bool {
        false
    }
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

/// A shard as releases before the cursor-and-log layout stored it: its cursor and full
/// record history, in one JSON object per `<hex-shard>.shard` file. Read as it is, and
/// converted on the shard's next append.
#[derive(Default, Serialize, Deserialize)]
struct LegacyShard {
    cursor: Option<HeadCursor>,
    records: Vec<StoredRecord>,
}

/// What every shard in this layout keeps at its `.shard` path, written before its first
/// record and when an earlier-layout shard is converted: a file a release that reads only the
/// old layout fails to parse, so it refuses the store rather than read the shard as empty.
#[derive(Serialize)]
struct MovedMarker {
    records: &'static str,
}

const MOVED: MovedMarker = MovedMarker {
    records: "moved to the .head and .log files beside this one; read by decern 0.7.0 or later",
};

/// One shard's commit record in the file backend: its cursor, and how many bytes of its
/// log hold the cursor's records. Rewritten atomically after each append, it is the commit
/// point: log bytes past `log_len` were never committed. A head with no cursor is a shard
/// created and not yet appended to.
#[derive(Serialize, Deserialize)]
struct FileHead {
    cursor: Option<HeadCursor>,
    log_len: u64,
}

/// **Single-host, multi-process** persistent `LedgerHeadStore` — the durable
/// reference backend for the sharded ledger on ONE machine.
///
/// Over the in-memory store this backend adds persistence and a cross-process lock.
/// [`with_shard`](FileLedgerHeadStore::with_shard) holds an **exclusive file lock
/// (`File::lock`) on a per-shard sidecar for the ENTIRE critical section** — acquire →
/// read the shard FRESH from disk → run `f` → durably write → release. That gives
/// cross-process exclusion on one host: two `decern-server` processes (or an operator CLI)
/// each open their OWN lock fd and genuinely mutually exclude, so a hash chain can never
/// fork and a read-total-then-append critical section can never both-read-the-same-total.
/// This is a HELD lock across the read, not a last-writer-wins rename.
///
/// **Scope.** The lock is host-local, so this backend is single-host multi-process. It is
/// NOT a multi-*host* distributed store: a second machine's lock on its own filesystem does
/// not see this one's. Multi-host coordination is `decern-store-postgres`, behind this same
/// trait, which serializes a shard with `pg_advisory_xact_lock`. `File::lock` is `flock` on
/// Unix and `LockFileEx` on Windows; CI exercises the exclusion, between two handles in one
/// process, on Linux only.
///
/// **On-disk layout** (all inside `root`, shard ids hex-encoded — see `shard_to_hex` — so
/// an untrusted tenant id can never traverse out):
/// - `<root>/<hex-shard>.log` — the shard's records, one byte-stable JSON line each,
///   appended in place and synced before the head moves.
/// - `<root>/<hex-shard>.head` — the cursor and the committed length of the log, rewritten
///   via `atomic_write_json` (temp file, fsync, atomic rename, parent-directory fsync). A
///   crash between the two leaves a log tail past the committed length, which the next
///   append discards; a log shorter than it is refused, since committed records went missing.
/// - `<root>/<hex-shard>.lock` — the stable per-shard advisory-lock sidecar (never renamed,
///   so the lock stays on one inode); its content is unused.
/// - `<root>/<hex-shard>.shard` — the earlier layout, the whole shard in one JSON object.
///   Read as it is until the shard's next append, which writes the log and head and leaves
///   a marker here that an earlier release refuses to read.
///
/// An append writes one line and one small file, so its cost does not grow with the shard.
/// Reading the history (verification, an evidence snapshot) reads the log.
pub struct FileLedgerHeadStore {
    root: PathBuf,
}

/// The files that hold one shard: its lock key (the earlier `.shard` path, whose `.lock`
/// sibling an earlier release locks too), head, and log.
struct ShardFiles {
    legacy: PathBuf,
    head: PathBuf,
    log: PathBuf,
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

    /// The files of `shard`. Rejects an empty shard id (its hex is `""`, giving
    /// `<root>/.shard` — a dotfile with no extension that `list_shards` would miss and
    /// `with_extension` would mangle), so the stem is always a non-empty hex string.
    fn files(&self, shard: &str) -> Result<ShardFiles, StoreError> {
        if shard.is_empty() {
            return Err(StoreError::Invalid(
                "ledger shard id must not be empty".into(),
            ));
        }
        let stem = self.root.join(shard_to_hex(shard));
        Ok(ShardFiles {
            legacy: stem.with_extension("shard"),
            head: stem.with_extension("head"),
            log: stem.with_extension("log"),
        })
    }
}

/// What a shard's `.shard` path holds.
enum Beside {
    Missing,
    Marker,
    /// An earlier-layout shard: the shard itself when it has no head, or, beside a head,
    /// what a crash between the head and the marker left, or what an earlier release wrote.
    Earlier(LegacyShard),
}

/// Read a shard's `.shard` path. A file that is neither the marker nor an earlier-layout
/// shard fails closed.
fn read_beside(path: &Path) -> Result<Beside, StoreError> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Beside::Missing),
        Err(e) => return Err(io(path, e)),
    };
    let marker = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("records")?.as_str().map(|r| r == MOVED.records));
    if marker == Some(true) {
        return Ok(Beside::Marker);
    }
    let state: LegacyShard = serde_json::from_slice(&bytes)
        .map_err(|e| StoreError::Serde(format!("shard file {}: {e}", path.display())))?;
    // Records with no cursor is not a shard with no history but a file that was altered.
    // Read as history-less it would be skipped by verification and extended from sequence 0
    // again, under any key.
    if state.cursor.is_none() && !state.records.is_empty() {
        return Err(StoreError::Invalid(format!(
            "shard file {} holds {} records and no cursor",
            path.display(),
            state.records.len()
        )));
    }
    Ok(Beside::Earlier(state))
}

/// The shard's head, or `None` when it has not been written in this layout.
fn read_head(path: &Path) -> Result<Option<FileHead>, StoreError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| StoreError::Serde(format!("shard head {}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io(path, e)),
    }
}

/// The committed records of a shard's log: its first `head.log_len` bytes, one record a
/// line, exactly `head.cursor.next_seq` of them. Bytes past the committed length are an
/// append that never committed and are not read.
fn read_log(path: &Path, head: &FileHead) -> Result<Vec<StoredRecord>, StoreError> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(io(path, e)),
    };
    let committed = usize::try_from(head.log_len)
        .ok()
        .filter(|&n| n <= bytes.len())
        .ok_or_else(|| {
            StoreError::Invalid(format!(
                "shard log {} holds {} bytes, fewer than the {} committed",
                path.display(),
                bytes.len(),
                head.log_len
            ))
        })?;
    let text = std::str::from_utf8(&bytes[..committed])
        .map_err(|e| StoreError::Invalid(format!("shard log {}: {e}", path.display())))?;
    let records: Vec<StoredRecord> = text
        .split_terminator('\n')
        .enumerate()
        .map(|(seq, line)| StoredRecord {
            seq: seq as u64,
            record_json: line.to_owned(),
        })
        .collect();
    let named = head.cursor.as_ref().map_or(0, |c| c.next_seq);
    if (committed > 0 && !text.ends_with('\n')) || records.len() as u64 != named {
        return Err(StoreError::Invalid(format!(
            "shard log {} holds {} committed records where its head names {named}",
            path.display(),
            records.len(),
        )));
    }
    Ok(records)
}

/// Append `lines` to the log after its first `committed` bytes, dropping any tail past them,
/// and sync it. Returns the log's new committed length, for the head to record.
fn append_log(path: &Path, committed: u64, lines: &[String]) -> Result<u64, StoreError> {
    use std::io::{Seek, SeekFrom, Write};
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| io(path, e))?;
    let len = file.metadata().map_err(|e| io(path, e))?.len();
    if len < committed {
        return Err(StoreError::Invalid(format!(
            "shard log {} holds {len} bytes, fewer than the {committed} committed",
            path.display()
        )));
    }
    if len > committed {
        file.set_len(committed).map_err(|e| io(path, e))?;
    }
    file.seek(SeekFrom::Start(committed))
        .map_err(|e| io(path, e))?;
    let mut written = committed;
    for line in lines {
        if line.contains('\n') {
            return Err(StoreError::Invalid(
                "a ledger record must be one line".into(),
            ));
        }
        file.write_all(line.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .map_err(|e| io(path, e))?;
        written += line.len() as u64 + 1;
    }
    file.sync_all().map_err(|e| io(path, e))?;
    Ok(written)
}

/// A log with records and no head beside it, where no earlier-layout shard holds the history
/// a conversion was writing, is a shard whose commit record went missing: a new shard has a
/// head before its log has a record. Read as genesis, its next append would truncate the log
/// and restart the chain, so it is refused.
fn refuse_orphan_log(files: &ShardFiles, beside: &Beside) -> Result<(), StoreError> {
    if matches!(beside, Beside::Earlier(l) if l.cursor.is_some()) {
        return Ok(());
    }
    match fs::metadata(&files.log) {
        Ok(m) if m.len() > 0 => Err(StoreError::Invalid(format!(
            "shard log {} holds records and has no head beside it",
            files.log.display()
        ))),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io(&files.log, e)),
    }
}

/// An earlier-layout shard beside a head is what a crash during conversion left, between the
/// head and the marker, only when its records are the log's first records. Anything else an
/// earlier release wrote after the conversion, and is refused rather than overwritten.
fn refuse_unless_prefix(
    files: &ShardFiles,
    head: &FileHead,
    old: &LegacyShard,
) -> Result<(), StoreError> {
    let log = read_log(&files.log, head)?;
    let prefix = old.records.len() <= log.len()
        && old
            .records
            .iter()
            .zip(&log)
            .all(|(a, b)| a.record_json == b.record_json);
    if prefix {
        return Ok(());
    }
    Err(StoreError::Invalid(format!(
        "shard file {} holds records its log does not: an earlier release wrote to the shard \
         after this one had converted it",
        files.legacy.display()
    )))
}

/// A shard as [`FileLedgerHeadStore::load`] found it: its head, what its `.shard` path holds,
/// and the records a caller asked for.
struct Loaded {
    head: Option<FileHead>,
    beside: Beside,
    records: Vec<StoredRecord>,
}

impl Loaded {
    fn cursor(&self) -> Option<HeadCursor> {
        match (&self.head, &self.beside) {
            (Some(h), _) => h.cursor.clone(),
            (None, Beside::Earlier(l)) => l.cursor.clone(),
            (None, _) => None,
        }
    }
}

impl FileLedgerHeadStore {
    /// The shard's cursor and, when `history`, its committed records, under the lock the
    /// caller holds. An earlier-layout shard with no head reads from its `.shard` file.
    fn load(&self, files: &ShardFiles, history: bool) -> Result<Loaded, StoreError> {
        let beside = read_beside(&files.legacy)?;
        let head = read_head(&files.head)?;
        let records = match &head {
            Some(head) => {
                if let Beside::Earlier(old) = &beside {
                    refuse_unless_prefix(files, head, old)?;
                }
                if history {
                    read_log(&files.log, head)?
                } else {
                    Vec::new()
                }
            }
            None => {
                refuse_orphan_log(files, &beside)?;
                match &beside {
                    Beside::Earlier(old) if history => old.records.clone(),
                    _ => Vec::new(),
                }
            }
        };
        Ok(Loaded {
            head,
            beside,
            records,
        })
    }

    /// Commit `record_json` as the record before `new_cursor`. Every step is written so a
    /// crash after it leaves a shard that reads as it did before the step or after the append:
    ///
    /// - a shard with a head: the line is appended past the committed length, then the head
    ///   moves, then the marker is written if its `.shard` path does not hold it;
    /// - an earlier-layout shard: its records and the line are written to the log, then the
    ///   head, then the marker over the `.shard` file;
    /// - a new shard: the marker, then a head with no cursor, then the line, then the head.
    fn commit(
        &self,
        files: &ShardFiles,
        loaded: Loaded,
        new_cursor: HeadCursor,
        record_json: String,
    ) -> Result<(), StoreError> {
        let Loaded { head, beside, .. } = loaded;
        let marked = matches!(beside, Beside::Marker);
        let (committed, mut lines, mark_after) = match (head, beside) {
            (Some(h), _) => (h.log_len, Vec::new(), !marked),
            (None, Beside::Earlier(old)) if old.cursor.is_some() => (
                0,
                old.records.into_iter().map(|r| r.record_json).collect(),
                true,
            ),
            (None, _) => {
                if !marked {
                    atomic_write_json(&files.legacy, &MOVED)?;
                }
                atomic_write_json(
                    &files.head,
                    &FileHead {
                        cursor: None,
                        log_len: 0,
                    },
                )?;
                (0, Vec::new(), false)
            }
        };
        lines.push(record_json);
        let log_len = append_log(&files.log, committed, &lines)?;
        // Durable before the lock releases: fsync'd temp + atomic rename + parent-dir
        // fsync, which also makes a new log file's directory entry durable.
        atomic_write_json(
            &files.head,
            &FileHead {
                cursor: Some(new_cursor),
                log_len,
            },
        )?;
        if mark_after {
            atomic_write_json(&files.legacy, &MOVED)?;
        }
        Ok(())
    }

    fn section(
        &self,
        shard: &str,
        history: bool,
        f: &mut ShardCriticalSection<'_>,
    ) -> Result<(), StoreError> {
        let files = self.files(shard)?;
        // `with_write_lock` opens `<hex-shard>.lock` FRESH on every call and holds an
        // exclusive `flock` for the whole closure. Opening the lock fd per call is
        // load-bearing, NOT incidental: `flock` is per-open-file-description, so a
        // cached/re-used fd would re-lock the same OFD immediately and silently destroy
        // same-process exclusion between two store instances — never cache the lock handle
        // in the struct. It is the lock an earlier release takes on the same shard.
        with_write_lock(&files.legacy, || {
            // Read FRESH from disk under the lock — never from an in-process cache — so a
            // commit by another process is always seen.
            let loaded = self.load(&files, history)?;
            let cursor = loaded.cursor();
            if let Some((new_cursor, record_json)) = f(cursor.as_ref(), &loaded.records)? {
                self.commit(&files, loaded, new_cursor, record_json)?;
            }
            Ok(())
        })
    }
}

impl LedgerHeadStore for FileLedgerHeadStore {
    fn with_shard(&self, shard: &str, f: &mut ShardCriticalSection<'_>) -> Result<(), StoreError> {
        self.section(shard, true, f)
    }

    fn with_shard_head(
        &self,
        shard: &str,
        f: &mut HeadCriticalSection<'_>,
    ) -> Result<(), StoreError> {
        self.section(shard, false, &mut |cursor, _| f(cursor))
    }

    fn list_shards(&self) -> Result<Vec<String>, StoreError> {
        let mut out = std::collections::BTreeSet::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io(&self.root, e)),
        };
        for entry in entries {
            let entry = entry.map_err(|e| io(&self.root, e))?;
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            // Shard data files only: a head, or an earlier-layout shard with no head beside
            // it; never the `.lock`, `.tmp` or `.log` siblings.
            let (stem, kind) = if let Some(stem) = name.strip_suffix(".head") {
                (stem, "head")
            } else if let Some(stem) = name.strip_suffix(".shard") {
                (stem, "shard")
            } else if let Some(stem) = name.strip_suffix(".log") {
                (stem, "log")
            } else {
                continue;
            };
            // Fail closed on an undecodable stem (see `shard_from_hex`): a shard whose
            // history exists must never silently drop from the audit set.
            let shard = shard_from_hex(stem)?;
            let files = self.files(&shard)?;
            // A head with no cursor is a new shard a crash left before its first record. A head,
            // or a `.shard` file with no listed head, that does not read fails the listing,
            // naming the file.
            let head_listed = !matches!(
                read_head(&files.head)?,
                None | Some(FileHead { cursor: None, .. })
            );
            match kind {
                "head" => {
                    if !head_listed {
                        continue;
                    }
                }
                // A converted shard is listed through its head, and its `.shard` file is read by
                // its sections; an earlier-layout one is listed once it has committed history,
                // as a listed head has.
                "shard" => {
                    if head_listed
                        || !matches!(
                            read_beside(&entry.path())?,
                            Beside::Earlier(l) if l.cursor.is_some()
                        )
                    {
                        continue;
                    }
                }
                // A log is listed through its head or the shard it is converting; one with
                // records and neither is refused, rather than dropped from the audit set.
                _ => {
                    if files.head.exists() {
                        continue;
                    }
                    refuse_orphan_log(&files, &read_beside(&files.legacy)?)?;
                    continue;
                }
            }
            out.insert(shard);
        }
        Ok(out.into_iter().collect())
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
                    signers: None,
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
                    last_hash: "h0".into(),
                    signers: None
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
                        signers: None,
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
                        signers: None,
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
                                    signers: None,
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

    fn cursor(next_seq: u64, last_hash: &str) -> HeadCursor {
        HeadCursor {
            next_seq,
            last_hash: last_hash.into(),
            signers: None,
        }
    }

    fn marked(path: &Path) -> bool {
        matches!(read_beside(path).unwrap(), Beside::Marker)
    }

    fn append(s: &dyn LedgerHeadStore, shard: &str, line: &str) {
        s.with_shard_head(shard, &mut |c| {
            let next = c.map(|c| c.next_seq).unwrap_or(0) + 1;
            Ok(Some((cursor(next, &format!("h{next}")), line.into())))
        })
        .unwrap();
    }

    fn history(s: &dyn LedgerHeadStore, shard: &str) -> (Option<HeadCursor>, Vec<String>) {
        let mut out = (None, Vec::new());
        s.with_shard(shard, &mut |c, records| {
            out = (
                c.cloned(),
                records.iter().map(|r| r.record_json.clone()).collect(),
            );
            Ok(None)
        })
        .unwrap();
        out
    }

    /// The head-only section sees the cursor `with_shard` sees and commits what it does, in
    /// the default every backend inherits and in the file backend's own.
    #[test]
    fn the_head_only_section_sees_and_commits_what_with_shard_does() {
        let dir = tmp_dir("head-only");
        let file = FileLedgerHeadStore::new(&dir).unwrap();
        let memory = MemoryLedgerHeadStore::new();
        for s in [&file as &dyn LedgerHeadStore, &memory] {
            for line in ["line-0", "line-1", "line-2"] {
                append(s, "acme", line);
            }
            let mut seen = None;
            s.with_shard_head("acme", &mut |c| {
                seen = c.cloned();
                Ok(None)
            })
            .unwrap();
            let (c, lines) = history(s, "acme");
            assert_eq!(seen, c);
            assert_eq!(seen.unwrap().next_seq, 3);
            assert_eq!(lines, ["line-0", "line-1", "line-2"]);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// An append writes one line to the log and a head of fixed size, whatever the shard
    /// already holds.
    #[test]
    fn an_append_writes_one_line_and_a_head_that_does_not_grow() {
        let dir = tmp_dir("append-is-a-line");
        let s = FileLedgerHeadStore::new(&dir).unwrap();
        let files = s.files("acme").unwrap();
        append(&s, "acme", "line-0");
        let first_head = fs::metadata(&files.head).unwrap().len();
        for i in 1..200 {
            append(&s, "acme", &format!("line-{i}"));
        }
        let log = fs::read_to_string(&files.log).unwrap();
        assert_eq!(log.lines().count(), 200);
        let head = fs::metadata(&files.head).unwrap().len();
        assert!(
            head < first_head + 16,
            "the head grew from {first_head} to {head} bytes"
        );
        assert!(marked(&files.legacy), "a new shard carries no marker");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A new shard writes the marker before its first record, so an earlier release, which
    /// lists and parses every `.shard` file, refuses the store rather than read the shard as
    /// empty and extend it from sequence 0.
    #[test]
    fn a_new_shard_is_marked_so_an_earlier_release_refuses_the_store() {
        let dir = tmp_dir("new-marked");
        let s = FileLedgerHeadStore::new(&dir).unwrap();
        let files = s.files("acme").unwrap();
        append(&s, "acme", "line-0");
        let left = fs::read(&files.legacy).expect("a new shard left no .shard file");
        assert!(
            serde_json::from_slice::<LegacyShard>(&left).is_err(),
            "an earlier release could read a new shard as an earlier-layout one"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A crash before a new shard's first record commits leaves a shard that reads as empty
    /// and takes the record again, rather than one refused for a log with no head.
    #[test]
    fn a_new_shard_a_crash_left_before_its_first_record_reads_as_empty() {
        let dir = tmp_dir("new-crash");
        let s = FileLedgerHeadStore::new(&dir).unwrap();
        let files = s.files("acme").unwrap();
        // After the marker; then after the head with no cursor and part of the line.
        atomic_write_json(&files.legacy, &MOVED).unwrap();
        assert_eq!(history(&s, "acme"), (None, Vec::new()));
        atomic_write_json(
            &files.head,
            &FileHead {
                cursor: None,
                log_len: 0,
            },
        )
        .unwrap();
        fs::write(&files.log, "line-").unwrap();
        assert_eq!(history(&s, "acme"), (None, Vec::new()));
        assert!(
            s.list_shards().unwrap().is_empty(),
            "a shard with no committed record is listed"
        );
        append(&s, "acme", "line-0");
        assert_eq!(s.list_shards().unwrap(), ["acme"]);
        assert_eq!(fs::read_to_string(&files.log).unwrap(), "line-0\n");
        assert_eq!(history(&s, "acme").1, ["line-0"]);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A shard file that does not read fails the listing, naming the file, as an altered
    /// earlier-layout shard does. A `.shard` file beside a head is read by the shard's
    /// sections, which refuse it by name, and a head with no cursor beside an earlier-layout
    /// file holding history is listed and refused.
    #[test]
    fn a_shard_file_that_does_not_read_is_refused_by_name() {
        let dir = tmp_dir("unreadable");
        let s = FileLedgerHeadStore::new(&dir).unwrap();
        append(&s, "good", "line-0");
        append(&s, "other", "line-0");
        let other = s.files("other").unwrap();
        fs::write(&other.legacy, "{not json").unwrap();
        let crafted = s.files("crafted").unwrap();
        atomic_write_json(
            &crafted.head,
            &FileHead {
                cursor: None,
                log_len: 0,
            },
        )
        .unwrap();
        fs::write(
            &crafted.legacy,
            serde_json::to_vec(&serde_json::json!({
                "cursor": {"next_seq": 1, "last_hash": "h1"},
                "records": [{"seq": 0, "record_json": "old-0"}],
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(s.list_shards().unwrap(), ["crafted", "good", "other"]);
        let e = s
            .with_shard("other", &mut |_, _| Ok(None))
            .unwrap_err()
            .to_string();
        assert!(e.contains(&other.legacy.display().to_string()), "{e}");
        assert!(s.with_shard("crafted", &mut |_, _| Ok(None)).is_err());
        assert_eq!(history(&s, "good").1, ["line-0"]);

        append(&s, "broken", "line-0");
        let broken = s.files("broken").unwrap();
        fs::write(&broken.head, "{not json").unwrap();
        let e = s.list_shards().unwrap_err().to_string();
        assert!(e.contains(&broken.head.display().to_string()), "{e}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// An earlier-layout file beside a head whose records the log does not hold was written
    /// by an earlier release after the conversion. Both sections refuse the shard, and the
    /// file is left as it is rather than replaced by the marker.
    #[test]
    fn an_earlier_release_write_beside_a_head_is_refused_not_overwritten() {
        let dir = tmp_dir("rolled-back");
        let s = FileLedgerHeadStore::new(&dir).unwrap();
        let files = s.files("acme").unwrap();
        append(&s, "acme", "new-0");
        append(&s, "acme", "new-1");
        let written = serde_json::to_vec(&serde_json::json!({
            "cursor": {"next_seq": 1, "last_hash": "h1"},
            "records": [{"seq": 0, "record_json": "old-0"}],
        }))
        .unwrap();
        fs::write(&files.legacy, &written).unwrap();
        assert!(s.with_shard("acme", &mut |_, _| Ok(None)).is_err());
        let mut ran = false;
        let r = s.with_shard_head("acme", &mut |_| {
            ran = true;
            Ok(Some((cursor(3, "h3"), "new-2".into())))
        });
        assert!(
            r.is_err() && !ran,
            "an append ran on a shard an earlier release wrote to"
        );
        assert_eq!(fs::read(&files.legacy).unwrap(), written);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A shard as an earlier release stored it is read as it is, by both sections and the
    /// listing, without being rewritten by a read; its next append converts it, keeping every
    /// record, and leaves at its old path a file the earlier release cannot read.
    #[test]
    fn an_earlier_layout_shard_is_read_as_it_is_and_converted_on_its_next_append() {
        let dir = tmp_dir("convert");
        let s = FileLedgerHeadStore::new(&dir).unwrap();
        let files = s.files("acme").unwrap();
        fs::write(
            &files.legacy,
            serde_json::to_vec(&serde_json::json!({
                "cursor": {"next_seq": 2, "last_hash": "h2"},
                "records": [
                    {"seq": 0, "record_json": "line-0"},
                    {"seq": 1, "record_json": "line-1"},
                ],
            }))
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            history(&s, "acme"),
            (
                Some(cursor(2, "h2")),
                vec!["line-0".into(), "line-1".into()]
            )
        );
        assert_eq!(s.list_shards().unwrap(), ["acme"]);
        assert!(
            !files.head.exists() && !files.log.exists(),
            "a read converted the shard"
        );

        append(&s, "acme", "line-2");
        let (c, lines) = history(&s, "acme");
        assert_eq!(c.unwrap().next_seq, 3);
        assert_eq!(lines, ["line-0", "line-1", "line-2"]);
        assert_eq!(s.list_shards().unwrap(), ["acme"]);
        let marker = fs::read(&files.legacy).unwrap();
        assert!(
            serde_json::from_slice::<LegacyShard>(&marker).is_err(),
            "an earlier release could still read the converted shard's old file"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// An append to a converted shard leaves its marker as it is. An earlier-layout file a
    /// crash left beside the head, between writing the head and the marker, is replaced by
    /// the marker at the next append, and its stale records are never read.
    #[test]
    fn a_converted_shard_keeps_its_marker_and_a_crash_left_file_gets_one() {
        let dir = tmp_dir("marker");
        let s = FileLedgerHeadStore::new(&dir).unwrap();
        let files = s.files("acme").unwrap();
        let earlier = serde_json::to_vec(&serde_json::json!({
            "cursor": {"next_seq": 1, "last_hash": "h1"},
            "records": [{"seq": 0, "record_json": "line-0"}],
        }))
        .unwrap();
        fs::write(&files.legacy, &earlier).unwrap();
        append(&s, "acme", "line-1");
        assert!(marked(&files.legacy));

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let before = fs::metadata(&files.legacy).unwrap().ino();
            append(&s, "acme", "line-2");
            let after = fs::metadata(&files.legacy).unwrap().ino();
            assert_eq!(before, after, "an append rewrote the marker");
        }
        #[cfg(not(unix))]
        append(&s, "acme", "line-2");

        fs::write(&files.legacy, &earlier).unwrap();
        assert!(!marked(&files.legacy));
        append(&s, "acme", "line-3");
        assert!(marked(&files.legacy));
        let (c, lines) = history(&s, "acme");
        assert_eq!(c.unwrap().next_seq, 4);
        assert_eq!(lines, ["line-0", "line-1", "line-2", "line-3"]);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Log bytes past the committed length are an append that never committed: not read,
    /// and dropped by the next append.
    #[test]
    fn a_log_tail_past_the_committed_length_is_not_read_and_is_dropped() {
        let dir = tmp_dir("uncommitted-tail");
        let s = FileLedgerHeadStore::new(&dir).unwrap();
        let files = s.files("acme").unwrap();
        append(&s, "acme", "line-0");
        let mut log = fs::OpenOptions::new()
            .append(true)
            .open(&files.log)
            .unwrap();
        std::io::Write::write_all(&mut log, b"line-uncommitted\npartial").unwrap();
        drop(log);
        assert_eq!(history(&s, "acme").1, ["line-0"]);
        append(&s, "acme", "line-1");
        assert_eq!(fs::read_to_string(&files.log).unwrap(), "line-0\nline-1\n");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A log shorter than its head's committed length has lost committed records, and is
    /// refused rather than extended.
    #[test]
    fn a_log_shorter_than_its_committed_length_is_refused() {
        let dir = tmp_dir("short-log");
        let s = FileLedgerHeadStore::new(&dir).unwrap();
        let files = s.files("acme").unwrap();
        append(&s, "acme", "line-0");
        append(&s, "acme", "line-1");
        fs::write(&files.log, "line-0\n").unwrap();
        assert!(s.with_shard("acme", &mut |_, _| Ok(None)).is_err());
        let mut ran = false;
        let r = s.with_shard_head("acme", &mut |c| {
            ran = true;
            Ok(Some((
                cursor(c.map(|c| c.next_seq).unwrap_or(0) + 1, "h"),
                "x".into(),
            )))
        });
        assert!(
            r.is_err() && ran,
            "the head-only section reads the head alone, and an append onto the short log is \
             refused"
        );
        assert!(
            s.with_shard("acme", &mut |_, _| Ok(None)).is_err(),
            "a refused log stays refused"
        );
        let _ = fs::remove_dir_all(&dir);
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
                        signers: None,
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
                        last_hash: "h0".into(),
                        signers: None
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
                last_hash: "h0".into(),
                signers: None
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
                        signers: None,
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
                                        signers: None,
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
                        signers: None,
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
            if let Some(stem) = name.strip_suffix(".head") {
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

    /// An earlier-layout shard file holding records but no cursor, or a log holding records
    /// with no head beside it, is an altered store, not a shard with no history: it is
    /// refused wherever it is read, so no key extends it from sequence 0 again.
    #[test]
    fn a_shard_with_records_and_no_cursor_is_refused_in_either_layout() {
        fn refused(s: &FileLedgerHeadStore, layout: &str) {
            assert!(
                s.list_shards().is_err(),
                "{layout}: a shard with records and no cursor was listed or skipped"
            );
            let mut ran = false;
            let r = s.with_shard_head("acme", &mut |_| {
                ran = true;
                Ok(None)
            });
            assert!(
                r.is_err() && !ran,
                "{layout}: the altered shard was opened for appending"
            );
        }

        let dir = tmp_dir("records-no-cursor-legacy");
        let s = FileLedgerHeadStore::new(&dir).unwrap();
        let legacy = s.files("acme").unwrap().legacy;
        fs::write(
            &legacy,
            serde_json::to_vec(&serde_json::json!({
                "cursor": null,
                "records": [{"seq": 0, "record_json": "line-0"}],
            }))
            .unwrap(),
        )
        .unwrap();
        refused(&s, "earlier layout");
        let _ = fs::remove_dir_all(&dir);

        let dir = tmp_dir("records-no-cursor-log");
        let s = FileLedgerHeadStore::new(&dir).unwrap();
        s.with_shard_head("acme", &mut |_| {
            Ok(Some((cursor(1, "h0"), "line-0".into())))
        })
        .unwrap();
        fs::remove_file(s.files("acme").unwrap().head).unwrap();
        refused(&s, "log and head");
        let _ = fs::remove_dir_all(&dir);
    }
}
