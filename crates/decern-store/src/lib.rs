// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
#![forbid(unsafe_code)]
//! decern-store — pure-Rust, database-free persistence for the tamper-evident
//! ledger and the Mission registry.
//!
//! Two durable concerns, no external database:
//! - the **ledger head store** ([`LedgerHeadStore`] + [`FileLedgerHeadStore`] /
//!   [`MemoryLedgerHeadStore`]): the per-shard head cursor plus the critical-section
//!   coordination the sharded ledger appends through, so several `decern-serve`
//!   replicas on one host can extend each shard's chain safely;
//! - the **mission registry** ([`MissionRegistry`] + [`FileMissionRegistry`] /
//!   [`MemoryMissionRegistry`]): the authoritative `(approver, expiry, terminated)`
//!   record the Mission mint path checks, so a mission's termination outlives any
//!   single in-memory `ApprovedMission` handle.
//!
//! Both sit on the same durable substrate: [`StoreError`], atomic JSON writes
//! (temp file, fsync, rename over the target) hardened to `0600`, a cross-process
//! file-fingerprint coherent map, and flock-based write locks. The backends are
//! pure Rust and need no database — sovereign and offline-servable. The optional
//! multi-host Postgres head store lives in the separate `decern-store-postgres`
//! crate.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store I/O error at {path}: {err}")]
    Io { path: String, err: String },
    #[error("store serialization error: {0}")]
    Serde(String),
    #[error("invalid record: {0}")]
    Invalid(String),
}

/// The in-memory view of a coherent-map file plus the fingerprint of the bytes it
/// was loaded from, guarded as one unit so a reload swaps both atomically.
struct CoherentCache<V> {
    map: BTreeMap<String, V>,
    fp: Option<FileFingerprint>,
}

/// A `String -> V` map persisted to one JSON file with **cross-process coherence** —
/// the vetted primitive behind decern's durable stores (the mission registry).
/// Encapsulated so the subtle coherence logic is written once and never re-derived
/// (and re-broken) per store.
///
/// A durable store may be written by a *different* process — an operator CLI, or a
/// second server replica behind a load balancer. A backend that answered only from
/// the map it loaded at `open` would keep serving a stale view: for the mission
/// registry, a termination that is a lie across processes. So this primitive keeps
/// the in-memory map coherent with the file:
/// - **[`read`](CoherentMap::read)** compares a cheap `(ino, size, mtime)`
///   fingerprint and reloads only when the file changed underneath us (the atomic
///   rename gives a torn-free snapshot, so a read takes no file lock); a file that
///   *vanishes* after we materialized it is treated as tampering and fails closed,
///   never as an empty map.
/// - **[`write`](CoherentMap::write)** takes an exclusive advisory lock on a stable
///   `<path>.lock` sidecar and read-modify-writes from *disk truth*, so two
///   processes mutating at once cannot clobber each other (a lost revocation is the
///   one failure a killswitch must never have). It takes the file lock BEFORE the
///   in-memory mutex and holds the mutex only to publish, so a foreign lock-holder
///   cannot stall this node's reads.
struct CoherentMap<V> {
    path: PathBuf,
    inner: Mutex<CoherentCache<V>>,
}

impl<V: Serialize + serde::de::DeserializeOwned> CoherentMap<V> {
    /// Open (or create) the backing file. A present file must parse, or open fails
    /// (fail-closed — a corrupt durable store is never silently discarded).
    ///
    /// If the file does not yet exist it is **materialized as an empty map** (under
    /// the write lock). This is deliberate: it makes the file's *disappearance*
    /// unambiguous. Were a handle allowed to hold `fp = None` (opened while the file
    /// was absent), a later create-then-delete by another process would read as
    /// `None == None` → an empty map (fail-open); by ensuring the file always exists
    /// after a successful open, an absent file thereafter always means a *deleted*
    /// file — tamper — and [`read`](Self::read) fails closed. (Deletion followed by a
    /// process *restart* is indistinguishable from never-created and is out of scope
    /// here; cross-restart truncation/deletion detection is the anchor's job.)
    fn open(path: PathBuf) -> Result<Self, StoreError> {
        if !path.exists()
            && let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
        }
        with_write_lock(&path, || {
            // Read first so a corrupt present file fails closed before we touch it.
            let map = read_coherent_map::<V>(&path)?;
            if !path.exists() {
                // Create the empty file so `fp` is `Some` from here on.
                atomic_write_json(&path, &map)?;
            }
            // Fingerprint AFTER the map read/create: the file now exists and, under
            // the write lock, no other process can have written between the read and
            // this stat, so `fp` and `map` reflect the same on-disk state.
            let fp = file_fingerprint(&path)?;
            Ok(CoherentMap {
                path: path.clone(),
                inner: Mutex::new(CoherentCache { map, fp }),
            })
        })
    }

    /// Reload from disk if the file changed since we last read it, then run `f` over
    /// the fresh map. Fails closed if the file vanished after being materialized.
    fn read<R>(&self, f: impl FnOnce(&BTreeMap<String, V>) -> R) -> Result<R, StoreError> {
        let mut g = self.inner.lock().map_err(poisoned)?;
        let current = file_fingerprint(&self.path)?;
        if current != g.fp {
            match current {
                // Appeared or changed since we last loaded → adopt disk truth.
                Some(fp) => {
                    g.map = read_coherent_map::<V>(&self.path)?;
                    g.fp = Some(fp);
                }
                // We materialized the file at open and it is now gone. That is not an
                // empty map — the file does not disappear in normal operation (atomic
                // rename never removes it). Fail closed rather than silently serving an
                // empty view. (`current == g.fp` when both are None, so we only reach
                // here with `g.fp == Some`.)
                None => {
                    return Err(StoreError::Invalid(format!(
                        "store file {} disappeared after being present — refusing to \
                         serve a stale/empty view (possible tampering)",
                        self.path.display()
                    )));
                }
            }
        }
        Ok(f(&g.map))
    }

    /// Read-modify-write under the cross-process lock, from disk truth. `f` mutates
    /// the map and returns `(result, dirty)`; the file is persisted iff `dirty`
    /// (so an idempotent no-op write skips the disk I/O). The refreshed map+fp are
    /// published to the in-memory cache before returning.
    fn write<R>(
        &self,
        f: impl FnOnce(&mut BTreeMap<String, V>) -> (R, bool),
    ) -> Result<R, StoreError> {
        with_write_lock(&self.path, || {
            let mut map = read_coherent_map::<V>(&self.path)?;
            let (result, dirty) = f(&mut map);
            if dirty {
                atomic_write_json(&self.path, &map)?;
            }
            // Refresh the fingerprint (under the lock, so it matches what we wrote),
            // then publish map+fp. A concurrent `read` racing this publish just
            // reloads from disk itself — always correct.
            let fp = file_fingerprint(&self.path)?;
            let mut g = self.inner.lock().map_err(poisoned)?;
            g.map = map;
            g.fp = fp;
            Ok(result)
        })
    }
}

/// A registered mission's authoritative state. The mission reference is
/// `(approver, s256)`; this is the persisted record the mint path checks so that a
/// mission's TERMINATION is effective beyond a single in-memory `ApprovedMission`
/// handle, and a mission reference that names nothing registered is refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionEntry {
    /// Principal id that approved the mission (must match the reference's approver).
    pub approver: String,
    /// Mission authority expiry (epoch secs) — the record GCs itself past this.
    pub expiry: u64,
    /// Once true, the mission mints no further tokens and can never revert to active.
    #[serde(default)]
    pub terminated: bool,
}

/// The **mission registry** — the authoritative, persistent record of approved
/// Missions, keyed by the mission reference hash `s256`.
///
/// Why it exists: without it, `ApprovedMission::terminate()` is a flip of an
/// in-memory field, so a token minted from a stale/reconstructed handle would not
/// see the termination, and a hand-built mission reference (`s256`) that names no
/// real approval could be stamped into a token. This registry makes the mission
/// reference *checkable at the mint*: mint only when `s256` resolves to a
/// registered, non-terminated, non-expired mission whose approver matches. It is
/// **local** (memory or file) — sovereign, consulted in-perimeter, no phone-home —
/// and GCs expired entries on write so it stays bounded
/// to live missions. Termination is monotone: a terminated mission can never revert
/// to active (a killswitch that can be un-pressed is not a killswitch).
pub trait MissionRegistry: Send + Sync {
    /// Register an approved mission as active. Idempotent for an already-active same
    /// `s256`; refused if that `s256` is already TERMINATED (no revival). Evicts
    /// entries already past `now` so the registry stays bounded.
    fn register(&self, s256: &str, entry: MissionEntry, now: u64) -> Result<(), StoreError>;

    /// The mission's current record, or `None` if `s256` is unknown. Consulted
    /// before minting a mission-bound token; a caller treats `Err` as not-mintable
    /// (fail-closed).
    fn status(&self, s256: &str) -> Result<Option<MissionEntry>, StoreError>;

    /// Terminate the mission named by `s256` (idempotent). A terminated mission
    /// mints no further tokens. Terminating an unknown `s256` is a no-op.
    fn terminate(&self, s256: &str, now: u64) -> Result<(), StoreError>;
}

/// Volatile backend — for tests and ephemeral nodes. Not durable.
#[derive(Default)]
pub struct MemoryMissionRegistry {
    inner: Mutex<BTreeMap<String, MissionEntry>>,
}

impl MemoryMissionRegistry {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Terminated tombstones are retained for this long PAST their own expiry, so a
/// deliberately-ended grant cannot be replayed the moment it lapses. The identity
/// layer's `approve()` expiry guard is the primary defense (a dead mission is never
/// granted); this keeps the store itself refusing re-registration for a bounded
/// window and bounds how long a terminated tombstone lingers. Active entries are
/// still evicted at their expiry.
const TERMINATED_TOMBSTONE_RETENTION_SECS: u64 = 30 * 24 * 60 * 60; // 30 days

/// Whether a registry entry survives GC at `now`: an active entry lives until its
/// expiry; a terminated tombstone lives for a retention horizon past it, so expiry
/// can never launder a termination into an Active re-registration.
fn mission_entry_retained(e: &MissionEntry, now: u64) -> bool {
    if e.terminated {
        e.expiry.saturating_add(TERMINATED_TOMBSTONE_RETENTION_SECS) > now
    } else {
        e.expiry > now
    }
}

/// Shared register logic: GC expired, then insert-if-new / no-op-if-active /
/// refuse-if-terminated. Returns `(result, dirty)` for the durable backend.
fn mission_register(
    map: &mut BTreeMap<String, MissionEntry>,
    s256: &str,
    entry: MissionEntry,
    now: u64,
) -> (Result<(), StoreError>, bool) {
    map.retain(|_, e| mission_entry_retained(e, now));
    match map.get(s256) {
        Some(existing) if existing.terminated => (
            Err(StoreError::Invalid(format!(
                "mission {s256} is terminated and cannot be re-registered"
            ))),
            false,
        ),
        Some(_) => (Ok(()), false), // already active — idempotent no-op
        None if entry.expiry <= now => (
            // Self-monotone: refuse registering an already-expired mission, independent of
            // the identity-layer approve() guard. Combined with retaining terminated
            // tombstones past expiry, this makes "expiry can never launder a termination
            // into an Active re-registration" true for ALL callers of this crate, not only
            // approve(). (An expired ACTIVE entry was already dropped by the retain above,
            // so an expired blob arrives here as None.)
            Err(StoreError::Invalid(format!(
                "mission {s256} expiry {} is not in the future (now {now}); cannot register",
                entry.expiry
            ))),
            false,
        ),
        None => {
            map.insert(s256.to_owned(), entry);
            (Ok(()), true)
        }
    }
}

impl MissionRegistry for MemoryMissionRegistry {
    fn register(&self, s256: &str, entry: MissionEntry, now: u64) -> Result<(), StoreError> {
        let mut g = self.inner.lock().map_err(poisoned)?;
        mission_register(&mut g, s256, entry, now).0
    }

    fn status(&self, s256: &str) -> Result<Option<MissionEntry>, StoreError> {
        let g = self.inner.lock().map_err(poisoned)?;
        Ok(g.get(s256).cloned())
    }

    fn terminate(&self, s256: &str, now: u64) -> Result<(), StoreError> {
        let mut g = self.inner.lock().map_err(poisoned)?;
        g.retain(|_, e| mission_entry_retained(e, now));
        if let Some(e) = g.get_mut(s256) {
            e.terminated = true;
        }
        Ok(())
    }
}

/// The default, database-free backend: mission records persisted with cross-process
/// coherence (see [`CoherentMap`]) — so a mission approved or TERMINATED by another
/// process (an operator CLI, a second replica) is seen at this node's mint path, and
/// survives a restart.
pub struct FileMissionRegistry {
    inner: CoherentMap<MissionEntry>,
}

impl FileMissionRegistry {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Ok(FileMissionRegistry {
            inner: CoherentMap::open(path.as_ref().to_owned())?,
        })
    }
}

impl MissionRegistry for FileMissionRegistry {
    fn register(&self, s256: &str, entry: MissionEntry, now: u64) -> Result<(), StoreError> {
        self.inner
            .write(|map| mission_register(map, s256, entry, now))?
    }

    fn status(&self, s256: &str) -> Result<Option<MissionEntry>, StoreError> {
        self.inner.read(|map| map.get(s256).cloned())
    }

    fn terminate(&self, s256: &str, now: u64) -> Result<(), StoreError> {
        self.inner.write(|map| {
            map.retain(|_, e| mission_entry_retained(e, now));
            let dirty = match map.get_mut(s256) {
                Some(e) if !e.terminated => {
                    e.terminated = true;
                    true
                }
                _ => false,
            };
            ((), dirty)
        })
    }
}

/// Serialize `value` as pretty JSON and write it to `path` atomically: a sibling
/// temp file is written, fsync'd, then renamed over the target (rename is atomic
/// within a filesystem), so a crash mid-write can never leave a half-written file.
/// Shared by the durable backends (the mission registry and the ledger head store)
/// where a lost write would resurrect terminated or superseded state.
fn atomic_write_json(path: &Path, value: &impl Serialize) -> Result<(), StoreError> {
    atomic_write_json_impl(path, value, true)
}

fn atomic_write_json_impl(
    path: &Path,
    value: &impl Serialize,
    durable: bool,
) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| StoreError::Serde(e.to_string()))?;
    let tmp = path.with_extension("tmp");
    {
        // 0600 (unix): every durable store file holds sensitive material, and the
        // rename below carries the tmp file's own mode onto
        // `path`, not the other way round, so this is what makes the FINAL file
        // non-world-readable too. `create(true).truncate(true)`, not `create_new` —
        // unlike a signing key (write-once, refuse-to-overwrite), a store file is
        // rewritten on every mutation by design.
        //
        // `OpenOptionsExt::mode` is NOT enough on its own: POSIX `open(2)` applies
        // the mode argument only at the instant O_CREAT actually creates a new
        // inode — if a `.tmp` sibling already exists (an interrupted prior write:
        // a crash, OOM-kill, or an older pre-hardening binary that wrote it via
        // plain `fs::File::create`), `mode()` is silently IGNORED and the reused
        // inode keeps its old, looser permissions, which then propagate onto the
        // final path via the rename below — silently defeating this entire
        // guarantee with no error and no log line. So the mode is set
        // UNCONDITIONALLY after open, whether the inode was freshly created or
        // reused, rather than relied upon as a creation-time side effect.
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| io(&tmp, e))?;
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| io(&tmp, e))?;
            f
        };
        // KNOWN GAP, not silently accidental: `std::fs` has no portable ACL/owner-only
        // API, so this store's 0600-at-rest guarantee above is unix-only — a durable
        // store file (credential registry included) written from a non-unix build
        // gets whatever default permissions the platform gives, unhardened. decern's own
        // CI/release only build unix targets (linux-musl), so this is not reachable
        // today, but it is a real, named gap should that ever change — mirroring the
        // pre-existing `FileFingerprint`/`fingerprint_of` non-unix note elsewhere in
        // this file (a documented degrade, not the decern-crypto module's refuse-to-write
        // stance, since that would make the entire store layer non-functional on any
        // platform without permission bits, not just the key-file path).
        #[cfg(not(unix))]
        let mut f = fs::File::create(&tmp).map_err(|e| io(&tmp, e))?;
        f.write_all(&bytes).map_err(|e| io(&tmp, e))?;
        f.flush().map_err(|e| io(&tmp, e))?;
        if durable {
            f.sync_all().map_err(|e| io(&tmp, e))?;
        }
    }
    fs::rename(&tmp, path).map_err(|e| io(path, e))?;
    if durable {
        // fsync the PARENT DIRECTORY so the rename itself (the new directory entry)
        // is durable. Without this, `sync_all` on the temp file makes the *bytes*
        // durable but not the rename that publishes them: a crash after `rename`
        // returns can reboot to the OLD inode, silently losing a revocation we
        // already reported as `Ok` — a resurrected killed credential.
        #[cfg(unix)]
        {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let dir = fs::File::open(parent).map_err(|e| io(parent, e))?;
            dir.sync_all().map_err(|e| io(parent, e))?;
        }
    }
    Ok(())
}

/// A cheap change-fingerprint for a store file, used to detect *out-of-process*
/// writes (killswitch propagation) without re-reading the whole file on every
/// check. Because the durable backends write via temp-file + atomic rename, every
/// write swaps in a fresh inode, so `ino` flips on any write; `size` and `mtime`
/// are belt-and-suspenders for filesystems that reuse inode numbers or where mtime
/// is coarse. Any difference triggers a reload — the comparison only ever errs
/// toward reloading, never toward trusting a stale cache.
///
/// **Platform caveat.** On non-unix targets `ino` is unavailable and hardcoded to
/// `0`, so change detection degrades to `(size, mtime)` only. A same-size rewrite
/// (e.g. a GC that drops one entry and adds an equal-length one) landing within a
/// single coarse mtime tick could then be missed cross-process. The sovereign node
/// target is unix (Linux/macOS), where the per-write inode flip closes this; a real
/// Windows deployment should switch this to a content hash or a monotonic counter.
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    ino: u64,
    size: u64,
    mtime: (i64, u32),
}

fn fingerprint_of(meta: &fs::Metadata) -> FileFingerprint {
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| (d.as_secs() as i64, d.subsec_nanos()))
        .unwrap_or((0, 0));
    #[cfg(unix)]
    let (ino, size) = {
        use std::os::unix::fs::MetadataExt;
        (meta.ino(), meta.size())
    };
    #[cfg(not(unix))]
    let (ino, size) = (0u64, meta.len());
    FileFingerprint { ino, size, mtime }
}

/// The current fingerprint of `path`, or `None` if it does not exist. A stat error
/// other than not-found is propagated (fail-closed: the caller cannot confirm the
/// file is unchanged, so it must not trust its cache).
fn file_fingerprint(path: &Path) -> Result<Option<FileFingerprint>, StoreError> {
    match fs::metadata(path) {
        Ok(meta) => Ok(Some(fingerprint_of(&meta))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io(path, e)),
    }
}

/// Run `f` while holding an exclusive advisory lock on a stable sidecar lock file
/// (`<path>.lock`), serializing a cross-process read-modify-write on a killswitch
/// file. The lock is taken on a DEDICATED inode that is never renamed: the data
/// file itself is replaced by atomic rename, which would move an `flock` off the
/// inode other processes are blocked on, so all writers must contend on the stable
/// sidecar instead. The lock releases when the handle drops at end of scope.
fn with_write_lock<T>(
    path: &Path,
    f: impl FnOnce() -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let lock_path = path.with_extension("lock");
    // The sidecar names (`<path>.lock`, `<path>.tmp`) must be distinct from the data
    // file, or the lock would collide with the file it guards (or `atomic_write_json`
    // would rename a file onto itself). All callers use `.json`/`.ledger` data paths;
    // this guards against a future caller passing a `*.lock`/`*.tmp` data path.
    debug_assert_ne!(lock_path, path, "data file must not be named *.lock");
    let lock = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false) // the lock file is a pure mutex; its content is never read or written
        .open(&lock_path)
        .map_err(|e| io(&lock_path, e))?;
    lock.lock().map_err(|e| io(&lock_path, e))?;
    let out = f();
    drop(lock); // release the advisory lock (explicit for clarity)
    out
}

/// Read a `String -> V` map from disk. A missing file is an empty map; a
/// present-but-unparseable file is a hard error (fail-closed — a corrupt durable
/// store is never silently treated as empty, which for a killswitch list would let
/// a revoked token come back).
fn read_coherent_map<V: serde::de::DeserializeOwned>(
    path: &Path,
) -> Result<BTreeMap<String, V>, StoreError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| StoreError::Serde(e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(io(path, e)),
    }
}

fn io(path: &Path, e: impl std::fmt::Display) -> StoreError {
    StoreError::Io {
        path: path.display().to_string(),
        err: e.to_string(),
    }
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> StoreError {
    StoreError::Invalid("directory store lock poisoned".into())
}

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
/// lock/transaction (a Postgres `SELECT ... FOR UPDATE` in the real backend),
/// generalizing the single-process `Mutex<Ledger>` every `AppState.ledger`
/// caller already holds today to work correctly across replicas. Hash+sign is
/// sub-millisecond, so the lock's hold time is short regardless of caller.
///
/// Implemented by a Postgres backend (`decern-store-postgres`), by
/// [`MemoryLedgerHeadStore`] here (fast, dependency-free tests, exercised by
/// `decern-ledger`'s sharded-ledger test suite), and by
/// [`FileLedgerHeadStore`] (a persistent **single-host, multi-process**
/// reference: `flock`-held per-shard critical sections on one machine). The
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
/// holds an **exclusive advisory file lock (`flock` `LOCK_EX`) on a per-shard
/// sidecar for the ENTIRE critical section** — acquire → read the shard's
/// cursor+records FRESH from disk → run `f` → durably write → release. That
/// gives cross-process exclusion on one host: two `decern-server` processes (or
/// an operator CLI) each open their OWN lock fd and genuinely mutually exclude,
/// so a hash chain can never fork and a read-total-then-append critical section
/// can never both-read-the-same-total. This is a HELD lock across the read, not
/// a last-writer-wins rename (two writers each read head=N, both write N+1, one
/// silently clobbered → forked ledger — the exact failure this trait prevents).
///
/// **Scope / honesty.** `flock` is host-local, so this backend is single-host
/// multi-process. It is NOT a multi-*host* distributed store: a second machine's
/// `flock` on its own filesystem does not see this one's. Multi-host coordination
/// is the pluggable Postgres/etcd/Redis backend (a `SELECT … FOR UPDATE` per
/// shard) behind this SAME trait — not shipped in v0.1. Unix only (`flock`).
///
/// **On-disk layout** (all inside `root`, shard ids hex-encoded — see
/// [`shard_to_hex`] — so an untrusted tenant id can never traverse out):
/// - `<root>/<hex-shard>.shard` — the shard's `{cursor, records}` as one JSON
///   object, rewritten wholesale on each append via [`atomic_write_json`]
///   (temp-file + fsync + atomic rename + parent-dir fsync).
/// - `<root>/<hex-shard>.lock` — the stable per-shard advisory-lock sidecar
///   (never renamed, so the lock stays on one inode); its content is unused.
/// - `<root>/<hex-shard>.tmp` — [`atomic_write_json`]'s transient sibling.
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

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("decern-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    // --------------------------- mission registry ---------------------------

    fn mentry(approver: &str, expiry: u64) -> MissionEntry {
        MissionEntry {
            approver: approver.into(),
            expiry,
            terminated: false,
        }
    }

    fn mission_lifecycle(r: &dyn MissionRegistry) {
        assert!(r.status("m1").unwrap().is_none(), "unknown mission → None");
        r.register("m1", mentry("corp", 1000), 10).unwrap();
        let got = r.status("m1").unwrap().unwrap();
        assert_eq!(got.approver, "corp");
        assert!(!got.terminated, "freshly registered is active");

        // re-register the same active mission is an idempotent no-op
        r.register("m1", mentry("corp", 1000), 10).unwrap();
        assert!(!r.status("m1").unwrap().unwrap().terminated);

        // terminate is monotone: it sticks and cannot be re-registered back to active
        r.terminate("m1", 10).unwrap();
        assert!(
            r.status("m1").unwrap().unwrap().terminated,
            "termination sticks"
        );
        let err = r.register("m1", mentry("corp", 1000), 10).unwrap_err();
        assert!(
            matches!(err, StoreError::Invalid(_)),
            "a terminated mission cannot be revived: {err}"
        );
        assert!(
            r.status("m1").unwrap().unwrap().terminated,
            "still terminated"
        );

        // terminating an unknown mission is a no-op
        r.terminate("ghost", 10).unwrap();
        assert!(r.status("ghost").unwrap().is_none());
    }

    #[test]
    fn mission_registry_memory_lifecycle() {
        mission_lifecycle(&MemoryMissionRegistry::new());
    }

    #[test]
    fn mission_registry_file_lifecycle() {
        let path = tmp("mission.json");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(path.with_extension("lock")).ok();
        mission_lifecycle(&FileMissionRegistry::open(&path).unwrap());
    }

    #[test]
    fn mission_registry_gc_drops_expired_on_write() {
        let r = MemoryMissionRegistry::new();
        r.register("old", mentry("corp", 100), 10).unwrap();
        assert!(r.status("old").unwrap().is_some());
        // a later register past `old`'s expiry evicts it — bounded to live missions
        r.register("new", mentry("corp", 500), 200).unwrap();
        assert!(
            r.status("old").unwrap().is_none(),
            "expired mission GC'd on write"
        );
        assert!(r.status("new").unwrap().is_some());
    }

    #[test]
    fn terminated_mission_does_not_revive_after_expiry() {
        // A terminated mission must not come back as Active once its own expiry lapses.
        // Before the fix, mission_register's `retain(e.expiry > now)` ran BEFORE the
        // terminated-check, so the terminated tombstone was GC-evicted at expiry and
        // re-registering the identical s256 returned Active — expiry laundered a
        // termination. Terminated tombstones are now retained past expiry, so the store
        // keeps refusing re-registration.
        let r = MemoryMissionRegistry::new();
        r.register("m", mentry("corp", 1_000), 100).unwrap();
        r.terminate("m", 100).unwrap();
        assert!(
            r.status("m").unwrap().unwrap().terminated,
            "terminated tombstone present"
        );
        // advance `now` past the mission's own expiry, then re-register the identical
        // s256: it must STILL be refused, not revived to Active.
        let revived = r.register("m", mentry("corp", 1_000), 5_000);
        assert!(
            revived.is_err(),
            "a terminated grant must not re-register as Active after its expiry"
        );
        if let Some(e) = r.status("m").unwrap() {
            assert!(e.terminated, "must stay terminated, never revive to Active");
        }
    }

    #[test]
    fn register_refuses_an_already_expired_mission() {
        // The store is self-monotone: registering a mission whose expiry has already
        // passed is refused, independent of the identity-layer approve() guard — so a
        // direct decern-store consumer cannot create (or revive) an expired entry as Active.
        let r = MemoryMissionRegistry::new();
        assert!(
            r.register("m", mentry("corp", 1_000), 5_000).is_err(),
            "an already-expired new registration must be refused"
        );
        // The direct-bypass revival: terminate, wait past the tombstone retention horizon
        // (so the tombstone is GC-evicted), then re-register the identical expired grant —
        // still refused, now by the expiry guard rather than the tombstone.
        r.register("m2", mentry("corp", 1_000), 100).unwrap();
        r.terminate("m2", 100).unwrap();
        let past_horizon = 1_000 + 30 * 24 * 60 * 60 + 1;
        assert!(
            r.register("m2", mentry("corp", 1_000), past_horizon)
                .is_err(),
            "an expired terminated grant must not re-register even after the tombstone horizon"
        );
    }

    #[test]
    fn mission_termination_propagates_across_processes() {
        // The core: a mission TERMINATED by one process must stop the mint
        // path in another — a stale in-memory handle is not the authority.
        let path = tmp("mission-xproc.json");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(path.with_extension("lock")).ok();
        let minter = FileMissionRegistry::open(&path).unwrap();
        let operator = FileMissionRegistry::open(&path).unwrap();

        operator
            .register("m", mentry("corp", 1_000_000), 10)
            .unwrap();
        assert!(
            !minter.status("m").unwrap().unwrap().terminated,
            "active to the minter"
        );
        // operator (another process) terminates the mission...
        operator.terminate("m", 10).unwrap();
        // ...the minter must SEE it and refuse to mint under it
        assert!(
            minter.status("m").unwrap().unwrap().terminated,
            "minter sees a termination written by another process"
        );
    }

    #[cfg(unix)]
    #[test]
    fn durable_store_files_are_0600_not_world_or_group_readable() {
        // atomic_write_json_impl is shared by every durable backend (the ledger head
        // store and the mission registry); a store file world-readable at 0644 would
        // let any local user read its contents without ever touching the process.
        // Assert the file this write path actually produces on disk carries 0600, not
        // just that the API compiles.
        use std::os::unix::fs::PermissionsExt;
        let path = tmp("mission-perms.json");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(path.with_extension("lock")).ok();
        let r = FileMissionRegistry::open(&path).unwrap();
        r.register("m-perm-check", mentry("root", 1000), 10)
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mission store file must be 0600, got {mode:o}");
    }

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
