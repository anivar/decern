// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The durable substrate both stores share: atomic JSON writes, file fingerprints,
//! exclusive advisory write locks and the cross-process coherent map.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;

use crate::StoreError;

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
pub(crate) struct CoherentMap<V> {
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
    pub(crate) fn open(path: PathBuf) -> Result<Self, StoreError> {
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
    pub(crate) fn read<R>(
        &self,
        f: impl FnOnce(&BTreeMap<String, V>) -> R,
    ) -> Result<R, StoreError> {
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
    pub(crate) fn write<R>(
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

/// Serialize `value` as pretty JSON and write it to `path` atomically: a sibling
/// temp file is written, fsync'd, then renamed over the target (rename is atomic
/// within a filesystem), so a crash mid-write can never leave a half-written file.
/// Shared by the durable backends (the mission registry and the ledger head store)
/// where a lost write would resurrect terminated or superseded state.
pub(crate) fn atomic_write_json(path: &Path, value: &impl Serialize) -> Result<(), StoreError> {
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
        // gets whatever default permissions the platform gives, unhardened. The release
        // ships a Windows binary, so the gap is live there — mirroring the
        // `FileFingerprint`/`fingerprint_of` non-unix note elsewhere in
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
        // already reported as `Ok` — a resurrected killed credential. Skipped on
        // non-unix targets, so there the rename is not made durable.
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
pub(crate) fn with_write_lock<T>(
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

pub(crate) fn io(path: &Path, e: impl std::fmt::Display) -> StoreError {
    StoreError::Io {
        path: path.display().to_string(),
        err: e.to_string(),
    }
}

pub(crate) fn poisoned<T>(_: std::sync::PoisonError<T>) -> StoreError {
    StoreError::Invalid("directory store lock poisoned".into())
}
