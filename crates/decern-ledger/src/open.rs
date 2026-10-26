// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Where a ledger's bytes live, and opening them: the location, the scan and heal of a torn tail,
//! and the append handle.

use crate::anchor::{ledger_extends_checkpoint_at, load_anchor};
use crate::checkpoint::{key_fingerprint, verify_checkpoint_sig};
use crate::error::{LedgerError, io_err};
use crate::segment;
use crate::verify::{VerifyReport, verify_prefix};
use decern_crypto::VerifyingKey;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

/// Where a [`Ledger`]'s bytes live: a single append-only file (the default)
/// or a segmented directory (opt-in, see
/// [`Ledger::open_segmented`]). `detect` is used ONLY by the path-taking free
/// functions (`verify`, `verify_with_keys`, `read_verified`,
/// `ledger_extends_checkpoint`) so they stay
/// segmentation-transparent for external callers with zero signature changes;
/// a `Ledger`'s own methods already know their kind from how they were
/// opened and never need to re-detect it.
#[derive(Clone)]
pub(crate) enum Location {
    Single(PathBuf),
    Segmented(PathBuf),
}

impl Location {
    pub(crate) fn detect(path: &Path) -> Self {
        if path.is_dir() {
            Location::Segmented(path.to_path_buf())
        } else {
            Location::Single(path.to_path_buf())
        }
    }

    /// Every file this location's bytes live in, in seq order. `Single` is
    /// always exactly one path (even if it doesn't exist yet — the same
    /// "doesn't exist" a plain `File::open` would report); `Segmented` reads
    /// the manifest and fails closed if a listed segment is missing from
    /// disk.
    fn resolved_paths(&self) -> Result<Vec<PathBuf>, LedgerError> {
        match self {
            Location::Single(p) => Ok(vec![p.clone()]),
            Location::Segmented(dir) => segment::segment_paths(dir),
        }
    }

    pub(crate) fn lines(&self) -> Result<segment::ChainedLines, LedgerError> {
        Ok(segment::chained_lines(self.resolved_paths()?))
    }

    /// The lines of this location's PREFIX — every fully `\n`-terminated line —
    /// with any crash-torn trailing fragment (bytes after the final newline of
    /// the last file) excluded. Returns the iterator plus `Some(TornFragment)` when
    /// such a fragment exists, or `None` when the last file ends cleanly (the
    /// normal case). Verification and root re-derivation both consume THIS, so a
    /// torn fragment is never mistaken for a corrupt record.
    pub(crate) fn prefix_lines(
        &self,
    ) -> Result<(segment::ChainedLines, Option<TornFragment>), LedgerError> {
        let paths = self.resolved_paths()?;
        let torn = match paths.last() {
            Some(last) => scan_torn_tail(last)?,
            None => None,
        };
        let limit = torn.as_ref().map(|t| t.offset).unwrap_or(u64::MAX);
        Ok((segment::chained_lines_bounded(paths, limit), torn))
    }
}

/// A crash-torn trailing fragment discovered on the last file: the file does
/// not end in `\n`, so everything from `offset` (the byte just past the final
/// newline, or 0 if the file has no newline at all) to EOF was only partially
/// written and must be discarded to recover the verified prefix.
pub(crate) struct TornFragment {
    pub(crate) path: PathBuf,
    pub(crate) offset: u64,
}

/// Inspect `path`'s LAST byte. Returns `None` (no torn tail) when the file is
/// missing, empty, or already ends in `\n`. Otherwise the file's final record
/// was not newline-terminated → returns the offset just past its last `\n` (0
/// if none), i.e. where the log must be truncated to drop the torn fragment.
/// Keyed purely on newline-termination: given `append` writes `line + "\n"` in a
/// single `write_all`, a present terminator proves the whole record reached the
/// file, and its absence proves a partial write — so a terminated line is never
/// a torn tail (a terminated-but-corrupt final record stays `Tamper`), and an
/// unterminated one always is (even if its bytes happen to parse — it was never
/// acked, and keeping it would fuse onto the next append on one physical line).
fn scan_torn_tail(path: &Path) -> Result<Option<TornFragment>, LedgerError> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err(path, e)),
    };
    let len = f.metadata().map_err(|e| io_err(path, e))?.len();
    if len == 0 {
        return Ok(None);
    }
    // Cheap last-byte check first: a clean, newline-terminated file (the common
    // case) costs one seek + one byte read and exits here.
    f.seek(SeekFrom::End(-1)).map_err(|e| io_err(path, e))?;
    let mut last = [0u8; 1];
    f.read_exact(&mut last).map_err(|e| io_err(path, e))?;
    if last[0] == b'\n' {
        return Ok(None);
    }
    // Unterminated: scan backward in chunks for the final newline. The torn
    // fragment is a single partially-written record, but records can be large,
    // so loop rather than assume it fits one chunk.
    const CHUNK: u64 = 64 * 1024;
    let mut pos = len;
    let mut buf = vec![0u8; CHUNK as usize];
    while pos > 0 {
        let read_len = CHUNK.min(pos);
        let start = pos - read_len;
        f.seek(SeekFrom::Start(start))
            .map_err(|e| io_err(path, e))?;
        let slice = &mut buf[..read_len as usize];
        f.read_exact(slice).map_err(|e| io_err(path, e))?;
        if let Some(idx) = slice.iter().rposition(|&b| b == b'\n') {
            // Byte just past this newline, in absolute file coordinates.
            return Ok(Some(TornFragment {
                path: path.to_path_buf(),
                offset: start + idx as u64 + 1,
            }));
        }
        pos = start;
    }
    // No newline anywhere: the whole file is one torn (never-acked) record.
    Ok(Some(TornFragment {
        path: path.to_path_buf(),
        offset: 0,
    }))
}

/// Verify the log an open will extend and return its report, whose `root` and `entries`
/// are the head to append from, healing a crash-torn tail iff it does not erase acked
/// history. A `signer` that another key has followed in the log is refused before
/// anything is written: its next record would not verify.
///
/// This is the code that implements the task's core distinction: the anchor is
/// the line between "a crash dropped an un-acked tail" (heal) and "someone
/// deleted acked records" (tamper). On [`LedgerError::TornTail`] the persisted
/// anchor is consulted BEFORE the file is mutated — if the verified prefix no
/// longer extends the last committed height, the torn tail is really a ragged
/// truncation of acked history and stays [`LedgerError::Tamper`], with the file
/// left untouched. Only once the prefix is proven to still cover the anchor is
/// the torn fragment physically discarded.
pub(crate) fn resolve_open_head(
    location: &Location,
    verifiers: &[VerifyingKey],
    signer: &VerifyingKey,
    anchor: Option<&Path>,
) -> Result<VerifyReport, LedgerError> {
    let (report, torn) = verify_prefix(location, verifiers, None)?;
    // Consult the anchor BEFORE any mutation, and before the signing key is judged: a
    // truncation is tamper whichever key opens the log.
    if let Some(anchor_path) = anchor
        && let Some(cp) = load_anchor(anchor_path)?
    {
        if !verifiers.iter().any(|k| verify_checkpoint_sig(&cp, k)) {
            return Err(LedgerError::Tamper {
                seq: cp.count,
                why: "anchor signature is not from a trusted ledger key \
                          (forged or wrong-key anchor)"
                    .into(),
            });
        }
        // `ledger_extends_checkpoint_at` re-derives the head over the
        // PREFIX only (torn fragment excluded), so a prefix shorter
        // than the committed height reports `false` here.
        if !ledger_extends_checkpoint_at(location, &cp)? {
            let why = if torn.is_some() {
                format!(
                    "ledger no longer extends its anchor at count {} — the trailing \
                     record is unterminated AND the verified prefix is below the last \
                     committed height (acked history truncated, not a crash tail)",
                    cp.count
                )
            } else {
                format!(
                    "ledger no longer extends its anchor at count {} — truncated or rewritten \
                     below the last committed height",
                    cp.count
                )
            };
            return Err(LedgerError::Tamper { seq: cp.count, why });
        }
    }
    let kid = key_fingerprint(signer);
    if let Some(next) = report.superseded_by(&kid) {
        return Err(LedgerError::KeySuperseded {
            kid,
            why: format!(
                "key {} signed after it, from seq {}; open the log with that key or a later one",
                next.kid, next.first_seq
            ),
        });
    }
    // Prefix covers the anchor (or there is none): the torn fragment was
    // never acked. Discard it durably, then adopt the healed head — but only a fragment a
    // crash mid-append could leave, which begins a record. Anything else means this is not a
    // ledger's tail, and truncating it would destroy a file that was never ours.
    if let Some(torn) = torn {
        if !begins_a_record(&torn.path, torn.offset)? {
            return Err(LedgerError::Tamper {
                seq: report.entries,
                why: format!(
                    "the unterminated last line of {} does not begin a ledger record; refusing \
                     to truncate a file that may not be a ledger",
                    torn.path.display()
                ),
            });
        }
        heal_torn_tail(&torn.path, torn.offset)?;
    }
    Ok(report)
}

/// Physically discard a crash-torn trailing fragment by truncating `path` to
/// `offset` (the byte just past the log's final newline). fsync'd so the
/// recovery is itself durable — a second crash cannot resurrect the fragment.
/// Called only after [`resolve_open_head`] has proven the prefix still covers
/// any anchor, so this never deletes acked history.
fn begins_a_record(path: &Path, offset: u64) -> Result<bool, LedgerError> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = File::open(path).map_err(|e| io_err(path, e))?;
    f.seek(SeekFrom::Start(offset))
        .map_err(|e| io_err(path, e))?;
    let mut first = [0u8; 1];
    let n = f.read(&mut first).map_err(|e| io_err(path, e))?;
    Ok(n == 1 && first[0] == b'{')
}

fn heal_torn_tail(path: &Path, offset: u64) -> Result<(), LedgerError> {
    let f = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| io_err(path, e))?;
    f.set_len(offset).map_err(|e| io_err(path, e))?;
    f.sync_all().map_err(|e| io_err(path, e))?;
    Ok(())
}

/// Open the ledger for append, owner-only.
///
/// The record holds decision subjects and the pseudonymous handles the subject-side audit
/// route is keyed by. It was being created at the process umask — commonly `0644` — while
/// the signing key and the mission registry beside it are `0600`, which made the audit log
/// the readable one. `.mode()` applies only when the file is created, so an existing file
/// is corrected too; both are needed, the same reasoning `decern-store` documents for the
/// mission registry.
///
/// Unlike the signing key this does not refuse a group- or other-readable file: a ledger
/// is not a secret in the way a key is, existing deployments have readable ones, and
/// failing their next append would be a worse outcome than tightening it in place.
pub(crate) fn open_append_owner_only(path: &Path) -> Result<File, LedgerError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| io_err(path, e))?;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| io_err(path, e))
    }
}

/// Take the one writer's lock on the single-file ledger at `path`, held while the returned
/// file stays open. Two processes appending to one ledger each extend the chain from the same
/// head and fork it, so a second writer is refused here, before its open-time verify could
/// trim the first writer's record in flight as a torn tail.
///
/// On Unix the lock is on the ledger file itself, so every path, link or mount that reaches
/// the same file shares it; readers take no lock and are not blocked. An existing ledger is
/// opened read-only for it and left as it is; an absent one is created, owner-only, and
/// [`WriterLock::created`] says so. On Windows a lock on the file would block the reads every
/// verify makes, so the lock is a sidecar `<ledger>.lock` beside the ledger's canonical path,
/// which another spelling or a symbolic link finds and a hard link does not. The sidecar is
/// left in place.
pub(crate) fn lock_single_writer(path: &Path) -> Result<WriterLock, LedgerError> {
    #[cfg(unix)]
    let (file, created, sidecar) = {
        use std::os::unix::fs::OpenOptionsExt;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(f) => (f, true, None::<PathBuf>),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match File::open(path) {
                Ok(f) => (f, false, None),
                // A symbolic link to a ledger not created yet: create it through the link.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let f = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .mode(0o600)
                        .open(path)
                        .map_err(|e| io_err(path, e))?;
                    (f, true, None)
                }
                Err(e) => return Err(io_err(path, e)),
            },
            Err(e) => return Err(io_err(path, e)),
        }
    };
    #[cfg(not(unix))]
    let (file, created, sidecar) = {
        let lock_path = writer_lock_path(path)?;
        (open_lock_file(&lock_path)?, false, Some(lock_path))
    };
    match file.try_lock() {
        Ok(()) => Ok(WriterLock {
            _file: file,
            created,
        }),
        Err(fs::TryLockError::WouldBlock) => Err(LedgerError::Io {
            path: path.display().to_string(),
            err: format!(
                "another process has this ledger open for writing{}; stop it, or give this \
                 process a ledger of its own",
                sidecar
                    .map(|p| format!(" (it holds {})", p.display()))
                    .unwrap_or_default()
            ),
        }),
        Err(fs::TryLockError::Error(e)) => Err(io_err(path, e)),
    }
}

/// The single-file ledger's writer lock, released when dropped.
pub(crate) struct WriterLock {
    _file: File,
    /// Whether taking the lock created the ledger file, which a ledger opened afresh starts
    /// from rather than verifying.
    pub(crate) created: bool,
}

/// The Windows sidecar, created if absent and never truncated. Compiled everywhere, so the
/// Unix build checks it too.
#[cfg_attr(unix, allow(dead_code))]
fn open_lock_file(lock_path: &Path) -> Result<File, LedgerError> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path)
        .map_err(|e| io_err(lock_path, e))
}

/// `<ledger>.lock` beside the ledger's canonical path, or, for a ledger not yet created,
/// beside its name in its directory's canonical path. Windows only, compiled everywhere.
#[cfg_attr(unix, allow(dead_code))]
fn writer_lock_path(path: &Path) -> Result<PathBuf, LedgerError> {
    let canonical = match fs::canonicalize(path) {
        Ok(p) => p,
        Err(_) => {
            let name = path.file_name().ok_or_else(|| LedgerError::Io {
                path: path.display().to_string(),
                err: "a ledger path must name a file".into(),
            })?;
            let dir = match path.parent() {
                Some(d) if !d.as_os_str().is_empty() => d,
                _ => Path::new("."),
            };
            fs::canonicalize(dir)
                .map_err(|e| io_err(dir, e))?
                .join(name)
        }
    };
    let mut name = canonical
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".lock");
    Ok(canonical.with_file_name(name))
}
