// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Per-epoch/size segmentation for the sovereign single-file [`crate::Ledger`].
//!
//! The single-file ledger is one ever-growing `.jsonl` plus an anchor sidecar;
//! opening it re-verifies the WHOLE chain, so a long-lived sovereign node's
//! startup cost and single-file size both grow unbounded. This module adds an
//! OPT-IN alternative: a directory of numbered segment files
//! (`00000001.jsonl`, `00000002.jsonl`, ...) plus a `manifest.json` naming
//! them in order, with exactly one active (unsealed, currently appended-to)
//! segment at a time.
//!
//! The chain hash itself (`hash = SHA-256(entry_bytes ‖ prev_hex)`) never
//! changes shape — a segment boundary is invisible to it. The first record of
//! a new segment carries `prev = <last sealed hash of the previous segment>`
//! exactly as any other record would, so cross-segment verification is the
//! SAME chain walk `verify_lines` already does, just fed lines from more than
//! one file, in order. This is what makes segmentation additive rather than a
//! parallel, divergent verification path.
//!
//! Existing single-file logs and every existing `Ledger::open*` call site are
//! completely unaffected: segmentation is reached only via the new
//! [`crate::Ledger::open_segmented`]/`open_segmented_anchored` constructors on
//! the WRITE side. On the READ side, every path-taking free function
//! (`verify`, `verify_with_keys`, `read_verified`,
//! `ledger_extends_checkpoint`) auto-detects: `path.is_dir()` means segmented,
//! anything else means the single-file path exactly as before (a directory
//! could never have been a valid single-file ledger anyway, so this can only
//! ever change behavior in a case that previously always errored).
//!
//! Manifest is UNTRUSTED metadata, same trust level as the single-file case's
//! bare file listing: it is a ROUTING HINT (which files, in what order) never
//! a source of truth for chain height. Dropping the newest segment(s) from
//! disk AND the manifest is a tail-truncation, exactly as deleting the tail of
//! a single file would be — invisible to the chain walk itself, caught only by
//! the externally-anchored checkpoint (`ledger_extends_checkpoint`,
//! `Ledger::verify_against_anchor`), which re-derives root+count from actual
//! segment BYTES, never from any count cached in the manifest.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Lines, Read, Take, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{LedgerError, io_err};

const MANIFEST_FILE: &str = "manifest.json";

/// When a segmented ledger rolls its active segment over to a new file. Both
/// may be set (roll over on whichever fires first); both `None` is legal but
/// pointless (a segmented ledger with exactly one ever-growing segment).
#[derive(Debug, Clone, Copy, Default)]
pub struct RolloverPolicy {
    pub max_bytes: Option<u64>,
    pub epoch_ms: Option<u64>,
}

impl RolloverPolicy {
    pub fn max_bytes(max_bytes: u64) -> Self {
        Self {
            max_bytes: Some(max_bytes),
            epoch_ms: None,
        }
    }

    pub fn epoch_ms(epoch_ms: u64) -> Self {
        Self {
            max_bytes: None,
            epoch_ms: Some(epoch_ms),
        }
    }

    pub fn either(max_bytes: u64, epoch_ms: u64) -> Self {
        Self {
            max_bytes: Some(max_bytes),
            epoch_ms: Some(epoch_ms),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SegmentMeta {
    pub file: String,
    pub start_seq: u64,
    /// `None` while this is the active (currently appended-to) segment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_seq: Option<u64>,
    /// The `ts_ms` of the entry that started this segment — the epoch-bucket
    /// rollover check compares a candidate entry's `ts_ms` against this, not
    /// wall-clock time, so rollover stays deterministic and testable (mirrors
    /// the caller-supplied-time convention `decern-cli`'s `--now` flags already
    /// use elsewhere; this crate makes no wall-clock call of its own).
    pub opened_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Manifest {
    pub version: u32,
    pub segments: Vec<SegmentMeta>,
}

impl Manifest {
    pub(crate) fn active(&self) -> Option<&SegmentMeta> {
        self.segments.iter().find(|s| s.end_seq.is_none())
    }

    pub(crate) fn active_mut(&mut self) -> Option<&mut SegmentMeta> {
        self.segments.iter_mut().find(|s| s.end_seq.is_none())
    }
}

pub(crate) fn segment_filename(index: u32) -> String {
    format!("{index:08}.jsonl")
}

/// A segment filename must be EXACTLY the shape [`segment_filename`] produces
/// — 8 ASCII digits + `.jsonl`, never a path separator, `..`, or an absolute
/// path. The manifest is untrusted metadata (see module docs): every
/// filename it names is validated the moment the manifest is loaded, so
/// nothing downstream (`segment_paths`'s `dir.join`, `max_index`'s
/// arithmetic) ever has to re-check a hostile string on its own. This closes
/// two things at once: a manifest entry's `file` field smuggling a
/// path-traversal payload (`dir.join("../secret")` escapes `dir` entirely,
/// same for an absolute path — both are Rust/OS-standard `Path::join`
/// behavior, not a bug in `join` itself), and an out-of-range index (e.g.
/// `4294967295.jsonl`, exactly `u32::MAX`) that could overflow the `+ 1` in
/// [`roll_over`] — the 8-digit cap keeps every valid index under 100,000,000,
/// nowhere near overflow, so the two fixes are the same one check.
fn validate_segment_filename(file: &str) -> Result<u32, LedgerError> {
    let bad = || LedgerError::Tamper {
        seq: 0,
        why: format!(
            "manifest names a segment file with an invalid shape: {file:?} (expected exactly \
             8 digits + \".jsonl\", e.g. 00000001.jsonl)"
        ),
    };
    let digits = file.strip_suffix(".jsonl").ok_or_else(bad)?;
    if digits.len() != 8 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    digits.parse().map_err(|_| bad())
}

/// Directory-scan variant of [`validate_segment_filename`]: a file on disk
/// that isn't a validly-shaped segment name (the manifest itself, a `.tmp`
/// file, anything else) is just not a segment — silently skipped, not an
/// error, since a segment directory legitimately holds non-segment files.
fn parse_index(filename: &str) -> Option<u32> {
    validate_segment_filename(filename).ok()
}

/// A valid manifest: has at least one segment; has EXACTLY one active
/// (unsealed, `end_seq: None`) segment, which must be the LAST entry; its
/// earliest segment starts at seq 0 (the true chain head); and every
/// adjacent pair hands off exactly where the next one starts, with no gap,
/// overlap, or reordering. Checked the moment a manifest is loaded (inside
/// [`load_manifest`], so every caller — `open_segmented`'s reopen path AND
/// every subsequent read through `segment_paths`, including
/// `Ledger::read_records`/`read_raw_records` on an ALREADY-OPEN handle,
/// neither of which re-runs the chain walk — gets this for free).
///
/// This is shape validation only: it can catch a manifest edit that changes
/// which SEGMENTS exist or what order they're listed in, but it has no way
/// to detect a manifest whose `file` field was swapped between two entries
/// while their `start_seq`/`end_seq` stayed put — that would still look
/// perfectly contiguous. Closing that would mean reading and checking each
/// segment's own first record against its declared `start_seq`, which is
/// exactly what the chain walk (`verify_lines`) already does — accepted as
/// the same "raw reads are unverified by design" property `read_records`/
/// `read_raw_records` already have for a plain single-file ledger (a
/// hand-edited `.jsonl` has the identical gap), not something this shape
/// check is meant to close.
fn validate_manifest_shape(manifest: &Manifest) -> Result<(), LedgerError> {
    if manifest.segments.is_empty() {
        return Err(LedgerError::Tamper {
            seq: 0,
            why: "manifest names zero segments — a valid segmented ledger always has at least \
                  one (segment::initialize never produces an empty list)"
                .into(),
        });
    }
    if manifest.segments[0].start_seq != 0 {
        return Err(LedgerError::Tamper {
            seq: 0,
            why: format!(
                "manifest's earliest segment {:?} starts at seq {}, not 0 — the true chain head \
                 is missing from this manifest",
                manifest.segments[0].file, manifest.segments[0].start_seq
            ),
        });
    }
    let active_count = manifest
        .segments
        .iter()
        .filter(|s| s.end_seq.is_none())
        .count();
    if active_count > 1 {
        return Err(LedgerError::Tamper {
            seq: 0,
            why: format!(
                "manifest names {active_count} active (unsealed) segments — exactly one is valid"
            ),
        });
    }
    if active_count == 1 && manifest.segments.last().is_none_or(|s| s.end_seq.is_some()) {
        return Err(LedgerError::Tamper {
            seq: 0,
            why: "manifest's active segment must be the last entry".into(),
        });
    }
    // Every segment but the tail must be sealed (guaranteed by the active-count
    // checks above) and must hand off exactly where the next one starts — no
    // gap, overlap, or reordering. A manifest edit that reorders two sealed
    // segments, or drops one from the middle while leaving the rest, changes
    // apparent read order (`segment_paths` walks the array in listed order) or
    // silently skips real committed records without tripping either check
    // above.
    for pair in manifest.segments.windows(2) {
        let (prev, next) = (&pair[0], &pair[1]);
        if prev.end_seq != Some(next.start_seq) {
            return Err(LedgerError::Tamper {
                seq: 0,
                why: format!(
                    "manifest segments {:?} (end_seq {:?}) and {:?} (start_seq {}) are not \
                     contiguous — segments must be listed in order with no gap, overlap, or \
                     reordering",
                    prev.file, prev.end_seq, next.file, next.start_seq
                ),
            });
        }
    }
    Ok(())
}

/// The highest segment index referenced by EITHER the manifest OR any file on
/// disk matching the segment naming pattern. Used to pick the next segment's
/// index on rollover: never derived from the manifest alone, so a rollover
/// that created a new segment file but crashed before committing the manifest
/// (an ORPHAN) can never be silently overwritten by a later rollover attempt
/// choosing the same index.
fn max_index(dir: &Path, manifest: &Manifest) -> Result<u32, LedgerError> {
    let mut max = manifest
        .segments
        .iter()
        .filter_map(|s| parse_index(&s.file))
        .max()
        .unwrap_or(0);
    for entry in fs::read_dir(dir).map_err(|e| io_err(dir, e))? {
        let entry = entry.map_err(|e| io_err(dir, e))?;
        if let Some(name) = entry.file_name().to_str()
            && let Some(idx) = parse_index(name)
        {
            max = max.max(idx);
        }
    }
    Ok(max)
}

/// Read `dir/manifest.json`; `None` if the directory has no manifest yet (a
/// fresh segmented ledger about to be created).
pub(crate) fn load_manifest(dir: &Path) -> Result<Option<Manifest>, LedgerError> {
    let path = dir.join(MANIFEST_FILE);
    match fs::read(&path) {
        Ok(bytes) => {
            let manifest: Manifest =
                serde_json::from_slice(&bytes).map_err(|e| LedgerError::Serde(e.to_string()))?;
            // Validate BEFORE returning — every caller (segment_paths on every
            // read, open_segmented's reopen path) then trusts a manifest that
            // already passed both checks, rather than re-validating (or, worse,
            // forgetting to) at each call site.
            for seg in &manifest.segments {
                validate_segment_filename(&seg.file)?;
            }
            validate_manifest_shape(&manifest)?;
            Ok(Some(manifest))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(&path, e)),
    }
}

/// Persist the manifest atomically (temp file + fsync + rename + parent-dir
/// fsync — the SAME durability discipline [`crate::save_anchor`] already
/// uses). This rename is the single commit point for a rollover: creating the
/// new segment file (before this call) is safely re-doable if a crash lands
/// before the rename lands (the new file is just an orphan, ignored on
/// reopen — see [`max_index`]); sealing the old segment's file permissions
/// (after this call) is safely re-appliable on every open regardless of when
/// a crash lands relative to it.
pub(crate) fn save_manifest(dir: &Path, manifest: &Manifest) -> Result<(), LedgerError> {
    let path = dir.join(MANIFEST_FILE);
    let tmp = dir.join("manifest.json.tmp");
    let bytes =
        serde_json::to_vec_pretty(manifest).map_err(|e| LedgerError::Serde(e.to_string()))?;
    {
        let mut f = File::create(&tmp).map_err(|e| io_err(&tmp, e))?;
        f.write_all(&bytes).map_err(|e| io_err(&tmp, e))?;
        f.sync_all().map_err(|e| io_err(&tmp, e))?;
    }
    fs::rename(&tmp, &path).map_err(|e| io_err(&path, e))?;
    if let Ok(dirf) = File::open(dir) {
        let _ = dirf.sync_all();
    }
    Ok(())
}

/// Best-effort: mark a sealed segment file read-only (0444 on Unix). Defense
/// in depth, never the real protection (that's the chain + signature +
/// externally-anchored checkpoint, which no filesystem permission bit can
/// substitute for) — so a failure here is silently ignored rather than
/// failing the ledger open/append that triggered it, and it is re-applied on
/// every open, making it eventually consistent with no crash-atomicity needs
/// of its own.
pub(crate) fn seal_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o444));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// The write-side counterpart of [`seal_file_permissions`]: ensure the ACTIVE
/// segment is writable (0644 on Unix). Applied on every open, symmetrically
/// with sealing every sealed segment — so a manifest edit that re-marks a
/// previously-sealed (and thus read-only) segment as active again still
/// reopens cleanly, rather than failing with a confusing permission-denied
/// deep inside the append path. Best-effort, same non-load-bearing status as
/// `seal_file_permissions`.
pub(crate) fn unseal_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Every segment file the manifest names, in seq order, resolved to full
/// paths — fails closed if any listed segment is missing from disk (whether
/// the missing file is a sealed or the active one, its absence is exactly the
/// tail/mid truncation this crate exists to catch).
pub(crate) fn segment_paths(dir: &Path) -> Result<Vec<PathBuf>, LedgerError> {
    let manifest = load_manifest(dir)?.ok_or_else(|| LedgerError::Io {
        path: dir.display().to_string(),
        err: "segmented ledger directory has no manifest.json (not a valid segmented ledger — \
              use Ledger::open_segmented to create one)"
            .into(),
    })?;
    manifest
        .segments
        .iter()
        .map(|s| {
            let p = dir.join(&s.file);
            if p.exists() {
                Ok(p)
            } else {
                Err(LedgerError::Tamper {
                    seq: s.start_seq,
                    why: format!(
                        "segment {} is listed in the manifest but missing from disk (tail- or \
                         mid-truncation, or a corrupted deployment)",
                        s.file
                    ),
                })
            }
        })
        .collect()
}

/// Create a brand-new segmented ledger directory: one empty active segment
/// plus its manifest. Returns the manifest. `dir` must already exist (callers
/// create it via `create_dir_all` first) and must NOT already hold a
/// manifest — callers only reach this on the `load_manifest` `None` branch.
pub(crate) fn initialize(dir: &Path) -> Result<Manifest, LedgerError> {
    let first = SegmentMeta {
        file: segment_filename(1),
        start_seq: 0,
        end_seq: None,
        opened_ms: 0,
    };
    let seg_path = dir.join(&first.file);
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&seg_path)
        .map_err(|e| io_err(&seg_path, e))?;
    let manifest = Manifest {
        version: 1,
        segments: vec![first],
    };
    save_manifest(dir, &manifest)?;
    Ok(manifest)
}

/// Roll the active segment over: seal it (in a cloned, not-yet-committed
/// manifest) at `current_seq`, create the fresh active segment, atomically
/// commit the new manifest, then chmod the now-sealed old segment. Returns
/// the new manifest and the newly active segment's path — the caller
/// (`Ledger::roll_over`) swaps its open file handle to it and keeps the
/// returned manifest as its new in-memory state.
pub(crate) fn roll_over(
    dir: &Path,
    manifest: &Manifest,
    current_seq: u64,
    next_ts_ms: u64,
) -> Result<(Manifest, PathBuf), LedgerError> {
    // checked_add rather than a plain `+ 1` that would silently wrap in a
    // release build (matching this codebase's own established practice of
    // checked/saturating arithmetic on untrusted-input-derived sizes, e.g.
    // `read_verified`'s `offset.saturating_add(limit)`).
    let next_index = max_index(dir, manifest)?
        .checked_add(1)
        .ok_or_else(|| LedgerError::Io {
            path: dir.display().to_string(),
            err: "segment index exhausted (at u32::MAX)".into(),
        })?;
    // `segment_filename`'s `{:08}` is a MINIMUM width, not a cap: past index
    // 99,999,999 it emits 9+ digits, which `validate_segment_filename` (the
    // read-side gate every reopen and every read passes through) then
    // rejects as an invalid shape — so `checked_add` alone does NOT make
    // rollover past this point safe, it only stops the much-further-out
    // u32::MAX wraparound. Catch the real, much lower boundary HERE, before
    // creating the segment file or touching the manifest, so the failure is
    // a loud, immediate, uncommitted error at the rollover that would have
    // crossed it — never a silent write that only reveals itself as a false
    // `Tamper` on the NEXT read or reopen.
    if next_index > 99_999_999 {
        return Err(LedgerError::Io {
            path: dir.display().to_string(),
            err: format!(
                "segment index exhausted: the next segment index ({next_index}) no longer fits \
                 the 8-digit segment filename shape this ledger's segments use — this deployment \
                 has performed the maximum ~100,000,000 supported segment rollovers"
            ),
        });
    }
    let new_filename = segment_filename(next_index);
    let new_path = dir.join(&new_filename);
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&new_path)
        .map_err(|e| io_err(&new_path, e))?;

    let mut new_manifest = manifest.clone();
    let old_active = new_manifest.active_mut().ok_or_else(|| LedgerError::Io {
        path: dir.display().to_string(),
        err: "segmented ledger manifest has no active segment to seal".into(),
    })?;
    old_active.end_seq = Some(current_seq);
    let old_active_file = old_active.file.clone();
    new_manifest.segments.push(SegmentMeta {
        file: new_filename,
        start_seq: current_seq,
        end_seq: None,
        opened_ms: next_ts_ms,
    });

    // Durably flush the outgoing segment's tail BEFORE the manifest rename seals
    // its `end_seq`. Otherwise a crash here can leave the manifest claiming
    // records as sealed history that never reached disk — surfacing on reopen as
    // either a silently-shorter ledger or a false `Tamper` at the segment seam.
    {
        let old_path = dir.join(&old_active_file);
        let f = OpenOptions::new()
            .append(true)
            .open(&old_path)
            .map_err(|e| io_err(&old_path, e))?;
        f.sync_all().map_err(|e| io_err(&old_path, e))?;
    }

    save_manifest(dir, &new_manifest)?; // <- the crash-atomic commit point
    seal_file_permissions(&dir.join(&old_active_file)); // best-effort, after commit

    Ok((new_manifest, new_path))
}

/// A lazily-opened, seamlessly chained line source across `paths`, in
/// order — files are opened one at a time as the iterator advances, never all
/// up front, so a caller that only needs the first few thousand records (a
/// windowed read, or [`crate::root_at_count`]'s early exit once its target
/// count is reached) never touches a later segment's bytes at all. This is
/// the point of segmentation: bounded verification cost, not just bounded
/// file size.
pub(crate) struct ChainedLines {
    paths: std::vec::IntoIter<PathBuf>,
    current: Option<(PathBuf, Lines<BufReader<Take<File>>>)>,
    done: bool,
    /// Byte limit applied to the LAST file only (`u64::MAX` = unbounded, the
    /// normal case). Used by the torn-tail heal path to read a file up to — but
    /// not past — its final newline, so a crash-truncated trailing fragment is
    /// never fed to the verifier. Every non-last file is always read in full.
    last_limit: u64,
}

impl Iterator for ChainedLines {
    type Item = Result<String, LedgerError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            if let Some((path, lines)) = self.current.as_mut() {
                match lines.next() {
                    Some(Ok(line)) => return Some(Ok(line)),
                    Some(Err(e)) => {
                        self.done = true;
                        return Some(Err(io_err(path, e)));
                    }
                    None => {
                        self.current = None;
                    }
                }
            } else {
                let next_path = self.paths.next()?;
                // `paths` is an ExactSizeIterator; if nothing remains after
                // popping, this was the final file, so the last-file byte limit
                // applies. All earlier files are read unbounded.
                let limit = if self.paths.len() == 0 {
                    self.last_limit
                } else {
                    u64::MAX
                };
                match File::open(&next_path) {
                    Ok(f) => {
                        self.current = Some((next_path, BufReader::new(f.take(limit)).lines()));
                    }
                    Err(e) => {
                        self.done = true;
                        return Some(Err(io_err(&next_path, e)));
                    }
                }
            }
        }
    }
}

pub(crate) fn chained_lines(paths: Vec<PathBuf>) -> ChainedLines {
    chained_lines_bounded(paths, u64::MAX)
}

/// Like [`chained_lines`], but reads at most `last_limit` bytes of the FINAL
/// file (earlier files always in full). The torn-tail heal path passes the
/// offset of the final newline so the unterminated trailing fragment is
/// excluded from verification.
pub(crate) fn chained_lines_bounded(paths: Vec<PathBuf>, last_limit: u64) -> ChainedLines {
    ChainedLines {
        paths: paths.into_iter(),
        current: None,
        done: false,
        last_limit,
    }
}
