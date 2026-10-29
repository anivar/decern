// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind

//! The atomic write the anchor and the segment manifest share: a temp file beside the target,
//! fsynced, renamed over it, and on Unix the directory synced so the rename is durable.

use crate::error::{LedgerError, io_err};
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// How an atomic write failed: before its rename, so the previous file stands and a retry is
/// safe, or after it, so the new file is on disk and a caller's memory may be behind it.
#[derive(Debug)]
pub(crate) enum AtomicWrite {
    NotLanded(LedgerError),
    Landed(LedgerError),
}

impl From<AtomicWrite> for LedgerError {
    fn from(e: AtomicWrite) -> Self {
        match e {
            AtomicWrite::NotLanded(e) | AtomicWrite::Landed(e) => e,
        }
    }
}

/// Write `bytes` at `path` atomically: into `tmp` beside it, fsynced, renamed over `path`, then
/// the directory synced. A failure before the rename leaves the previous file and is reported as
/// not landed; a failure after it, the directory sync, leaves the new file and is reported as
/// landed. The directory sync runs on Unix only: elsewhere a directory cannot be opened as a
/// file, the sync is skipped, and the rename is not made durable, as the store's own atomic
/// write does.
pub(crate) fn write_atomic(path: &Path, tmp: &Path, bytes: &[u8]) -> Result<(), AtomicWrite> {
    let not_landed = AtomicWrite::NotLanded;
    {
        let mut f = File::create(tmp).map_err(|e| not_landed(io_err(tmp, e)))?;
        f.write_all(bytes).map_err(|e| not_landed(io_err(tmp, e)))?;
        f.sync_all().map_err(|e| not_landed(io_err(tmp, e)))?;
    }
    std::fs::rename(tmp, path).map_err(|e| not_landed(io_err(path, e)))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    sync_dir(parent).map_err(AtomicWrite::Landed)
}

/// Make a rename inside `dir` durable: on Unix, open the directory and fsync it, and return the
/// error when either step fails, so no caller answers `Ok` over a rename a crash may undo.
/// Elsewhere a directory cannot be opened as a file; nothing is done and the rename is not made
/// durable.
fn sync_dir(dir: &Path) -> Result<(), LedgerError> {
    #[cfg(unix)]
    {
        let dir_file = File::open(dir).map_err(|e| io_err(dir, e))?;
        dir_file.sync_all().map_err(|e| io_err(dir, e))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}
