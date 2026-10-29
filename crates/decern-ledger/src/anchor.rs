// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Anchors: persisting a checkpoint as the ledger's anchor file, loading it, and checking that a
//! ledger still extends a checkpoint.

#[cfg(doc)]
use crate::Ledger;
use crate::checkpoint::Checkpoint;
use crate::error::{LedgerError, io_err};
use crate::open::Location;
use crate::record::{GENESIS, RecordIn, chain_hash};
use std::path::Path;

/// The operator-independent tamper check: does the ledger at `path` still extend a
/// previously issued `cp`? Re-derives the head over the first `cp.count` records
/// from the stored bytes and confirms it equals `cp.root`. If the operator edited,
/// reordered, or truncated any entry at or before `count`, the re-derived root
/// diverges and this returns `Ok(false)` — caught by anyone holding the old
/// checkpoint, without trusting the operator. A well-behaved append-only log always
/// extends its past checkpoints.
pub fn ledger_extends_checkpoint(path: &Path, cp: &Checkpoint) -> Result<bool, LedgerError> {
    ledger_extends_checkpoint_at(&Location::detect(path), cp)
}

pub(crate) fn ledger_extends_checkpoint_at(
    location: &Location,
    cp: &Checkpoint,
) -> Result<bool, LedgerError> {
    Ok(root_at_count(location, cp.count)?.as_deref() == Some(cp.root.as_str()))
}

/// Persist a checkpoint as the ledger's anchor file, atomically (temp + fsync +
/// rename, and on Unix a parent-dir fsync) so a crash cannot leave a half-written anchor,
/// nor on Unix a non-durable one — a lost anchor write would silently lower the height
/// truncation is checked against. A parent-dir fsync that fails is this function's error,
/// never an `Ok`; on a target that cannot open a directory the rename is not made durable.
/// See [`Ledger::seal_anchor`].
pub fn save_anchor(anchor_path: &Path, cp: &Checkpoint) -> Result<(), LedgerError> {
    let bytes = serde_json::to_vec_pretty(cp).map_err(|e| LedgerError::Serde(e.to_string()))?;
    let tmp = anchor_path.with_extension("anchor-tmp");
    crate::fsync::write_atomic(anchor_path, &tmp, &bytes).map_err(LedgerError::from)
}

/// Load the persisted anchor, or `None` if no anchor file exists yet. A present but
/// unparseable anchor is a hard error (fail-closed — a corrupt anchor is never
/// silently treated as "no committed height").
pub fn load_anchor(anchor_path: &Path) -> Result<Option<Checkpoint>, LedgerError> {
    match std::fs::read(anchor_path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).map_err(|e| LedgerError::Serde(e.to_string()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(anchor_path, e)),
    }
}

/// Re-derive the hash-chain head after exactly the first `count` records. Mirrors
/// [`verify`]'s per-record hashing (stored bytes + prev), independently, so any
/// rewrite below `count` changes the result. `None` if the file holds fewer than
/// `count` records (truncated below the checkpoint).
fn root_at_count(location: &Location, count: u64) -> Result<Option<String>, LedgerError> {
    if count == 0 {
        return Ok(Some(GENESIS.to_owned()));
    }
    let mut prev = GENESIS.to_owned();
    let mut seen: u64 = 0;
    // Consume the PREFIX (any crash-torn trailing fragment excluded), so the
    // anchor/truncation check derives the head over ACKED history only and a
    // half-written tail can neither spoof a match nor spuriously error. A prefix
    // shorter than `count` still yields `None` — the truncation-below-anchor
    // signal, which is exactly how a ragged attacker truncation stays Tamper.
    let (lines, _torn) = location.prefix_lines()?;
    for line in lines {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: RecordIn = serde_json::from_str(&line).map_err(|e| LedgerError::Tamper {
            seq: seen,
            why: format!("unparseable record: {e}"),
        })?;
        if record.prev != prev {
            return Err(LedgerError::Tamper {
                seq: seen,
                why: "broken chain link (prev mismatch)".into(),
            });
        }
        let hash = hex::encode(chain_hash(record.entry.get().as_bytes(), &record.prev));
        if hash != record.hash {
            return Err(LedgerError::Tamper {
                seq: seen,
                why: "entry altered (hash mismatch)".into(),
            });
        }
        prev = record.hash;
        seen += 1;
        if seen == count {
            return Ok(Some(prev));
        }
    }
    Ok(None)
}
