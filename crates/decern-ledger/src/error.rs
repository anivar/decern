// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The ledger's error type.

use std::path::Path;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LedgerError {
    #[error("ledger I/O error at {path}: {err}")]
    Io { path: String, err: String },
    #[error("ledger serialization error: {0}")]
    Serde(String),
    #[error("TAMPER at seq {seq}: {why}")]
    Tamper { seq: u64, why: String },
    /// The log's FINAL physical line is structurally incomplete — the file does
    /// not end in a newline, so the trailing record was only partially written
    /// (a crash between/mid the single `append` write and its `flush`/`sync`).
    /// DISTINCT from [`Tamper`](LedgerError::Tamper) on purpose: a benign
    /// crash-during-append must never be reported as an attack. The verified
    /// PREFIX — every fully-terminated, chain-valid, signature-valid record —
    /// is intact and is the ledger; `healed_entries` is its length and
    /// `healed_root` its head hash. The open path HEALS this (truncates the torn
    /// fragment at `torn_from_offset` in `torn_path`) after first confirming the
    /// prefix still extends any persisted anchor — because a crash can only ever
    /// drop an un-acked tail, whereas a shorter-than-anchor prefix means acked
    /// history was deleted and stays [`Tamper`](LedgerError::Tamper). The
    /// read-only `verify*` entry points surface this variant rather than healing.
    #[error(
        "TORN TAIL: unterminated trailing record (crash mid-append); \
         {healed_entries} verified records intact before it"
    )]
    TornTail {
        healed_entries: u64,
        healed_root: Option<String>,
        torn_path: String,
        torn_from_offset: u64,
    },
    /// The signing key may not extend this log: another key has signed after it, or, in a
    /// sharded store several processes write, the shard's latest record is signed by a key
    /// this process does not hold. This key may be the one out of date; the refusal comes
    /// before anything is written.
    #[error("signing key {kid} may not extend this log: {why}")]
    KeySuperseded { kid: String, why: String },
}

pub(crate) fn io_err(path: &Path, e: impl std::fmt::Display) -> LedgerError {
    LedgerError::Io {
        path: path.display().to_string(),
        err: e.to_string(),
    }
}
