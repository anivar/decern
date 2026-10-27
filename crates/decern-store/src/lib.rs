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
//! (temp file, fsync, rename over the target) hardened to `0600` on Unix, a
//! cross-process file-fingerprint coherent map, and exclusive file locks. The backends are
//! pure Rust and need no database — sovereign and offline-servable. The optional
//! multi-host Postgres head store lives in the separate `decern-store-postgres`
//! crate.

mod fsio;
mod head;
mod missions;

pub use head::{
    FileLedgerHeadStore, HeadCriticalSection, HeadCursor, KeySpan, LedgerHeadStore,
    MemoryLedgerHeadStore, ShardCriticalSection, ShardSigners, ShardWrite, StoredRecord,
};
pub use missions::{FileMissionRegistry, MemoryMissionRegistry, MissionEntry, MissionRegistry};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store I/O error at {path}: {err}")]
    Io { path: String, err: String },
    #[error("store serialization error: {0}")]
    Serde(String),
    #[error("invalid record: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod testing {
    use std::path::PathBuf;

    pub(crate) fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("decern-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }
}
