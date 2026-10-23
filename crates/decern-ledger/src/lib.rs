// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
#![forbid(unsafe_code)]
//! decern-ledger — the tamper-evident decision ledger (the audit column).
//!
//! Every authority decision is appended as a hash-chained, Ed25519-signed
//! record: `hash = SHA-256(entry_bytes ‖ prev_hash)`, signature over `hash`.
//! Any edit, reorder or in-place deletion breaks the chain; a wholesale
//! rewrite fails signature verification against the ledger key. What the
//! chain alone cannot detect is truncation of the *tail* — that is what
//! `root()` is for: export the head hash and anchor it externally (a
//! regulator, a notary, another system). Anchored root + intact chain =
//! complete, unmodified history.
//!
//! The chain hash covers the EXACT entry bytes as stored on disk (captured
//! via serde_json's RawValue at verify time), never a re-serialization — so
//! byte-stability is structural, not an assumption about JSON round-trips.
//! (Float round-tripping is NOT stable in serde_json without the
//! `float_roundtrip` feature; hashing re-serialized bytes was a confirmed
//! false-tamper bug that could brick an honest ledger.)

pub mod jcs;
pub mod merkle;
mod segment;
pub mod sharded;
pub use jcs::{canonicalize, digest};
pub use segment::RolloverPolicy;
pub use sharded::{
    ShardVerification, ShardedLedger, UNATTRIBUTED_SHARD, verify_sharded_dir,
    verify_sharded_dir_with_keys,
};

mod anchor;
mod bundle;
mod checkpoint;
mod error;
mod ledger;
mod open;
mod record;
mod verify;

pub use anchor::{ledger_extends_checkpoint, load_anchor, save_anchor};
pub use bundle::{BundleVerdict, verify_evidence_bundle};
pub use checkpoint::{
    Checkpoint, ConsistencyProof, EvidenceSnapshot, InclusionProof, TreeHead,
    verify_checkpoint_sig, verify_tree_head_sig,
};
pub use error::LedgerError;
pub use ledger::Ledger;
pub use record::{
    AssertedBy, ChallengeRecord, DIGEST_AUTHORITY, DIGEST_PARAMETERS, DecisionSubject, EdgeType,
    Entry, GENESIS, MissionRef, Party, Record, SponsorSource,
};
pub use verify::{
    SignerSpan, VerifyReport, inclusion_proofs_over, leaves_from_lines, merkle_leaves_at,
    merkle_leaves_with_keys, read_verified, read_verified_with_keys, verify, verify_with_keys,
};

pub(crate) use checkpoint::{checkpoint_bytes, key_fingerprint, tree_head_bytes};
pub(crate) use error::io_err;
pub(crate) use record::chain_hash;
pub(crate) use verify::verify_stored_records;

#[cfg(test)]
mod tests;
