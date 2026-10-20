// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Checkpoints and tree heads, the commitments a ledger signs: the bytes each signature covers, and
//! checking those signatures. Also the inclusion and consistency proofs, which carry no signature
//! of their own.

#[cfg(doc)]
use crate::{Ledger, sharded};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use decern_crypto::VerifyingKey;
use serde::{Deserialize, Serialize};

/// A signed, externally-anchorable commitment to the ledger's state at a moment:
/// the head `root` over the first `count` entries, timestamped and signed by the
/// ledger key. It leaks no entry content — only a hash, a count, and a signature —
/// so it is safe to publish, hand to a notary, or submit to a SCITT transparency
/// service. Because the log is append-only, the root over the first `count` entries
/// is fixed forever; an external party holding a checkpoint can re-derive that root
/// from the file and, if it disagrees, prove the operator rewrote history — the
/// operator-INDEPENDENT verification a log inside the operator's own stack lacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub root: String,
    pub count: u64,
    pub ts_ms: u64,
    /// Hex of the Ed25519 ledger key that signed both the entries and this commitment.
    pub pubkey_hex: String,
    /// Ed25519 signature over the canonical commitment bytes.
    pub sig_b64: String,
}

/// A signed, externally-anchorable commitment to the ledger's MERKLE state: the RFC 9162
/// tree root over the first `tree_size` record hashes, timestamped and signed by the ledger
/// key. Parallel to [`Checkpoint`] (the linear-chain head): a `TreeHead` enables COMPACT
/// third-party proofs — an inclusion proof shows one record is in the log without shipping
/// the whole tail, and a consistency proof between an anchored earlier `TreeHead` and a
/// later one proves nothing below the earlier size was rewritten or dropped (closing
/// equivocation). Leaks no entry content — only a root, a size, and a signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeHead {
    /// Hex of the RFC 9162 Merkle Tree Hash over the first `tree_size` record hashes.
    pub merkle_root: String,
    pub tree_size: u64,
    pub ts_ms: u64,
    /// Hex of the Ed25519 ledger key that signed this commitment.
    pub pubkey_hex: String,
    /// Ed25519 signature over the `decern-ledger-tree-head` domain-separated bytes.
    pub sig_b64: String,
}

/// A single-snapshot evidence bundle: record count, raw bytes, and signed commitments
/// (checkpoint and merkle tree head) all derived from the same log state at one moment.
/// This is the return type of [`Ledger::snapshot_for_bundle`] and
/// [`ShardedLedger::evidence_snapshot`](sharded::ShardedLedger::evidence_snapshot).
pub type EvidenceSnapshot = (
    u64,                                   // record count
    Vec<Box<serde_json::value::RawValue>>, // raw record bytes
    Checkpoint,                            // signed linear-chain commitment
    TreeHead,                              // signed merkle-tree commitment
);

/// A compact RFC 9162 inclusion proof (hex-encoded): the record at `leaf_index` in a tree
/// of `tree_size` leaves is committed by a [`TreeHead`]'s root. `leaf_data` is the record's
/// chain hash (the Merkle leaf data — a verifier hashes it with the `0x00` leaf prefix);
/// `audit_path` is the sibling hashes bottom-up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub leaf_data: String,
    pub audit_path: Vec<String>,
}

/// A compact RFC 9162 consistency proof (hex-encoded) that the tree of the first
/// `first_size` leaves is an exact prefix of the tree of `second_size` leaves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub first_size: u64,
    pub second_size: u64,
    pub proof: Vec<String>,
}

/// Domain-separated commitment bytes: a fixed `tag` plus a hex field and two decimal
/// integers joined by a unit-separator byte (0x1F) that appears in neither hex nor a
/// decimal, so no two distinct field tuples collide AND no two tags cross-verify (a
/// checkpoint signature can never be replayed as a tree-head signature, or vice versa).
/// Shared by [`checkpoint_bytes`] and [`tree_head_bytes`] so the signing convention lives
/// in one place.
fn commitment_bytes(tag: &str, hex_field: &str, a: u64, b: u64) -> Vec<u8> {
    format!("{tag}\x1f{hex_field}\x1f{a}\x1f{b}").into_bytes()
}

/// The chain-head commitment (linear hash-chain root over `count` entries).
pub(crate) fn checkpoint_bytes(root: &str, count: u64, ts_ms: u64) -> Vec<u8> {
    commitment_bytes("decern-ledger-checkpoint", root, count, ts_ms)
}

/// The Merkle-tree-head commitment (RFC 9162 root over `tree_size` record hashes).
pub(crate) fn tree_head_bytes(merkle_root: &str, tree_size: u64, ts_ms: u64) -> Vec<u8> {
    commitment_bytes("decern-ledger-tree-head", merkle_root, tree_size, ts_ms)
}

/// Hex of an Ed25519 public key — the `kid` fingerprint stamped on each record and
/// the id an auditor pins.
pub(crate) fn key_fingerprint(vk: &VerifyingKey) -> String {
    hex::encode(vk.to_bytes())
}

#[must_use = "signature verification result must be checked"]
pub fn verify_checkpoint_sig(cp: &Checkpoint, pubkey: &VerifyingKey) -> bool {
    let Ok(bytes) = B64.decode(&cp.sig_b64) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = bytes.try_into() else {
        return false;
    };
    let sig = decern_crypto::Signature::from_bytes(&sig_arr);
    pubkey
        .verify_strict(&checkpoint_bytes(&cp.root, cp.count, cp.ts_ms), &sig)
        .is_ok()
}

/// Verify a tree head's own signature against a pinned key — the Merkle counterpart of
/// [`verify_checkpoint_sig`]. The domain-separated `decern-ledger-tree-head` tag means this
/// never cross-verifies a checkpoint signature. Does not read the ledger.
#[must_use = "signature verification result must be checked"]
pub fn verify_tree_head_sig(th: &TreeHead, pubkey: &VerifyingKey) -> bool {
    let Ok(bytes) = B64.decode(&th.sig_b64) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = bytes.try_into() else {
        return false;
    };
    let sig = decern_crypto::Signature::from_bytes(&sig_arr);
    pubkey
        .verify_strict(
            &tree_head_bytes(&th.merkle_root, th.tree_size, th.ts_ms),
            &sig,
        )
        .is_ok()
}
