// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! What a ledger issues over its own records: checkpoints, tree heads, inclusion and
//! consistency proofs, the snapshot an evidence bundle is cut from, and its anchor.

use super::Ledger;
use crate::anchor::{ledger_extends_checkpoint_at, load_anchor, save_anchor};
use crate::checkpoint::{
    Checkpoint, ConsistencyProof, EvidenceSnapshot, InclusionProof, TreeHead, checkpoint_bytes,
    tree_head_bytes, verify_checkpoint_sig,
};
use crate::error::LedgerError;
use crate::merkle;
use crate::verify::{inclusion_proofs_over, leaves_from_records};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use decern_crypto::Signer;
use std::path::Path;

impl Ledger {
    /// Sign the current head into a [`Checkpoint`] for external anchoring — the
    /// operator-independent half of the audit story. Hand it to a notary / SCITT
    /// transparency service / another party; they can later prove the log was not
    /// rewritten below this point without trusting the operator.
    pub fn checkpoint(&self, ts_ms: u64) -> Checkpoint {
        let root = self.last_hash.clone();
        let count = self.next_seq;
        let sig = self.key.sign(&checkpoint_bytes(&root, count, ts_ms));
        Checkpoint {
            root,
            count,
            ts_ms,
            pubkey_hex: self.pubkey_hex(),
            sig_b64: B64.encode(sig.to_bytes()),
        }
    }

    /// Read every record's chain hash, in order, as the Merkle LEAF DATA (the 32 raw bytes
    /// each record's `hash` hex encodes). The RFC 9162 tree is built over these, so a leaf
    /// is exactly what the chain already commits to — a verifier who checks the chain has
    /// already derived every leaf. Audit/export path only (scans the whole file). Fails
    /// closed on a record with a missing or non-hex `hash`.
    pub(crate) fn merkle_leaves(&self) -> Result<Vec<Vec<u8>>, LedgerError> {
        let count = self.next_seq as usize;
        leaves_from_records(&self.read_records(0, count)?)
    }

    /// Sign the current MERKLE tree head — the RFC 9162 root over all record hashes,
    /// externally anchorable like [`checkpoint`](Ledger::checkpoint) but enabling COMPACT
    /// third-party inclusion/consistency proofs. `tree_size == count`. Signs through the
    /// ledger key (a keyless hash committed by a key, same as a checkpoint).
    pub fn tree_head(&self, ts_ms: u64) -> Result<TreeHead, LedgerError> {
        let leaves = self.merkle_leaves()?;
        let root_hex = hex::encode(merkle::tree_hash(&leaves));
        Ok(self.sign_tree_head(root_hex, leaves.len() as u64, ts_ms))
    }

    /// Sign a tree head over an already-computed root — the signing half of
    /// [`tree_head`](Ledger::tree_head), for a caller who derived the leaves outside the
    /// lock. Signs exactly what it is given: a root computed from a prefix that has since
    /// been appended past is still a consistent commitment to that prefix, the same answer
    /// the caller would have gotten before the append.
    pub fn sign_tree_head(&self, merkle_root: String, tree_size: u64, ts_ms: u64) -> TreeHead {
        let sig = self
            .key
            .sign(&tree_head_bytes(&merkle_root, tree_size, ts_ms));
        TreeHead {
            merkle_root,
            tree_size,
            ts_ms,
            pubkey_hex: self.pubkey_hex(),
            sig_b64: B64.encode(sig.to_bytes()),
        }
    }

    /// A compact RFC 9162 inclusion proof that the record at `seq` (0-based) is committed
    /// by the current tree head's root. `Err` if `seq` is past the end of the log.
    pub fn inclusion_proof(&self, seq: u64) -> Result<InclusionProof, LedgerError> {
        let leaves = self.merkle_leaves()?;
        let idx = seq as usize;
        let path = merkle::inclusion_proof(&leaves, idx).ok_or_else(|| LedgerError::Tamper {
            seq,
            why: "inclusion index past the end of the log".into(),
        })?;
        Ok(InclusionProof {
            leaf_index: seq,
            tree_size: leaves.len() as u64,
            leaf_data: hex::encode(&leaves[idx]),
            audit_path: path.iter().map(hex::encode).collect(),
        })
    }

    /// Inclusion proofs for several records, over one pass of the log.
    ///
    /// [`inclusion_proof`](Ledger::inclusion_proof) derives every leaf in the log to prove
    /// one record is in it, which is the right shape for one proof and the wrong shape for
    /// a page of them: asking for `m` proofs that way reads and parses the whole log `m`
    /// times, and does it holding the lock an append needs. This derives the leaves once.
    ///
    /// Returns proofs in the order the sequences were given. A sequence past the end of the
    /// log fails the whole call rather than being skipped — a page of proofs with a hole in
    /// it, where the hole is silent, is worse than no page.
    pub fn inclusion_proofs(&self, seqs: &[u64]) -> Result<Vec<InclusionProof>, LedgerError> {
        inclusion_proofs_over(&self.merkle_leaves()?, seqs)
    }

    /// A compact RFC 9162 consistency proof that the log of the first `first_size` records
    /// is an exact prefix of the current log — the operator-independent equivocation /
    /// truncation check against an EARLIER anchored tree head. `1 <= first_size <= count`.
    pub fn consistency_proof(&self, first_size: u64) -> Result<ConsistencyProof, LedgerError> {
        let leaves = self.merkle_leaves()?;
        let path = merkle::consistency_proof(&leaves, first_size as usize).ok_or_else(|| {
            LedgerError::Tamper {
                seq: first_size,
                why: "consistency first_size out of range (need 1..=count)".into(),
            }
        })?;
        Ok(ConsistencyProof {
            first_size,
            second_size: leaves.len() as u64,
            proof: path.iter().map(hex::encode).collect(),
        })
    }

    /// A single-snapshot read for an evidence bundle: checkpoint, tree_head, and raw records
    /// are ALL derived from the SAME in-memory (self.last_hash, self.next_seq) state captured
    /// at one moment — unlike calling `checkpoint()`/`tree_head()`/`read_raw_records()` separately
    /// (which lets an `append()` land between calls and make the three mutually inconsistent:
    /// `checkpoint.count != tree_head.tree_size` or `checkpoint.root` computed over different
    /// records than `tree_head`).
    ///
    /// This is the single-file analog of [`ShardedLedger::evidence_snapshot`](crate::sharded::ShardedLedger::evidence_snapshot).
    /// The snapshot captures the log's state at call time; a concurrent `append()` does not
    /// change the returned values. Returns `(count, raw_records, checkpoint, tree_head)`.
    pub fn snapshot_for_bundle(&self, ts_ms: u64) -> Result<EvidenceSnapshot, LedgerError> {
        // Capture the head state once — this is the "snapshot" that all derived values build from.
        let count = self.next_seq;
        let root = self.last_hash.clone();

        // All three outputs are now derived from this same (root, count) pair, so they are
        // mutually consistent even if an append happens after this point.
        let raw_records = self.read_raw_records(0, count as usize)?;

        let cp_sig = self.key.sign(&checkpoint_bytes(&root, count, ts_ms));
        let checkpoint = Checkpoint {
            root,
            count,
            ts_ms,
            pubkey_hex: self.pubkey_hex(),
            sig_b64: B64.encode(cp_sig.to_bytes()),
        };

        let leaves = leaves_from_records(&self.read_records(0, count as usize)?)?;
        let merkle_root = hex::encode(merkle::tree_hash(&leaves));
        let tree_size = leaves.len() as u64;
        let th_sig = self
            .key
            .sign(&tree_head_bytes(&merkle_root, tree_size, ts_ms));
        let tree_head = TreeHead {
            merkle_root,
            tree_size,
            ts_ms,
            pubkey_hex: self.pubkey_hex(),
            sig_b64: B64.encode(th_sig.to_bytes()),
        };

        Ok((count, raw_records, checkpoint, tree_head))
    }

    /// Seal the current head into the persisted ANCHOR file — the last committed
    /// height, durably recorded on THIS node (not only handed to an external notary).
    /// On the next [`open_anchored`](Ledger::open_anchored) /
    /// [`verify_against_anchor`](Ledger::verify_against_anchor) the log must still
    /// extend it, which is what makes a tail-truncation across a restart detectable
    /// — a plain reopen accepts any internally-consistent shorter chain and cannot.
    pub fn seal_anchor(&self, anchor_path: &Path, ts_ms: u64) -> Result<Checkpoint, LedgerError> {
        let cp = self.checkpoint(ts_ms);
        save_anchor(anchor_path, &cp)?;
        Ok(cp)
    }

    /// Fail-closed truncation/rewrite check against the persisted anchor. Call it
    /// right after opening (or use [`open_anchored`](Ledger::open_anchored)): if an
    /// anchor exists it must (a) be signed by a key in this ledger's keyring — a
    /// forged anchor cannot be used to downgrade the committed height — and (b) still
    /// be extended by the log (at least `count` records that re-derive `root`). Any
    /// failure is `Tamper`: the log was truncated below, or rewritten at/below, its
    /// last committed height. No anchor file ⇒ `Ok` (nothing committed yet).
    pub fn verify_against_anchor(&self, anchor_path: &Path) -> Result<(), LedgerError> {
        let Some(cp) = load_anchor(anchor_path)? else {
            return Ok(());
        };
        // (a) The anchor must be vouched by a trusted ledger key (current or retired),
        // else an attacker could drop a self-signed anchor at a lower count to mask a
        // truncation.
        if !self.verifiers.iter().any(|k| verify_checkpoint_sig(&cp, k)) {
            return Err(LedgerError::Tamper {
                seq: cp.count,
                why:
                    "anchor signature is not from a trusted ledger key (forged or wrong-key anchor)"
                        .into(),
            });
        }
        // (b) The log must still extend the anchor's committed height.
        if !ledger_extends_checkpoint_at(&self.location, &cp)? {
            return Err(LedgerError::Tamper {
                seq: cp.count,
                why: format!(
                    "ledger no longer extends its anchor at count {} — truncated or rewritten \
                     below the last committed height",
                    cp.count
                ),
            });
        }
        Ok(())
    }
}
