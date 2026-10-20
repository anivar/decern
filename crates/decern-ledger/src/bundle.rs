// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Verifying an exported evidence bundle offline, against a keyring pinned out of band.

use crate::checkpoint::{Checkpoint, TreeHead, verify_checkpoint_sig, verify_tree_head_sig};
use crate::merkle;
use crate::record::{GENESIS, RecordIn, chain_hash};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use decern_crypto::VerifyingKey;
use serde::{Deserialize, Serialize};

/// The per-check result of verifying an exported evidence bundle offline. `accepted` is
/// the AND of every APPLICABLE check (an `Option` check that is `None` did not apply and
/// does not gate acceptance). Serializable so a CLI can emit it as `--json` verbatim.
#[derive(Debug, Clone, Serialize)]
pub struct BundleVerdict {
    pub accepted: bool,
    pub format: String,
    pub records: usize,
    pub from: u64,
    /// True when the bundle is a full tail from genesis (`from == 0`) — only then can a
    /// verifier recompute the Merkle root and a consistency proof from the records alone.
    pub full_tail: bool,
    pub chain_ok: bool,
    pub record_sigs_ok: bool,
    pub checkpoint_sig_ok: bool,
    pub tree_head_present: bool,
    pub tree_head_sig_ok: bool,
    /// `Some(ok)` when recomputed from a full tail; `None` for a partial tail.
    pub merkle_root_ok: Option<bool>,
    pub anchor_ok: bool,
    /// `Some(ok)` when an `--against` earlier tree head was supplied AND checkable.
    pub consistency_ok: Option<bool>,
    pub errors: Vec<String>,
}

#[derive(Deserialize)]
struct BundleIn {
    #[serde(default)]
    format: String,
    #[serde(default)]
    span: SpanIn,
    checkpoint: Checkpoint,
    #[serde(default)]
    tree_head: Option<TreeHead>,
    #[serde(default)]
    records: Vec<RecordIn>,
}

#[derive(Deserialize, Default)]
struct SpanIn {
    #[serde(default)]
    from: u64,
}

/// Does any key in `keys` verify `sig_b64` over `msg`? (Keyring-aware: a rotated log's
/// records are signed by different keys; a verifier holds the current + retired public
/// keys.) Fail-closed on a malformed signature.
fn any_key_verifies(msg: &[u8], sig_b64: &str, keys: &[VerifyingKey]) -> bool {
    let Ok(bytes) = B64.decode(sig_b64) else {
        return false;
    };
    let Ok(arr): Result<[u8; 64], _> = bytes.try_into() else {
        return false;
    };
    let sig = decern_crypto::Signature::from_bytes(&arr);
    keys.iter().any(|k| k.verify_strict(msg, &sig).is_ok())
}

/// Verify an exported `decern-evidence-bundle` OFFLINE against a PINNED keyring — the standalone
/// third-party check with no call back to the server. `bundle_json` is the RAW bundle file
/// text (NOT a re-serialized `Value`): each record's `entry` is captured as verbatim bytes,
/// because the chain commits to those exact bytes. `keys` is the pinned current + retired
/// public keys (obtained OUT OF BAND — never from the bundle). `against`, if given, is an
/// independently-anchored EARLIER tree head; a consistency check then proves the bundle did
/// not rewrite or drop anything below that earlier size (equivocation/truncation).
///
/// Checks (all fail-closed): every record hash re-derives from its verbatim bytes; the chain
/// links (genesis when `from == 0`); every record signature; the checkpoint signature; the
/// tree-head signature; the anchor (last hash == checkpoint root, positions match count ==
/// tree_size); and — for a full tail — the recomputed Merkle root equals the signed tree
/// head, plus any requested consistency proof against the anchored earlier head.
pub fn verify_evidence_bundle(
    bundle_json: &str,
    keys: &[VerifyingKey],
    against: Option<&TreeHead>,
) -> BundleVerdict {
    let mut errors: Vec<String> = Vec::new();
    let b: BundleIn = match serde_json::from_str(bundle_json) {
        Ok(b) => b,
        Err(e) => {
            return BundleVerdict {
                accepted: false,
                format: String::new(),
                records: 0,
                from: 0,
                full_tail: false,
                chain_ok: false,
                record_sigs_ok: false,
                checkpoint_sig_ok: false,
                tree_head_present: false,
                tree_head_sig_ok: false,
                merkle_root_ok: None,
                anchor_ok: false,
                consistency_ok: None,
                errors: vec![format!("bundle does not parse: {e}")],
            };
        }
    };

    let from = b.span.from;
    let full_tail = from == 0;
    let n = b.records.len();

    // 1) Per-record hash re-derivation + 2) chain links.
    let mut chain_ok = true;
    let mut leaves: Vec<Vec<u8>> = Vec::with_capacity(n);
    for (i, r) in b.records.iter().enumerate() {
        let want = hex::encode(chain_hash(r.entry.get().as_bytes(), &r.prev));
        if want != r.hash {
            chain_ok = false;
            errors.push(format!(
                "record {i}: hash does not re-derive from its bytes"
            ));
        }
        let expected_prev = if i == 0 {
            if full_tail {
                GENESIS.to_owned()
            } else {
                r.prev.clone() // no genesis anchor for a partial tail; link-only below
            }
        } else {
            b.records[i - 1].hash.clone()
        };
        if r.prev != expected_prev {
            chain_ok = false;
            errors.push(format!(
                "record {i}: prev does not link to the previous record"
            ));
        }
        match hex::decode(&r.hash) {
            Ok(bytes) => leaves.push(bytes),
            Err(_) => {
                chain_ok = false;
                errors.push(format!("record {i}: hash is not valid hex"));
            }
        }
    }

    // 3) Every record signature against the pinned keyring.
    let mut record_sigs_ok = true;
    for (i, r) in b.records.iter().enumerate() {
        let Ok(msg) = hex::decode(&r.hash) else {
            record_sigs_ok = false;
            continue;
        };
        if !any_key_verifies(&msg, &r.sig_b64, keys) {
            record_sigs_ok = false;
            errors.push(format!(
                "record {i}: signature not verified by any pinned key"
            ));
        }
    }

    // 4) Checkpoint + 5) tree-head signatures.
    let checkpoint_sig_ok = keys.iter().any(|k| verify_checkpoint_sig(&b.checkpoint, k));
    if !checkpoint_sig_ok {
        errors.push("checkpoint signature not verified by any pinned key".into());
    }
    let tree_head_present = b.tree_head.is_some();
    let tree_head_sig_ok = match &b.tree_head {
        Some(th) => {
            let ok = keys.iter().any(|k| verify_tree_head_sig(th, k));
            if !ok {
                errors.push("tree-head signature not verified by any pinned key".into());
            }
            ok
        }
        None => {
            // Fail-closed: this verifier attests the UPGRADED bundle (the server always
            // emits a signed Merkle tree head). A bundle without one gets no Merkle
            // commitment, so it is rejected with a legible reason rather than a silent
            // acceptance that overstates what was checked.
            errors.push(
                "bundle has no tree_head (Merkle commitment); this verifier requires the \
                 upgraded decern-evidence-bundle shape"
                    .into(),
            );
            false
        }
    };

    // 6) Anchor: the tail terminates at the signed head and positions line up.
    let mut anchor_ok = true;
    match b.records.last() {
        Some(last) if last.hash == b.checkpoint.root => {}
        Some(_) => {
            anchor_ok = false;
            errors.push("last record hash != checkpoint root".into());
        }
        None => {
            // Empty tail: the checkpoint alone attests the head; only valid when from==count.
            if from != b.checkpoint.count {
                anchor_ok = false;
                errors.push("empty tail but from != checkpoint count".into());
            }
        }
    }
    if from + n as u64 != b.checkpoint.count {
        anchor_ok = false;
        errors.push("from + record count != checkpoint count".into());
    }
    if let Some(th) = &b.tree_head
        && th.tree_size != b.checkpoint.count
    {
        anchor_ok = false;
        errors.push("tree_head size != checkpoint count".into());
    }

    // 7) Full-tail Merkle root recomputation.
    let merkle_root_ok = match (&b.tree_head, full_tail && chain_ok) {
        (Some(th), true) => {
            let recomputed = hex::encode(merkle::tree_hash(&leaves));
            let ok = recomputed == th.merkle_root;
            if !ok {
                errors.push("recomputed Merkle root != signed tree head".into());
            }
            Some(ok)
        }
        _ => None,
    };

    // 8) Optional consistency against an anchored earlier tree head (full tail only).
    let consistency_ok = match (against, &b.tree_head, full_tail && chain_ok) {
        (Some(earlier), Some(current), true) => {
            // The earlier head must itself be pinned-key-signed, else it anchors nothing.
            let earlier_sig = keys.iter().any(|k| verify_tree_head_sig(earlier, k));
            let first = earlier.tree_size as usize;
            let ok = earlier_sig
                && first <= leaves.len()
                && merkle::consistency_proof(&leaves, first).is_some_and(|path| {
                    match (
                        hex_to_32(&earlier.merkle_root),
                        hex_to_32(&current.merkle_root),
                    ) {
                        (Some(fr), Some(sr)) => merkle::verify_consistency(
                            earlier.tree_size,
                            current.tree_size,
                            &fr,
                            &sr,
                            &path,
                        ),
                        _ => false,
                    }
                });
            if !ok {
                errors.push(
                    "consistency proof against the earlier anchored tree head FAILED \
                     (possible equivocation/truncation, or the earlier head is unsigned)"
                        .into(),
                );
            }
            Some(ok)
        }
        (Some(_), _, false) => {
            errors
                .push("consistency check needs a full tail (from==0) to recompute; skipped".into());
            Some(false)
        }
        _ => None,
    };

    let accepted = chain_ok
        && record_sigs_ok
        && checkpoint_sig_ok
        && tree_head_sig_ok
        && anchor_ok
        && merkle_root_ok.unwrap_or(true)
        && consistency_ok.unwrap_or(true);

    BundleVerdict {
        accepted,
        format: b.format,
        records: n,
        from,
        full_tail,
        chain_ok,
        record_sigs_ok,
        checkpoint_sig_ok,
        tree_head_present,
        tree_head_sig_ok,
        merkle_root_ok,
        anchor_ok,
        consistency_ok,
        errors,
    }
}

/// Decode a 64-hex-char string into 32 bytes, or `None`.
fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}
