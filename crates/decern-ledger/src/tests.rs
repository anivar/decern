// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
use crate::checkpoint::{checkpoint_bytes, key_fingerprint};
use crate::record::chain_hash;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use decern_crypto::{Signer, SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};

use super::*;
use decern_crypto::Verifier;
use serde_json::json;

pub(crate) fn entry(action: &str, decision: bool) -> Entry {
    Entry {
        seq: 0, // assigned by append
        ts_ms: 1234,
        subject_type: "Principal".into(),
        subject_id: "agent1".into(),
        action: action.into(),
        resource_type: "Resource".into(),
        resource_id: "claim1".into(),
        context: json!({"now": 100}),
        decision,
        reasons: vec![],
        ..Default::default()
    }
}

pub(crate) fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("decern-ledger-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn h32(hex_str: &str) -> [u8; 32] {
    <[u8; 32]>::try_from(hex::decode(hex_str).unwrap()).unwrap()
}

/// The unlocked path is the locked path: raw lines yield the same leaves, the same
/// proofs, and a head that verifies — one definition of a leaf, reachable two ways.

#[test]
fn the_out_of_lock_projection_path_equals_the_in_lock_one() {
    let key = decern_crypto::generate().unwrap();
    let vk = key.verifying_key();
    let path = tmp("raw-lines.ledger");
    let _ = std::fs::remove_file(&path);
    let mut l = Ledger::open(&path, key).unwrap();
    for i in 0..5 {
        l.append(entry(&format!("a{i}"), i % 2 == 0)).unwrap();
    }

    let lines = l.raw_records().unwrap();
    assert_eq!(lines.len(), 5);
    let from_lines = leaves_from_lines(&lines).unwrap();
    let from_records = l.merkle_leaves().unwrap();
    assert_eq!(from_lines, from_records);

    let seqs = [0u64, 3, 4];
    let over = inclusion_proofs_over(&from_lines, &seqs).unwrap();
    let method = l.inclusion_proofs(&seqs).unwrap();
    for (a, b) in over.iter().zip(&method) {
        assert_eq!(a.leaf_index, b.leaf_index);
        assert_eq!(a.tree_size, b.tree_size);
        assert_eq!(a.leaf_data, b.leaf_data);
        assert_eq!(a.audit_path, b.audit_path);
    }

    let root_hex = hex::encode(merkle::tree_hash(&from_lines));
    let signed = l.sign_tree_head(root_hex, from_lines.len() as u64, 2_000);
    let direct = l.tree_head(2_000).unwrap();
    assert_eq!(signed.merkle_root, direct.merkle_root);
    assert_eq!(signed.tree_size, direct.tree_size);
    assert!(verify_tree_head_sig(&signed, &vk));
}

/// A line without a decodable hash fails the whole derivation, exactly as the
/// record form does — a leaf set with a silent hole would prove the wrong tree.
#[test]
fn a_line_without_a_hash_fails_leaf_derivation_closed() {
    let lines = vec![r#"{"entry":{}}"#.to_owned()];
    assert!(leaves_from_lines(&lines).is_err());
    let lines = vec![r#"{"hash":"zz"}"#.to_owned()];
    assert!(leaves_from_lines(&lines).is_err());
}

#[test]
fn merkle_tree_head_and_proofs_verify_against_a_real_ledger() {
    let key = decern_crypto::generate().unwrap();
    let vk = key.verifying_key();
    let path = tmp("merkle-th.ledger");
    let _ = std::fs::remove_file(&path);
    let mut l = Ledger::open(&path, key.clone()).unwrap();

    // Grow to 4 records and anchor an EARLIER tree head.
    for i in 0..4 {
        l.append(entry(&format!("a{i}"), true)).unwrap();
    }
    let th4 = l.tree_head(1_000).unwrap();
    assert_eq!(th4.tree_size, 4);
    assert!(verify_tree_head_sig(&th4, &vk));

    // Grow to 7 records; a NEW tree head over the whole log.
    for i in 0..3 {
        l.append(entry(&format!("b{i}"), false)).unwrap();
    }
    let th7 = l.tree_head(2_000).unwrap();
    assert_eq!(th7.tree_size, 7);
    assert!(verify_tree_head_sig(&th7, &vk));

    // The tree-head signature is pinned to the ledger key AND domain-separated: a
    // wrong key or a tampered root does not verify.
    let other = decern_crypto::generate().unwrap().verifying_key();
    assert!(
        !verify_tree_head_sig(&th7, &other),
        "wrong key must not verify"
    );
    let mut tampered = th7.clone();
    tampered.merkle_root = "00".repeat(32);
    assert!(
        !verify_tree_head_sig(&tampered, &vk),
        "tampered root rejected"
    );
    // A checkpoint signature must NOT cross-verify as a tree head (distinct domain tag).
    let cp = l.checkpoint(2_000);
    let cross = TreeHead {
        merkle_root: cp.root.clone(),
        tree_size: cp.count,
        ts_ms: cp.ts_ms,
        pubkey_hex: cp.pubkey_hex.clone(),
        sig_b64: cp.sig_b64.clone(),
    };
    assert!(
        !verify_tree_head_sig(&cross, &vk),
        "a checkpoint sig must not verify as a tree head"
    );

    // Inclusion: every record is provably in the size-7 tree under th7's root.
    let root7 = h32(&th7.merkle_root);
    for seq in 0..7u64 {
        let ip = l.inclusion_proof(seq).unwrap();
        assert_eq!(ip.tree_size, 7);
        let leaf_hash = merkle::hash_leaf(&hex::decode(&ip.leaf_data).unwrap());
        let audit: Vec<[u8; 32]> = ip.audit_path.iter().map(|h| h32(h)).collect();
        assert!(
            merkle::verify_inclusion(seq, 7, &leaf_hash, &root7, &audit),
            "record {seq} must prove included"
        );
    }
    assert!(
        l.inclusion_proof(7).is_err(),
        "out-of-range inclusion rejected"
    );

    // Consistency: the anchored size-4 tree is an exact prefix of the size-7 head —
    // the operator cannot have rewritten or dropped anything below seq 4.
    let root4 = h32(&th4.merkle_root);
    let consist = l.consistency_proof(4).unwrap();
    assert_eq!((consist.first_size, consist.second_size), (4, 7));
    let cpath: Vec<[u8; 32]> = consist.proof.iter().map(|h| h32(h)).collect();
    assert!(
        merkle::verify_consistency(4, 7, &root4, &root7, &cpath),
        "size-4 prefix must reconcile with the size-7 head"
    );
    // A forged earlier root (equivocation) does NOT reconcile.
    let mut forged = root4;
    forged[0] ^= 0xFF;
    assert!(!merkle::verify_consistency(4, 7, &forged, &root7, &cpath));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn evidence_bundle_verifies_offline_and_catches_tamper() {
    let key = decern_crypto::generate().unwrap();
    let vk = key.verifying_key();
    let path = tmp("bundle-verify.ledger");
    let _ = std::fs::remove_file(&path);
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    for i in 0..5 {
        l.append(entry(&format!("e{i}"), true)).unwrap();
    }
    let earlier = l.tree_head(500).unwrap(); // size 5 — an externally-anchored head
    for i in 0..3 {
        l.append(entry(&format!("f{i}"), false)).unwrap();
    }
    let count = l.count() as usize; // 8

    // Assemble the bundle from VERBATIM record bytes (`RawValue::get()`), exactly as
    // the server ships them — routing records through json!/Value would reorder the
    // entry keys (no preserve_order here) and break the very hashes we verify.
    let make_bundle = |from: usize| -> String {
        let recs = l.read_raw_records(from, count - from).unwrap();
        let records_arr = format!(
            "[{}]",
            recs.iter().map(|r| r.get()).collect::<Vec<_>>().join(",")
        );
        format!(
            "{{\"format\":\"decern-evidence-bundle/1\",\"span\":{{\"from\":{from}}},\
             \"checkpoint\":{cp},\"tree_head\":{th},\"records\":{records_arr}}}",
            cp = serde_json::to_string(&l.checkpoint(900)).unwrap(),
            th = serde_json::to_string(&l.tree_head(900).unwrap()).unwrap(),
        )
    };

    // Full tail: everything verifies, the Merkle root recomputes, and the size-5
    // anchored head is a proven prefix of the size-8 head.
    let full = make_bundle(0);
    let v = verify_evidence_bundle(&full, &[vk], Some(&earlier));
    assert!(v.accepted, "full bundle must verify: {:?}", v.errors);
    assert_eq!(v.merkle_root_ok, Some(true));
    assert_eq!(v.consistency_ok, Some(true));

    // Wrong pinned key → rejected (record + checkpoint + tree-head sigs all fail).
    let other = decern_crypto::generate().unwrap().verifying_key();
    assert!(!verify_evidence_bundle(&full, &[other], None).accepted);

    // Tampered record entry → its hash no longer re-derives → rejected.
    let tampered = full.replacen("\"e0\"", "\"e0X\"", 1);
    let vt = verify_evidence_bundle(&tampered, &[vk], None);
    assert!(
        !vt.accepted && !vt.chain_ok,
        "tamper caught: {:?}",
        vt.errors
    );

    // Partial tail (from=3): the Merkle root can't be recomputed (None) but every other
    // check still passes, so the bundle is accepted.
    let partial = make_bundle(3);
    let vp = verify_evidence_bundle(&partial, &[vk], None);
    assert!(vp.accepted, "partial tail verifies: {:?}", vp.errors);
    assert_eq!(vp.merkle_root_ok, None);

    // Equivocation: an earlier head with a forged (unsigned) root fails consistency.
    let mut forged = earlier.clone();
    forged.merkle_root = "11".repeat(32);
    let vf = verify_evidence_bundle(&full, &[vk], Some(&forged));
    assert_eq!(vf.consistency_ok, Some(false));
    assert!(!vf.accepted);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn edge_type_omitted_when_attenuate_recorded_when_mint() {
    // Attenuate (the default) is skipped → existing records are byte-identical,
    // so their hashes and signatures are unaffected.
    let att = serde_json::to_string(&entry("issue_token", true)).unwrap();
    assert!(
        !att.contains("\"edge\""),
        "attenuate edge must be omitted: {att}"
    );

    // A mint (trusted-issuer crossing) is recorded explicitly.
    let mut e = entry("issue_token", true);
    e.edge = EdgeType::Mint;
    let mint = serde_json::to_string(&e).unwrap();
    assert!(
        mint.contains("\"edge\":\"Mint\""),
        "mint edge recorded: {mint}"
    );

    // Both round-trip; a record with no `edge` deserializes as Attenuate.
    assert_eq!(
        serde_json::from_str::<Entry>(&mint).unwrap().edge,
        EdgeType::Mint
    );
    assert_eq!(
        serde_json::from_str::<Entry>(&att).unwrap().edge,
        EdgeType::Attenuate
    );
}

#[test]
fn append_verify_resume() {
    let path = tmp("ok.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();

    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.append(entry("MoveMoney", false)).unwrap();
    drop(l);

    // resume with the same key: chain verifies, seq continues
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    let rec = l.append(entry("Read", true)).unwrap();
    assert_eq!(rec.entry.seq, 2);

    let report = verify(&path, Some(&key.verifying_key())).unwrap();
    assert_eq!(report.entries, 3);
    assert!(report.root.is_some());
}

#[test]
fn sync_enabled_ledger_appends_and_verifies() {
    // fsync-per-append must be transparent to correctness: same chain, same verify.
    let path = tmp("synced.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.set_sync(true);
    l.append(entry("Read", true)).unwrap();
    l.append(entry("MoveMoney", false)).unwrap();
    drop(l);
    let report = verify(&path, Some(&key.verifying_key())).unwrap();
    assert_eq!(report.entries, 2);
    assert!(report.signatures_checked);
}

#[test]
fn append_all_is_one_durable_step_and_keeps_the_chain() {
    let path = tmp("synced-batch.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.set_sync(true);
    let records = l
        .append_all(vec![
            entry("Read", true),
            entry("Read", false),
            entry("MoveMoney", false),
        ])
        .unwrap();
    assert_eq!(records.len(), 3);
    assert!(
        records
            .windows(2)
            .all(|w| w[1].entry.seq == w[0].entry.seq + 1),
        "contiguous"
    );
    // Sync is back on for the next single append.
    l.append(entry("Read", true)).unwrap();
    drop(l);
    let report = verify(&path, Some(&key.verifying_key())).unwrap();
    assert_eq!(report.entries, 4);
    assert!(report.signatures_checked);
}

#[test]
fn read_raw_records_bytes_reproduce_the_stored_hash() {
    // The evidence-bundle contract: the VERBATIM bytes read back must let an
    // external party recompute each record's hash. `read_records` (parse→Value)
    // would reorder keys and break this; `read_raw_records` must not.
    let path = tmp("raw.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    // A context with several keys — reserialization would reorder them.
    let mut e = entry("Pay", true);
    e.context = json!({"z": 1, "a": 2, "m": 3, "amount_minor": 500});
    l.append(e).unwrap();
    l.append(entry("Read", true)).unwrap();

    let raw = l.read_raw_records(0, 100).unwrap();
    assert_eq!(raw.len(), 2);

    // Recompute the chain exactly as an external verifier would.
    #[derive(serde::Deserialize)]
    struct Rec {
        entry: Box<serde_json::value::RawValue>,
        prev: String,
        hash: String,
    }
    let mut prev = GENESIS.to_owned();
    for line in &raw {
        let r: Rec = serde_json::from_str(line.get()).unwrap();
        let got = hex::encode(chain_hash(r.entry.get().as_bytes(), &prev));
        assert_eq!(got, r.hash, "verbatim bytes reproduce the stored hash");
        assert_eq!(r.prev, prev, "chain link continuous");
        prev = r.hash;
    }
    assert_eq!(prev, *l.root(), "final recomputed hash == head");
}

#[test]
fn read_verified_returns_a_verified_window_and_fails_closed_on_tamper() {
    let path = tmp("readv.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.append(entry("MoveMoney", false)).unwrap();
    l.append(entry("Read", true)).unwrap();
    drop(l);

    // Full read with the public key: chain + signatures verified, all 3 records back,
    // each carrying its `entry` (with the seq inside), same shape read_records returns.
    let (report, recs) = read_verified(&path, Some(&key.verifying_key()), 0, 100).unwrap();
    assert_eq!(report.entries, 3);
    assert!(report.signatures_checked);
    assert_eq!(recs.len(), 3);
    assert_eq!(recs[0]["entry"]["seq"], json!(0));
    assert_eq!(recs[2]["entry"]["action"], json!("Read"));

    // Windowed (offset 1, limit 1): whole chain still verified, only the 2nd record
    // materialized.
    let (report, recs) = read_verified(&path, None, 1, 1).unwrap();
    assert_eq!(report.entries, 3, "whole chain scanned for integrity");
    assert!(!report.signatures_checked, "no key → chain-only");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["entry"]["seq"], json!(1));
    assert_eq!(recs[0]["entry"]["action"], json!("MoveMoney"));

    // Tamper: flip the deny to allow without re-chaining → a READ must refuse, never
    // hand back the altered record as if it were sound.
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let mut rec: Record = serde_json::from_str(&lines[1]).unwrap();
    rec.entry.decision = true;
    lines[1] = serde_json::to_string(&rec).unwrap();
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    let err = read_verified(&path, Some(&key.verifying_key()), 0, 100).unwrap_err();
    assert!(matches!(err, LedgerError::Tamper { seq: 1, .. }), "{err}");
}

#[test]
fn flipped_decision_detected() {
    let path = tmp("tamper.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.append(entry("MoveMoney", false)).unwrap();
    l.append(entry("Read", true)).unwrap();
    drop(l);

    // flip the deny to an allow without re-chaining
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let mut rec: Record = serde_json::from_str(&lines[1]).unwrap();
    rec.entry.decision = true;
    lines[1] = serde_json::to_string(&rec).unwrap();
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let err = verify(&path, Some(&key.verifying_key())).unwrap_err();
    assert!(matches!(err, LedgerError::Tamper { seq: 1, .. }), "{err}");
}

#[test]
fn rewrite_with_other_key_detected() {
    let path = tmp("rewrite.ledger");
    std::fs::remove_file(&path).ok();
    let honest = decern_crypto::generate().unwrap();
    let insider = decern_crypto::generate().unwrap();

    // insider fabricates a perfectly self-consistent chain with their own key
    let mut l = Ledger::open(&path, insider).unwrap();
    l.append(entry("MoveMoney", true)).unwrap();
    drop(l);

    // chain alone verifies...
    assert!(verify(&path, None).is_ok());
    // ...but not against the honest ledger key
    let err = verify(&path, Some(&honest.verifying_key())).unwrap_err();
    assert!(matches!(err, LedgerError::Tamper { .. }));
}

#[test]
fn hostile_float_context_cannot_false_tamper() {
    // Regression: serde_json float round-trips are NOT byte-stable
    // without the float_roundtrip feature. These exact values used to
    // brick an honest ledger. The hash must cover stored bytes, so
    // append -> verify -> reopen must all succeed.
    let path = tmp("floats.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, key.clone()).unwrap();

    for ctx in [
        json!({"now": 100, "z": 1.0715660391465826e-75}),
        json!({"v": 2.291712365432881e-9}),
        json!({"now": 100, "a": 0.1, "b": 1e308, "c": -5.5e-324}),
    ] {
        let mut e = entry("Read", false);
        e.context = ctx;
        l.append(e).unwrap();
    }
    drop(l);

    let report = verify(&path, Some(&key.verifying_key())).expect("honest ledger must verify");
    assert_eq!(report.entries, 3);
    // and it must reopen for new writes
    let mut l = Ledger::open(&path, key).expect("honest ledger must reopen");
    l.append(entry("Read", true)).unwrap();
}

#[test]
fn corrupt_ledger_refuses_new_writes() {
    let path = tmp("refuse.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    drop(l);

    // corrupt it
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replace("Read", "Raid")).unwrap();

    assert!(Ledger::open(&path, key).is_err());
}

#[test]
fn checkpoint_signs_and_verifies() {
    let path = tmp("cp-sig.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();
    let other = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.append(entry("MoveMoney", false)).unwrap();

    let cp = l.checkpoint(9_999);
    assert_eq!(cp.count, 2);
    assert_eq!(cp.root, l.root());
    assert_eq!(cp.pubkey_hex, l.pubkey_hex());
    // the ledger key vouches for the commitment; a different key does not
    assert!(verify_checkpoint_sig(&cp, &key.verifying_key()));
    assert!(!verify_checkpoint_sig(&cp, &other.verifying_key()));
    // and a forged field is rejected (signature covers root+count+ts)
    let mut forged = cp.clone();
    forged.count = 3;
    assert!(!verify_checkpoint_sig(&forged, &key.verifying_key()));
}

#[test]
fn append_only_log_extends_its_own_checkpoint() {
    let path = tmp("cp-extend.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, key).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.append(entry("MoveMoney", false)).unwrap();
    let cp = l.checkpoint(1); // an external party holds this
    // more activity happens afterwards
    l.append(entry("Read", true)).unwrap();
    drop(l);
    // the honest, append-only log still extends the held checkpoint
    assert!(ledger_extends_checkpoint(&path, &cp).unwrap());
}

#[test]
fn rewrite_below_a_held_checkpoint_is_caught() {
    let path = tmp("cp-rewrite.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, key).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.append(entry("MoveMoney", false)).unwrap();
    l.append(entry("Read", true)).unwrap();
    let cp = l.checkpoint(1);
    drop(l);

    // operator flips the recorded deny to an allow (without re-chaining)
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let mut rec: Record = serde_json::from_str(&lines[1]).unwrap();
    rec.entry.decision = true;
    lines[1] = serde_json::to_string(&rec).unwrap();
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    // the external holder's re-derivation refuses to confirm the checkpoint
    let r = ledger_extends_checkpoint(&path, &cp);
    assert!(
        matches!(r, Err(LedgerError::Tamper { .. })) || matches!(r, Ok(false)),
        "rewrite below a checkpoint must break extension: {r:?}"
    );
}

#[test]
fn truncation_below_a_held_checkpoint_is_caught() {
    let path = tmp("cp-truncate.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, key).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.append(entry("MoveMoney", false)).unwrap();
    l.append(entry("Read", true)).unwrap();
    let cp = l.checkpoint(1); // commits to 3 entries
    drop(l);

    // operator drops the last recorded entry
    let text = std::fs::read_to_string(&path).unwrap();
    let kept: Vec<&str> = text.lines().take(2).collect();
    std::fs::write(&path, kept.join("\n") + "\n").unwrap();

    // fewer records than the checkpoint committed to → does not extend
    assert!(!ledger_extends_checkpoint(&path, &cp).unwrap());
}

#[test]
fn decision_entry_serialization_is_stable() {
    // Golden serialization + chain hash for a plain Decision entry. The chain
    // commits to these exact bytes, so if field order or naming drifts, every
    // existing ledger stops verifying.
    let js = serde_json::to_string(&entry("Read", true)).unwrap();
    assert_eq!(
        js,
        r#"{"seq":0,"ts_ms":1234,"subject_type":"Principal","subject_id":"agent1","action":"Read","resource_type":"Resource","resource_id":"claim1","context":{"now":100},"decision":true,"reasons":[]}"#,
        "Decision entry serialization drifted from the golden value"
    );
    assert_eq!(
        hex::encode(chain_hash(js.as_bytes(), GENESIS)),
        "7b53ca2b3294bd92166dc254d1b56ee12a2a95b76807c08867147729405f8194",
        "Decision entry chain hash drifted from the golden value"
    );
}

// ------------------------------- key rotation -------------------------------

#[test]
fn rotation_keeps_the_whole_chain_verifiable() {
    // The core: rotating the signing key must NOT brick a long-lived log.
    let path = tmp("rotate.ledger");
    std::fs::remove_file(&path).ok();
    let old = decern_crypto::generate().unwrap();
    let new = decern_crypto::generate().unwrap();

    let mut l = Ledger::open(&path, old.clone()).unwrap();
    l.append(entry("Read", true)).unwrap(); // signed by old
    l.append(entry("Write", true)).unwrap(); // signed by old
    l.rotate(new.clone()).unwrap();
    l.append(entry("MoveMoney", false)).unwrap(); // signed by new
    drop(l);

    // The whole chain verifies under the keyring (old + new)...
    let report = verify_with_keys(&path, &[old.verifying_key(), new.verifying_key()]).unwrap();
    assert_eq!(report.entries, 3);
    assert!(report.signatures_checked);

    // ...but NOT under either key alone: the pre-rotation records need `old`, the
    // post-rotation record needs `new`.
    assert!(
        verify(&path, Some(&old.verifying_key())).is_err(),
        "old key alone cannot verify the post-rotation tail"
    );
    assert!(
        verify(&path, Some(&new.verifying_key())).is_err(),
        "new key alone cannot verify the pre-rotation head"
    );
}

#[test]
fn rotated_ledger_reopens_with_retired_verifiers() {
    let path = tmp("rotate-reopen.ledger");
    std::fs::remove_file(&path).ok();
    let old = decern_crypto::generate().unwrap();
    let new = decern_crypto::generate().unwrap();

    let mut l = Ledger::open(&path, old.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.rotate(new.clone()).unwrap();
    l.append(entry("Write", true)).unwrap();
    drop(l);

    // Reopening with the CURRENT key alone fails (the head was signed by `old`)...
    assert!(
        Ledger::open(&path, new.clone()).is_err(),
        "reopen without the retired key must fail on the old-signed head"
    );
    // ...but succeeds when the retired public key is supplied, and can append more.
    let mut l = Ledger::open_with_verifiers(&path, new.clone(), vec![old.verifying_key()]).unwrap();
    assert_eq!(l.count(), 2);
    l.append(entry("MoveMoney", true)).unwrap(); // signed by new, seq 2
    assert!(l.self_verify().is_ok());
    // the keyring an auditor pins spans both keys
    let fps = l.verifier_fingerprints();
    assert!(fps.contains(&key_fingerprint(&old.verifying_key())));
    assert!(fps.contains(&key_fingerprint(&new.verifying_key())));
}

#[test]
fn a_record_signed_by_an_untrusted_key_is_tamper() {
    // A record whose kid names a key NOT in the ring must be rejected — an
    // auditor cannot be fooled into trusting a signer of the attacker's choosing.
    let path = tmp("rotate-untrusted.ledger");
    std::fs::remove_file(&path).ok();
    let honest = decern_crypto::generate().unwrap();
    let attacker = decern_crypto::generate().unwrap();

    let mut l = Ledger::open(&path, honest.clone()).unwrap();
    l.append(entry("Read", true)).unwrap(); // kid = honest fingerprint
    drop(l);

    // A ring that does NOT contain the record's signing key: its kid names a key
    // not in the ring → tamper (fail-closed on an unknown signer), NOT skipped.
    let err = verify_with_keys(&path, &[attacker.verifying_key()]).unwrap_err();
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "a record whose kid is not in the ring must be tamper: {err}"
    );
    // The honest ring verifies fine.
    assert!(verify_with_keys(&path, &[honest.verifying_key()]).is_ok());
}

/// Append a record signed by `key` without going through [`Ledger`], which refuses a key it
/// may not sign with: what someone holding a retired key and the file could write.
fn append_signed_by(path: &Path, key: &SigningKey, kid: Option<&str>) {
    let text = std::fs::read_to_string(path).unwrap();
    let last: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    let prev = last["hash"].as_str().unwrap();
    let mut e = entry("MoveMoney", true);
    e.seq = text.lines().count() as u64;
    let entry_json = serde_json::to_string(&e).unwrap();
    let hash = chain_hash(entry_json.as_bytes(), prev);
    let sig = B64.encode(key.sign(&hash).to_bytes());
    let kid = kid.map(|k| format!(r#","kid":"{k}""#)).unwrap_or_default();
    let line = format!(
        r#"{{"entry":{entry_json},"prev":"{prev}","hash":"{}","sig_b64":"{sig}"{kid}}}"#,
        hex::encode(hash)
    );
    std::fs::write(path, text + &line + "\n").unwrap();
}

/// A log signed by `old` for two records, then by `new` for one.
fn rotated_log(name: &str) -> (PathBuf, SigningKey, SigningKey) {
    let path = tmp(name);
    std::fs::remove_file(&path).ok();
    let old = decern_crypto::generate().unwrap();
    let new = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, old.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.append(entry("Write", true)).unwrap();
    l.rotate(new.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    (path, old, new)
}

#[test]
fn the_report_names_each_signer_from_its_first_record() {
    let (path, old, new) = rotated_log("signers.ledger");
    let (old_kid, new_kid) = (
        key_fingerprint(&old.verifying_key()),
        key_fingerprint(&new.verifying_key()),
    );
    let report = verify_with_keys(&path, &[old.verifying_key(), new.verifying_key()]).unwrap();
    assert_eq!(
        report.signers,
        vec![
            SignerSpan {
                kid: old_kid.clone(),
                first_seq: 0
            },
            SignerSpan {
                kid: new_kid.clone(),
                first_seq: 2
            },
        ]
    );
    assert_eq!(report.superseded_by(&old_kid).map(|s| s.first_seq), Some(2));
    assert!(report.superseded_by(&new_kid).is_none());
    // A kid is only a claim until its signature is checked.
    assert!(verify(&path, None).unwrap().signers.is_empty());
}

#[test]
fn a_retired_key_may_not_sign_after_its_successor() {
    let (path, old, new) = rotated_log("retired-signs-again.ledger");
    let (old_kid, new_kid) = (
        key_fingerprint(&old.verifying_key()),
        key_fingerprint(&new.verifying_key()),
    );
    append_signed_by(&path, &old, Some(&old_kid));
    let ring = [old.verifying_key(), new.verifying_key()];
    match verify_with_keys(&path, &ring).unwrap_err() {
        LedgerError::Tamper { seq: 3, why } => {
            assert!(why.contains(&new_kid) && why.contains("seq 2"), "{why}");
        }
        e => panic!("a retired key signing after its successor must be tamper: {e}"),
    }
    assert!(Ledger::open_with_verifiers(&path, new, vec![old.verifying_key()]).is_err());
}

#[test]
fn an_evidence_bundle_applies_key_succession() {
    let (path, old, new) = rotated_log("bundle-succession.ledger");
    append_signed_by(&path, &old, Some(&key_fingerprint(&old.verifying_key())));
    let text = std::fs::read_to_string(&path).unwrap();
    let records = text.lines().collect::<Vec<_>>().join(",");
    let bundle = format!(
        r#"{{"format":"decern-evidence-bundle/1","span":{{"from":0}},"checkpoint":{{"root":"","count":4,"ts_ms":0,"pubkey_hex":"","sig_b64":""}},"records":[{records}]}}"#
    );
    let v = verify_evidence_bundle(&bundle, &[old.verifying_key(), new.verifying_key()], None);
    assert!(v.chain_ok && !v.record_sigs_ok, "{:?}", v.errors);
    let record_errors: Vec<_> = v
        .errors
        .iter()
        .filter(|e| e.starts_with("record "))
        .collect();
    assert_eq!(record_errors.len(), 1, "{record_errors:?}");
    assert!(
        record_errors[0].starts_with("record 3:") && record_errors[0].contains("succeeded"),
        "{record_errors:?}"
    );
}

#[test]
fn a_record_without_a_kid_is_attributed_to_the_key_that_signed_it() {
    let (path, old, new) = rotated_log("kidless-after-kid.ledger");
    append_signed_by(&path, &old, None);
    match verify_with_keys(&path, &[old.verifying_key(), new.verifying_key()]).unwrap_err() {
        LedgerError::Tamper { seq: 3, why } => assert!(why.contains("succeeded"), "{why}"),
        e => panic!("a retired key's record without a kid must be tamper: {e}"),
    }
}

/// Remove every `kid` the given key's records carry, as someone with the file could: the label
/// is outside the signed bytes.
fn strip_kid(path: &Path, key: &SigningKey) {
    let kid = key_fingerprint(&key.verifying_key());
    let text = std::fs::read_to_string(path).unwrap();
    std::fs::write(path, text.replace(&format!(r#","kid":"{kid}""#), "")).unwrap();
}

#[test]
fn removing_kids_does_not_let_a_retired_key_sign_again() {
    // The old key's records lose their label, then it signs again with one.
    let (path, old, new) = rotated_log("strip-old-kids.ledger");
    strip_kid(&path, &old);
    append_signed_by(&path, &old, Some(&key_fingerprint(&old.verifying_key())));
    let ring = [old.verifying_key(), new.verifying_key()];
    match verify_with_keys(&path, &ring).unwrap_err() {
        LedgerError::Tamper { seq: 3, why } => assert!(why.contains("succeeded"), "{why}"),
        e => panic!("expected tamper at seq 3: {e}"),
    }

    // Every label gone, and the old key signs again without one.
    let (path, old, new) = rotated_log("strip-all-kids.ledger");
    strip_kid(&path, &old);
    strip_kid(&path, &new);
    let ring = [old.verifying_key(), new.verifying_key()];
    let report = verify_with_keys(&path, &ring).unwrap();
    assert_eq!(
        report
            .superseded_by(&key_fingerprint(&old.verifying_key()))
            .map(|s| s.first_seq),
        Some(2)
    );
    // Opening with the old key is refused on the signatures, not the labels.
    assert!(matches!(
        Ledger::open_with_verifiers(&path, old.clone(), vec![new.verifying_key()]),
        Err(LedgerError::KeySuperseded { .. })
    ));
    append_signed_by(&path, &old, None);
    assert!(matches!(
        verify_with_keys(&path, &ring),
        Err(LedgerError::Tamper { seq: 3, .. })
    ));
}

#[test]
fn a_legacy_prefix_does_not_let_rotate_go_back() {
    let path = tmp("legacy-rotate-back.ledger");
    std::fs::remove_file(&path).ok();
    let old = decern_crypto::generate().unwrap();
    let new = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, old.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    drop(l);
    strip_kid(&path, &old);
    let mut l = Ledger::open(&path, old.clone()).unwrap();
    l.rotate(new).unwrap();
    l.append(entry("Write", true)).unwrap();
    assert!(matches!(
        l.rotate(old),
        Err(LedgerError::KeySuperseded { .. })
    ));
}

#[test]
fn opening_with_a_superseded_key_is_refused_before_anything_is_written() {
    let (path, old, new) = rotated_log("superseded-open.ledger");
    // A torn tail the open would otherwise heal by truncating the file.
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(br#"{"entry":"#);
    std::fs::write(&path, &bytes).unwrap();

    let err = match Ledger::open_with_verifiers(&path, old.clone(), vec![new.verifying_key()]) {
        Ok(_) => panic!("a key its successor has followed must not open the log"),
        Err(e) => e,
    };
    match err {
        LedgerError::KeySuperseded { kid, why } => {
            assert_eq!(kid, key_fingerprint(&old.verifying_key()));
            assert!(
                why.contains(&key_fingerprint(&new.verifying_key())),
                "{why}"
            );
        }
        e => panic!("expected KeySuperseded: {e}"),
    }
    assert_eq!(
        std::fs::read(&path).unwrap(),
        bytes,
        "the refused open wrote nothing"
    );
    // The current key with the retired one opens it, healing the tail.
    assert_eq!(
        Ledger::open_with_verifiers(&path, new, vec![old.verifying_key()])
            .unwrap()
            .count(),
        3
    );
}

#[test]
fn a_truncation_is_tamper_whichever_key_opens_the_log() {
    let (path, old, new) = rotated_log("superseded-anchor.ledger");
    let anchor = tmp("superseded-anchor.anchor");
    std::fs::remove_file(&anchor).ok();
    let mut l = Ledger::open_with_verifiers(&path, new.clone(), vec![old.verifying_key()]).unwrap();
    l.append(entry("Write", true)).unwrap();
    l.seal_anchor(&anchor, 1).unwrap(); // committed height = 4
    drop(l);
    // The last record dropped at a line boundary: no torn tail, three records left.
    let text = std::fs::read_to_string(&path).unwrap();
    let kept: Vec<&str> = text.lines().take(3).collect();
    std::fs::write(&path, kept.join("\n") + "\n").unwrap();

    match Ledger::open_anchored(&path, old, vec![new.verifying_key()], &anchor) {
        Err(LedgerError::Tamper { .. }) => {}
        Err(e) => panic!("a truncation must be tamper, not a key refusal: {e}"),
        Ok(_) => panic!("a truncated log must not open"),
    }
}

/// A crash mid-append leaves an unterminated fragment that begins a record. An unterminated
/// file that does not, such as a key file opened as a ledger by mistake, is refused and left as
/// it is rather than truncated.
#[test]
fn an_unterminated_tail_that_is_not_a_record_is_refused_and_kept() {
    let path = tmp("not-a-ledger.jsonl");
    std::fs::write(&path, "a0".repeat(32)).unwrap();
    let key = decern_crypto::generate().unwrap();
    match Ledger::open(&path, key.clone()) {
        Err(LedgerError::Tamper { why, .. }) => assert!(why.contains("does not begin"), "{why}"),
        Err(e) => panic!("expected tamper: {e}"),
        Ok(_) => panic!("a file that is not a ledger must not open"),
    }
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "a0".repeat(32));

    // A real torn record after a good one still heals.
    let path = tmp("torn-record.jsonl");
    std::fs::remove_file(&path).ok();
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    drop(l);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(br#"{"entry":{"seq":1"#);
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(Ledger::open(&path, key).unwrap().count(), 1);
}

/// A prefix taken under the lock reads exactly the records written by then, however many are
/// appended after it, and never part of a line being written.
#[test]
fn a_prefix_reads_what_was_written_when_it_was_taken() {
    let path = tmp("prefix.jsonl");
    std::fs::remove_file(&path).ok();
    let mut l = Ledger::open(&path, decern_crypto::generate().unwrap()).unwrap();
    for _ in 0..3 {
        l.append(entry("Read", true)).unwrap();
    }
    let prefix = l.prefix();
    l.append(entry("Write", true)).unwrap();
    // A half-written line after the prefix, as an append in progress leaves it.
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(br#"{"entry":{"seq":4"#);
    std::fs::write(&path, &bytes).unwrap();
    let lines = prefix.lines().unwrap();
    assert_eq!(prefix.count(), 3);
    assert_eq!(lines.len(), 3);
    assert_eq!(lines, l.raw_records().unwrap()[..3].to_vec());

    // Fewer records on disk than the prefix counts — the file cut behind the ledger's back —
    // is refused, never read as a shorter log.
    let kept: Vec<&str> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .take(2)
        .collect();
    std::fs::write(&path, kept.join("\n") + "\n").unwrap();
    assert!(matches!(
        prefix.lines(),
        Err(LedgerError::Tamper { seq: 2, .. })
    ));
}

#[test]
fn rotating_back_to_a_superseded_key_is_refused() {
    let path = tmp("rotate-back.ledger");
    std::fs::remove_file(&path).ok();
    let old = decern_crypto::generate().unwrap();
    let new = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, old.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    // Back before the new key has signed anything: nothing has followed the old key.
    l.rotate(new.clone()).unwrap();
    l.rotate(old.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.rotate(new.clone()).unwrap();
    l.append(entry("Write", true)).unwrap();
    assert!(matches!(
        l.rotate(old.clone()),
        Err(LedgerError::KeySuperseded { .. })
    ));
    // The refusal left the new key signing.
    l.append(entry("Read", true)).unwrap();
    assert!(l.self_verify().is_ok());
}

#[test]
fn a_legacy_prefix_without_kids_is_extended_with_them() {
    let path = tmp("legacy-prefix.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    drop(l);
    let kid = key_fingerprint(&key.verifying_key());
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replace(&format!(r#","kid":"{kid}""#), "")).unwrap();

    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Write", true)).unwrap();
    let report = l.self_verify().unwrap();
    assert_eq!(report.entries, 2);
    assert_eq!(report.signers, vec![SignerSpan { kid, first_seq: 0 }]);
}

// ------------------------------ persisted anchor ------------------------------

#[test]
fn anchor_catches_truncation_across_a_reopen() {
    // The core: a plain reopen accepts a truncated (still internally
    // consistent) log; the persisted anchor makes the truncation fail-closed.
    let path = tmp("anchor-truncate.ledger");
    let anchor = tmp("anchor-truncate.anchor");
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&anchor).ok();
    let key = decern_crypto::generate().unwrap();

    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.append(entry("Write", true)).unwrap();
    l.append(entry("MoveMoney", false)).unwrap();
    l.seal_anchor(&anchor, 1).unwrap(); // committed height = 3
    drop(l);

    // an insider truncates the last recorded decision
    let text = std::fs::read_to_string(&path).unwrap();
    let kept: Vec<&str> = text.lines().take(2).collect();
    std::fs::write(&path, kept.join("\n") + "\n").unwrap();

    // a plain reopen is fooled — the 2-record log is internally consistent...
    assert!(
        Ledger::open(&path, key.clone()).is_ok(),
        "plain reopen cannot see the truncation"
    );
    // ...but open_anchored refuses: the log no longer extends its committed height.
    let err = match Ledger::open_anchored(&path, key.clone(), Vec::new(), &anchor) {
        Ok(_) => panic!("open_anchored must catch the truncation"),
        Err(e) => e,
    };
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "anchor must catch the truncation: {err}"
    );
}

#[test]
fn anchor_accepts_a_legit_append_only_extension() {
    let path = tmp("anchor-extend.ledger");
    let anchor = tmp("anchor-extend.anchor");
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&anchor).ok();
    let key = decern_crypto::generate().unwrap();

    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.seal_anchor(&anchor, 1).unwrap(); // committed height = 1
    l.append(entry("Write", true)).unwrap(); // honest append-only growth
    drop(l);

    // reopening against the anchor succeeds — the log still extends height 1
    let l = Ledger::open_anchored(&path, key, Vec::new(), &anchor).unwrap();
    assert_eq!(l.count(), 2);
    // no anchor file at all is also fine (nothing committed yet)
    let missing = tmp("anchor-missing.anchor");
    std::fs::remove_file(&missing).ok();
    assert!(l.verify_against_anchor(&missing).is_ok());
}

/// The Ed25519 identity point is a valid encoding of a key of order 1. Under the
/// cofactorless verification equation, the signature `R = identity, S = 0` satisfies
/// it for EVERY message — so an operator who hands an auditor this public key can
/// hand them any log at all and have every record "verify". RFC 8032 §5.1.7 permits
/// the cofactorless check; rejecting a small-order key is what makes verification
/// mean something to a party who did not write the log.
fn small_order_key_and_universal_forgery() -> (VerifyingKey, decern_crypto::Signature) {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut sig_bytes = [0u8; 64];
    sig_bytes[0] = 1; // R = identity, S = 0
    (
        VerifyingKey::from_bytes(&identity).expect("identity is a valid encoding"),
        decern_crypto::Signature::from_bytes(&sig_bytes),
    )
}

#[test]
fn a_small_order_key_cannot_verify_a_signature_it_never_made() {
    let (key, forgery) = small_order_key_and_universal_forgery();
    // The premise: this pair really does satisfy the permissive equation.
    assert!(
        key.verify(b"any message at all", &forgery).is_ok(),
        "the forgery must pass the cofactorless check, or this test proves nothing"
    );
    for msg in [&b"any message at all"[..], b"a fabricated record"] {
        assert!(
            key.verify_strict(msg, &forgery).is_err(),
            "a small-order key must not verify {}",
            String::from_utf8_lossy(msg)
        );
    }
}

#[test]
fn a_fabricated_anchor_under_a_small_order_key_is_refused() {
    let (key, forgery) = small_order_key_and_universal_forgery();
    let cp = Checkpoint {
        root: "00".repeat(32),
        count: 9999,
        ts_ms: 1,
        pubkey_hex: hex::encode(key.to_bytes()),
        sig_b64: B64.encode(forgery.to_bytes()),
    };
    assert!(
        !verify_checkpoint_sig(&cp, &key),
        "an anchor over a height that was never reached must not verify"
    );
    let th = TreeHead {
        merkle_root: "00".repeat(32),
        tree_size: 9999,
        ts_ms: 1,
        pubkey_hex: hex::encode(key.to_bytes()),
        sig_b64: B64.encode(forgery.to_bytes()),
    };
    assert!(!verify_tree_head_sig(&th, &key));
}

#[test]
fn a_forged_anchor_from_an_untrusted_key_is_refused() {
    // An attacker who truncates the log and drops a self-signed anchor at the
    // lower height must not be able to mask the truncation — the anchor's own
    // signature must come from a trusted ledger key.
    let path = tmp("anchor-forged.ledger");
    let anchor = tmp("anchor-forged.anchor");
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&anchor).ok();
    let key = decern_crypto::generate().unwrap();
    let attacker = decern_crypto::generate().unwrap();

    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.append(entry("Write", true)).unwrap();
    let honest = l.checkpoint(9); // correct (root, count) for the current head
    drop(l);

    // The attacker fabricates an anchor over the SAME (root, count) — so it still
    // "extends" the log — but signs it with their OWN key (the honest ledger's
    // records are kid-bound to `key`, so the attacker can't even open it).
    let sig = attacker.sign(&checkpoint_bytes(&honest.root, honest.count, honest.ts_ms));
    let forged = Checkpoint {
        root: honest.root,
        count: honest.count,
        ts_ms: honest.ts_ms,
        pubkey_hex: hex::encode(attacker.verifying_key().to_bytes()),
        sig_b64: B64.encode(sig.to_bytes()),
    };
    save_anchor(&anchor, &forged).unwrap();

    // the honest ledger refuses the anchor: its signer is not in the keyring
    let l = Ledger::open(&path, key).unwrap();
    let err = l.verify_against_anchor(&anchor).unwrap_err();
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "a forged anchor must be refused: {err}"
    );
}

#[test]
fn legacy_kidless_records_verify_against_the_ring() {
    // A record written before rotation support has no `kid`. It must still verify
    // against the trusted key (the try-each-key fallback), so upgrading the code
    // does not brick pre-existing logs.
    let path = tmp("legacy-kidless.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();

    // Append normally, then strip the `kid` field to simulate a legacy line.
    // Do it by byte surgery on the trailing `,"kid":"<hex>"` — parsing to Value
    // and re-serializing would reorder the `entry` bytes and break the hash
    // (which is exactly why the stored bytes, not a reparse, are the proof).
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    drop(l);
    let kid = key_fingerprint(&key.verifying_key());
    let text = std::fs::read_to_string(&path).unwrap();
    let stripped = text.trim_end().replace(&format!(",\"kid\":\"{kid}\""), "");
    assert!(!stripped.contains("kid"), "kid removed: {stripped}");
    std::fs::write(&path, stripped + "\n").unwrap();

    // No kid on the record → verified against any trusted key in the ring.
    assert!(verify(&path, Some(&key.verifying_key())).is_ok());
    assert!(verify_with_keys(&path, &[key.verifying_key()]).is_ok());
}

// ===================== per-epoch/size segmentation =====================

fn tmp_dir(name: &str) -> PathBuf {
    let d = tmp(name);
    std::fs::remove_dir_all(&d).ok();
    d
}

#[test]
fn open_segmented_creates_a_directory_with_one_active_segment_and_a_manifest() {
    let dir = tmp_dir("seg-init");
    let key = decern_crypto::generate().unwrap();
    let _l = Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()).unwrap();
    assert!(dir.join("manifest.json").exists());
    assert!(dir.join("00000001.jsonl").exists());
}

#[test]
fn segmented_append_and_reopen_preserves_root_and_count() {
    let dir = tmp_dir("seg-reopen");
    let key = decern_crypto::generate().unwrap();
    {
        let mut l =
            Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::default())
                .unwrap();
        for i in 0..5 {
            l.append(entry(&format!("act{i}"), true)).unwrap();
        }
    }
    let l2 = Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()).unwrap();
    assert_eq!(l2.count(), 5);
    let recs = l2.read_records(0, 10).unwrap();
    assert_eq!(recs.len(), 5);
}

#[test]
fn segmented_size_rollover_creates_a_second_segment_and_chain_still_verifies() {
    let dir = tmp_dir("seg-size-rollover");
    let key = decern_crypto::generate().unwrap();
    let vk = key.verifying_key();
    let mut l = Ledger::open_segmented(
        &dir,
        key,
        Vec::new(),
        RolloverPolicy::max_bytes(200), // small enough that a few entries force rollover
    )
    .unwrap();
    for i in 0..8 {
        l.append(entry(&format!("action-{i}"), true)).unwrap();
    }
    drop(l);

    let segs: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".jsonl"))
        .collect();
    assert!(
        segs.len() >= 2,
        "expected rollover to produce multiple segments, got {}",
        segs.len()
    );

    // The whole segmented directory verifies end-to-end via the SAME free
    // function a single file would use — auto-detected via is_dir().
    let report = verify_with_keys(&dir, &[vk]).unwrap();
    assert_eq!(report.entries, 8);

    // Every seq is present exactly once, in order, across the boundary.
    let recs = read_verified(&dir, None, 0, 100).unwrap().1;
    let seqs: Vec<u64> = recs
        .iter()
        .map(|r| r["entry"]["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, (0..8).collect::<Vec<_>>());
}

#[test]
fn segmented_epoch_rollover_triggers_on_a_bucket_change() {
    let dir = tmp_dir("seg-epoch-rollover");
    let key = decern_crypto::generate().unwrap();
    let mut l =
        Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::epoch_ms(1000)).unwrap();
    let mut e0 = entry("a", true);
    e0.ts_ms = 500; // bucket 0
    l.append(e0).unwrap();
    let mut e1 = entry("b", true);
    e1.ts_ms = 1500; // bucket 1 — crosses the boundary, must roll over
    l.append(e1).unwrap();
    drop(l);

    let segs: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".jsonl"))
        .collect();
    assert_eq!(segs.len(), 2, "epoch bucket change must trigger a rollover");
}

#[cfg(unix)]
#[test]
fn segmented_sealed_segment_is_chmod_read_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp_dir("seg-chmod");
    let key = decern_crypto::generate().unwrap();
    let mut l =
        Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::max_bytes(150)).unwrap();
    for i in 0..8 {
        l.append(entry(&format!("action-{i}"), true)).unwrap();
    }
    drop(l);
    let sealed = dir.join("00000001.jsonl");
    let mode = std::fs::metadata(&sealed).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o400,
        "a sealed segment must be read-only AND not readable by group or other"
    );
}

#[test]
fn segmented_read_records_offset_limit_spans_a_segment_boundary_and_matches_single_file() {
    // offset/limit must be a GLOBAL record index across segments, not
    // re-applied per file. Build the SAME 5 entries
    // into a single-file ledger and a 2-segment ledger (rollover forced
    // after the 2nd entry) and assert every windowed read matches exactly.
    let single_path = tmp("seg-cmp-single.log");
    std::fs::remove_file(&single_path).ok();
    let seg_dir = tmp_dir("seg-cmp-segmented");
    let key = decern_crypto::generate().unwrap();

    let mut single = Ledger::open(&single_path, key.clone()).unwrap();
    let mut segmented =
        Ledger::open_segmented(&seg_dir, key, Vec::new(), RolloverPolicy::max_bytes(1)).unwrap(); // 1 byte: rolls over before EVERY append after the first

    for i in 0..5 {
        let e = entry(&format!("act{i}"), true);
        single.append(e.clone()).unwrap();
        segmented.append(e).unwrap();
    }

    // Confirm the rollover actually produced multiple segments (else this
    // test would trivially pass without exercising the boundary at all).
    let segs = std::fs::read_dir(&seg_dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".jsonl")
        })
        .count();
    assert!(segs >= 3, "expected several segments, got {segs}");

    for (offset, limit) in [(0usize, 5usize), (1, 3), (2, 2), (3, 100), (4, 1), (0, 1)] {
        let a = single.read_records(offset, limit).unwrap();
        let b = segmented.read_records(offset, limit).unwrap();
        assert_eq!(a, b, "read_records({offset}, {limit}) mismatch");

        let ar = single.read_raw_records(offset, limit).unwrap();
        let br = segmented.read_raw_records(offset, limit).unwrap();
        let a_strs: Vec<&str> = ar.iter().map(|v| v.get()).collect();
        let b_strs: Vec<&str> = br.iter().map(|v| v.get()).collect();
        assert_eq!(
            a_strs, b_strs,
            "read_raw_records({offset}, {limit}) verbatim-byte mismatch"
        );
    }
}

#[test]
fn segmented_verify_fails_closed_when_a_manifest_listed_segment_is_missing() {
    let dir = tmp_dir("seg-missing-segment");
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open_segmented(
        &dir,
        key.clone(),
        Vec::new(),
        RolloverPolicy::max_bytes(150),
    )
    .unwrap();
    for i in 0..8 {
        l.append(entry(&format!("action-{i}"), true)).unwrap();
    }
    drop(l);

    // Delete a SEALED segment's bytes but leave the manifest still naming
    // it — the mid-log analogue of a tail truncation. The manifest is
    // untrusted metadata; only the actual bytes are load-bearing.
    std::fs::remove_file(dir.join("00000001.jsonl")).unwrap();

    let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
        Err(e) => e,
        Ok(_) => panic!("expected open_segmented to fail on a missing segment"),
    };
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "expected Tamper, got {err:?}"
    );
}

#[test]
fn segmented_anchor_catches_a_truncation_that_deletes_a_whole_sealed_segment() {
    // Parity with the single-file case: the chain walk ALONE cannot
    // distinguish "the log always had 3 records" from "the log had 5 and
    // lost the last 2 (plus their segment + manifest entry)" — that is
    // exactly what an externally-persisted anchor exists to catch.
    let dir = tmp_dir("seg-anchor-truncation");
    let anchor_path = tmp("seg-anchor-truncation.anchor");
    std::fs::remove_file(&anchor_path).ok();
    let key = decern_crypto::generate().unwrap();

    let mut l = Ledger::open_segmented(
        &dir,
        key.clone(),
        Vec::new(),
        RolloverPolicy::max_bytes(150),
    )
    .unwrap();
    for i in 0..8 {
        l.append(entry(&format!("action-{i}"), true)).unwrap();
    }
    l.seal_anchor(&anchor_path, 999).unwrap();
    drop(l);

    // Attacker deletes the newest (active) segment's file AND its
    // manifest entry, then re-marks the new tail as active so the
    // manifest stays SHAPE-VALID (exactly one active segment) — the full,
    // sophisticated attacker capability, not just "delete a file and
    // leave a dangling reference" (that simpler case is covered by
    // `segmented_verify_fails_closed_when_a_manifest_listed_segment_is_missing`
    // and is caught earlier, by `segment_paths` itself).
    let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
    let last = manifest.segments.pop().unwrap();
    if let Some(new_last) = manifest.segments.last_mut() {
        new_last.end_seq = None;
    }
    segment::save_manifest(&dir, &manifest).unwrap();
    std::fs::remove_file(dir.join(&last.file)).unwrap();

    let err = match Ledger::open_segmented_anchored(
        &dir,
        key,
        Vec::new(),
        RolloverPolicy::default(),
        &anchor_path,
    ) {
        Err(e) => e,
        Ok(_) => panic!("expected open_segmented_anchored to fail: anchor no longer extended"),
    };
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "expected Tamper (anchor no longer extended), got {err:?}"
    );
}

#[test]
fn open_on_a_segmented_directory_returns_a_clear_error_not_a_raw_os_error() {
    let dir = tmp_dir("seg-vs-open");
    let key = decern_crypto::generate().unwrap();
    let _l =
        Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::default()).unwrap();
    let err = match Ledger::open(&dir, key) {
        Err(e) => e,
        Ok(_) => panic!("expected Ledger::open to refuse a segmented directory"),
    };
    match err {
        LedgerError::Io { err, .. } => assert!(
            err.contains("open_segmented"),
            "expected a clear pointer to open_segmented, got: {err}"
        ),
        other => panic!("expected LedgerError::Io, got {other:?}"),
    }
}

#[test]
fn open_segmented_ignores_an_orphan_segment_left_by_a_crashed_rollover() {
    let dir = tmp_dir("seg-orphan");
    let key = decern_crypto::generate().unwrap();
    {
        let mut l = Ledger::open_segmented(
            &dir,
            key.clone(),
            Vec::new(),
            RolloverPolicy::default(), // never auto-rolls; we simulate the crash by hand
        )
        .unwrap();
        l.append(entry("a", true)).unwrap();
    }
    // Simulate a rollover that created the new segment file but crashed
    // before the manifest commit: an extra, higher-numbered file the
    // manifest does not (yet) know about.
    std::fs::write(dir.join("00000002.jsonl"), b"").unwrap();

    let mut l =
        Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::max_bytes(1)).unwrap();
    assert_eq!(l.count(), 1, "the orphan must not be silently adopted");
    // The very next append forces a rollover (max_bytes=1); it must pick
    // an index that does NOT collide with the orphan.
    l.append(entry("b", true)).unwrap();
    assert!(
        dir.join("00000003.jsonl").exists(),
        "rollover must skip past the orphan's index, not overwrite it"
    );
    let orphan_still_empty = std::fs::metadata(dir.join("00000002.jsonl")).unwrap().len();
    assert_eq!(
        orphan_still_empty, 0,
        "orphan must never be silently reused/overwritten"
    );
}

// ===== segmented-ledger hardening: rollover filenames =====

#[test]
fn roll_over_ignores_a_planted_out_of_range_filename_instead_of_overflowing() {
    // A file named exactly u32::MAX (10 digits) would overflow the naive
    // `max_index + 1` in roll_over if it were adopted as a real segment
    // index. validate_segment_filename's 8-digit shape requirement makes
    // max_index's directory scan treat it as "not a segment file" at
    // all (the same as it already treats manifest.json itself) — so
    // rollover proceeds completely unaffected by the decoy, rather than
    // erroring OR overflowing.
    let dir = tmp_dir("seg-overflow-guard");
    let key = decern_crypto::generate().unwrap();
    let mut l =
        Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::max_bytes(1)).unwrap();
    l.append(entry("a", true)).unwrap();
    std::fs::write(dir.join("4294967295.jsonl"), b"").unwrap();

    l.append(entry("b", true))
        .expect("the decoy filename must not block a normal rollover");
    assert!(
        dir.join("00000002.jsonl").exists(),
        "rollover must proceed to the next real index, unaffected by the decoy"
    );
    assert!(
        !dir.join("00000000.jsonl").exists(),
        "must never silently wrap to and create index 0"
    );
}

#[test]
fn open_segmented_rejects_a_manifest_that_names_an_out_of_range_segment_filename() {
    // Unlike a decoy file merely sitting in the directory (ignored, see
    // the sibling test above), a MANIFEST entry naming an out-of-range
    // filename must be rejected outright — load_manifest validates every
    // segment's `file` field unconditionally, the moment the manifest is
    // read, before anything downstream (segment_paths, the active-segment
    // pick) can act on it.
    let dir = tmp_dir("seg-overflow-manifest");
    let key = decern_crypto::generate().unwrap();
    {
        let mut l =
            Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::default())
                .unwrap();
        l.append(entry("a", true)).unwrap();
    }
    let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
    manifest.segments[0].file = "4294967295.jsonl".into();
    // Bypass save_manifest's own (correct) behavior of writing whatever
    // it's given — write the tampered manifest directly so this test
    // exercises `load_manifest`'s READ-time validation, not a write-path
    // check that doesn't exist and shouldn't need to.
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
        Err(e) => e,
        Ok(_) => panic!("expected an out-of-range manifest filename to be rejected"),
    };
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "expected Tamper (invalid segment filename), got {err:?}"
    );
}

#[test]
fn open_segmented_rejects_a_manifest_with_two_active_segments() {
    let dir = tmp_dir("seg-dual-active");
    let key = decern_crypto::generate().unwrap();
    {
        let mut l =
            Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::max_bytes(1))
                .unwrap();
        for i in 0..3 {
            l.append(entry(&format!("a{i}"), true)).unwrap();
        }
    }
    // Clear end_seq on an already-sealed, non-tail segment — a manifest
    // edit alone, no signing key, no byte-level tamper — producing a
    // shape-invalid "dual active" manifest.
    let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
    manifest.segments[0].end_seq = None;
    segment::save_manifest(&dir, &manifest).unwrap();

    let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
        Err(e) => e,
        Ok(_) => panic!("expected a dual-active manifest to be rejected"),
    };
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "expected Tamper (dual active segment), got {err:?}"
    );
}

#[test]
fn open_segmented_rejects_a_manifest_whose_active_segment_is_not_the_last_entry() {
    let dir = tmp_dir("seg-active-not-tail");
    let key = decern_crypto::generate().unwrap();
    {
        let mut l =
            Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::max_bytes(1))
                .unwrap();
        for i in 0..3 {
            l.append(entry(&format!("a{i}"), true)).unwrap();
        }
    }
    // Swap which segment is "active" WITHOUT changing which one is last —
    // mark the true tail sealed and an earlier one active, still exactly
    // one active segment overall (so the dual-active check alone would
    // not catch this), but not the last entry.
    let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
    let last_end = manifest.segments.last().unwrap().end_seq;
    manifest.segments[0].end_seq = None;
    manifest.segments.last_mut().unwrap().end_seq = last_end.or(Some(3));
    segment::save_manifest(&dir, &manifest).unwrap();

    let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
        Err(e) => e,
        Ok(_) => panic!("expected a non-tail-active manifest to be rejected"),
    };
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "expected Tamper (active segment not last), got {err:?}"
    );
}

#[test]
fn segment_paths_rejects_a_path_traversal_filename_in_the_manifest() {
    // A manifest entry's `file` field must be validated BEFORE it is ever
    // joined onto the segment directory — otherwise an unverified read
    // (read_records/read_raw_records, which the admin ledger browser and
    // the evidence-bundle endpoint both call) could be redirected to
    // return the content of an arbitrary file outside the ledger dir.
    let dir = tmp_dir("seg-traversal");
    let outside = tmp("seg-traversal-secret.jsonl");
    std::fs::write(&outside, b"{\"leaked\":true}\n").unwrap();
    let key = decern_crypto::generate().unwrap();
    {
        let mut l =
            Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::default())
                .unwrap();
        l.append(entry("a", true)).unwrap();
    }
    let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
    manifest.segments[0].file = "../seg-traversal-secret.jsonl".into();
    segment::save_manifest(&dir, &manifest).unwrap();

    let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
        Err(e) => e,
        Ok(_) => panic!("expected a path-traversal filename to be rejected"),
    };
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "expected Tamper (invalid segment filename), got {err:?}"
    );
}

#[test]
fn fresh_epoch_only_ledger_does_not_waste_an_empty_first_segment() {
    // segment::initialize hardcodes the first segment's opened_ms to 0;
    // without the "active segment is still empty" guard in
    // should_roll_over, the FIRST real append (a realistic ts_ms, order
    // 10^12) would roll over before writing anything, since its epoch
    // bucket almost never matches bucket 0.
    let dir = tmp_dir("seg-epoch-fresh-no-waste");
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::epoch_ms(86_400_000))
        .unwrap();
    let mut e = entry("first", true);
    e.ts_ms = 1_780_000_000_000; // a realistic, far-from-zero epoch ms
    l.append(e).unwrap();
    drop(l);

    assert!(
        dir.join("00000001.jsonl").exists(),
        "the first entry must land in segment 1"
    );
    assert!(
        !dir.join("00000002.jsonl").exists(),
        "a still-empty first segment must never be rolled over"
    );
    let bytes = std::fs::metadata(dir.join("00000001.jsonl")).unwrap().len();
    assert!(bytes > 0, "segment 1 must actually hold the record");
}

#[test]
fn segmented_deleting_a_middle_segment_with_manifest_reconciled_is_still_caught() {
    // Dropping a middle segment (and editing the manifest to skip it) now
    // breaks start/end contiguity between the two neighbors, so
    // validate_manifest_shape's contiguity check rejects it at
    // load_manifest time — before verify_lines' unconditional per-record
    // seq/prev checks would ever get a chance to catch it independently.
    // Locks in defense-in-depth: two layers now catch this, not one.
    let dir = tmp_dir("seg-middle-gap");
    let key = decern_crypto::generate().unwrap();
    {
        let mut l =
            Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::max_bytes(1))
                .unwrap();
        for i in 0..4 {
            l.append(entry(&format!("a{i}"), true)).unwrap();
        }
    }
    let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
    assert!(manifest.segments.len() >= 3, "need a real middle segment");
    let middle = manifest.segments.remove(1);
    segment::save_manifest(&dir, &manifest).unwrap();
    std::fs::remove_file(dir.join(&middle.file)).unwrap();

    let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
        Err(e) => e,
        Ok(_) => panic!("expected a reconciled middle-segment gap to still be caught"),
    };
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "expected Tamper (sequence break), got {err:?}"
    );
}

#[test]
fn segmented_read_verified_offset_window_matches_read_records_across_a_boundary() {
    // read_verified windows by a per-record `count` incremented inside
    // verify_lines; read_records/read_raw_records window by Iterator::skip
    // over raw lines. These are two independently-implemented mechanisms
    // that only agree because no writer path ever emits a blank line —
    // this pins that agreement down for a segmented ledger with a
    // non-zero offset spanning a boundary, so a future change that
    // decouples the two counting schemes would be caught here.
    let dir = tmp_dir("seg-read-verified-parity");
    let key = decern_crypto::generate().unwrap();
    let vk = key.verifying_key();
    let mut l =
        Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::max_bytes(1)).unwrap();
    for i in 0..6 {
        l.append(entry(&format!("a{i}"), true)).unwrap();
    }

    for (offset, limit) in [(0usize, 100usize), (2, 3), (1, 1), (5, 10)] {
        let direct = l.read_records(offset, limit).unwrap();
        let (_report, verified) = read_verified(&dir, Some(&vk), offset, limit).unwrap();
        assert_eq!(
            direct, verified,
            "read_verified({offset}, {limit}) must match read_records exactly"
        );
    }
}

// ===== segmented-ledger hardening: filename ceiling =====

#[test]
fn roll_over_refuses_to_create_a_segment_past_the_8_digit_filename_ceiling() {
    // Fabricate a manifest whose sole active segment is already at the
    // maximum representable 8-digit index (99,999,999) — no need to
    // actually perform 100 million real rollovers to reach the
    // boundary. `segment_filename`'s `{:08}` is a MINIMUM width, not a
    // cap, so the next policy-triggered rollover would otherwise
    // silently create a 9-digit filename that `validate_segment_filename`
    // (the very check that closed the original planted-decoy overflow
    // bug) then rejects as Tamper on the NEXT read or reopen. The
    // rollover must instead refuse cleanly, at append() time.
    let dir = tmp_dir("seg-8digit-ceiling");
    std::fs::create_dir_all(&dir).unwrap();
    let seg_file = segment::segment_filename(99_999_999);
    std::fs::write(dir.join(&seg_file), b"").unwrap();
    let manifest = segment::Manifest {
        version: 1,
        segments: vec![segment::SegmentMeta {
            file: seg_file,
            start_seq: 0,
            end_seq: None,
            opened_ms: 0,
        }],
    };
    segment::save_manifest(&dir, &manifest).unwrap();

    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::max_bytes(1))
        .unwrap();
    l.append(entry("a", true)).unwrap(); // lands in the pre-seeded segment (active_is_empty)
    let err = match l.append(entry("b", true)) {
        Err(e) => e,
        Ok(_) => panic!("expected rollover past the 8-digit ceiling to be refused"),
    };
    assert!(
        matches!(err, LedgerError::Io { .. }),
        "expected a clean Io error at rollover time, got {err:?}"
    );
    drop(l);

    // Crucially: the refused rollover must not have half-committed
    // anything — the ledger must still open and verify cleanly
    // afterward, holding exactly the one entry that succeeded.
    let reopened =
        Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::max_bytes(1)).unwrap();
    assert_eq!(
        reopened.count(),
        1,
        "only the first append should have landed"
    );
}

#[test]
fn segmented_epoch_policy_keeps_two_same_bucket_entries_in_one_segment() {
    // Regression for the opened_ms-never-rebased gap: segment 1's
    // opened_ms is hardcoded to 0 by segment::initialize (no entry
    // exists yet to read a real timestamp from). Without rebasing it to
    // the first real entry's ts_ms once that entry lands, EVERY append
    // after the first would compare a real ts_ms (~10^12) against the
    // stale 0 and roll over one record after the first no matter how
    // close in time the two really are — silently defeating epoch-based
    // grouping for the entirety of a fresh ledger's first bucket.
    let dir = tmp_dir("seg-epoch-rebase");
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::epoch_ms(86_400_000))
        .unwrap();
    let mut e0 = entry("a", true);
    e0.ts_ms = 1_780_000_000_000; // some real Unix-ms timestamp
    l.append(e0).unwrap();
    let mut e1 = entry("b", true);
    e1.ts_ms = 1_780_000_000_500; // 500ms later, same epoch bucket
    l.append(e1).unwrap();
    drop(l);

    let segs: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".jsonl"))
        .collect();
    assert_eq!(
        segs.len(),
        1,
        "two entries in the same real epoch bucket must stay in one segment"
    );
}

#[test]
fn open_segmented_rejects_a_manifest_with_reordered_sealed_segments() {
    // Swapping the array order of two already-sealed segments (no
    // deletion, no active-segment tampering — both existing checks stay
    // silent) still breaks start/end contiguity between neighbors and
    // must be rejected, since segment_paths reads files strictly in
    // manifest array order.
    let dir = tmp_dir("seg-reordered");
    let key = decern_crypto::generate().unwrap();
    {
        let mut l =
            Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::max_bytes(1))
                .unwrap();
        for i in 0..4 {
            l.append(entry(&format!("a{i}"), true)).unwrap();
        }
    }
    let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
    assert!(
        manifest.segments.len() >= 3,
        "need at least two sealed segments to swap"
    );
    manifest.segments.swap(0, 1);
    segment::save_manifest(&dir, &manifest).unwrap();

    let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
        Err(e) => e,
        Ok(_) => panic!("expected a reordered manifest to be rejected"),
    };
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "expected Tamper (non-contiguous segments), got {err:?}"
    );
}

#[test]
fn open_segmented_rejects_a_manifest_with_zero_segments() {
    // segment::initialize never produces an empty segments list, so this
    // is a shape no legitimate code path can reach — rejecting it is
    // zero-false-positive-risk and closes a gap where the free,
    // path-only read functions (verify/read_verified, which never call
    // open_segmented's separate zero-active check) would otherwise
    // silently report a clean, empty ledger while real segment files
    // with real records sit untouched on disk.
    let dir = tmp_dir("seg-zero-segments");
    let key = decern_crypto::generate().unwrap();
    {
        let mut l =
            Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::default())
                .unwrap();
        l.append(entry("a", true)).unwrap();
    }
    let empty = segment::Manifest {
        version: 1,
        segments: vec![],
    };
    segment::save_manifest(&dir, &empty).unwrap();

    let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
        Err(e) => e,
        Ok(_) => panic!("expected a zero-segment manifest to be rejected"),
    };
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "expected Tamper (zero segments), got {err:?}"
    );
}

// ===== segmented-ledger hardening: manifest integrity =====

#[test]
fn segmented_manifest_missing_its_head_segment_is_rejected_including_on_an_already_open_handle() {
    // The contiguity check alone only verifies ADJACENT pairs — dropping
    // the earliest segment leaves every remaining pair still mutually
    // contiguous, so it needed its own explicit anchor-to-seq-0 check.
    // Exercise BOTH the reopen path AND the path this gap actually
    // mattered for: read_records on an ALREADY-OPEN handle, which
    // re-reads the manifest fresh on every call but never re-runs the
    // chain walk that would otherwise have caught this independently.
    let dir = tmp_dir("seg-head-drop");
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::max_bytes(1))
        .unwrap();
    for i in 0..4 {
        l.append(entry(&format!("a{i}"), true)).unwrap();
    }
    let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
    assert!(
        manifest.segments.len() >= 3,
        "need a real head segment to drop"
    );
    manifest.segments.remove(0);
    segment::save_manifest(&dir, &manifest).unwrap();

    let err = l
        .read_records(0, 100)
        .expect_err("head-dropped manifest must be rejected, not silently shifted");
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "expected Tamper (missing chain head), got {err:?}"
    );
    drop(l);

    let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
        Err(e) => e,
        Ok(_) => panic!("expected a head-dropped manifest to be rejected on reopen"),
    };
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "expected Tamper (missing chain head), got {err:?}"
    );
}

#[cfg(unix)]
#[test]
fn opened_ms_rebase_rolls_back_in_memory_on_a_failed_persist_so_a_retry_still_persists_it() {
    use std::os::unix::fs::PermissionsExt;
    // If the rebase mutated self.rollover.manifest BEFORE the fallible
    // save_manifest call (with no rollback on failure), a retry with the
    // identical timestamp would find opened_ms already "correct" in
    // memory and silently skip persisting it to disk forever. Force the
    // first attempt's persist to fail, then confirm a retry with the
    // SAME entry still lands the correction on disk.
    let dir = tmp_dir("seg-rebase-rollback");
    let key = decern_crypto::generate().unwrap();
    let mut l = Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::epoch_ms(86_400_000))
        .unwrap();

    let mut e0 = entry("a", true);
    e0.ts_ms = 1_780_000_000_000;
    let mut perms = std::fs::metadata(&dir).unwrap().permissions();
    perms.set_mode(0o500);
    std::fs::set_permissions(&dir, perms.clone()).unwrap();
    l.append(e0.clone())
        .expect_err("save_manifest should fail while the dir is read-only");
    perms.set_mode(0o700);
    std::fs::set_permissions(&dir, perms).unwrap();

    l.append(e0).unwrap();

    let manifest = segment::load_manifest(&dir).unwrap().unwrap();
    assert_eq!(
        manifest.segments[0].opened_ms, 1_780_000_000_000,
        "the retry must have persisted the rebased opened_ms to disk"
    );
}

// ===================== torn-tail vs tamper (crash recovery) =====================

/// A ledger written before a field existed must still verify, byte for byte,
/// after that field is added. Every optional column is `skip_serializing_if`
/// for exactly this reason, and the chain hashes the bytes on disk — so the
/// guarantee is only real if a record lacking the newest fields still checks
/// out. Written as literal on-disk lines rather than by re-serializing, so
/// this fails if a future field ever starts emitting a default.
#[test]
fn a_record_written_before_the_newest_columns_still_verifies() {
    let key = decern_crypto::generate().unwrap();
    let vk = key.verifying_key();
    let path = tmp("pre-columns-compat.ledger");
    std::fs::remove_file(&path).ok();

    // Append through the current code, then confirm the bytes carry none of
    // the default-valued columns: their absence is what an older writer
    // produced, so today's output IS the old shape when nothing set them.
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("act0", true)).unwrap();
    drop(l);

    let line = std::fs::read_to_string(&path).unwrap();
    assert!(
        !line.contains("decision_subject_source"),
        "a default source must not be written; old records would not have it: {line}"
    );
    assert!(
        !line.contains("sponsor_source"),
        "a default sponsor source must not be written either: {line}"
    );

    // The chain covers the exact bytes above, so this is the real check: an
    // entry with none of the newer columns verifies as authentic.
    let report = verify(&path, Some(&vk)).unwrap();
    assert_eq!(report.entries, 1);
    assert!(report.signatures_checked);

    // And it round-trips: reading it back yields the defaults rather than
    // failing to parse, which is what lets an old ledger be read at all.
    let (_r, records) = read_verified(&path, Some(&vk), 0, 1).unwrap();
    let rec = records.first().expect("one record");
    assert!(rec["entry"].get("decision_subject_source").is_none());
    std::fs::remove_file(&path).ok();
}

/// Write `n` valid, chain+signature-valid records, then return the file's
/// full lines so a test can rebuild a deliberately damaged tail.
fn seed_lines(path: &Path, key: &SigningKey, n: usize) -> Vec<String> {
    std::fs::remove_file(path).ok();
    let mut l = Ledger::open(path, key.clone()).unwrap();
    for i in 0..n {
        l.append(entry(&format!("act{i}"), true)).unwrap();
    }
    drop(l);
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn crash_torn_tail_heals_as_torn_tail_not_tamper() {
    let key = decern_crypto::generate().unwrap();
    let vk = key.verifying_key();
    let path = tmp("torn-heals.ledger");
    let lines = seed_lines(&path, &key, 3);

    // Simulate a crash mid-append of record 2: the first two records are
    // whole + newline-terminated; the third is a half-written fragment with
    // NO trailing newline.
    let torn = format!(
        "{}\n{}\n{}",
        lines[0],
        lines[1],
        &lines[2][..lines[2].len() / 2]
    );
    std::fs::write(&path, &torn).unwrap();

    // The read-only verifier SURFACES this as TornTail, distinct from Tamper.
    let err = verify(&path, Some(&vk)).unwrap_err();
    match err {
        LedgerError::TornTail { healed_entries, .. } => assert_eq!(healed_entries, 2),
        other => panic!("expected TornTail, got {other:?}"),
    }

    // Opening HEALS: the verified 2-record prefix is intact and appendable.
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("after-heal", true)).unwrap();
    drop(l);

    // Reopen: clean, three records (2 healed + 1 new), no torn tail remains.
    let report = verify(&path, Some(&vk)).unwrap();
    assert_eq!(report.entries, 3);
}

#[test]
fn unterminated_but_complete_final_record_is_discarded_then_appends_cleanly() {
    // The strongest proof the rule is keyed on NEWLINE-TERMINATION, not on
    // parseability: the final record's bytes are entirely present and parse
    // fine — only its terminating '\n' never reached disk. It must still be
    // discarded, because keeping an unterminated line would fuse the next
    // append onto it as one physical line and corrupt the log.
    let key = decern_crypto::generate().unwrap();
    let vk = key.verifying_key();
    let path = tmp("torn-complete.ledger");
    let lines = seed_lines(&path, &key, 3);

    // All three records complete; drop ONLY the trailing newline.
    std::fs::write(&path, format!("{}\n{}\n{}", lines[0], lines[1], lines[2])).unwrap();

    // Surfaced as TornTail even though the final line parses cleanly.
    match verify(&path, Some(&vk)).unwrap_err() {
        LedgerError::TornTail { healed_entries, .. } => assert_eq!(healed_entries, 2),
        other => panic!("expected TornTail, got {other:?}"),
    }

    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("after-heal", true)).unwrap();
    drop(l);

    // The append landed on its own line — not fused — and verifies.
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        text.lines().count(),
        3,
        "records must stay one-per-line: {text}"
    );
    assert!(
        text.ends_with('\n'),
        "healed log is newline-terminated again"
    );
    assert_eq!(verify(&path, Some(&vk)).unwrap().entries, 3);
}

#[test]
fn attacker_ragged_truncation_below_anchor_stays_tamper() {
    // The discriminating case the review demands: an attacker truncates
    // MID-record so the file ends WITHOUT a newline (entering the heal path),
    // but the healed prefix falls BELOW the committed anchor height. This is
    // deletion of acked history, not a crash tail → must stay Tamper, and the
    // file must NOT be mutated before that verdict.
    let key = decern_crypto::generate().unwrap();
    let path = tmp("torn-below-anchor.ledger");
    let anchor = tmp("torn-below-anchor.anchor");
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&anchor).ok();

    let mut l = Ledger::open(&path, key.clone()).unwrap();
    for i in 0..3 {
        l.append(entry(&format!("act{i}"), true)).unwrap();
    }
    l.seal_anchor(&anchor, 1_000).unwrap(); // commits to 3 records
    drop(l);

    let lines: Vec<String> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    // Keep 1 whole record + a ragged (unterminated) fragment of record 1 →
    // healed prefix = 1 < anchored 3.
    let ragged = format!("{}\n{}", lines[0], &lines[1][..lines[1].len() / 2]);
    std::fs::write(&path, &ragged).unwrap();
    let len_before = std::fs::metadata(&path).unwrap().len();

    let err = match Ledger::open_anchored(&path, key.clone(), Vec::new(), &anchor) {
        Ok(_) => panic!("ragged truncation below the anchor must fail to open"),
        Err(e) => e,
    };
    assert!(
        matches!(err, LedgerError::Tamper { .. }),
        "ragged truncation below the anchor must be Tamper, got {err:?}"
    );
    // The verdict was reached WITHOUT healing/truncating the file.
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        len_before,
        "the file must not be mutated when the torn tail is really a truncation attack"
    );
}

#[test]
fn terminated_final_record_with_broken_signature_stays_tamper() {
    // A fully newline-terminated final record that fails signature is NOT a
    // torn tail — a terminated line can't be a partial write. Stays Tamper.
    let key = decern_crypto::generate().unwrap();
    let vk = key.verifying_key();
    let path = tmp("terminated-bad-sig.ledger");
    let lines = seed_lines(&path, &key, 3);

    // Corrupt one base64 char of the last record's signature, keep the '\n'.
    let mut last: serde_json::Value = serde_json::from_str(&lines[2]).unwrap();
    let sig = last["sig_b64"].as_str().unwrap().to_owned();
    let flipped = if sig.starts_with('A') { 'B' } else { 'A' };
    last["sig_b64"] = json!(format!("{flipped}{}", &sig[1..]));
    let corrupt = format!(
        "{}\n{}\n{}\n",
        lines[0],
        lines[1],
        serde_json::to_string(&last).unwrap()
    );
    std::fs::write(&path, &corrupt).unwrap();

    match verify(&path, Some(&vk)).unwrap_err() {
        LedgerError::Tamper { .. } => {}
        other => panic!("terminated bad-signature record must be Tamper, got {other:?}"),
    }
}

#[test]
fn terminated_final_record_with_broken_chain_stays_tamper() {
    // Same guarantee for a broken hash-chain link on a terminated final line.
    let key = decern_crypto::generate().unwrap();
    let vk = key.verifying_key();
    let path = tmp("terminated-bad-chain.ledger");
    let lines = seed_lines(&path, &key, 3);

    // Flip a byte inside the final record's stored entry: breaks its hash
    // (and thus the chain), while the line stays newline-terminated.
    let mut last: serde_json::Value = serde_json::from_str(&lines[2]).unwrap();
    last["hash"] = json!("00".repeat(32));
    let corrupt = format!(
        "{}\n{}\n{}\n",
        lines[0],
        lines[1],
        serde_json::to_string(&last).unwrap()
    );
    std::fs::write(&path, &corrupt).unwrap();

    match verify(&path, Some(&vk)).unwrap_err() {
        LedgerError::Tamper { .. } => {}
        other => panic!("terminated broken-chain record must be Tamper, got {other:?}"),
    }
}

#[test]
fn healthy_log_ends_newline_terminated_and_reopens_clean() {
    // The single-write append terminates every record in the same write, so
    // a clean shutdown always leaves a newline-terminated file with no torn
    // tail — the round-trip the heal path must never disturb.
    let key = decern_crypto::generate().unwrap();
    let vk = key.verifying_key();
    let path = tmp("healthy-roundtrip.ledger");
    seed_lines(&path, &key, 4);

    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(*bytes.last().unwrap(), b'\n', "log is newline-terminated");
    assert_eq!(verify(&path, Some(&vk)).unwrap().entries, 4);
    // Reopen (no heal) and keep appending.
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("more", true)).unwrap();
    drop(l);
    assert_eq!(verify(&path, Some(&vk)).unwrap().entries, 5);
}

#[test]
fn anchored_crash_tail_above_the_anchor_heals_and_opens() {
    // The POSITIVE control mirroring `attacker_ragged_truncation_below_anchor`:
    // an honest crash left an unterminated tail whose verified prefix STILL
    // covers the committed height. `open_anchored` must walk the anchor
    // check, heal, AND pass the post-heal `verify_against_anchor` — i.e. an
    // anchored deployment recovers from a crash instead of bricking.
    let key = decern_crypto::generate().unwrap();
    let vk = key.verifying_key();
    let path = tmp("anchored-crash-tail.ledger");
    let anchor = tmp("anchored-crash-tail.anchor");
    std::fs::remove_file(&path).ok();
    std::fs::remove_file(&anchor).ok();

    let mut l = Ledger::open(&path, key.clone()).unwrap();
    for i in 0..3 {
        l.append(entry(&format!("act{i}"), true)).unwrap();
    }
    l.seal_anchor(&anchor, 1_000).unwrap(); // commits to 3 records
    l.append(entry("act3", true)).unwrap(); // a 4th, un-acked record
    drop(l);

    let lines: Vec<String> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    // Crash mid-append of record 3: records 0..=2 whole + terminated (== the
    // anchored height), record 3 a ragged unterminated fragment.
    let torn = format!(
        "{}\n{}\n{}\n{}",
        lines[0],
        lines[1],
        lines[2],
        &lines[3][..lines[3].len() / 2]
    );
    std::fs::write(&path, &torn).unwrap();

    // Heals to the 3 acked records AND satisfies the anchor.
    let mut l = Ledger::open_anchored(&path, key.clone(), Vec::new(), &anchor).unwrap();
    l.append(entry("act3-again", true)).unwrap();
    drop(l);
    assert_eq!(verify(&path, Some(&vk)).unwrap().entries, 4);
}

#[test]
fn segmented_torn_tail_in_active_segment_heals() {
    // The heal path routes through `open_segmented_inner` too, and
    // `prefix_lines` keys off the LAST (active) segment. A torn tail in the
    // active segment must heal, leaving the earlier segment's records intact
    // and the chain verifying across the boundary.
    let key = decern_crypto::generate().unwrap();
    let vk = key.verifying_key();
    let dir = tmp("segmented-torn");
    std::fs::remove_dir_all(&dir).ok();

    // A tiny size policy forces a rollover, so records land in >1 segment.
    let policy = RolloverPolicy {
        max_bytes: Some(1),
        epoch_ms: None,
    };
    let mut l = Ledger::open_segmented(&dir, key.clone(), Vec::new(), policy).unwrap();
    for i in 0..4 {
        l.append(entry(&format!("s{i}"), true)).unwrap();
    }
    drop(l);

    // Locate the active (last) segment file and ragged-truncate its final line.
    let paths = segment::segment_paths(&dir).unwrap();
    let active = paths.last().unwrap().clone();
    let alines: Vec<String> = std::fs::read_to_string(&active)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert!(!alines.is_empty(), "active segment should hold >=1 record");
    let kept = &alines[..alines.len() - 1];
    let mut body = kept.iter().map(|s| format!("{s}\n")).collect::<String>();
    // Append a ragged (unterminated) fragment of the last record.
    let torn = alines.last().unwrap();
    body.push_str(&torn[..torn.len() / 2]);
    std::fs::write(&active, &body).unwrap();

    // Read-only verify surfaces TornTail; open heals and stays appendable.
    assert!(matches!(
        verify(&dir, Some(&vk)).unwrap_err(),
        LedgerError::TornTail { .. }
    ));
    let healed_before = match verify(&dir, Some(&vk)).unwrap_err() {
        LedgerError::TornTail { healed_entries, .. } => healed_entries,
        _ => unreachable!(),
    };
    let mut l = Ledger::open_segmented(&dir, key.clone(), Vec::new(), policy).unwrap();
    l.append(entry("post-heal", true)).unwrap();
    drop(l);
    assert_eq!(
        verify(&dir, Some(&vk)).unwrap().entries,
        healed_before + 1,
        "chain verifies across the segment boundary after healing the active tail"
    );
}
/// The ledger holds decision subjects and the pseudonymous handles the subject-side
/// audit route is keyed by. It was created at the process umask — commonly 0644 —
/// while the signing key and the mission registry beside it are 0600, which made the
/// audit log the readable one of the three.
#[cfg(unix)]
#[test]
fn a_ledger_file_is_not_readable_by_group_or_other() {
    use std::os::unix::fs::PermissionsExt;
    let path = tmp("perm-new.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();
    let mut led = Ledger::open(&path, key).unwrap();
    led.append(entry("Read", true)).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "ledger must be 0600, got {mode:o}");
}

/// A ledger written before this change is tightened when it is next opened, rather
/// than left readable forever. `.mode()` alone would not do it: it applies only on
/// creation.
#[cfg(unix)]
#[test]
fn reopening_an_existing_world_readable_ledger_tightens_it() {
    use std::os::unix::fs::PermissionsExt;
    let path = tmp("perm-tighten.ledger");
    std::fs::remove_file(&path).ok();
    let key = decern_crypto::generate().unwrap();
    {
        let mut led = Ledger::open(&path, key.clone()).unwrap();
        led.append(entry("Read", true)).unwrap();
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _led = Ledger::open(&path, key).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "reopen must tighten, got {mode:o}");
}

/// A caller no issuer vouched for is recorded without `iss`, rather than with an empty or
/// null one, and a record written with an issuer still reads.
#[test]
fn asserted_by_omits_an_issuer_nobody_verified() {
    let unissued = AssertedBy {
        sub: "agent-1".into(),
        client_id: "agent-1".into(),
        iss: None,
    };
    assert_eq!(
        serde_json::to_value(&unissued).unwrap(),
        json!({"sub": "agent-1", "client_id": "agent-1"})
    );
    let earlier: AssertedBy = serde_json::from_value(
        json!({"sub": "s", "client_id": "c", "iss": "https://issuer.example/"}),
    )
    .unwrap();
    assert_eq!(earlier.iss.as_deref(), Some("https://issuer.example/"));
}

/// Open `path` as a second writer, which must be refused, and return the refusal.
fn second_writer_refused(path: &Path, key: &SigningKey) -> String {
    match Ledger::open(path, key.clone()) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a second writer opened {}", path.display()),
    }
}

/// A ledger has one writer. A second open is refused before it reads the log, so it cannot
/// trim the first writer's record in flight as a torn tail; the lock follows the file under
/// another spelling of its path and through a symbolic or, on Unix, a hard link, and is
/// released with the ledger.
#[test]
fn a_second_writer_is_refused_before_it_touches_the_log() {
    let path = tmp("single-writer.jsonl");
    let _ = std::fs::remove_file(&path);
    let key = decern_crypto::generate().unwrap();
    let mut first = Ledger::open(&path, key.clone()).unwrap();
    first.append(entry("Read", true)).unwrap();
    // The first writer's next record, part-way to disk.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"{\"entry\":{\"seq\":1").unwrap();
    }
    let before = std::fs::read(&path).unwrap();

    let e = second_writer_refused(&path, &key);
    assert!(e.contains("another process has this ledger open"), "{e}");
    let parent = path.parent().unwrap();
    second_writer_refused(&parent.join(".").join("single-writer.jsonl"), &key);
    #[cfg(unix)]
    {
        let link = parent.join("single-writer-link.jsonl");
        let hard = parent.join("single-writer-hard.jsonl");
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&hard);
        std::os::unix::fs::symlink(&path, &link).unwrap();
        second_writer_refused(&link, &key);
        std::fs::hard_link(&path, &hard).unwrap();
        second_writer_refused(&hard, &key);
        std::fs::remove_file(&link).unwrap();
        std::fs::remove_file(&hard).unwrap();
    }
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "the refused opens left the log as it was"
    );

    drop(first);
    let reopened = Ledger::open(&path, key).expect("the lock goes with the ledger");
    drop(reopened);
    let _ = std::fs::remove_file(&path);
}

/// A ledger first opened through a symbolic link whose target did not exist yet is the same
/// file as its target once created, so opening the target is refused while the first is open.
#[cfg(unix)]
#[test]
fn a_ledger_created_through_a_link_shares_the_lock_with_its_target() {
    let dir = tmp("link-before-target");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("ledger.jsonl");
    let link = dir.join("via-link.jsonl");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let key = decern_crypto::generate().unwrap();
    let first = Ledger::open(&link, key.clone()).unwrap();
    assert!(
        target.exists(),
        "opening through the link created the target"
    );
    let e = second_writer_refused(&target, &key);
    assert!(e.contains("another process"), "{e}");
    drop(first);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A ledger with no file, opened beside an anchor that counts a record, is refused as a
/// truncation, and only by an anchor a ledger key signed. On Unix the writer lock creates the
/// file and the open verifies it; this is the check where no file is created.
#[test]
fn an_anchor_that_counts_a_record_refuses_a_ledger_with_no_file() {
    let key = decern_crypto::generate().unwrap();
    let path = tmp("removed-history.jsonl");
    let empty = tmp("removed-history-0.anchor");
    let counted = tmp("removed-history-1.anchor");
    let _ = std::fs::remove_file(&path);
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.seal_anchor(&empty, 1).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.seal_anchor(&counted, 2).unwrap();
    drop(l);

    let trusted = [key.verifying_key()];
    assert!(crate::open::refuse_removed_history(None, &trusted).is_ok());
    assert!(crate::open::refuse_removed_history(Some(&empty), &trusted).is_ok());
    assert!(matches!(
        crate::open::refuse_removed_history(Some(&counted), &trusted),
        Err(LedgerError::Tamper { seq: 1, .. })
    ));
    let stranger = [decern_crypto::generate().unwrap().verifying_key()];
    match crate::open::refuse_removed_history(Some(&empty), &stranger) {
        Err(LedgerError::Tamper { why, .. }) => assert!(why.contains("signature"), "{why}"),
        other => panic!("an anchor no ledger key signed was trusted: {other:?}"),
    }
    for f in [&path, &empty, &counted] {
        let _ = std::fs::remove_file(f);
    }
}

/// Taking the lock leaves a file that is not a ledger refused and with its own mode, and an
/// anchored open of a ledger whose file was removed is refused at its anchor's count.
#[cfg(unix)]
#[test]
fn a_refused_file_keeps_its_mode_and_a_removed_ledger_is_refused_at_its_anchor() {
    use std::os::unix::fs::PermissionsExt;
    let key = decern_crypto::generate().unwrap();

    let not_a_ledger = tmp("not-a-ledger.txt");
    std::fs::write(&not_a_ledger, "{\"just\":\"a config\"}\n").unwrap();
    std::fs::set_permissions(&not_a_ledger, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Ledger::open(&not_a_ledger, key.clone()).is_err());
    let mode = std::fs::metadata(&not_a_ledger)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o644, "a refused file keeps its mode");
    let _ = std::fs::remove_file(&not_a_ledger);

    let path = tmp("anchored-then-gone.jsonl");
    let anchor = tmp("anchored-then-gone.anchor");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&anchor);
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    l.seal_anchor(&anchor, 1).unwrap();
    drop(l);
    std::fs::remove_file(&path).unwrap();
    match Ledger::open_anchored(&path, key.clone(), Vec::new(), &anchor) {
        Err(LedgerError::Tamper { seq: 1, why }) => assert!(why.contains("anchor"), "{why}"),
        Err(e) => panic!("refused for another reason: {e}"),
        Ok(_) => panic!("an anchored open of a removed ledger was not refused"),
    }
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&anchor);
}
