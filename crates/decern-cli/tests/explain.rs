// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! CLI integration: `decern explain <ledger> <seq>` reads a record and explains
//! it faithfully from what was recorded, verifying the chain.

use std::process::Command;

use decern_crypto::generate;
use decern_ledger::Entry;
use decern_store::{FileLedgerHeadStore, LedgerHeadStore};
use std::sync::Arc;

fn entry(resource_id: &str, decision: bool, reason: &str) -> Entry {
    Entry {
        ts_ms: 1,
        subject_type: "Principal".into(),
        subject_id: "alice".into(),
        action: "Read".into(),
        resource_type: "Resource".into(),
        resource_id: resource_id.into(),
        context: serde_json::json!({ "now": 1 }),
        decision,
        reasons: vec![reason.into()],
        parameter_digest: Some("abc123def456".into()),
        sponsor: Some(decern_ledger::Party {
            kind: "Principal".into(),
            id: "root".into(),
        }),
        mission: None,
        decision_subject: Some(decern_ledger::Party {
            kind: "Resource".into(),
            id: resource_id.into(),
        }),
        ..Default::default()
    }
}

#[test]
fn explain_outputs_human_readable_entry() {
    let dir = std::env::temp_dir().join(format!("decern-cli-explain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let ledger_path = dir.join("ledger.jsonl");
    let key = generate().unwrap();
    let _store: Arc<dyn LedgerHeadStore> = Arc::new(FileLedgerHeadStore::new(&dir).unwrap());

    let ledger = decern_ledger::Ledger::open(&ledger_path, key.clone()).unwrap();
    let ledger = Arc::new(tokio::sync::Mutex::new(ledger));

    // Append a test record
    {
        let mut l = ledger.blocking_lock();
        let _ = l.append(entry("doc1", true, "owner:alice"));
    }
    let pubkey = key.verifying_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let bin = env!("CARGO_BIN_EXE_decern");

    // Explain seq=0 in human-readable mode
    let output = Command::new(bin)
        .args(["explain", "--ledger"])
        .arg(&ledger_path)
        .args(["--seq", "0"])
        .args(["--pubkey", &pubkey_hex])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "explain must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Check for key fields in output
    assert!(stdout.contains("seq:"), "output must show sequence number");
    assert!(
        stdout.contains("alice"),
        "output must show subject ID (alice)"
    );
    assert!(stdout.contains("Read"), "output must show action");
    assert!(stdout.contains("ALLOW"), "output must show decision");
    assert!(stdout.contains("owner:alice"), "output must show reasoning");

    // This run supplied --pubkey, so the signature genuinely was verified.
    let sig_line = stdout
        .lines()
        .find(|l| l.contains("signature:"))
        .expect("output must report signature status");
    assert!(
        sig_line.contains("(verified)"),
        "with --pubkey the signature must be reported as verified: {sig_line}"
    );
}

/// An explanation must never claim a verification it did not perform. Without
/// `--pubkey` the chain is still checked, but no signature is examined.
#[test]
fn explain_without_pubkey_does_not_claim_verification() {
    let dir = std::env::temp_dir().join(format!("decern-cli-explain-nokey-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ledger_path = dir.join("ledger.jsonl");

    let key = generate().unwrap();
    {
        let mut ledger = decern_ledger::Ledger::open(&ledger_path, key).unwrap();
        let _ = ledger.append(entry("claim1", true, "owner:alice"));
    }

    let output = Command::new(env!("CARGO_BIN_EXE_decern"))
        .args(["explain", "--ledger"])
        .arg(&ledger_path)
        .args(["--seq", "0"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "explain must succeed without a key; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sig_line = stdout
        .lines()
        .find(|l| l.contains("signature:"))
        .expect("output must report signature status");
    assert!(
        sig_line.contains("not checked"),
        "without --pubkey the signature must be reported as not checked: {sig_line}"
    );
    assert!(
        !sig_line.contains("(verified)"),
        "an unchecked signature must never be labelled verified: {sig_line}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn explain_detects_tampered_chain() {
    let dir =
        std::env::temp_dir().join(format!("decern-cli-explain-tamper-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let ledger_path = dir.join("ledger.jsonl");
    let key = generate().unwrap();
    let _store: Arc<dyn LedgerHeadStore> = Arc::new(FileLedgerHeadStore::new(&dir).unwrap());

    let ledger = decern_ledger::Ledger::open(&ledger_path, key.clone()).unwrap();
    let ledger = Arc::new(tokio::sync::Mutex::new(ledger));

    // Append test records
    {
        let mut l = ledger.blocking_lock();
        let _ = l.append(entry("doc1", true, "owner:alice"));
        let _ = l.append(entry("doc2", false, "not-owner"));
    }
    let pubkey = key.verifying_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    // Corrupt the ledger by flipping a byte in the first record's resource_id
    let contents = std::fs::read_to_string(&ledger_path).unwrap();
    let corrupted = contents.replace("doc1", "docX");
    std::fs::write(&ledger_path, corrupted).unwrap();

    let bin = env!("CARGO_BIN_EXE_decern");

    // Try to explain seq=1 (which is still correct but depends on seq=0's hash)
    let output = Command::new(bin)
        .args(["explain", "--ledger"])
        .arg(&ledger_path)
        .args(["--seq", "1"])
        .args(["--pubkey", &pubkey_hex])
        .output()
        .unwrap();

    // Must fail because the chain is broken
    assert!(
        !output.status.success(),
        "explain must fail on tampered chain; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TAMPER") || stderr.contains("tamper") || stderr.contains("chain"),
        "error must mention tampering; stderr: {}",
        stderr
    );
}

#[test]
fn explain_json_output() {
    let dir = std::env::temp_dir().join(format!("decern-cli-explain-json-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let ledger_path = dir.join("ledger.jsonl");
    let key = generate().unwrap();
    let _store: Arc<dyn LedgerHeadStore> = Arc::new(FileLedgerHeadStore::new(&dir).unwrap());

    let ledger = decern_ledger::Ledger::open(&ledger_path, key.clone()).unwrap();
    let ledger = Arc::new(tokio::sync::Mutex::new(ledger));

    // Append a test record
    {
        let mut l = ledger.blocking_lock();
        let _ = l.append(entry("doc1", false, "not-authorized"));
    }
    let pubkey = key.verifying_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let bin = env!("CARGO_BIN_EXE_decern");

    // Explain with --json flag
    let output = Command::new(bin)
        .args(["explain", "--ledger"])
        .arg(&ledger_path)
        .args(["--seq", "0"])
        .args(["--pubkey", &pubkey_hex])
        .args(["--json"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "explain with --json must succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse as JSON to verify structure
    let json: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(
        json.is_ok(),
        "--json output must be valid JSON; got: {}",
        stdout
    );

    let obj = json.unwrap();
    assert!(obj.get("seq").is_some(), "JSON must have seq field");
    assert!(
        obj.get("subject_id").is_some(),
        "JSON must have subject_id field"
    );
    assert!(
        obj.get("decision").is_some(),
        "JSON must have decision field"
    );
}

#[test]
fn explain_seq_out_of_bounds() {
    let dir =
        std::env::temp_dir().join(format!("decern-cli-explain-bounds-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let ledger_path = dir.join("ledger.jsonl");
    let key = generate().unwrap();
    let _store: Arc<dyn LedgerHeadStore> = Arc::new(FileLedgerHeadStore::new(&dir).unwrap());

    let ledger = decern_ledger::Ledger::open(&ledger_path, key.clone()).unwrap();
    let ledger = Arc::new(tokio::sync::Mutex::new(ledger));

    // Append one record
    {
        let mut l = ledger.blocking_lock();
        let _ = l.append(entry("doc1", true, "ok"));
    }
    let pubkey = key.verifying_key();
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let bin = env!("CARGO_BIN_EXE_decern");

    // Try to explain seq=1 when only seq=0 exists
    let output = Command::new(bin)
        .args(["explain", "--ledger"])
        .arg(&ledger_path)
        .args(["--seq", "1"])
        .args(["--pubkey", &pubkey_hex])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "explain must fail for out-of-bounds seq"
    );
}
