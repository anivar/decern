// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! CLI integration: `decern verify --anchor` proves the log still extends a tree head
//! published earlier, so a record dropped after it was committed is detectable by someone
//! who is not the operator.

use std::path::{Path, PathBuf};
use std::process::Command;

use decern_crypto::{SigningKey, generate};
use decern_ledger::{Entry, Ledger};

fn entry(resource_id: &str) -> Entry {
    Entry {
        ts_ms: 1,
        subject_type: "Principal".into(),
        subject_id: "alice".into(),
        action: "Read".into(),
        resource_type: "Resource".into(),
        resource_id: resource_id.into(),
        context: serde_json::json!({ "now": 1 }),
        decision: true,
        reasons: vec!["owner:alice".into()],
        ..Default::default()
    }
}

struct Fixture {
    dir: PathBuf,
    ledger_path: PathBuf,
    anchor_path: PathBuf,
    pubkey_hex: String,
    key: SigningKey,
}

/// Seed `n` records, publish a tree head over them, and keep the key so a test can keep
/// appending — the anchored size has to be a real prefix, not the whole log.
fn seed_and_anchor(name: &str, n: usize) -> Fixture {
    let dir = std::env::temp_dir().join(format!("decern-anchor-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let ledger_path = dir.join("ledger.jsonl");
    let key = generate().unwrap();
    let pubkey_hex = hex::encode(key.verifying_key().to_bytes());

    let mut ledger = Ledger::open(&ledger_path, key.clone()).unwrap();
    for i in 0..n {
        ledger.append(entry(&format!("doc{i}"))).unwrap();
    }
    let th = ledger.tree_head(1_700_000_000_000).unwrap();
    drop(ledger);

    let anchor_path = dir.join("anchor.json");
    std::fs::write(&anchor_path, serde_json::to_string(&th).unwrap()).unwrap();

    Fixture {
        dir,
        ledger_path,
        anchor_path,
        pubkey_hex,
        key,
    }
}

fn verify_against(f: &Fixture, pubkey_hex: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_decern"))
        .args(["verify", "--ledger"])
        .arg(&f.ledger_path)
        .args(["--pubkey", pubkey_hex])
        .arg("--anchor")
        .arg(&f.anchor_path)
        .output()
        .unwrap()
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// A log that has only grown since the commitment still extends it.
#[test]
fn a_log_that_only_grew_still_extends_its_anchor() {
    let f = seed_and_anchor("grow", 3);

    // Append after publishing, so the anchored tree is a strict prefix of the current one.
    let mut ledger = Ledger::open(&f.ledger_path, f.key.clone()).unwrap();
    ledger.append(entry("doc-after-anchor")).unwrap();
    drop(ledger);

    let out = verify_against(&f, &f.pubkey_hex);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "a grown log must still extend its anchor; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("log extends the anchored tree (3 -> 4 records)"),
        "the consistency result must name both sizes: {stdout}"
    );
    assert!(
        stdout.contains("anchor:     signature verified"),
        "the anchor's own signature must be checked when a key is given: {stdout}"
    );
    cleanup(&f.dir);
}

/// The check a chain cannot make on its own. Records the anchor committed to are removed,
/// and what remains is a perfectly well-formed chain — the operator rewrote it that way.
/// Only the earlier commitment exposes it.
#[test]
fn a_log_truncated_below_its_anchor_is_detected() {
    let f = seed_and_anchor("trunc", 4);

    let all = std::fs::read_to_string(&f.ledger_path).unwrap();
    let lines: Vec<&str> = all.lines().collect();
    assert_eq!(lines.len(), 4, "seeded four records");
    std::fs::write(&f.ledger_path, format!("{}\n{}\n", lines[0], lines[1])).unwrap();

    // The remaining log verifies on its own. That is exactly the problem.
    let plain = Command::new(env!("CARGO_BIN_EXE_decern"))
        .args(["verify", "--ledger"])
        .arg(&f.ledger_path)
        .args(["--pubkey", &f.pubkey_hex])
        .output()
        .unwrap();
    assert!(
        plain.status.success(),
        "a truncated log stays internally consistent, which is why an anchor is needed; stderr: {}",
        String::from_utf8_lossy(&plain.stderr)
    );

    let out = verify_against(&f, &f.pubkey_hex);
    assert!(
        !out.status.success(),
        "a log truncated below its anchor must fail; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("TRUNCATED") || stderr.contains("DIVERGED"),
        "the failure must name what happened: {stderr}"
    );
    cleanup(&f.dir);
}

/// An anchor that does not verify under the reader's own key is refused, not believed.
#[test]
fn an_anchor_not_signed_by_the_ledger_key_is_refused() {
    let f = seed_and_anchor("forged", 2);
    let other_hex = hex::encode(generate().unwrap().verifying_key().to_bytes());

    let out = verify_against(&f, &other_hex);
    assert!(
        !out.status.success(),
        "an anchor that does not verify under the given key must be refused; stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    cleanup(&f.dir);
}
