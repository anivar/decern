// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! CLI integration: `decern verify --sharded <dir>` audits a flock head-store
//! deployment. A clean set of shards passes (exit 0); a tampered shard is detected and
//! reported (non-zero exit). Drives the shipped `decern` binary end to end, covering
//! the argument wiring the library-level verify test cannot reach.

use std::process::Command;
use std::sync::Arc;

use decern_crypto::generate;
use decern_ledger::{Entry, ShardedLedger};
use decern_store::{FileLedgerHeadStore, LedgerHeadStore};

fn entry(resource_id: &str) -> Entry {
    Entry {
        ts_ms: 1,
        subject_type: "Principal".into(),
        subject_id: "corp".into(),
        action: "Read".into(),
        resource_type: "Resource".into(),
        resource_id: resource_id.into(),
        context: serde_json::json!({ "now": 1 }),
        decision: true,
        ..Default::default()
    }
}

/// Find the on-disk `.shard` file whose stored records mention `marker`.
fn shard_file_containing(dir: &std::path::Path, marker: &str) -> std::path::PathBuf {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.extension().and_then(|e| e.to_str()) == Some("shard")
                && std::fs::read_to_string(p)
                    .map(|s| s.contains(marker))
                    .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("no .shard file containing {marker:?}"))
}

#[test]
fn verify_sharded_passes_clean_then_detects_a_tampered_shard() {
    let dir =
        std::env::temp_dir().join(format!("decern-cli-verify-sharded-{}", std::process::id()));
    // Self-healing: a prior failed run (or a recycled pid) must not leave stale shards
    // that a fresh append would extend.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Build a small real sharded ledger on disk: two shards, one with two records.
    let key = generate().unwrap();
    let store: Arc<dyn LedgerHeadStore> = Arc::new(FileLedgerHeadStore::new(&dir).unwrap());
    let ledger = ShardedLedger::new(store, key, Vec::new());
    ledger.append("acme", entry("acme-r0")).unwrap();
    ledger.append("acme", entry("acme-r1")).unwrap();
    ledger.append("beta", entry("beta-r0")).unwrap();
    let pubkey = ledger.pubkey_hex();

    let bin = env!("CARGO_BIN_EXE_decern");

    // Clean: every shard verifies, exit 0.
    let clean = Command::new(bin)
        .args(["verify", "--sharded"])
        .arg(&dir)
        .args(["--pubkey", &pubkey])
        .output()
        .unwrap();
    assert!(
        clean.status.success(),
        "clean sharded ledger must verify (exit 0); stderr: {}",
        String::from_utf8_lossy(&clean.stderr)
    );

    // Flip a byte inside one shard's stored record (kept the same length so the outer
    // JSON still parses) — the hash recompute is what must fire.
    let target = shard_file_containing(&dir, "acme-r1");
    let corrupted = std::fs::read_to_string(&target)
        .unwrap()
        .replace("acme-r1", "acme-rX");
    std::fs::write(&target, corrupted).unwrap();

    // Tampered: non-zero exit, and the offending shard is named.
    let tampered = Command::new(bin)
        .args(["verify", "--sharded"])
        .arg(&dir)
        .args(["--pubkey", &pubkey])
        .output()
        .unwrap();
    assert!(
        !tampered.status.success(),
        "a tampered shard must fail verification (non-zero exit)"
    );
    assert!(
        String::from_utf8_lossy(&tampered.stdout).contains("TAMPER"),
        "the tampered shard must be reported; stdout: {}",
        String::from_utf8_lossy(&tampered.stdout)
    );

    // clap wiring: exactly one of --ledger / --sharded is required.
    let neither = Command::new(bin).arg("verify").output().unwrap();
    assert!(
        !neither.status.success(),
        "verify with neither --ledger nor --sharded must be rejected"
    );
    let both = Command::new(bin)
        .args(["verify", "--sharded"])
        .arg(&dir)
        .args(["--ledger"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(
        !both.status.success(),
        "verify with both --ledger and --sharded must be rejected"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
