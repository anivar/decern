// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! CLI integration: a ledger whose signing key was rotated verifies end to end when
//! `--pubkey` is given once per key, and not with the current key alone.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;

use decern_crypto::generate;
use decern_ledger::{Entry, Ledger, ShardedLedger};
use decern_store::{FileLedgerHeadStore, LedgerHeadStore};

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
        ..Default::default()
    }
}

fn fresh_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("decern-rotation-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn decern(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_decern"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn a_rotated_ledger_verifies_with_every_key_and_not_with_the_current_one_alone() {
    let dir = fresh_dir("single");
    let path = dir.join("ledger.jsonl");
    let (old, new) = (generate().unwrap(), generate().unwrap());
    let old_kid = hex::encode(old.verifying_key().to_bytes());
    let new_kid = hex::encode(new.verifying_key().to_bytes());

    let mut ledger = Ledger::open(&path, old).unwrap();
    ledger.append(entry("doc0")).unwrap();
    ledger.append(entry("doc1")).unwrap();
    let before = ledger.tree_head(1_700_000_000_000).unwrap();
    ledger.rotate(new).unwrap();
    ledger.append(entry("doc2")).unwrap();
    let after = ledger.tree_head(1_700_000_000_001).unwrap();
    drop(ledger);
    let ledger = path.to_str().unwrap();

    let both = decern(&[
        "verify", "--ledger", ledger, "--pubkey", &old_kid, "--pubkey", &new_kid,
    ]);
    let out = String::from_utf8_lossy(&both.stdout);
    assert!(both.status.success(), "{out}");
    assert!(
        out.contains(&format!("signer:     {old_kid} from seq 0"))
            && out.contains(&format!("signer:     {new_kid} from seq 2")),
        "{out}"
    );

    let current = decern(&["verify", "--ledger", ledger, "--pubkey", &new_kid]);
    assert!(!current.status.success());
    let err = String::from_utf8_lossy(&current.stderr);
    assert!(
        err.contains(&old_kid),
        "the refusal names the record's key: {err}"
    );

    // A tree head from either side of the rotation is signed by one of the keys given.
    for (name, head) in [("before", &before), ("after", &after)] {
        let anchor = dir.join(format!("{name}.json"));
        std::fs::write(&anchor, serde_json::to_string(head).unwrap()).unwrap();
        let run = decern(&[
            "verify",
            "--ledger",
            ledger,
            "--pubkey",
            &old_kid,
            "--pubkey",
            &new_kid,
            "--anchor",
            anchor.to_str().unwrap(),
        ]);
        assert!(
            run.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&run.stderr)
        );
    }

    let explained = decern(&[
        "explain", "--ledger", ledger, "--seq", "0", "--pubkey", &old_kid, "--pubkey", &new_kid,
    ]);
    let out = String::from_utf8_lossy(&explained.stdout);
    assert!(
        explained.status.success() && out.contains("yes (verified)"),
        "{out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_rotated_shard_store_verifies_with_every_key() {
    let dir = fresh_dir("sharded");
    let (old, new) = (generate().unwrap(), generate().unwrap());
    let old_kid = hex::encode(old.verifying_key().to_bytes());
    let new_kid = hex::encode(new.verifying_key().to_bytes());
    let store: Arc<dyn LedgerHeadStore> = Arc::new(FileLedgerHeadStore::new(&dir).unwrap());
    let before = ShardedLedger::new(store.clone(), old.clone(), Vec::new());
    before.append("acme", entry("r0")).unwrap();
    let after = ShardedLedger::new(store, new, vec![old.verifying_key()]);
    after.append("acme", entry("r1")).unwrap();
    let dir_arg = dir.to_str().unwrap();

    let both = decern(&[
        "verify",
        "--sharded",
        dir_arg,
        "--pubkey",
        &old_kid,
        "--pubkey",
        &new_kid,
    ]);
    assert!(
        both.status.success(),
        "{}",
        String::from_utf8_lossy(&both.stdout)
    );
    let current = decern(&["verify", "--sharded", dir_arg, "--pubkey", &new_kid]);
    let out = String::from_utf8_lossy(&current.stdout);
    assert!(
        !current.status.success() && out.contains("TAMPER shard acme"),
        "{out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
