// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
#![cfg(unix)]

use decern_ledger::{Entry, Ledger, RolloverPolicy};
use std::os::unix::fs::PermissionsExt;

const UNDER_UMASK_022: &str = "DECERN_TEST_UNDER_UMASK_022";
const NAME: &str = "a_segment_created_at_rollover_is_owner_only";

/// A segment collects decision records from the rollover that creates it until the next
/// rollover seals it or the ledger is reopened, and nothing tightens its mode in between, so
/// it has to be owner-only from creation, as the single-file ledger is.
///
/// Only a umask that leaves group and other bits set can tell a `0600` creation from the
/// default, so the body runs in a child process under umask 022 whatever the caller's is.
#[test]
fn a_segment_created_at_rollover_is_owner_only() {
    if std::env::var_os(UNDER_UMASK_022).is_none() {
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(r#"umask 022 && exec "$0" --exact "$1" --nocapture"#)
            .arg(&exe)
            .arg(NAME)
            .env(UNDER_UMASK_022, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        // A filter that matches nothing runs zero tests and exits 0, so success alone would
        // let a renamed test pass without its body.
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "the body did not pass under umask 022:\n{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let dir = std::env::temp_dir().join(format!("decern-segment-mode-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("probe");
    std::fs::File::create(&probe).unwrap();
    let probe_mode = std::fs::metadata(&probe).unwrap().permissions().mode() & 0o077;
    assert_ne!(
        probe_mode, 0,
        "umask 022 is not in effect: a default file is {probe_mode:o}"
    );
    let key = decern_crypto::generate().unwrap();
    let mut ledger =
        Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::max_bytes(200)).unwrap();
    for i in 0..8 {
        ledger
            .append(Entry {
                action: format!("a{i}"),
                subject_type: "Principal".into(),
                subject_id: "s".into(),
                resource_type: "R".into(),
                resource_id: "r".into(),
                context: serde_json::json!({"now": 1}),
                ..Default::default()
            })
            .unwrap();
    }

    let segments: Vec<(String, u32)> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".jsonl"))
        .map(|e| {
            let mode = e.metadata().unwrap().permissions().mode() & 0o777;
            (e.file_name().to_string_lossy().into_owned(), mode)
        })
        .collect();
    assert!(segments.len() > 1, "no rollover happened: {segments:?}");
    for (name, mode) in &segments {
        assert_eq!(
            mode & 0o077,
            0,
            "{name} is readable beyond its owner: {mode:o}"
        );
    }
    drop(ledger);
    let _ = std::fs::remove_dir_all(&dir);
}
