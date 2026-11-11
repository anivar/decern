// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! CLI integration: `decern explain` prints what a record holds for a person to read, and
//! a record holds what a caller sent. A control character in it must reach the terminal as
//! text.

use std::process::Command;

use decern_crypto::generate;
use decern_ledger::{AssertedBy, DecisionSubject, Entry, Ledger, MissionRef, Party};

/// ESC and CSI open a terminal control sequence, BEL rings, DEL and a bare newline rewrite
/// what the reader sees.
const HOSTILE: &str = "x\u{1b}[2J\u{9b}31m\u{7}\u{7f}\nforged: line";

#[test]
fn explain_prints_no_control_character_from_a_record() {
    let dir = std::env::temp_dir().join(format!("decern-explain-escapes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ledger_path = dir.join("ledger.jsonl");

    let entry = Entry {
        ts_ms: 1,
        subject_type: HOSTILE.into(),
        subject_id: HOSTILE.into(),
        action: HOSTILE.into(),
        resource_type: HOSTILE.into(),
        resource_id: HOSTILE.into(),
        decision: true,
        reasons: vec![HOSTILE.into()],
        digests: [(HOSTILE.to_owned(), HOSTILE.to_owned())].into(),
        asserted_by: Some(AssertedBy {
            sub: HOSTILE.into(),
            client_id: HOSTILE.into(),
            iss: Some(HOSTILE.into()),
        }),
        sponsor: Some(Party {
            kind: HOSTILE.into(),
            id: HOSTILE.into(),
        }),
        mission: Some(MissionRef {
            approver: HOSTILE.into(),
            s256: HOSTILE.into(),
        }),
        decision_subject: Some(DecisionSubject {
            handle: HOSTILE.into(),
            scheme: Some(HOSTILE.into()),
            purpose: Some(HOSTILE.into()),
        }),
        ..Default::default()
    };
    let key = generate().unwrap();
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let mut ledger = Ledger::open(&ledger_path, key).unwrap();
    ledger.append(entry).unwrap();
    drop(ledger);

    let out = Command::new(env!("CARGO_BIN_EXE_decern"))
        .args(["explain", "--seq", "0", "--ledger"])
        .arg(&ledger_path)
        .args(["--pubkey", &pubkey])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let stray: Vec<char> = text
        .chars()
        .filter(|c| c.is_control() && *c != '\n')
        .collect();
    assert!(stray.is_empty(), "control characters printed: {stray:?}");
    // A newline inside a value would let a record forge a line of this output.
    assert!(
        !text.lines().any(|line| line.starts_with("forged: line")),
        "a value broke out of its line:\n{text}"
    );
    // The value is still there to read, escaped.
    assert!(text.contains("\\u{1b}[2J"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}
