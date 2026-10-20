// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
use super::*;
use crate::tests::{entry, tmp};
use crate::verify::verify;
use std::fs::File;

/// A full disk can stop a write part-way, leaving part of a record in the file. Once
/// space returns, an append would land behind that fragment and the log would no longer
/// verify, so the ledger refuses every append until it is reopened, and the reopen
/// trims the fragment.
#[test]
fn a_failed_write_stops_appends_until_the_ledger_is_reopened() {
    use std::io::Write as _;
    let key = decern_crypto::generate().unwrap();
    let vk = key.verifying_key();
    let path = tmp("failed-write-stops.ledger");
    let _ = std::fs::remove_file(&path);
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    assert!(!l.has_failed());

    // The write fails after part of the record reached the file.
    let writable = std::mem::replace(&mut l.file, File::open(&path).unwrap());
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(br#"{"entry":{"seq":1,"#)
        .unwrap();
    assert!(l.append(entry("Read", true)).is_err());
    assert!(l.has_failed());

    // Space returns and the file is writable again; the ledger still refuses.
    l.file = writable;
    let err = l.append(entry("Read", true)).unwrap_err();
    assert!(
        err.to_string().contains("reopen it before appending"),
        "{err}"
    );
    drop(l);

    // Reopening trims the fragment; the ledger continues and verifies whole.
    let mut l = Ledger::open(&path, key.clone()).unwrap();
    l.append(entry("Read", true)).unwrap();
    drop(l);
    let report = verify(&path, Some(&vk)).unwrap();
    assert_eq!(report.entries, 2, "{report:?}");
    let _ = std::fs::remove_file(&path);
}
