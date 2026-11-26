// SPDX-License-Identifier: Apache-2.0
//! Fuzz the authority graph parser: attacker-controlled JSON entities must
//! parse and validate without panicking, and a Kernel that loads must decide
//! without panicking.
#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(entities) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    if !entities.is_array() {
        return;
    }

    let dir = match decern_kernel::graph::Directory::parse(&entities) {
        Ok(d) => d,
        Err(_) => return,
    };
    let _ = dir.validate();

    for id in dir.principals.keys() {
        let _ = dir.ancestors_of(id);
        let _ = dir.revoked(id);
        let _ = dir.descendants_of(id);
    }
});
