// SPDX-License-Identifier: Apache-2.0
//! Fuzz the AuthZEN evaluation request shape: the JSON an attacker sends to
//! `POST /access/v1/evaluation`. Every path must resolve to a result or a
//! refusal, never a panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    if !v.is_object() {
        return;
    }
    let obj = v.as_object().unwrap();
    let subject = obj.get("subject");
    let action = obj.get("action");
    let resource = obj.get("resource");
    let context = obj.get("context");

    if let (Some(s), Some(a), Some(r)) = (subject, action, resource) {
        let _ = extract_entity_ref(s);
        let _ = extract_entity_ref(r);
        let _ = a.get("name").and_then(Value::as_str);
        if let Some(c) = context {
            let _ = c.is_object();
            if let Some(obj) = c.as_object() {
                let _ = obj.get("now");
                let _ = obj.get("mission");
                let _ = obj.get("human_approved");
                let _ = obj.get("consent");
                let _ = obj.get("decision_subject");
            }
        }
    }
});

fn extract_entity_ref(v: &Value) -> Option<(&str, &str)> {
    let obj = v.as_object()?;
    let ty = obj.get("type")?.as_str()?;
    let id = obj.get("id")?.as_str()?;
    Some((ty, id))
}
