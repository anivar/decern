// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! RFC 8785 JSON Canonicalization Scheme (JCS) + `parameter_digest`.
//!
//! `parameter_digest` binds an authorization decision to the EXACT parameters it was
//! made over — SHA-256 over the RFC 8785 canonical form of those parameters.
//! Recording it in a decision [`crate::Entry`] closes the TOCTOU gap between
//! "authorized" and "executed" (bind permits to concrete params): the anchored
//! record proves WHICH arguments were authorized, so a later execution against
//! different arguments is detectably off-record. Two callers that canonicalize the
//! same JSON — regardless of key order
//! or incidental whitespace — get byte-identical output and thus the same digest.
//!
//! Faithfulness: object keys are sorted by UTF-16 code unit (§3.2.3), array order is
//! preserved, no insignificant whitespace is emitted, and scalar/number/string
//! escaping is delegated to `serde_json`'s RFC 8259 writer (minimal escapes,
//! lowercase `\uXXXX` for other control chars, non-ASCII emitted as-is, shortest-
//! round-trip numbers). The only deviation from strict RFC 8785 is exotic float
//! *exponent notation* (serde_json/ryu vs ECMAScript `Number::toString`), which
//! cannot arise for the integer/decimal parameters MCP tool calls carry; NaN and
//! Infinity are not representable in JSON at all.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Serialize `v` into its RFC 8785 canonical form: deterministic and independent of
/// input key order or whitespace.
pub fn canonicalize(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

/// SHA-256 (lowercase hex) over the canonical form of `v` — how every entry in
/// [`crate::Entry::digests`] is computed, whatever is being pinned.
pub fn digest(v: &Value) -> String {
    hex::encode(Sha256::digest(canonicalize(v).as_bytes()))
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            // §3.2.3: property names sorted as arrays of UTF-16 code units.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                // A key is a JSON string; escape it exactly like a string scalar.
                out.push_str(&serde_json::to_string(k).expect("string key serializes"));
                out.push(':');
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        // Scalars: serde_json emits RFC 8259 minimal escaping (lowercase `\u` for
        // other controls, non-ASCII as-is) and shortest-round-trip numbers, no
        // whitespace — exactly the JCS scalar rules.
        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null => {
            out.push_str(&serde_json::to_string(v).expect("scalar serializes"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_change_the_canonical_form() {
        let a = json!({"b": 1, "a": 2, "c": 3});
        let b = json!({"c": 3, "a": 2, "b": 1});
        assert_eq!(canonicalize(&a), r#"{"a":2,"b":1,"c":3}"#);
        assert_eq!(canonicalize(&a), canonicalize(&b));
        assert_eq!(digest(&a), digest(&b));
    }

    #[test]
    fn different_values_yield_different_digests() {
        assert_ne!(
            digest(&json!({"amount": 100})),
            digest(&json!({"amount": 101})),
        );
        // Type-sensitive: the string "100" is not the number 100.
        assert_ne!(
            digest(&json!({"amount": 100})),
            digest(&json!({"amount": "100"})),
        );
    }

    #[test]
    fn nested_objects_are_sorted_but_array_order_is_preserved() {
        // Objects inside arrays get their keys sorted; the array itself keeps order.
        let v = json!([{"b": 1, "a": 2}, {"d": 4, "c": 3}]);
        assert_eq!(canonicalize(&v), r#"[{"a":2,"b":1},{"c":3,"d":4}]"#);
        assert_ne!(digest(&json!([1, 2, 3])), digest(&json!([3, 2, 1])),);
    }

    #[test]
    fn keys_are_ordered_by_utf16_code_unit_not_utf8_bytes() {
        // U+10000 is UTF-16 surrogate pair D800 DC00; U+FFFF is FFFF. So U+10000
        // sorts BEFORE U+FFFF in UTF-16 — the OPPOSITE of code-point/UTF-8 order.
        // This proves we follow §3.2.3, not a naive byte sort.
        let v = json!({"\u{FFFF}": 1, "\u{10000}": 2});
        let c = canonicalize(&v);
        let sup = c.find('\u{10000}').unwrap();
        let bmp = c.find('\u{FFFF}').unwrap();
        assert!(
            sup < bmp,
            "U+10000 must sort before U+FFFF (UTF-16 order): {c}"
        );
    }

    #[test]
    fn strings_are_escaped_and_round_trip_to_the_same_value() {
        // Quote and backslash must be escaped; the canonical form is still valid
        // JSON that parses back to the original value.
        let v = json!({"k": "a\"b\\c\n\u{0001}"});
        let c = canonicalize(&v);
        assert!(c.contains("\\\""), "quote escaped: {c}");
        assert!(c.contains("\\\\"), "backslash escaped: {c}");
        assert!(c.contains("\\u0001"), "control char is lowercase \\u: {c}");
        assert_eq!(serde_json::from_str::<Value>(&c).unwrap(), v);
    }

    #[test]
    fn no_insignificant_whitespace() {
        let v = json!({"a": [1, {"x": true}], "b": null});
        assert_eq!(canonicalize(&v), r#"{"a":[1,{"x":true}],"b":null}"#);
    }
}
