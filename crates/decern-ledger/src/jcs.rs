// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! RFC 8785 JSON Canonicalization Scheme (JCS) + `digest`.
//!
//! `digest` binds a decision to the EXACT value it was taken against — SHA-256 over
//! the RFC 8785 canonical form of that value. Recording one under
//! [`crate::DIGEST_PARAMETERS`] in a decision [`crate::Entry`] closes the TOCTOU gap
//! between "authorized" and "executed": the anchored record proves WHICH arguments
//! were authorized, so a later execution against different arguments is detectably
//! off-record. Two callers that canonicalize the same JSON — whatever the key order,
//! whitespace, or spelling of a number — get byte-identical output, and so the same
//! digest, as does any other conformant JCS implementation.
//!
//! Faithfulness: object keys are sorted by UTF-16 code unit (§3.2.3), array order is
//! preserved, no insignificant whitespace is emitted, numbers are serialized as
//! ECMAScript prints them (§3.2.2.3, see `write_number`), and string escaping is
//! `serde_json`'s RFC 8259 writer — minimal escapes, lowercase `\uXXXX` for other
//! control chars, non-ASCII emitted as-is. NaN and Infinity, which §3.2.2.3 requires
//! an implementation to reject, are not representable in a [`Value`] to begin with.
//!
//! The one place this is wider than a double-based implementation: an integer outside
//! §3.2.2.3's interoperable range of ±(2^53−1) keeps every digit rather than rounding
//! to the nearest double. See `write_number` for why that direction is the safe one.

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
        Value::Number(n) => write_number(n, out),
        // The rest: serde_json emits RFC 8259 minimal escaping (lowercase `\u` for
        // other controls, non-ASCII as-is) and no whitespace — the JCS scalar rules.
        Value::String(_) | Value::Bool(_) | Value::Null => {
            out.push_str(&serde_json::to_string(v).expect("scalar serializes"));
        }
    }
}

/// §3.2.2.3: a JSON number is an IEEE-754 double, serialized by ECMAScript's
/// `Number::toString`. That is not what a shortest-round-trip float printer emits —
/// ECMAScript prints `3` where Rust prints `3.0`, and `100000000000000000000` where
/// Rust prints `1e20` — so a value canonicalized here and by any other JCS
/// implementation would otherwise hash differently.
fn write_number(n: &serde_json::Number, out: &mut String) {
    // An integer inside §3.2.2.3's interoperable range (±(2^53−1)) has the same form
    // under both readings, so it is emitted as written. Outside that range a double
    // cannot hold the value at all: rounding to one would let two distinct ids share
    // a digest, so the exact integer is kept and the divergence is a verifier's
    // inability to represent it, never a collision here.
    if !n.is_f64() {
        out.push_str(&n.to_string());
        return;
    }
    // `Value` cannot hold NaN or Infinity (`Number::from_f64` rejects both), so
    // §3.2.2.3's "terminate with an error" case is unreachable rather than handled.
    out.push_str(&ecmascript_number(
        n.as_f64().expect("is_f64 was just checked"),
    ));
}

/// ECMA-262 `Number::toString(x, 10)`, restricted to the finite doubles JSON can carry.
fn ecmascript_number(x: f64) -> String {
    if x == 0.0 {
        return "0".to_string(); // also -0.0, which ECMAScript prints unsigned
    }
    if x < 0.0 {
        return format!("-{}", ecmascript_number(-x));
    }
    // Shortest round-trip digits `s` (`k` of them) and `n` with x = s × 10^(n−k), via
    // ryu-js: Ryu adapted to ECMAScript's rules, which §3.2.2.3 defers to. The same
    // generator the maintained JCS crates use.
    let mut buf = ryu_js::Buffer::new();
    let printed = buf.format_finite(x);
    let (mantissa, exponent) = match printed.split_once('e') {
        Some((m, e)) => (m, e.parse::<i32>().expect("Ryu writes an integer exponent")),
        None => (printed, 0),
    };
    let (int_digits, frac_digits) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let written = format!("{int_digits}{frac_digits}");
    // Ryu pads integral values with a trailing zero ("3.0") and fractions with a
    // leading one ("0.5"); neither is significant, and `n` is measured from the first
    // significant digit.
    let leading = written.len() - written.trim_start_matches('0').len();
    let digits = written[leading..].trim_end_matches('0');
    let n = exponent + int_digits.len() as i32 - leading as i32;
    let k = digits.len() as i32;
    if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat(-n as usize))
    } else {
        let sign = if n > 0 { '+' } else { '-' };
        let magnitude = (n - 1).abs();
        if k == 1 {
            format!("{digits}e{sign}{magnitude}")
        } else {
            format!("{}.{}e{sign}{magnitude}", &digits[..1], &digits[1..])
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

    /// Every expectation here is `String(x)` in an ECMAScript engine, which is what
    /// §3.2.2.3 requires. A shortest-round-trip float printer disagrees on most of
    /// them (`3.0`, `1e20`, `1e-6`, `-0.0`), so this is the check that a value
    /// digested here matches one digested by any other JCS implementation.
    #[test]
    fn numbers_serialize_as_ecmascript_prints_them() {
        for (x, want) in [
            (3.0, "3"),
            (-3.0, "-3"),
            (0.0, "0"),
            (-0.0, "0"),
            (1.5, "1.5"),
            (0.1, "0.1"),
            (1e15, "1000000000000000"),
            (1e20, "100000000000000000000"),
            // 10^21 is where ECMAScript leaves fixed notation.
            (1e21, "1e+21"),
            (1e-6, "0.000001"),
            // ...and 10^-7 is where it leaves it going the other way.
            (1e-7, "1e-7"),
            (f64::MAX, "1.7976931348623157e+308"),
            (5e-324, "5e-324"),
        ] {
            assert_eq!(ecmascript_number(x), want, "for {x:?}");
            assert_eq!(canonicalize(&json!(x)), want, "canonicalized {x:?}");
        }
    }

    /// The whole point of canonicalizing: one value, one digest, however it was
    /// written. `3` and `3.0` are the same IEEE-754 double, so they must agree.
    #[test]
    fn integral_floats_and_integers_share_a_digest() {
        let written_as_integer: Value = serde_json::from_str(r#"{"qty":3}"#).unwrap();
        let written_as_float: Value = serde_json::from_str(r#"{"qty":3.0}"#).unwrap();
        let written_in_exponent: Value = serde_json::from_str(r#"{"qty":3e0}"#).unwrap();
        assert_eq!(canonicalize(&written_as_integer), r#"{"qty":3}"#);
        assert_eq!(digest(&written_as_integer), digest(&written_as_float));
        assert_eq!(digest(&written_as_integer), digest(&written_in_exponent));
    }

    /// An integer too large for a double keeps every digit. Rounding it to the
    /// nearest double would give two distinct ids one digest, which is the one
    /// failure a binding must not have.
    #[test]
    fn integers_beyond_the_interoperable_range_keep_their_digits() {
        let a: Value = serde_json::from_str(r#"{"id":9007199254740993}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"id":9007199254740992}"#).unwrap();
        assert_eq!(canonicalize(&a), r#"{"id":9007199254740993}"#);
        assert_ne!(digest(&a), digest(&b));
    }
}
