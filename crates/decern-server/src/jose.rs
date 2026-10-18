// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Decoding shared by every reader of a compact JWS here: the caller postures and the
//! standing token. Each reader words its own refusal and carries its own error type, so
//! these return the reason as text and the caller wraps it.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::Value;

/// A JWS segment decoded as JSON: base64url without padding (RFC 7515 §2), then strict
/// JSON — trailing characters after the value are refused (§10.12). A duplicated member
/// name resolves to the lexically last into a map and is refused into a derived struct;
/// §4 permits either. The reason names `what` — "`what` is not base64url" or "`what` is
/// not JSON".
pub(crate) fn decode_json<T: for<'de> Deserialize<'de>>(
    part: &str,
    what: &str,
) -> Result<T, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| format!("{what} is not base64url"))?;
    serde_json::from_slice(&bytes).map_err(|_| format!("{what} is not JSON"))
}

/// Refuse a header that names `crit`. RFC 7515 §4.1.11: the extensions it lists MUST be
/// understood and processed, and a JWS naming one the recipient does not understand is
/// invalid. A reader calling this implements none, so any `crit` is refused; §4.1.11 also
/// lets a recipient refuse a list naming a parameter RFC 7515 itself defines. Header
/// parameters that are not critical stay ignored, as §4 requires.
pub(crate) fn refuse_crit(header: &BTreeMap<String, Value>, what: &str) -> Result<(), String> {
    if header.contains_key("crit") {
        return Err(format!(
            "{what} names a critical header extension this server does not implement"
        ));
    }
    Ok(())
}

/// A claim that must be a number when present (RFC 7519 §2 NumericDate, which JSON permits
/// to be fractional, so it is read as `f64`). Absent is `None`; present and not a number is
/// refused rather than read as absent. The reason reads "`what` `name` is not a number".
pub(crate) fn numeric_date(
    claims: &BTreeMap<String, Value>,
    name: &str,
    what: &str,
) -> Result<Option<f64>, String> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => v
            .as_f64()
            .map(Some)
            .ok_or_else(|| format!("{what} {name} is not a number")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Every reader's refusal text is built from these, so the wording is pinned here.
    #[test]
    fn a_segment_that_is_not_base64url_or_not_json_is_refused_by_name() {
        let e = decode_json::<Value>("not base64url!", "token header").unwrap_err();
        assert_eq!(e, "token header is not base64url");
        let e = decode_json::<Value>(&URL_SAFE_NO_PAD.encode("{"), "token claims").unwrap_err();
        assert_eq!(e, "token claims is not JSON");
        // §2: padding is omitted, so a padded segment is not base64url here.
        let padded = base64::engine::general_purpose::URL_SAFE.encode("{}");
        assert!(padded.ends_with('='));
        assert!(decode_json::<Value>(&padded, "token header").is_err());
        // §10.12: a valid object followed by more characters is not a valid JWS.
        let trailing = URL_SAFE_NO_PAD.encode(r#"{"tag":"value"}ABCD"#);
        assert_eq!(
            decode_json::<Value>(&trailing, "token header").unwrap_err(),
            "token header is not JSON"
        );
    }

    /// §4: a parser rejects a duplicated name or keeps the lexically last. Into a map it
    /// keeps the last; into a derived struct it rejects.
    #[test]
    fn a_duplicated_member_name_keeps_the_last_in_a_map_and_fails_a_struct() {
        let dup = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","alg":"EdDSA"}"#);
        let map: BTreeMap<String, Value> = decode_json(&dup, "token header").unwrap();
        assert_eq!(map["alg"], "EdDSA");

        #[derive(Deserialize)]
        struct Header {
            #[serde(default)]
            #[allow(dead_code)]
            alg: Option<String>,
        }
        assert!(decode_json::<Header>(&dup, "token header").is_err());
    }

    #[test]
    fn any_crit_is_refused_and_other_parameters_are_not_looked_at() {
        let named: BTreeMap<String, Value> =
            serde_json::from_value(json!({ "alg": "EdDSA", "crit": ["exp"], "exp": 1 })).unwrap();
        assert_eq!(
            refuse_crit(&named, "standing_token"),
            Err(
                "standing_token names a critical header extension this server does not implement"
                    .to_owned()
            )
        );
        let open: BTreeMap<String, Value> =
            serde_json::from_value(json!({ "alg": "EdDSA", "x-anything": true })).unwrap();
        assert_eq!(refuse_crit(&open, "standing_token"), Ok(()));
    }

    #[test]
    fn a_numeric_date_is_absent_a_number_or_refused() {
        let claims: BTreeMap<String, Value> = serde_json::from_value(json!({
            "exp": 1_700_000_000.5,
            "nbf": "soon",
        }))
        .unwrap();
        assert_eq!(numeric_date(&claims, "iat", "token"), Ok(None));
        assert_eq!(
            numeric_date(&claims, "exp", "token"),
            Ok(Some(1_700_000_000.5))
        );
        assert_eq!(
            numeric_date(&claims, "nbf", "agent token"),
            Err("agent token nbf is not a number".to_owned())
        );
    }
}
