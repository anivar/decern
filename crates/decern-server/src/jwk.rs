// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! A JSON Web Key (RFC 7517) that verifies an HTTP message signature or a token, held to the
//! Algorithm Determination rules of `draft-hardt-httpbis-signature-key-09` §3.3, which AAuth
//! `-11` §11.3.1 adopts: `alg` present and fully specified, `kty` and `crv` consistent with
//! it, no symmetric key and no polymorphic `EdDSA`. Ed25519 is the one algorithm implemented,
//! so every other `alg` is refused as unsupported.
//!
//! The rules bind the key a verifier selects and that key alone (§3.3), so a key set is
//! filtered to its usable members rather than refused for an unusable one; a member that does
//! not even parse as a JWK of this shape is skipped by the caller the same way. A JWK member
//! this type does not declare is ignored, as RFC 7517 §4 requires.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

/// The one fully-specified identifier this deployment verifies (RFC 9864 §2.2).
pub(crate) const ED25519: &str = "Ed25519";

#[derive(Deserialize)]
pub(crate) struct Jwk {
    #[serde(default)]
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    pub(crate) kid: Option<String>,
    #[serde(default, rename = "use")]
    pub(crate) use_: Option<String>,
}

impl Jwk {
    /// The Ed25519 key this JWK names, or why it names none this deployment can use. The
    /// algorithm is taken from `alg` and never from `kty`/`crv`, which must agree with it.
    pub(crate) fn ed25519(&self) -> Result<VerifyingKey, String> {
        if self.kty == "oct" {
            return Err("a symmetric key (kty oct) cannot verify a signature".into());
        }
        let alg = self
            .alg
            .as_deref()
            .ok_or("the key names no alg, and the algorithm is taken from it")?;
        if alg.starts_with("HS") {
            return Err(format!(
                "alg {} names a shared secret, not a public key",
                crate::caller::brief(alg)
            ));
        }
        if alg == "EdDSA" {
            return Err(format!(
                "alg EdDSA is polymorphic; this deployment verifies {ED25519}"
            ));
        }
        if alg != ED25519 {
            return Err(format!(
                "alg {} is not one this deployment verifies; {ED25519} only",
                crate::caller::brief(alg)
            ));
        }
        if self.kty != "OKP" || self.crv.as_deref() != Some("Ed25519") {
            return Err(format!(
                "alg {ED25519} needs kty OKP and crv Ed25519, and this key disagrees"
            ));
        }
        let x = self.x.as_deref().ok_or("the key carries no x")?;
        let bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|_| "the key's x is not base64url".to_owned())?
            .try_into()
            .map_err(|_| "the key's x is not 32 bytes".to_owned())?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| "the key's x is not a valid point".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn x() -> String {
        URL_SAFE_NO_PAD.encode(
            decern_crypto::SigningKey::from_bytes(&[5u8; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    fn jwk(v: serde_json::Value) -> Jwk {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn an_ed25519_key_that_names_its_algorithm_is_usable() {
        let k = jwk(
            json!({ "kty": "OKP", "crv": "Ed25519", "alg": "Ed25519", "x": x(),
                            "kid": "k1", "use": "sig", "ext": true }),
        );
        assert!(k.ed25519().is_ok());
        assert_eq!(k.kid.as_deref(), Some("k1"));
    }

    /// §3.3: `alg` is required, a polymorphic or symmetric one is refused, `kty`/`crv`
    /// must agree with it, and nothing but Ed25519 is implemented.
    #[test]
    fn a_key_the_rules_refuse_is_unusable() {
        for (v, why) in [
            (
                json!({ "kty": "OKP", "crv": "Ed25519", "x": x() }),
                "names no alg",
            ),
            (
                json!({ "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "x": x() }),
                "polymorphic",
            ),
            (
                json!({ "kty": "EC", "crv": "Ed25519", "alg": "Ed25519", "x": x() }),
                "disagrees",
            ),
            (
                json!({ "kty": "OKP", "crv": "X25519", "alg": "Ed25519", "x": x() }),
                "disagrees",
            ),
            (
                json!({ "kty": "OKP", "alg": "Ed25519", "x": x() }),
                "disagrees",
            ),
            (
                json!({ "kty": "oct", "alg": "HS256", "k": "AAAA" }),
                "symmetric",
            ),
            (
                json!({ "kty": "OKP", "crv": "Ed25519", "alg": "HS256", "x": x() }),
                "shared secret",
            ),
            (
                json!({ "kty": "EC", "crv": "P-256", "alg": "ES256", "x": "AA", "y": "AA" }),
                "Ed25519 only",
            ),
            (
                json!({ "kty": "OKP", "crv": "Ed25519", "alg": "Ed25519", "x": "AAAA" }),
                "32 bytes",
            ),
            (
                json!({ "kty": "OKP", "crv": "Ed25519", "alg": "Ed25519" }),
                "no x",
            ),
        ] {
            let e = jwk(v.clone()).ed25519().expect_err("should be unusable");
            assert!(e.contains(why), "{v}: {e}");
        }
    }
}
