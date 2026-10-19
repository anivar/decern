// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! RFC 9421 HTTP Message Signatures: the verifier's half, for one signature on a request.
//!
//! The signature headers are parsed as structured fields with `sfv`, not by hand. RFC 9421
//! §7.5.3 gives the reason: a parser that let a quoted component name run past its closing
//! quote would let the sender write into the signature base. RFC 9421 references RFC 8941,
//! so RFC 9651 §2.4 keeps Dates and Display Strings out of these two fields, and the parser
//! is held to that version.
//!
//! This module owns what the RFC fixes: how the fields parse, how each covered component's
//! value is derived (§2.1, §2.2), and how the signature base is assembled (§2.5), with
//! `@signature-params` serialized from the parsed input as §3.2 step 7 requires rather than
//! copied from the bytes received. It also holds the one profile rule both signature
//! postures share, which signature parameters are accepted. Each posture owns the rest of
//! its profile (§1.4): the label, the components it requires, how fresh `created` must be,
//! and the key that verifies.

use axum::http::{HeaderMap, Uri};
use sfv::{BareItem, Dictionary, FieldType, ListEntry, Parser, Version};

use crate::caller::Denied;

/// The derived components this verifier computes for a request: the ones either profile
/// requires. `@target-uri` and `@scheme` need the scheme, which a server behind a
/// TLS-terminating front does not see as the client sent it; `@query`, `@query-param` and
/// `@request-target` are not implemented because no profile here covers them; `@status`
/// belongs to responses (RFC 9421 §2.2.9).
const DERIVED: [&str; 3] = ["@method", "@authority", "@path"];

/// The value of every line named `name`, each trimmed and joined with `", "` (RFC 9421
/// §2.1). The structured fields are parsed from the same combination (RFC 9651 §4.2), so a
/// second line is read rather than left behind the first. `None` when no line is present.
pub(crate) fn field(headers: &HeaderMap, name: &str) -> Result<Option<String>, Denied> {
    let mut values = Vec::new();
    for line in headers.get_all(name) {
        let value = line
            .to_str()
            .map_err(|_| Denied::Invalid(format!("{name} is not visible ASCII")))?;
        values.push(value.trim());
    }
    Ok((!values.is_empty()).then(|| values.join(", ")))
}

/// The request's `@authority` (RFC 9421 §2.2.3): host and optional port, the host
/// lowercased. Taken from the target URI when the request line carries one, an absolute-form
/// target, and from the single `Host` line otherwise. Missing, repeated or malformed, there
/// is no authority to sign, which §2.5 step 2.5 makes an error rather than an empty value.
/// A default port is kept: dropping it needs the scheme, which a server behind a
/// TLS-terminating front does not see.
pub(crate) fn authority(uri: &Uri, headers: &HeaderMap) -> Result<String, Denied> {
    let parsed = match uri.authority() {
        Some(a) => a.clone(),
        None => {
            let mut lines = headers.get_all("host").iter();
            let (Some(host), None) = (lines.next(), lines.next()) else {
                return Err(Denied::Invalid(
                    "request must carry exactly one Host".into(),
                ));
            };
            host.as_bytes()
                .try_into()
                .map_err(|_| Denied::Invalid("Host is not an authority".into()))?
        }
    };
    let host = parsed.host().to_ascii_lowercase();
    Ok(match parsed.port() {
        Some(port) => format!("{host}:{}", port.as_str()),
        None => host,
    })
}

/// One signature as the request presents it, before any key is consulted.
#[derive(Debug)]
pub(crate) struct Presented {
    /// The covered components, in the order they were signed.
    pub(crate) components: Vec<String>,
    pub(crate) created: i64,
    /// `@signature-params` as RFC 9421 §2.3 serializes it.
    params: String,
    pub(crate) signature: Vec<u8>,
}

/// The one signature labelled `label`, from `Signature-Input` and `Signature`.
///
/// RFC 9421 §3.2 step 1 lets a verifier choose among several signatures. This one does not
/// choose, so a second signature, or one under another label, is refused rather than passed
/// over. A parameter other than `created` and `keyid` is refused as well: §2.3 lets a signer
/// attach any, and accepting one nothing here enforces would let it claim a property —
/// `nonce`, `expires`, `tag` — that was never checked. `keyid` is shape-checked only; keys
/// are chosen by the posture, never by the signer.
pub(crate) fn presented(label: &str, input: &str, signature: &str) -> Result<Presented, Denied> {
    let inputs = dictionary(input, "Signature-Input")?;
    let signatures = dictionary(signature, "Signature")?;
    for (what, d) in [("Signature-Input", &inputs), ("Signature", &signatures)] {
        if d.len() != 1 || !d.contains_key(label) {
            return Err(Denied::Invalid(format!(
                "{what} must carry exactly one signature, labelled {label}"
            )));
        }
    }

    let Some(ListEntry::InnerList(list)) = inputs.get(label) else {
        return Err(Denied::Invalid(
            "Signature-Input member is not an inner list".into(),
        ));
    };
    let mut components: Vec<String> = Vec::with_capacity(list.items.len());
    for item in &list.items {
        let BareItem::String(name) = &item.bare_item else {
            return Err(Denied::Invalid(
                "a covered component is not a string".into(),
            ));
        };
        let name = name.as_str();
        // §2.5 step 2.5: a parameter the verifier does not understand is an error, and
        // this verifier implements none of `sf`, `key`, `bs`, `req`, `tr` or `name`.
        if !item.params.is_empty() {
            return Err(Denied::Invalid(format!(
                "covered component {} carries a parameter this verifier does not implement",
                crate::caller::printable(name)
            )));
        }
        if !valid_component_name(name) {
            return Err(Denied::Invalid(format!(
                "{} is not a component this verifier can derive",
                crate::caller::printable(name)
            )));
        }
        // §2.5 step 2.1.
        if components.iter().any(|c| c == name) {
            return Err(Denied::Invalid(format!(
                "covered component {} is listed twice",
                crate::caller::printable(name)
            )));
        }
        components.push(name.to_owned());
    }

    let mut created = None;
    for (key, value) in &list.params {
        match (key.as_str(), value) {
            ("created", BareItem::Integer(i)) => created = Some(i64::from(*i)),
            ("created", _) => {
                return Err(Denied::Invalid(
                    "Signature-Input created is not an integer".into(),
                ));
            }
            ("keyid", BareItem::String(_)) => {}
            ("keyid", _) => {
                return Err(Denied::Invalid(
                    "Signature-Input keyid is not a string".into(),
                ));
            }
            (other, _) => {
                return Err(Denied::Invalid(format!(
                    "Signature-Input names an unsupported parameter {other}"
                )));
            }
        }
    }
    let created =
        created.ok_or_else(|| Denied::Invalid("Signature-Input carries no created".into()))?;
    let params = vec![ListEntry::InnerList(list.clone())]
        .serialize()
        .ok_or_else(|| Denied::Invalid("Signature-Input does not serialize".into()))?;

    let Some(ListEntry::Item(item)) = signatures.get(label) else {
        return Err(Denied::Invalid("Signature member is not an item".into()));
    };
    let BareItem::ByteSequence(bytes) = &item.bare_item else {
        return Err(Denied::Invalid("Signature is not a byte sequence".into()));
    };
    // RFC 9421 §4.2 defines no parameter on a signature value, so one is refused for the
    // reason an unrecognised `Signature-Input` parameter is.
    if !item.params.is_empty() {
        return Err(Denied::Invalid("Signature carries a parameter".into()));
    }

    Ok(Presented {
        components,
        created,
        params,
        signature: bytes.clone(),
    })
}

impl Presented {
    /// The posture's covered-component profile, compared exactly: order included, since the
    /// order is what the signer committed to.
    pub(crate) fn covers_exactly(&self, required: &[&str]) -> Result<(), Denied> {
        if self
            .components
            .iter()
            .map(String::as_str)
            .ne(required.iter().copied())
        {
            return Err(Denied::Invalid(
                "Signature-Input does not cover exactly the required components".into(),
            ));
        }
        Ok(())
    }

    /// `created` no more than `behind` seconds old and no more than `ahead` seconds in
    /// the future.
    pub(crate) fn fresh(&self, now: i64, behind: i64, ahead: i64) -> Result<(), Denied> {
        let age = now.saturating_sub(self.created);
        if !(-ahead..=behind).contains(&age) {
            return Err(Denied::Invalid(
                "signature is outside the accepted freshness window".into(),
            ));
        }
        Ok(())
    }
}

/// What a covered component's value is drawn from. The posture builds it, so the posture
/// decides which request it is describing (RFC 9421 §7.4.3).
pub(crate) struct Message<'a> {
    /// As received: the method is case-sensitive and §2.2.1 transforms nothing.
    pub(crate) method: &'a str,
    /// From [`authority`].
    pub(crate) authority: &'a str,
    pub(crate) path: &'a str,
    /// The header fields a signature may cover, by lowercase name, each from [`field`].
    pub(crate) fields: &'a [(&'a str, &'a str)],
}

impl Message<'_> {
    fn value(&self, name: &str) -> Result<&str, Denied> {
        let value = match name {
            "@method" => self.method,
            "@authority" => self.authority,
            "@path" => self.path,
            // §7.5.1: a name starting with `@` is derived, never looked up as a field.
            n if n.starts_with('@') => {
                return Err(Denied::Invalid(format!(
                    "derived component {n} is not available here"
                )));
            }
            n => self
                .fields
                .iter()
                .find(|(field, _)| *field == n)
                .map(|(_, v)| *v)
                .ok_or_else(|| {
                    Denied::Invalid(format!("covered field {n} is not in the request"))
                })?,
        };
        // §2: no component value may carry a newline, and §2.5 step 4 refuses a non-ASCII
        // base. Header values cannot hold either, but the other inputs are not header values.
        if value.contains('\n') || !value.is_ascii() {
            return Err(Denied::Invalid(format!(
                "component {name} has a value that cannot be signed"
            )));
        }
        Ok(value)
    }
}

/// The RFC 9421 §2.5 signature base for `presented` over `msg`.
pub(crate) fn signature_base(msg: &Message<'_>, presented: &Presented) -> Result<String, Denied> {
    let mut base = String::new();
    for name in &presented.components {
        let value = msg.value(name)?;
        // Every accepted name is a known derived name or a lowercase token, so quoting it
        // needs no escaping.
        base.push('"');
        base.push_str(name);
        base.push_str("\": ");
        base.push_str(value);
        base.push('\n');
    }
    base.push_str("\"@signature-params\": ");
    base.push_str(&presented.params);
    Ok(base)
}

/// `raw` as a Dictionary whose keys, the signature labels, are all distinct. RFC 9651 §4.2.2
/// keeps the last of a repeated key; RFC 9421 §4 requires a label to be unique within the
/// message, so a repeat is refused before that rule could fold it away. The keys are read in
/// a first pass because the parsed Dictionary no longer shows the repeat.
fn dictionary(raw: &str, what: &str) -> Result<Dictionary, Denied> {
    let malformed = |_| Denied::Invalid(format!("{what} is not a structured-field dictionary"));
    let labels = Parser::new(raw)
        .with_version(Version::Rfc8941)
        .parse_dictionary_with_visitor(Labels(Vec::new()))
        .map_err(malformed)?;
    if let Some(repeat) = labels
        .iter()
        .enumerate()
        .find_map(|(i, l)| labels[..i].contains(l).then_some(l))
    {
        return Err(Denied::Invalid(format!(
            "{what} names the label {} more than once",
            crate::caller::printable(repeat)
        )));
    }
    Parser::new(raw)
        .with_version(Version::Rfc8941)
        .parse::<Dictionary>()
        .map_err(malformed)
}

/// Collects a Dictionary's keys in order, repeats included, and discards the values.
struct Labels(Vec<String>);

impl<'de> sfv::visitor::DictionaryVisitor<'de> for Labels {
    type Out = Vec<String>;
    type Error = std::convert::Infallible;

    fn entry(
        &mut self,
        key: &'de sfv::KeyRef,
    ) -> Result<impl sfv::visitor::EntryVisitor<'de>, Self::Error> {
        self.0.push(key.as_str().to_owned());
        Ok(sfv::visitor::Ignored)
    }

    fn finish(self) -> Result<Self::Out, Self::Error> {
        Ok(self.0)
    }
}

/// A derived component this verifier implements, or a lowercase field name (RFC 9421 §2.1:
/// component names for fields are the lowercased field name, a `tchar` token).
fn valid_component_name(name: &str) -> bool {
    if name.starts_with('@') {
        return DERIVED.contains(&name);
    }
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)
        })
}

/// `Signature-Input` and `Signature` values labelled `sig1` for a signature over `lines`,
/// with the base written out line by line rather than built by the code under test, so a
/// fixture and the verifier share no code.
#[cfg(test)]
pub(crate) fn sign_for_test(
    key: &decern_crypto::SigningKey,
    lines: &[(&str, &str)],
    created: i64,
) -> (String, String) {
    use base64::Engine as _;
    use decern_crypto::Signer as _;
    let components: Vec<String> = lines
        .iter()
        .map(|(name, _)| format!("\"{name}\""))
        .collect();
    let params = format!("({});created={created}", components.join(" "));
    let mut base: String = lines
        .iter()
        .map(|(name, value)| format!("\"{name}\": {value}\n"))
        .collect();
    base.push_str(&format!("\"@signature-params\": {params}"));
    let signature = key.sign(base.as_bytes());
    (
        format!("sig1={params}"),
        format!(
            "sig1=:{}:",
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signature, VerifyingKey};

    /// RFC 9421 Appendix B.1.4, `test-key-ed25519`.
    const TEST_KEY_ED25519_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";

    fn test_key() -> VerifyingKey {
        let x: [u8; 32] = URL_SAFE_NO_PAD
            .decode(TEST_KEY_ED25519_X)
            .unwrap()
            .try_into()
            .unwrap();
        VerifyingKey::from_bytes(&x).unwrap()
    }

    fn verifies(base: &str, presented: &Presented) -> bool {
        let sig = Signature::from_slice(&presented.signature).unwrap();
        test_key().verify_strict(base.as_bytes(), &sig).is_ok()
    }

    /// The RFC's own Ed25519 vector, B.2.6: the base this module builds from the test
    /// request must be the base the RFC's signature was made over.
    #[test]
    fn rfc_9421_b_2_6_verifies() {
        let input = r#"sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519""#;
        let signature = "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:";
        let p = presented("sig-b26", input, signature).unwrap();
        let fields = [
            ("date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("content-type", "application/json"),
            ("content-length", "18"),
        ];
        let msg = Message {
            method: "POST",
            authority: "example.com",
            path: "/foo",
            fields: &fields,
        };
        let base = signature_base(&msg, &p).unwrap();
        assert_eq!(
            base,
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\": POST\n\"@path\": /foo\n\
             \"@authority\": example.com\n\"content-type\": application/json\n\
             \"content-length\": 18\n\"@signature-params\": (\"date\" \"@method\" \"@path\" \
             \"@authority\" \"content-type\" \"content-length\");created=1618884473;\
             keyid=\"test-key-ed25519\""
        );
        assert!(verifies(&base, &p));
    }

    /// RFC 9421 B.4: two `Accept` lines are one component value, joined with `", "`, and
    /// the signature over that value verifies. Swapping the lines changes the value.
    #[test]
    fn rfc_9421_b_4_combines_field_lines() {
        let mut headers = HeaderMap::new();
        headers.append("accept", "application/json".parse().unwrap());
        headers.append("accept", "*/*".parse().unwrap());
        let accept = field(&headers, "accept").unwrap().unwrap();
        assert_eq!(accept, "application/json, */*");

        let input = r#"transform=("@method" "@path" "@authority" "accept");created=1618884473;keyid="test-key-ed25519""#;
        let signature = "transform=:ZT1kooQsEHpZ0I1IjCqtQppOmIqlJPeo7DHR3SoMn0s5JZ1eRGS0A+vyYP9t/LXlh5QMFFQ6cpLt2m0pmj3NDA==:";
        let p = presented("transform", input, signature).unwrap();
        let fields = [("accept", accept.as_str())];
        let msg = Message {
            method: "GET",
            authority: "example.org",
            path: "/demo",
            fields: &fields,
        };
        assert!(verifies(&signature_base(&msg, &p).unwrap(), &p));

        let mut swapped = HeaderMap::new();
        swapped.append("accept", "*/*".parse().unwrap());
        swapped.append("accept", "application/json".parse().unwrap());
        let accept = field(&swapped, "accept").unwrap().unwrap();
        let fields = [("accept", accept.as_str())];
        let msg = Message {
            fields: &fields,
            ..msg
        };
        assert!(!verifies(&signature_base(&msg, &p).unwrap(), &p));
    }

    /// RFC 9421 §3.2 step 7: `@signature-params` is the parsed input serialized again, so
    /// optional whitespace in the received field does not reach the base.
    #[test]
    fn signature_params_are_serialized_from_the_parsed_input() {
        let p = presented(
            "sig1",
            r#"sig1=(  "@method"   "@path" );created=1;  keyid="k""#,
            "sig1=:AAAA:",
        )
        .unwrap();
        assert_eq!(p.params, r#"("@method" "@path");created=1;keyid="k""#);
    }

    /// §2.2.1: the method is case-sensitive. A signature over `POST` is not a signature
    /// over `post`.
    #[test]
    fn the_method_is_taken_as_received() {
        let p = presented("sig1", r#"sig1=("@method");created=1"#, "sig1=:AAAA:").unwrap();
        let msg = Message {
            method: "post",
            authority: "a",
            path: "/",
            fields: &[],
        };
        assert_eq!(
            signature_base(&msg, &p).unwrap(),
            "\"@method\": post\n\"@signature-params\": (\"@method\");created=1"
        );
    }

    /// §7.5.3: a malformed structured field is refused outright. A quote left open must
    /// not swallow what follows into a component name.
    #[test]
    fn malformed_inputs_are_refused() {
        for input in [
            r#"sig1=("@method" "@path);created=1"#,
            r#"sig1=("@method");created=1.5"#,
            r#"sig1=("@method");created=@1"#,
            r#"sig1=(@method);created=1"#,
            "sig1=",
            "",
        ] {
            assert!(
                presented("sig1", input, "sig1=:AAAA:").is_err(),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn exactly_one_signature_under_the_profile_label() {
        let one = r#"sig1=("@method");created=1"#;
        assert!(presented("sig1", one, "sig1=:AAAA:").is_ok());
        assert!(presented("sig2", one, "sig2=:AAAA:").is_err());
        let two = r#"sig1=("@method");created=1, sig2=("@path");created=1"#;
        assert!(presented("sig1", two, "sig1=:AAAA:").is_err());
        assert!(presented("sig1", one, "sig1=:AAAA:, sig2=:AAAA:").is_err());
        // RFC 9421 §4: a label is unique in the message. RFC 9651 §4.2.2 alone would fold
        // the repeat into its last value and verify that, unseen by anything reading the first.
        let repeated = r#"sig1=("@path");created=1, sig1=("@method");created=2"#;
        assert!(presented("sig1", repeated, "sig1=:AAAA:").is_err());
        assert!(presented("sig1", one, "sig1=:AAAA:, sig1=:AAAA:").is_err());
    }

    #[test]
    fn only_created_and_keyid_are_accepted() {
        for param in ["alg=\"ed25519\"", "expires=2", "nonce=\"n\"", "tag=\"t\""] {
            let input = format!(r#"sig1=("@method");created=1;{param}"#);
            assert!(presented("sig1", &input, "sig1=:AAAA:").is_err(), "{param}");
        }
        // Shapes the old string matcher let through: a token `keyid`, a signed `created`, a
        // trailing `;`. RFC 8941 has none of them.
        for input in [
            r#"sig1=("@method")"#,
            r#"sig1=("@method");created=1;keyid=k"#,
            r#"sig1=("@method");created=+1"#,
            r#"sig1=("@method");created=1;"#,
        ] {
            assert!(presented("sig1", input, "sig1=:AAAA:").is_err(), "{input}");
        }
    }

    #[test]
    fn unsupported_component_names_are_refused() {
        for input in [
            r#"sig1=("@method";req);created=1"#,
            r#"sig1=("Content-Type");created=1"#,
            r#"sig1=("@target-uri");created=1"#,
            r#"sig1=("@method" "@method");created=1"#,
            r#"sig1=("a\"b");created=1"#,
        ] {
            assert!(
                presented("sig1", input, "sig1=:AAAA:").is_err(),
                "accepted {input:?}"
            );
        }
    }

    /// RFC 9651 §2.4: these fields are defined against RFC 8941, which has no Date or
    /// Display String, so a value of either type fails the parse rather than reaching a
    /// type check further on.
    #[test]
    fn the_fields_parse_as_rfc_8941() {
        assert!(dictionary(r#"sig1=("@method");created=1;x=@1"#, "Signature-Input").is_err());
        assert!(dictionary(r#"sig1=("@method");created=1;x=%"d""#, "Signature-Input").is_err());
        assert!(dictionary(r#"sig1=("@method");created=1;x=1"#, "Signature-Input").is_ok());
    }

    /// RFC 9421 §2 and §2.5 step 4: no value with a newline, and no non-ASCII byte, reaches
    /// the base. Header values cannot carry either; this holds for the other inputs too.
    #[test]
    fn a_value_that_cannot_be_signed_is_refused() {
        let p = presented("sig1", r#"sig1=("x-a");created=1"#, "sig1=:AAAA:").unwrap();
        for value in ["a\nb", "caf\u{e9}"] {
            let fields = [("x-a", value)];
            let msg = Message {
                method: "GET",
                authority: "a",
                path: "/",
                fields: &fields,
            };
            assert!(signature_base(&msg, &p).is_err(), "{value:?}");
        }
    }

    #[test]
    fn a_covered_field_must_be_present() {
        let p = presented(
            "sig1",
            r#"sig1=("content-digest");created=1"#,
            "sig1=:AAAA:",
        )
        .unwrap();
        let msg = Message {
            method: "POST",
            authority: "a",
            path: "/",
            fields: &[],
        };
        assert!(signature_base(&msg, &p).is_err());
    }

    #[test]
    fn the_target_authority_is_preferred_to_host() {
        let with_host = |values: &[&str]| {
            let mut headers = HeaderMap::new();
            for v in values {
                headers.append("host", v.parse().unwrap());
            }
            headers
        };
        let origin: Uri = "/p".parse().unwrap();
        let get = |uri: &Uri, hosts: &[&str]| authority(uri, &with_host(hosts));

        assert_eq!(get(&origin, &["Host.Example"]).unwrap(), "host.example");
        assert_eq!(
            get(&origin, &["pdp.example:8443"]).unwrap(),
            "pdp.example:8443"
        );
        let absolute: Uri = "https://Target.Example/p".parse().unwrap();
        assert_eq!(get(&absolute, &["host.example"]).unwrap(), "target.example");
        // §2.2.3: host and optional port, so userinfo in the target is not signed.
        let userinfo: Uri = "http://u@pdp.example/p".parse().unwrap();
        assert_eq!(get(&userinfo, &[]).unwrap(), "pdp.example");

        for hosts in [
            &[][..],
            &["a.example", "b.example"],
            &[""],
            &["a\t.example"],
        ] {
            assert!(get(&origin, hosts).is_err(), "{hosts:?}");
        }
    }

    #[test]
    fn freshness_is_bounded_both_ways() {
        let p = |created| Presented {
            components: vec![],
            created,
            params: String::new(),
            signature: vec![],
        };
        assert!(p(1000).fresh(1060, 60, 5).is_ok());
        assert!(p(1000).fresh(1061, 60, 5).is_err());
        assert!(p(1005).fresh(1000, 60, 5).is_ok());
        assert!(p(1006).fresh(1000, 60, 5).is_err());
        assert!(p(i64::MIN).fresh(i64::MAX, 60, 5).is_err());
    }

    #[test]
    fn the_signature_is_a_byte_sequence() {
        let input = r#"sig1=("@method");created=1"#;
        // RFC 9651 §4.2.7: a parser SHOULD NOT fail on missing `=` padding.
        let unpadded = STANDARD.encode([7u8; 64]).trim_end_matches('=').to_owned();
        assert_eq!(
            presented("sig1", input, &format!("sig1=:{unpadded}:"))
                .unwrap()
                .signature,
            vec![7u8; 64]
        );
        for sig in [
            "sig1=AAAA",
            "sig1=\"AAAA\"",
            "sig1=:AA$A:",
            "sig1=:AAAA:;x=1",
        ] {
            assert!(presented("sig1", input, sig).is_err(), "{sig}");
        }
        let p = presented(
            "sig1",
            input,
            &format!("sig1=:{}:", STANDARD.encode([7u8; 64])),
        )
        .unwrap();
        assert_eq!(p.signature, vec![7u8; 64]);
    }
}
