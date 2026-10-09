// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! What a deployment says about itself at boot, checked at boot: the request entity
//! types it maps onto the model's, and the public URL it advertises. A flag that cannot
//! work is a startup failure here, never a per-request one.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use decern_kernel::Kernel;

/// `--authzen-type-alias REQUEST=MODEL`, both sides non-empty, no request type aliased
/// twice: two aliases for one spelling would leave the type a record carries to argument
/// order.
pub(crate) fn parse_type_aliases(pairs: &[String]) -> Result<BTreeMap<String, String>> {
    let mut aliases = std::collections::BTreeMap::new();
    for pair in pairs {
        let (request, model) = pair
            .split_once('=')
            .with_context(|| format!("--authzen-type-alias {pair:?}: expected REQUEST=MODEL"))?;
        let (request, model) = (request.trim(), model.trim());
        if request.is_empty() || model.is_empty() {
            anyhow::bail!(
                "--authzen-type-alias {pair:?}: both sides of REQUEST=MODEL are required"
            );
        }
        if aliases
            .insert(request.to_owned(), model.to_owned())
            .is_some()
        {
            anyhow::bail!("--authzen-type-alias: request type {request:?} is aliased twice");
        }
    }
    Ok(aliases)
}

/// Every alias must name an entity type the model declares: a request mapped onto a type
/// the kernel has never heard of would be refused on every decision, and a typo in a flag
/// is a boot-time fact, not a per-request one.
pub(crate) fn check_type_aliases(
    kernel: &Kernel,
    aliases: &BTreeMap<String, String>,
) -> Result<()> {
    let declared: BTreeSet<String> = kernel.entity_types().collect();
    for (request, model) in aliases {
        if declared.contains(request) {
            anyhow::bail!(
                "--authzen-type-alias {request}={model}: {request} is an entity type of the \
                 model, and the model's own types are not remapped"
            );
        }
        if !declared.contains(model) {
            anyhow::bail!(
                "--authzen-type-alias {request}={model}: {model} is not an entity type of the \
                 model (declared: {})",
                declared.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        }
    }
    Ok(())
}

/// `--public-url`: an origin — `https://host[:port]`, or `http://` on a loopback address
/// or `localhost` — with no userinfo, path, query or fragment; one trailing slash is
/// dropped and the scheme is lowercased. What is advertised as the policy decision point
/// is what a PEP will resolve, so anything else is refused at boot rather than published.
pub(crate) fn parse_public_url(url: &str) -> Result<String> {
    let url = url.trim();
    if url.contains('#') {
        anyhow::bail!("--public-url {url:?}: an origin only, with no fragment");
    }
    let uri: axum::http::Uri = url
        .parse()
        .with_context(|| format!("--public-url {url:?}: not a URL"))?;
    let scheme = uri
        .scheme_str()
        .map(str::to_ascii_lowercase)
        .with_context(|| format!("--public-url {url:?}: expected https://host[:port]"))?;
    let authority = uri
        .authority()
        .with_context(|| format!("--public-url {url:?}: no host"))?;
    if authority.as_str().contains('@') {
        anyhow::bail!("--public-url {url:?}: an origin only, with no userinfo");
    }
    let host = authority.host();
    let host_is_valid = match host.strip_prefix('[') {
        Some(literal) => literal
            .strip_suffix(']')
            .is_some_and(|ip| ip.parse::<std::net::Ipv6Addr>().is_ok()),
        None => {
            !host.is_empty()
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        }
    };
    if !host_is_valid {
        anyhow::bail!("--public-url {url:?}: {host:?} is not a host");
    }
    if authority.as_str().len() > host.len() && !authority.port_u16().is_some_and(|p| p != 0) {
        anyhow::bail!("--public-url {url:?}: the port is not a port");
    }
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        anyhow::bail!("--public-url {url:?}: an origin only, with no path or query");
    }
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match scheme.as_str() {
        "https" => {}
        "http" if loopback => {}
        "http" => anyhow::bail!(
            "--public-url {url:?}: http:// is accepted on loopback only; a published decision point is https://"
        ),
        other => anyhow::bail!("--public-url {url:?}: scheme {other:?} is not https"),
    }
    Ok(format!("{scheme}://{authority}"))
}

#[cfg(test)]
mod tests {
    use decern_kernel::{Kernel, Model};

    #[test]
    fn type_aliases_map_request_spellings_and_refuse_a_double_alias() {
        let aliases =
            super::parse_type_aliases(&["user=Principal".into(), " record = Resource ".into()])
                .unwrap();
        assert_eq!(aliases.get("user").map(String::as_str), Some("Principal"));
        assert_eq!(aliases.get("record").map(String::as_str), Some("Resource"));
        for bad in ["user", "user=", "=Principal", " = "] {
            assert!(
                super::parse_type_aliases(&[bad.to_owned()]).is_err(),
                "{bad:?} must be refused"
            );
        }
        assert!(
            super::parse_type_aliases(&["user=Principal".into(), "user=Agent".into()]).is_err(),
            "a request type aliased twice must be refused"
        );
    }

    #[test]
    fn a_type_with_no_alias_passes_through_unchanged() {
        let base = crate::testutil::mission_base();
        let (mut st, _pk) = crate::testutil::mission_state_at(&base);
        st.type_aliases = std::sync::Arc::new(std::collections::BTreeMap::from([(
            "user".to_owned(),
            "Principal".to_owned(),
        )]));
        assert_eq!(st.model_type("user"), "Principal");
        assert_eq!(st.model_type("Resource"), "Resource");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn an_alias_must_name_an_entity_type_the_model_declares() {
        let kernel = Kernel::new(&Model::builtin()).unwrap();
        let good = std::collections::BTreeMap::from([("user".to_owned(), "Principal".to_owned())]);
        assert!(super::check_type_aliases(&kernel, &good).is_ok());
        let typo = std::collections::BTreeMap::from([("user".to_owned(), "Prinicpal".to_owned())]);
        let err = super::check_type_aliases(&kernel, &typo)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Prinicpal") && err.contains("Principal"),
            "{err}"
        );
        // The model's own types are not remapped: `Principal=Resource` would make every
        // request about a principal a request about a resource.
        let remap =
            std::collections::BTreeMap::from([("Principal".to_owned(), "Resource".to_owned())]);
        assert!(super::check_type_aliases(&kernel, &remap).is_err());
    }

    #[test]
    fn a_public_url_is_an_origin_https_or_loopback_http() {
        for (given, kept) in [
            ("https://pdp.example", "https://pdp.example"),
            ("https://pdp.example:8443/", "https://pdp.example:8443"),
            ("HTTPS://pdp.example", "https://pdp.example"),
            ("http://localhost:8080", "http://localhost:8080"),
            ("http://127.0.0.1:8080/", "http://127.0.0.1:8080"),
            ("http://127.0.0.2:8080", "http://127.0.0.2:8080"),
            ("http://[::1]:8080", "http://[::1]:8080"),
        ] {
            assert_eq!(super::parse_public_url(given).unwrap(), kept, "{given}");
        }
        for bad in [
            "pdp.example",                  // no scheme
            "http://pdp.example",           // http off loopback
            "http://localhost.pdp.example", // a host that merely starts with localhost
            "http://10.0.0.1",              // not loopback
            "ftp://pdp.example",            // not https
            "https://pdp.example/pdp",      // a path
            "https://pdp.example//",        // a second slash is a path
            "https://pdp.example?x=1",      // a query
            "https://pdp.example#frag",     // a fragment
            "https://user@pdp.example",     // userinfo
            "https://",                     // no host
            "https://:8443",                // no host
            "https://pdp.example:abc",      // a port that is not one
            "https://pdp.example:0",        // nor is zero
            "https://pdp.example:",         // nor nothing
            "https://pdp.example:8443:1",   // nor two
            "https://pdp example",          // a space
            "https://pdp.example\\evil",    // a backslash
            "http://[::1",                  // unterminated literal
            "https://[::1]x",               // a literal followed by something else
            "https://[not-an-ip]",          // brackets around something that is not IPv6
        ] {
            assert!(
                super::parse_public_url(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }
}
