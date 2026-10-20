// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The command line `decern-serve` takes, the default ledger and Mission registry paths, and the
//! caller posture the flags establish.

use crate::aauth;
use crate::bearer;
use crate::caller;
use crate::sig;
use crate::spiffe;
use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    group(clap::ArgGroup::new("posture").required(false).multiple(false)),
    name = "decern-serve",
    version,
    about = "Thin proven-decision PDP with a tamper-evident ledger"
)]
pub(crate) struct Args {
    /// Model directory; omit for the built-in model.
    #[arg(long, value_name = "DIR")]
    pub(crate) model: Option<PathBuf>,
    /// A request entity type and the model entity type it names, as `REQUEST=MODEL`
    /// (`user=Principal`). Repeatable. AuthZEN lets a PEP spell types in its own terms;
    /// the record carries the model's. A type with no alias passes through unchanged.
    #[arg(long = "authzen-type-alias", value_name = "REQUEST=MODEL")]
    pub(crate) authzen_type_alias: Vec<String>,
    /// This deployment's public base URL, advertised as the policy decision point by
    /// `GET /.well-known/authzen-configuration` (AuthZEN 1.0 metadata). `https://`, or
    /// `http://` on loopback for a local walkthrough; no path, query or fragment. Omit
    /// and the document is not served.
    #[arg(long = "public-url", value_name = "URL")]
    pub(crate) public_url: Option<String>,
    /// Single-file ledger path (default backend). Mutually exclusive with `--sharded`.
    #[arg(long, value_name = "PATH", conflicts_with = "sharded")]
    pub(crate) ledger: Option<PathBuf>,
    /// Hosted mode. Target is either a directory (per-shard `flock` head store —
    /// several `decern-serve` processes on ONE host share one tamper-evident
    /// ledger) or a `postgres://` URL (multi-HOST head store, requires building
    /// with `--features postgres`). Mutually exclusive with `--ledger`.
    #[arg(long, value_name = "DIR_OR_POSTGRES_URL")]
    pub(crate) sharded: Option<String>,
    /// 32-byte hex signing seed file; created if absent. Omit for an ephemeral key.
    #[arg(long, value_name = "PATH")]
    pub(crate) key: Option<PathBuf>,
    /// Mission registry file — the durable record of approved Missions the mint path
    /// checks (`decern-identity`). Default: `decern-missions.json` alongside the ledger.
    #[arg(long, value_name = "PATH")]
    pub(crate) missions: Option<PathBuf>,
    /// Require every decision to name a live Mission in `context.mission`.
    /// When set, client-supplied `human_approved` and `consent` are stripped (or the
    /// decision is Denied). `human_approved` is then re-derived from the verified
    /// grant, for MoveMoney. `consent` is NOT re-derived and never has been since a
    /// Mission stopped standing in for it: a Mission is an approver's grant, and
    /// consent is a claim about the resource owner. So this flag makes on-behalf-of
    /// PII access fail closed rather than server-derived — there is no server-side
    /// consent signal today. MoveMoney requires a Mission unconditionally regardless
    /// of this flag; this opt-in extends the same requirement to Read and AccessPII.
    #[arg(long)]
    pub(crate) require_mission: bool,
    /// Hex Ed25519 public key of an issuer whose standing tokens this deployment
    /// accepts. Repeatable. Omit to accept no challenges. Keys are configured rather
    /// than fetched: a decision must not depend on a third party being reachable, and
    /// this binary carries no outbound TLS stack.
    #[arg(long = "standing-issuer-key", value_name = "HEX")]
    pub(crate) standing_issuer_keys: Vec<String>,
    /// The `iss` an access token must carry, matched exactly (RFC 9068 §4). Given with
    /// `--bearer-audience` and at least one `--bearer-issuer-key`, this turns on bearer
    /// validation for the decision and mission-mutation endpoints.
    #[arg(long, value_name = "URL", group = "posture", requires_all = ["bearer_audience", "bearer_issuer_keys"])]
    bearer_issuer: Option<String>,
    /// This deployment's resource identifier, which a token's `aud` must contain
    /// (RFC 8707 §2). Without it a token minted for any other service the same issuer
    /// serves would be accepted here.
    #[arg(long, value_name = "URI", requires = "bearer_issuer")]
    bearer_audience: Option<String>,
    /// Hex Ed25519 public key an access token may be signed by. Repeatable, so a key
    /// rollover is two configured keys rather than a window with none. Configured and
    /// not fetched, for the reason given on `--standing-issuer-key`.
    #[arg(
        long = "bearer-issuer-key",
        value_name = "HEX",
        requires = "bearer_issuer"
    )]
    bearer_issuer_keys: Vec<String>,
    /// A scope every access token must carry in its `scope` claim. Repeatable; all are
    /// required, and a verified token missing one is refused with 403
    /// `insufficient_scope`. Omit to accept a valid token whatever it is scoped for.
    #[arg(
        long = "bearer-scope",
        value_name = "SCOPE",
        requires = "bearer_issuer"
    )]
    bearer_scopes: Vec<String>,
    /// An agent identifier this deployment recognizes and the one Ed25519 key it may
    /// sign requests with, as `ID=HEX`. Repeatable: one entry per agent, and a key
    /// rollover is a second entry for the same ID rather than an atomic swap. Turns on
    /// RFC 9421 signed-request validation (see `docs/CLI.md` "Sender-constrained caller
    /// authentication") for the decision and mission-mutation endpoints. An identifier
    /// with no entry here cannot authenticate under this mode, by design: keys are
    /// configured, never fetched.
    #[arg(
        long = "signed-agent-key",
        value_name = "ID=HEX",
        group = "posture",
        requires = "signed_audience"
    )]
    signed_agent_keys: Vec<String>,
    /// This deployment's resource identifier, which a signed request's bound token's
    /// `aud` must contain. Required with `--signed-agent-key`, same role as
    /// `--bearer-audience`.
    #[arg(long, value_name = "URI")]
    signed_audience: Option<String>,
    /// An agent identifier that may name principals other than itself. Repeatable. Workload
    /// postures only (`--signed-agent-key`, `--spiffe-trust-domain`, `--aauth-provider`): a
    /// gateway that proves possession of a key on every request, or presents an SVID or an
    /// agent token, is still a PEP. An identifier that cannot authenticate cannot be a PEP
    /// either. Omit to bind every workload caller to itself.
    #[arg(long = "pep", value_name = "ID")]
    pep: Vec<String>,
    /// A SPIFFE trust domain this deployment accepts, and the JWK Set holding its
    /// JWT-SVID signing keys, as `TRUST_DOMAIN=PATH`. Repeatable: one entry per federated
    /// domain. The file is read once at startup and refused there if it carries no
    /// `use: jwt-svid` key, an entry without a `kid`, or a key this deployment cannot
    /// verify with — a bundle problem should surface on boot, not when a caller arrives.
    /// Keys are configured, never fetched. Turns on JWT-SVID validation (see `docs/CLI.md`
    /// "SPIFFE JWT-SVID validation") for the decision and mission-mutation endpoints.
    #[arg(
        long = "spiffe-trust-domain",
        value_name = "TRUST_DOMAIN=PATH",
        group = "posture",
        requires = "spiffe_audience"
    )]
    spiffe_trust_domains: Vec<String>,
    /// This deployment's resource identifier, which an SVID's `aud` must contain. Required
    /// with `--spiffe-trust-domain`, same role as `--bearer-audience`.
    #[arg(long, value_name = "URI")]
    spiffe_audience: Option<String>,
    /// An AAuth agent provider this deployment accepts, and the JWK Set holding the keys it
    /// signs agent tokens with, as `ISS=PATH`. Repeatable: one entry per provider. The file
    /// is read once at startup and refused there if it carries no usable Ed25519 signing key
    /// or an entry without a `kid`. Keys are configured, never fetched: the draft's `dwk`
    /// discovery is deliberately not performed, so an agent whose provider is not named here
    /// is refused before any cryptography runs. Turns on AAuth agent-token validation for the
    /// decision and mission-mutation endpoints.
    #[arg(
        long = "aauth-provider",
        value_name = "ISS=PATH",
        group = "posture",
        requires = "aauth_audience"
    )]
    aauth_providers: Vec<String>,
    /// This deployment's authority, which a request's authority must equal. Required with
    /// `--aauth-provider`, and not optional: an agent token carries no `aud`, so without this
    /// a request signed for one deployment would verify at another that pins the same
    /// provider.
    #[arg(long, value_name = "AUTHORITY")]
    aauth_audience: Option<String>,
    /// Accept every caller, because something in front has already authenticated them.
    /// One posture is required to start, this or `--bearer-issuer`, `--signed-agent-key`,
    /// `--spiffe-trust-domain` or `--aauth-provider`: "no token configured"
    /// and "authentication deliberately delegated" are indistinguishable from inside this
    /// process and mean very different things outside it.
    #[arg(long, group = "posture")]
    trust_proxy: bool,
    /// Address to bind. Default loopback.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:8080")]
    pub(crate) addr: String,
}

/// The default single-file ledger path when neither `--ledger` nor `--sharded`
/// is given. Applied at the use site (not as a clap `default_value`) so that a
/// present-but-default `--ledger` cannot slip past the `--sharded` conflict.
pub(crate) const DEFAULT_LEDGER: &str = "decern-ledger.jsonl";

/// The mission-registry filename used when `--missions` is not given.
const DEFAULT_MISSIONS_FILE: &str = "decern-missions.json";

/// Whether a `--sharded` target names a Postgres head store rather than a directory.
pub(crate) fn is_postgres_target(target: &str) -> bool {
    target.starts_with("postgres://") || target.starts_with("postgresql://")
}

/// The default mission-registry path: alongside the ledger it accompanies.
///
/// The rule is explicit so a `postgres://` sharded target is never `Path::join`ed as
/// if it were a directory (a URL is not a path):
///   - `--ledger <file>` given → sibling of that file.
///   - `--sharded <dir>` (a directory target) → `<dir>/decern-missions.json`.
///   - default single-file ledger, or a `--sharded postgres://…` target → the
///     filename in the current directory (alongside the default ledger).
pub(crate) fn default_missions_path(ledger: Option<&PathBuf>, sharded: Option<&String>) -> PathBuf {
    if let Some(l) = ledger {
        return l
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.join(DEFAULT_MISSIONS_FILE))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_MISSIONS_FILE));
    }
    if let Some(target) = sharded {
        let is_pg = is_postgres_target(target);
        if !is_pg {
            return Path::new(target).join(DEFAULT_MISSIONS_FILE);
        }
    }
    PathBuf::from(DEFAULT_MISSIONS_FILE)
}

/// How the caller of the deciding routes is established, from the flags. Refusing to start
/// with no answer is the point: a server that cannot say who is asking should say so in its
/// configuration, not in an audit. There is no bind-address carve-out — loopback is not a
/// trust boundary on a shared host or inside a container's network namespace, and nothing
/// here checks peer credentials.
pub(crate) fn caller_from(args: &Args) -> Result<caller::Caller> {
    // clap's `posture` group refuses two postures at parse time. Counted here as well, so a
    // future edit to that attribute degrades to this error rather than the first posture below
    // quietly winning.
    let named = [
        args.bearer_issuer.is_some(),
        !args.signed_agent_keys.is_empty(),
        !args.spiffe_trust_domains.is_empty(),
        !args.aauth_providers.is_empty(),
        args.trust_proxy,
    ];
    if named.iter().filter(|n| **n).count() > 1 {
        anyhow::bail!(
            "--bearer-issuer, --signed-agent-key, --spiffe-trust-domain, --aauth-provider and \
             --trust-proxy each establish the caller; name one"
        );
    }
    if !args.pep.is_empty()
        && args.signed_agent_keys.is_empty()
        && args.spiffe_trust_domains.is_empty()
        && args.aauth_providers.is_empty()
    {
        anyhow::bail!(
            "--pep names a caller exempt from the self-only bind, which only the workload \
             postures apply: pass --signed-agent-key, --spiffe-trust-domain or --aauth-provider, \
             or drop --pep. \
             Bearer and --trust-proxy already authenticate a PEP that may name other parties"
        );
    }
    if !args.signed_agent_keys.is_empty() {
        let mut agents = std::collections::BTreeMap::new();
        for entry in &args.signed_agent_keys {
            let (id, hex_key) = split_entry("--signed-agent-key", entry, "ID=HEX")?;
            if id.is_empty() {
                anyhow::bail!("--signed-agent-key {entry} names an empty agent id");
            }
            agents.insert(
                id.to_owned(),
                parse_issuer_key(hex_key, "--signed-agent-key")?,
            );
        }
        // clap's `requires` establishes this; the check stays for the same reason the
        // bearer path's does — a future edit to the clap attribute should degrade to
        // this error, not an unconfigured guard.
        let Some(audience) = args.signed_audience.clone() else {
            anyhow::bail!("--signed-agent-key requires --signed-audience");
        };
        let pep = pep_set(&args.pep, "agent id", |id| {
            if !agents.contains_key(id) {
                anyhow::bail!(
                    "--pep {id} is not in --signed-agent-key; a PEP must be able to authenticate"
                );
            }
            Ok(())
        })?;
        let mut cfg = sig::SigConfig::new(agents, audience);
        cfg.pep = pep;
        return Ok(caller::Caller::Signed(Box::new(cfg)));
    }
    if !args.spiffe_trust_domains.is_empty() {
        let mut trust_domains = std::collections::BTreeMap::new();
        for entry in &args.spiffe_trust_domains {
            let (domain, path) = split_entry("--spiffe-trust-domain", entry, "TRUST_DOMAIN=PATH")?;
            if domain.is_empty() {
                anyhow::bail!("--spiffe-trust-domain {entry} names an empty trust domain");
            }
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading the trust bundle for {domain} at {path}"))?;
            // Refused here rather than at request time: an operator should learn a bundle
            // is unusable when the process starts, not when the first caller arrives.
            let keys = spiffe::load_bundle(&raw)
                .map_err(|e| anyhow::anyhow!("trust bundle for {domain} at {path}: {e}"))?;
            if trust_domains.insert(domain.to_owned(), keys).is_some() {
                anyhow::bail!("--spiffe-trust-domain names {domain} more than once");
            }
        }
        let Some(audience) = args.spiffe_audience.clone() else {
            anyhow::bail!("--spiffe-trust-domain requires --spiffe-audience");
        };
        // A PEP still has to authenticate, so it must name a trust domain this deployment
        // accepts. Unlike the signed posture there is no per-agent list to check against —
        // an SVID's identity is minted by its issuer — so the check is on the domain.
        let pep = pep_set(&args.pep, "workload id", |id| {
            let domain = id
                .strip_prefix("spiffe://")
                .and_then(|r| r.split_once('/'))
                .map(|(d, _)| d)
                .ok_or_else(|| {
                    anyhow::anyhow!("--pep {id} is not a SPIFFE ID under this posture")
                })?;
            if !trust_domains.contains_key(domain) {
                anyhow::bail!(
                    "--pep {id} is in no configured trust domain; a PEP must be able to authenticate"
                );
            }
            Ok(())
        })?;
        return Ok(caller::Caller::Spiffe(Box::new(spiffe::SpiffeConfig {
            trust_domains,
            audience,
            pep,
        })));
    }
    if !args.aauth_providers.is_empty() {
        let mut providers = std::collections::BTreeMap::new();
        for entry in &args.aauth_providers {
            let (iss, path) = split_entry("--aauth-provider", entry, "ISS=PATH")?;
            // The draft requires a provider identifier to be a valid HTTPS URL. Checked at
            // startup so a malformed one fails the boot rather than every request.
            if !aauth::valid_provider_url(iss) {
                anyhow::bail!("--aauth-provider {iss} is not an https:// agent provider URL");
            }
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading the key set for {iss} at {path}"))?;
            let keys = aauth::load_provider_keys(&raw)
                .map_err(|e| anyhow::anyhow!("key set for {iss} at {path}: {e}"))?;
            if providers.insert(iss.to_owned(), keys).is_some() {
                anyhow::bail!("--aauth-provider names {iss} more than once");
            }
        }
        let Some(authority) = args.aauth_audience.clone() else {
            anyhow::bail!("--aauth-provider requires --aauth-audience");
        };
        // A PEP must be able to authenticate, and an agent identity is minted by its
        // provider, so there is no per-agent list to check against — only that the operator
        // named something non-empty.
        let pep = pep_set(&args.pep, "agent id", |_| Ok(()))?;
        return Ok(caller::Caller::Aauth(Box::new(aauth::AauthConfig {
            providers,
            authority,
            pep,
        })));
    }
    let Some(issuer) = args.bearer_issuer.clone() else {
        if args.trust_proxy {
            return Ok(caller::Caller::TrustedProxy);
        }
        anyhow::bail!(
            "refusing to serve the decision and mission-mutation endpoints with no way to \
             establish the caller: pass --bearer-issuer/--bearer-audience/--bearer-issuer-key \
             to validate access tokens here, --signed-agent-key/--signed-audience for signed \
             requests, --spiffe-trust-domain/--spiffe-audience for SPIFFE JWT-SVIDs, \
             --aauth-provider/--aauth-audience for AAuth agent tokens, or --trust-proxy to \
             state that something in front already authenticates them (see docs/CLI.md \"The \
             trust boundary\")"
        );
    };
    // A key that cannot be read is a startup failure, never a token that quietly fails to
    // verify later.
    let mut keys = Vec::new();
    for hex_key in &args.bearer_issuer_keys {
        keys.push(parse_issuer_key(hex_key, "--bearer-issuer-key")?);
    }
    // clap's `requires_all` establishes these; the checks stay so a future edit to the
    // clap attributes degrades to this error instead of an unconfigured guard.
    let Some(audience) = args.bearer_audience.clone() else {
        anyhow::bail!("--bearer-issuer requires --bearer-audience");
    };
    if keys.is_empty() {
        anyhow::bail!("--bearer-issuer requires at least one --bearer-issuer-key");
    }
    Ok(caller::Caller::Bearer(Box::new(bearer::Config {
        issuer,
        audience,
        keys,
        scopes: args.bearer_scopes.clone(),
    })))
}

/// One repeatable `NAME=VALUE` entry, refused with the flag and the shape it takes when it has
/// no `=`.
fn split_entry<'a>(flag: &str, entry: &'a str, shape: &str) -> Result<(&'a str, &'a str)> {
    entry
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("{flag} {entry} is not {shape}"))
}

/// The `--pep` ids under a workload posture: none empty, each passing the posture's own check.
fn pep_set(
    ids: &[String],
    noun: &str,
    mut check: impl FnMut(&str) -> Result<()>,
) -> Result<std::collections::BTreeSet<String>> {
    let mut pep = std::collections::BTreeSet::new();
    for id in ids {
        if id.is_empty() {
            anyhow::bail!("--pep names an empty {noun}");
        }
        check(id)?;
        pep.insert(id.clone());
    }
    Ok(pep)
}

/// A configured Ed25519 public key, read at boot. `flag` names the option in the error, because
/// this is the operator's first encounter with a key they have just pasted and the useful thing
/// to say is which one.
pub(crate) fn parse_issuer_key(hex_key: &str, flag: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(hex_key.trim())
        .with_context(|| format!("decoding {flag} {hex_key}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{flag} must be 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).with_context(|| format!("invalid Ed25519 key for {flag}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller;
    use clap::Parser;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    /// docs/CLI.md's `decern-serve` option table is a claim about this binary — one that
    /// has drifted before: flags shipped that the table never gained, and rows outlived
    /// the flags they described. Diffed by name, so drift is a red build.
    #[test]
    fn the_serve_table_matches_the_binary() {
        use clap::CommandFactory;
        let doc = include_str!("../../../docs/CLI.md");
        let heading = "## `decern-serve`";
        let start = doc
            .find(heading)
            .expect("decern-serve section in docs/CLI.md");
        let section = &doc[start + heading.len()..];
        let section = &section[..section.find("\n## ").unwrap_or(section.len())];
        let mut documented: Vec<String> = section
            .lines()
            .filter_map(|l| l.strip_prefix("| `--"))
            .map(|rest| {
                let name: String = rest
                    .chars()
                    .take_while(|c| *c != ' ' && *c != '`')
                    .collect();
                format!("--{name}")
            })
            .collect();
        let mut real: Vec<String> = Args::command()
            .get_arguments()
            .filter(|a| !matches!(a.get_id().as_str(), "help" | "version"))
            .filter_map(|a| a.get_long().map(|l| format!("--{l}")))
            .collect();
        documented.sort();
        real.sort();
        assert_eq!(
            documented, real,
            "the decern-serve table and the binary disagree — fix whichever is wrong"
        );
    }

    /// The startup rule: a server that cannot say how its callers are established does not
    /// start. There is no bind-address carve-out to test, because there is no carve-out.
    #[test]
    fn with_no_posture_named_the_server_refuses_to_start() {
        let args = Args::parse_from(["decern-serve"]);
        let Err(e) = caller_from(&args) else {
            panic!("a server with no way to establish the caller must not start");
        };
        // The refusal is where an operator learns the options, so it names every posture.
        for flag in [
            "--bearer-issuer",
            "--signed-agent-key",
            "--spiffe-trust-domain",
            "--aauth-provider",
            "--trust-proxy",
        ] {
            assert!(e.to_string().contains(flag), "{flag} missing from: {e}");
        }
    }

    #[test]
    fn trust_proxy_names_the_delegated_posture() {
        let args = Args::parse_from(["decern-serve", "--trust-proxy"]);
        assert!(matches!(
            caller_from(&args).unwrap(),
            caller::Caller::TrustedProxy
        ));
    }

    #[test]
    fn the_bearer_flags_configure_the_guard() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let hex_key = hex::encode(key.verifying_key().to_bytes());
        let args = Args::parse_from([
            "decern-serve",
            "--bearer-issuer",
            "https://issuer.example/",
            "--bearer-audience",
            "https://pdp.example/",
            "--bearer-issuer-key",
            &hex_key,
            "--bearer-scope",
            "decern.decide",
        ]);
        let caller::Caller::Bearer(cfg) = caller_from(&args).unwrap() else {
            panic!("bearer flags must configure the bearer guard");
        };
        assert_eq!(cfg.issuer, "https://issuer.example/");
        assert_eq!(cfg.audience, "https://pdp.example/");
        assert_eq!(cfg.keys.len(), 1);
        assert_eq!(cfg.scopes, vec!["decern.decide".to_owned()]);
    }

    #[test]
    fn the_signed_agent_key_flags_configure_the_guard() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let hex_key = hex::encode(key.verifying_key().to_bytes());
        let args = Args::parse_from([
            "decern-serve",
            "--signed-agent-key",
            &format!("agent-1={hex_key}"),
            "--signed-audience",
            "https://pdp.example/access/v1/evaluation",
        ]);
        let caller::Caller::Signed(cfg) = caller_from(&args).unwrap() else {
            panic!("--signed-agent-key must configure the signed guard");
        };
        assert_eq!(cfg.audience, "https://pdp.example/access/v1/evaluation");
        assert_eq!(cfg.agents.len(), 1);
        assert!(cfg.agents.contains_key("agent-1"));
        assert!(cfg.pep.is_empty());
    }

    #[test]
    fn pep_names_must_already_be_signed_agents() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let hex_key = hex::encode(key.verifying_key().to_bytes());
        let args = Args::parse_from([
            "decern-serve",
            "--signed-agent-key",
            &format!("agent-1={hex_key}"),
            "--signed-audience",
            "https://pdp.example/access/v1/evaluation",
            "--pep",
            "corp",
        ]);
        assert!(caller_from(&args).is_err());
    }

    #[test]
    fn pep_marks_a_configured_agent_as_a_gateway() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let hex_key = hex::encode(key.verifying_key().to_bytes());
        let args = Args::parse_from([
            "decern-serve",
            "--signed-agent-key",
            &format!("agent-1={hex_key}"),
            "--signed-audience",
            "https://pdp.example/access/v1/evaluation",
            "--pep",
            "agent-1",
        ]);
        let caller::Caller::Signed(cfg) = caller_from(&args).unwrap() else {
            panic!("--pep must configure the signed guard");
        };
        assert!(cfg.pep.contains("agent-1"));
    }

    /// `--pep` exempts a caller from the self-only bind, so a posture that has no such
    /// bind has nothing to exempt. Refused at startup rather than ignored: a
    /// security-relevant flag that silently does nothing is worse than one that is
    /// refused. Not a clap `requires`, because it must accept either workload posture.
    #[test]
    fn pep_without_a_workload_posture_is_a_startup_failure() {
        for argv in [
            vec!["decern-serve", "--pep", "agent-1", "--trust-proxy"],
            vec![
                "decern-serve",
                "--pep",
                "agent-1",
                "--bearer-issuer",
                "https://issuer.example/",
                "--bearer-audience",
                "https://pdp.example/",
                "--bearer-issuer-key",
                &"11",
            ],
        ] {
            let Ok(args) = Args::try_parse_from(&argv) else {
                continue; // clap refused it first, which is also fine
            };
            match caller_from(&args) {
                Ok(_) => panic!("{argv:?} accepted --pep for a posture with no self-only bind"),
                Err(e) => assert!(e.to_string().contains("--pep"), "{argv:?}: {e}"),
            }
        }
    }

    /// `requires = "signed_audience"` on the clap arg makes this a parse-time failure,
    /// not a `caller_from` one — checked here so the enforcement point can't quietly move.
    #[test]
    fn signed_agent_key_without_signed_audience_is_a_startup_failure() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let hex_key = hex::encode(key.verifying_key().to_bytes());
        assert!(
            Args::try_parse_from([
                "decern-serve",
                "--signed-agent-key",
                &format!("agent-1={hex_key}"),
            ])
            .is_err()
        );
    }

    #[test]
    fn a_malformed_signed_agent_key_entry_is_a_startup_failure() {
        let args = Args::parse_from([
            "decern-serve",
            "--signed-agent-key",
            "agent-1-with-no-equals-sign",
            "--signed-audience",
            "https://pdp.example/access/v1/evaluation",
        ]);
        assert!(caller_from(&args).is_err());
    }

    /// A trust bundle is read and validated at startup, so a deployment learns its bundle
    /// is unusable when the process starts rather than when the first caller arrives.
    #[test]
    fn the_spiffe_flags_load_a_bundle_and_configure_the_guard() {
        let dir = std::env::temp_dir().join(format!("decern-spiffe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bundle.json");
        // A real P-256 point, so the loader's validation is exercised rather than bypassed.
        let mut scalar = [0u8; 32];
        scalar[31] = 7;
        let sk = p256::ecdsa::SigningKey::from_bytes(&scalar.into()).unwrap();
        let pt = sk.verifying_key().to_sec1_point(false);
        let b64 = |b: &[u8]| {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
        };
        std::fs::write(
            &path,
            json!({"keys":[{"kty":"EC","crv":"P-256","kid":"k1","use":"jwt-svid",
                            "x": b64(pt.x().unwrap()), "y": b64(pt.y().unwrap())}]})
            .to_string(),
        )
        .unwrap();

        let args = Args::parse_from([
            "decern-serve",
            "--spiffe-trust-domain",
            &format!("example.org={}", path.display()),
            "--spiffe-audience",
            "https://pdp.example/",
        ]);
        let caller::Caller::Spiffe(cfg) = caller_from(&args).unwrap() else {
            panic!("--spiffe-trust-domain must configure the spiffe guard");
        };
        assert_eq!(cfg.audience, "https://pdp.example/");
        assert!(cfg.trust_domains.contains_key("example.org"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_spiffe_trust_domain_entry_is_a_startup_failure() {
        let args = Args::parse_from([
            "decern-serve",
            "--spiffe-trust-domain",
            "no-equals-sign",
            "--spiffe-audience",
            "https://pdp.example/",
        ]);
        assert!(caller_from(&args).is_err());
    }

    #[test]
    fn a_missing_spiffe_bundle_file_is_a_startup_failure() {
        let args = Args::parse_from([
            "decern-serve",
            "--spiffe-trust-domain",
            "example.org=/nonexistent/bundle.json",
            "--spiffe-audience",
            "https://pdp.example/",
        ]);
        assert!(caller_from(&args).is_err());
    }

    /// Five postures, one ArgGroup: naming two is a parse-time conflict, so the binary cannot
    /// start holding an ambiguous answer to "how is the caller established". Each posture is
    /// given whole, so the refusal can only come from the group, never from a missing audience.
    #[test]
    fn two_postures_at_once_is_a_startup_failure() {
        let key = "11".repeat(32);
        let signed = format!("a={key}");
        let postures: [Vec<&str>; 5] = [
            vec!["--trust-proxy"],
            vec![
                "--signed-agent-key",
                &signed,
                "--signed-audience",
                "https://pdp.example",
            ],
            vec![
                "--spiffe-trust-domain",
                "e=x",
                "--spiffe-audience",
                "https://pdp.example",
            ],
            vec![
                "--aauth-provider",
                "https://p.example=x",
                "--aauth-audience",
                "pdp.example",
            ],
            vec![
                "--bearer-issuer",
                "https://iss.example",
                "--bearer-audience",
                "https://pdp.example",
                "--bearer-issuer-key",
                &key,
            ],
        ];
        for one in &postures {
            let mut argv = vec!["decern-serve"];
            argv.extend(one.iter().copied());
            assert!(
                Args::try_parse_from(&argv).is_ok(),
                "{argv:?} alone was refused"
            );
        }
        for (i, a) in postures.iter().enumerate() {
            for b in &postures[i + 1..] {
                let mut argv = vec!["decern-serve"];
                argv.extend(a.iter().copied());
                argv.extend(b.iter().copied());
                let Err(e) = Args::try_parse_from(&argv) else {
                    panic!("{argv:?} named two postures and was accepted");
                };
                assert_eq!(
                    e.kind(),
                    clap::error::ErrorKind::ArgumentConflict,
                    "{argv:?}: {e}"
                );
            }
        }
    }

    /// The same rule without clap: any two postures reaching `caller_from` are refused, not
    /// resolved by whichever it checks first. Each pair is set on the parsed flags directly, so
    /// this holds even if the clap group is loosened.
    #[test]
    fn caller_from_refuses_two_postures_on_its_own() {
        let set: [fn(&mut Args); 5] = [
            |a| a.bearer_issuer = Some("https://iss.example".into()),
            |a| a.signed_agent_keys = vec![format!("a={}", "11".repeat(32))],
            |a| a.spiffe_trust_domains = vec!["e=x".into()],
            |a| a.aauth_providers = vec!["https://p.example=x".into()],
            |a| a.trust_proxy = true,
        ];
        for i in 0..set.len() {
            for j in i + 1..set.len() {
                let mut args = Args::parse_from(["decern-serve"]);
                set[i](&mut args);
                set[j](&mut args);
                let Err(e) = caller_from(&args) else {
                    panic!("postures {i} and {j} reached caller_from and one was chosen");
                };
                assert!(
                    e.to_string().contains("each establish the caller"),
                    "{i},{j}: {e}"
                );
            }
        }
    }

    #[test]
    fn a_malformed_bearer_issuer_key_is_a_startup_failure() {
        let args = Args::parse_from([
            "decern-serve",
            "--bearer-issuer",
            "https://issuer.example/",
            "--bearer-audience",
            "https://pdp.example/",
            "--bearer-issuer-key",
            "not-hex",
        ]);
        assert!(caller_from(&args).is_err());
    }
}
