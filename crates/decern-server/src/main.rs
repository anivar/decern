// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! decern-serve — a thin PDP: every decision is proven-model-evaluated AND recorded before it is served.

mod audit;
mod bearer;
mod challenge;
mod decide;
mod mission;
mod record;
mod routes;
#[cfg(test)]
mod testutil;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use decern_kernel::{Kernel, Model};
use decern_ledger::{Ledger, ShardedLedger, UNATTRIBUTED_SHARD};
use decern_store::{FileLedgerHeadStore, FileMissionRegistry};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{Value, json};

use crate::record::reserved_tenant_collision;
use crate::routes::app;

#[derive(Parser)]
#[command(
    name = "decern-serve",
    version,
    about = "Thin proven-decision PDP with a tamper-evident ledger"
)]
struct Args {
    /// Model directory; omit for the built-in model.
    #[arg(long, value_name = "DIR")]
    model: Option<PathBuf>,
    /// Single-file ledger path (default backend). Mutually exclusive with `--sharded`.
    #[arg(long, value_name = "PATH", conflicts_with = "sharded")]
    ledger: Option<PathBuf>,
    /// Hosted mode. Target is either a directory (per-shard `flock` head store —
    /// several `decern-serve` processes on ONE host share one tamper-evident
    /// ledger) or a `postgres://` URL (multi-HOST head store, requires building
    /// with `--features postgres`). Mutually exclusive with `--ledger`.
    #[arg(long, value_name = "DIR_OR_POSTGRES_URL")]
    sharded: Option<String>,
    /// 32-byte hex signing seed file; created if absent. Omit for an ephemeral key.
    #[arg(long, value_name = "PATH")]
    key: Option<PathBuf>,
    /// Mission registry file — the durable record of approved Missions the mint path
    /// checks (`decern-identity`). Default: `decern-missions.json` alongside the ledger.
    #[arg(long, value_name = "PATH")]
    missions: Option<PathBuf>,
    /// Require every decision to name a live Mission in `context.mission`.
    /// When set, client-supplied `human_approved` / `consent` are ignored; those
    /// flags are derived server-side from the verified Mission (or the decision
    /// is Denied). Start opt-in; operators harden MoveMoney behind this flag.
    #[arg(long)]
    require_mission: bool,
    /// Hex Ed25519 public key of an issuer whose standing tokens this deployment
    /// accepts. Repeatable. Omit to accept no challenges. Keys are configured rather
    /// than fetched: a decision must not depend on a third party being reachable, and
    /// this binary carries no outbound TLS stack.
    #[arg(long = "standing-issuer-key", value_name = "HEX")]
    standing_issuer_keys: Vec<String>,
    /// The `iss` an access token must carry, matched exactly (RFC 9068 §4). Given with
    /// `--bearer-audience` and at least one `--bearer-issuer-key`, this turns on bearer
    /// validation for the decision and mission-mutation endpoints.
    #[arg(long, value_name = "URL", requires_all = ["bearer_audience", "bearer_issuer_keys"])]
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
    /// Accept every caller, because something in front has already authenticated them.
    /// One of this or the bearer flags is required to start: "no token configured" and
    /// "authentication deliberately delegated" are indistinguishable from inside this
    /// process and mean very different things outside it.
    #[arg(long, conflicts_with = "bearer_issuer")]
    trust_proxy: bool,
    /// Address to bind. Default loopback.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:8080")]
    addr: String,
}

/// The default single-file ledger path when neither `--ledger` nor `--sharded`
/// is given. Applied at the use site (not as a clap `default_value`) so that a
/// present-but-default `--ledger` cannot slip past the `--sharded` conflict.
const DEFAULT_LEDGER: &str = "decern-ledger.jsonl";

/// The mission-registry filename used when `--missions` is not given.
const DEFAULT_MISSIONS_FILE: &str = "decern-missions.json";

/// The default mission-registry path: alongside the ledger it accompanies.
///
/// The rule is explicit so a `postgres://` sharded target is never `Path::join`ed as
/// if it were a directory (a URL is not a path):
///   - `--ledger <file>` given → sibling of that file.
///   - `--sharded <dir>` (a directory target) → `<dir>/decern-missions.json`.
///   - default single-file ledger, or a `--sharded postgres://…` target → the
///     filename in the current directory (alongside the default ledger).
fn default_missions_path(ledger: Option<&PathBuf>, sharded: Option<&String>) -> PathBuf {
    if let Some(l) = ledger {
        return l
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.join(DEFAULT_MISSIONS_FILE))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_MISSIONS_FILE));
    }
    if let Some(target) = sharded {
        let is_pg = target.starts_with("postgres://") || target.starts_with("postgresql://");
        if !is_pg {
            return Path::new(target).join(DEFAULT_MISSIONS_FILE);
        }
    }
    PathBuf::from(DEFAULT_MISSIONS_FILE)
}

/// The recording backend. Both arms are fail-closed by construction: an
/// `append` that cannot durably commit returns `Err`, never a silent `Ok`, so
/// `record_and_respond` turns either failure into a 503 — a decision is never
/// served unrecorded regardless of backend.
pub(crate) enum LedgerBackend {
    /// Sovereign single-file ledger (default), serialized in-process.
    Single(Mutex<Ledger>),
    /// Hosted per-shard ledger over a `flock` head store, safe for several
    /// processes on one host to extend concurrently.
    Sharded(ShardedLedger),
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) kernel: Arc<Kernel>,
    /// The boot-pinned model. `mission::approve` reads the approver's authority from
    /// this SAME base model (not the live directory), so a Mission approval is bounded
    /// by exactly what a token minted under it would later be bounded by.
    model: Arc<Model>,
    pub(crate) backend: Arc<LedgerBackend>,
    /// The durable record of approved Missions. Held so a mission's termination
    /// outlives any single in-memory handle and is seen across processes.
    missions: Arc<FileMissionRegistry>,
    pub(crate) pubkey: VerifyingKey,
    /// When true, every decide must name a live `context.mission`.
    require_mission: bool,
    /// Issuer keys a standing token may be signed by. Empty means this deployment
    /// accepts no challenges, which is the default and is stated in its disclosure.
    standing_issuers: Arc<Vec<VerifyingKey>>,
    /// The authority every decision this process makes is taken against, digested once.
    /// The kernel is pinned at boot and exposes no way to mutate it, so this is a
    /// constant for the life of the process rather than something to recompute per
    /// request — and recomputing it per request would serialize the whole entity graph
    /// on the decision path.
    authority_digest: Arc<str>,
    /// How this deployment establishes callers, as the disclosure endpoint reports it —
    /// derived from the running configuration at boot, like everything else it says.
    caller_disclosure: Arc<Value>,
}

/// The `caller` object the subject-side disclosure reports: which posture, and under
/// `bearer` the audience a token must be bound to — public by construction, it is what
/// every client must already know to mint a usable token.
pub(crate) fn caller_disclosure(caller: &bearer::Caller) -> Value {
    match caller {
        bearer::Caller::Bearer(c) => json!({ "mode": "bearer", "audience": c.audience }),
        bearer::Caller::TrustedProxy => json!({ "mode": "trusted-proxy" }),
    }
}

fn load_signing_key(path: Option<&PathBuf>) -> Result<SigningKey> {
    let mut seed = [0u8; 32];
    match path {
        Some(p) if p.exists() => {
            let hex = std::fs::read_to_string(p)
                .with_context(|| format!("reading key {}", p.display()))?;
            seed = hex::decode(hex.trim())
                .context("decoding key hex")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
        }
        other => {
            getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("generating key: {e}"))?;
            if let Some(p) = other {
                std::fs::write(p, hex::encode(seed))
                    .with_context(|| format!("writing key {}", p.display()))?;
            }
        }
    }
    Ok(SigningKey::from_bytes(&seed))
}

/// The server's own wall clock in epoch seconds — the single time authority for every
/// decision. Never read from a request body (see `decide`).
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// How the caller of the deciding routes is established, from the flags. Refusing to start
/// with no answer is the point: a server that cannot say who is asking should say so in its
/// configuration, not in an audit. There is no bind-address carve-out — loopback is not a
/// trust boundary on a shared host or inside a container's network namespace, and nothing
/// here checks peer credentials.
fn caller_from(args: &Args) -> Result<bearer::Caller> {
    let Some(issuer) = args.bearer_issuer.clone() else {
        if args.trust_proxy {
            return Ok(bearer::Caller::TrustedProxy);
        }
        anyhow::bail!(
            "refusing to serve the decision and mission-mutation endpoints with no way to \
             establish the caller: pass --bearer-issuer/--bearer-audience/--bearer-issuer-key \
             to validate access tokens here, or --trust-proxy to state that something in front \
             already authenticates them (see docs/CLI.md \"The trust boundary\")"
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
    Ok(bearer::Caller::Bearer(Box::new(bearer::Config {
        issuer,
        audience,
        keys,
        scopes: args.bearer_scopes.clone(),
    })))
}

/// A configured Ed25519 public key, read at boot. `flag` names the option in the error, because
/// this is the operator's first encounter with a key they have just pasted and the useful thing
/// to say is which one.
fn parse_issuer_key(hex_key: &str, flag: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(hex_key.trim())
        .with_context(|| format!("decoding {flag} {hex_key}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{flag} must be 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).with_context(|| format!("invalid Ed25519 key for {flag}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    // First, before anything touches disk: a server that cannot say how its callers are
    // established refuses to start, and a refused boot should leave nothing behind.
    let caller = Arc::new(caller_from(&args)?);
    let caller_desc = match caller.as_ref() {
        bearer::Caller::Bearer(c) => format!("bearer for {}", c.audience),
        bearer::Caller::TrustedProxy => "caller trusted (--trust-proxy)".to_owned(),
    };
    let model = match &args.model {
        Some(d) => {
            Model::from_dir(d).with_context(|| format!("loading model from {}", d.display()))?
        }
        None => Model::builtin(),
    };
    let kernel = Kernel::new(&model)?;
    let key = load_signing_key(args.key.as_ref())?;
    let pubkey = key.verifying_key();

    // Resolve the mission-registry path while `args.ledger`/`args.sharded` are still
    // borrowable (the backend match below consumes `args.ledger`). The registry is
    // OPENED after the backend so a boot that bails does not create its file.
    let missions_path = args
        .missions
        .clone()
        .unwrap_or_else(|| default_missions_path(args.ledger.as_ref(), args.sharded.as_ref()));

    let (backend, backend_desc) = match &args.sharded {
        Some(target) => {
            // Fail closed at boot: a directory tenant equal to the reserved
            // unattributed-shard name would silently co-mingle with it.
            if let Some(who) = reserved_tenant_collision(kernel.directory()) {
                anyhow::bail!(
                    "refusing to serve sharded: {who} uses the reserved shard name {UNATTRIBUTED_SHARD:?}"
                );
            }
            let is_pg = target.starts_with("postgres://") || target.starts_with("postgresql://");
            // A postgres URL can carry a password — never echo it in the log line.
            let desc = if is_pg {
                "sharded (postgres head store)".to_string()
            } else {
                format!("sharded {target}")
            };
            let store: Arc<dyn decern_store::LedgerHeadStore> = if is_pg {
                #[cfg(feature = "postgres")]
                {
                    Arc::new(
                        decern_store_postgres::PostgresLedgerHeadStore::new(target)
                            .with_context(|| "connecting sharded postgres head store")?,
                    )
                }
                #[cfg(not(feature = "postgres"))]
                {
                    anyhow::bail!(
                        "a postgres:// sharded head store requires a build with `--features postgres`"
                    );
                }
            } else {
                Arc::new(
                    FileLedgerHeadStore::new(target)
                        .with_context(|| format!("opening sharded head store at {target}"))?,
                )
            };
            let sharded = ShardedLedger::new(store, key, vec![]);
            (LedgerBackend::Sharded(sharded), desc)
        }
        None => {
            let path = args.ledger.unwrap_or_else(|| PathBuf::from(DEFAULT_LEDGER));
            let mut ledger = Ledger::open(&path, key)?;
            // Durable by default in the server: an append the PEP acks (and acts
            // on) must survive a crash — `sync_data` before `append` returns.
            ledger.set_sync(true);
            let desc = format!("ledger {}", path.display());
            (LedgerBackend::Single(Mutex::new(ledger)), desc)
        }
    };

    let missions = Arc::new(
        FileMissionRegistry::open(&missions_path)
            .with_context(|| format!("opening mission registry at {}", missions_path.display()))?,
    );

    // Parse configured standing issuers at boot: a key that cannot be read is a
    // startup failure, never a challenge that quietly fails to verify later.
    let mut standing_issuers = Vec::new();
    for hex_key in &args.standing_issuer_keys {
        standing_issuers.push(parse_issuer_key(hex_key, "--standing-issuer-key")?);
    }

    // Digest the authority once: a decision is a function of the principal, this graph,
    // this policy and the time, and the first three do not change while the process runs.
    let authority_digest: Arc<str> = Arc::from(
        decern_ledger::digest(
            &serde_json::to_value(&model).context("serializing the model to digest it")?,
        )
        .as_str(),
    );

    let state = AppState {
        kernel: Arc::new(kernel),
        model: Arc::new(model),
        backend: Arc::new(backend),
        missions,
        pubkey,
        require_mission: args.require_mission,
        standing_issuers: Arc::new(standing_issuers),
        authority_digest,
        caller_disclosure: Arc::new(caller_disclosure(&caller)),
    };
    let listener = tokio::net::TcpListener::bind(&args.addr)
        .await
        .with_context(|| format!("binding {}", args.addr))?;
    println!(
        "decern-serve on {} — {}, missions {}, {}, kid {}",
        args.addr,
        backend_desc,
        missions_path.display(),
        caller_desc,
        hex::encode(pubkey.to_bytes())
    );
    axum::serve(listener, app(state, caller))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Resolve when the process is asked to stop — SIGINT (Ctrl-C) or, on Unix, SIGTERM.
/// `axum::serve` then stops accepting, drains in-flight requests, and returns, so
/// `AppState` (and any head-store connection it holds) drops on a normal control-flow
/// path — destructors run — instead of being skipped by a default signal termination.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            // If the handler cannot be installed, fall back to Ctrl-C alone rather
            // than resolving immediately (which would shut the server down at once).
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The startup rule: a server that cannot say how its callers are established does not
    /// start. There is no bind-address carve-out to test, because there is no carve-out.
    #[test]
    fn with_no_posture_named_the_server_refuses_to_start() {
        let args = Args::parse_from(["decern-serve"]);
        let Err(e) = caller_from(&args) else {
            panic!("a server with no way to establish the caller must not start");
        };
        assert!(e.to_string().contains("--trust-proxy"), "{e}");
    }

    #[test]
    fn trust_proxy_names_the_delegated_posture() {
        let args = Args::parse_from(["decern-serve", "--trust-proxy"]);
        assert!(matches!(
            caller_from(&args).unwrap(),
            bearer::Caller::TrustedProxy
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
        let bearer::Caller::Bearer(cfg) = caller_from(&args).unwrap() else {
            panic!("bearer flags must configure the bearer guard");
        };
        assert_eq!(cfg.issuer, "https://issuer.example/");
        assert_eq!(cfg.audience, "https://pdp.example/");
        assert_eq!(cfg.keys.len(), 1);
        assert_eq!(cfg.scopes, vec!["decern.decide".to_owned()]);
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

    /// The disclosure's caller object under bearer validation names the audience — which is
    /// public by construction: every client must already know it to mint a usable token.
    #[test]
    fn the_caller_disclosure_names_the_bearer_audience() {
        let d = caller_disclosure(&bearer::Caller::Bearer(Box::new(bearer::Config {
            issuer: "https://issuer.example/".into(),
            audience: "https://pdp.example/".into(),
            keys: vec![SigningKey::from_bytes(&[6u8; 32]).verifying_key()],
            scopes: vec![],
        })));
        assert_eq!(d["mode"], "bearer");
        assert_eq!(d["audience"], "https://pdp.example/");
    }
}
