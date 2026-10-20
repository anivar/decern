// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Starting the server and stopping it: every flag is checked before anything is written, so a
//! refused boot leaves nothing behind, and the server stops on SIGINT or, on Unix, SIGTERM.

use crate::args::{
    Args, DEFAULT_LEDGER, ShardedTarget, caller_from, default_missions_path, parse_issuer_key,
};
use crate::caller;
use crate::deployment;
use crate::record::reserved_tenant_collision;
use crate::routes::app;
use crate::{AppState, LedgerBackend, caller_disclosure};
use anyhow::{Context, Result};
use clap::Parser;
use decern_kernel::{Kernel, Model};
use decern_ledger::{Ledger, ShardedLedger, UNATTRIBUTED_SHARD};
use decern_store::{FileLedgerHeadStore, FileMissionRegistry};
use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// The ledger signing key, through `decern-crypto`'s own key discipline rather than a
/// second implementation of it.
///
/// It is the key every record and every tree head is signed with, so a world-readable copy is
/// enough for anyone on the host to forge history that verifies. A plain write would create it
/// at the process umask, commonly `0644`. `decern_crypto::save_signing_key` creates at `0600`
/// and refuses to overwrite; its loader refuses a key that is group- or other-readable, so a
/// file later `chmod`ed open fails closed instead of signing quietly. Its loader zeroizes the
/// seed it reads.
fn load_signing_key(path: Option<&PathBuf>) -> Result<SigningKey> {
    let Some(p) = path else {
        // No `--key`: an ephemeral key, which means nothing recorded today verifies
        // tomorrow. Nothing touches disk, so there is no file discipline to apply.
        return decern_crypto::generate().map_err(|e| anyhow::anyhow!("generating key: {e}"));
    };
    if p.exists() {
        return decern_crypto::load_signing_key(p)
            .with_context(|| format!("reading key {}", p.display()));
    }
    let key = decern_crypto::generate().map_err(|e| anyhow::anyhow!("generating key: {e}"))?;
    // `create_new` under the hood, so a key that appears between the check above and this
    // write is an error rather than a silent overwrite of somebody else's key.
    decern_crypto::save_signing_key(&key, p)
        .with_context(|| format!("writing key {}", p.display()))?;
    Ok(key)
}

pub(crate) async fn serve() -> Result<()> {
    serve_with(Args::parse()).await
}

/// Start the server `args` describe. Every check a flag can fail runs before the first write,
/// so a refused boot leaves no key, ledger or registry behind and a failed deployment can be
/// retried as it stands. The caller posture comes first of all.
pub(crate) async fn serve_with(args: Args) -> Result<()> {
    let caller = Arc::new(caller_from(&args)?);
    let caller_desc = caller_summary(&caller);
    let model = match &args.model {
        Some(d) => {
            Model::from_dir(d).with_context(|| format!("loading model from {}", d.display()))?
        }
        None => Model::builtin(),
    };
    let kernel = Kernel::new(&model)?;
    let sharded = args
        .sharded
        .as_deref()
        .map(ShardedTarget::parse)
        .transpose()?;
    if sharded.is_some() {
        // Fail closed at boot: a directory tenant equal to the reserved
        // unattributed-shard name would silently co-mingle with it.
        if let Some(who) = reserved_tenant_collision(kernel.directory()) {
            anyhow::bail!(
                "refusing to serve sharded: {who} uses the reserved shard name {UNATTRIBUTED_SHARD:?}"
            );
        }
    }
    #[cfg(not(feature = "postgres"))]
    if matches!(sharded, Some(ShardedTarget::Postgres(_))) {
        anyhow::bail!(POSTGRES_FEATURE);
    }
    // A key that cannot be read is a startup failure, never a challenge that quietly fails to
    // verify later.
    let mut standing_issuers = Vec::new();
    for hex_key in &args.standing_issuer_keys {
        standing_issuers.push(parse_issuer_key(hex_key, "--standing-issuer-key")?);
    }
    let type_aliases = deployment::parse_type_aliases(&args.authzen_type_alias)?;
    deployment::check_type_aliases(&kernel, &type_aliases)?;
    let public_url = args
        .public_url
        .as_deref()
        .map(deployment::parse_public_url)
        .transpose()?
        .map(Arc::from);
    // Digest the authority once: a decision is a function of the principal, this graph,
    // this policy and the time, and the first three do not change while the process runs.
    let authority_digest: Arc<str> = Arc::from(
        decern_ledger::digest(
            &serde_json::to_value(&model).context("serializing the model to digest it")?,
        )
        .as_str(),
    );
    let missions_path = args
        .missions
        .clone()
        .unwrap_or_else(|| default_missions_path(args.ledger.as_ref(), sharded.as_ref()));

    // A port already taken is refused here too, before anything is written.
    let listener = tokio::net::TcpListener::bind(&args.addr)
        .await
        .with_context(|| format!("binding {}", args.addr))?;
    let bound = listener.local_addr().context("reading the bound address")?;

    // The writes, each after what it depends on: the key, the ledger it signs, the registry.
    let key = load_signing_key(args.key.as_ref())?;
    let pubkey = key.verifying_key();
    let (backend, backend_desc) = match sharded {
        Some(target) => {
            let desc = target.describe();
            let store: Arc<dyn decern_store::LedgerHeadStore> = match target {
                ShardedTarget::Postgres(url) => postgres_head_store(&url)?,
                ShardedTarget::Dir(dir) => {
                    Arc::new(FileLedgerHeadStore::new(&dir).with_context(|| {
                        format!("opening sharded head store at {}", dir.display())
                    })?)
                }
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

    let state = AppState {
        kernel: Arc::new(kernel),
        model: Arc::new(model),
        backend: Arc::new(backend),
        type_aliases: Arc::new(type_aliases),
        public_url,
        missions,
        pubkey,
        require_mission: args.require_mission,
        standing_issuers: Arc::new(standing_issuers),
        authority_digest,
        caller_disclosure: Arc::new(caller_disclosure(&caller)),
    };
    println!(
        "decern-serve on {} — {}, missions {}, {}, kid {}",
        bound,
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

/// The caller posture in the startup line's words.
fn caller_summary(caller: &caller::Caller) -> String {
    match caller {
        caller::Caller::Bearer(c) => format!("bearer for {}", c.audience),
        caller::Caller::Signed(c) => format!("signed-request for {}", c.audience),
        caller::Caller::Spiffe(c) => format!(
            "SPIFFE JWT-SVID for {} across {} trust domain(s)",
            c.audience,
            c.trust_domains.len()
        ),
        caller::Caller::Aauth(c) => format!(
            "AAuth agent tokens for {} across {} provider(s)",
            c.authority,
            c.providers.len()
        ),
        caller::Caller::TrustedProxy => "caller trusted (--trust-proxy)".to_owned(),
    }
}

#[cfg(not(feature = "postgres"))]
const POSTGRES_FEATURE: &str =
    "a postgres:// sharded head store requires a build with `--features postgres`";

/// The shared head store several replicas coordinate through. The error never carries the URL,
/// which can hold a password.
fn postgres_head_store(url: &str) -> Result<Arc<dyn decern_store::LedgerHeadStore>> {
    #[cfg(feature = "postgres")]
    {
        Ok(Arc::new(
            decern_store_postgres::PostgresLedgerHeadStore::new(url)
                .context("connecting sharded postgres head store")?,
        ))
    }
    #[cfg(not(feature = "postgres"))]
    {
        let _ = url;
        anyhow::bail!(POSTGRES_FEATURE)
    }
}

/// Resolve when the process is asked to stop — SIGINT (Ctrl-C) or, on Unix, SIGTERM.
/// `axum::serve` then stops accepting, drains in-flight requests, and returns, so
/// `AppState` (and any head-store connection it holds) drops on a normal control-flow
/// path — destructors run — instead of being skipped by a default signal termination.
async fn shutdown_signal() {
    let ctrl_c = async {
        // A handler that cannot be installed resolves at once; wait on SIGTERM alone instead
        // of stopping the server as soon as it starts.
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
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

    /// The ledger signing key authenticates every record and every tree head, so a
    /// world-readable copy is enough for anyone on the host to forge history that
    /// verifies, and a plain write at the process umask would commonly leave it 0644.
    #[cfg(unix)]
    #[test]
    fn a_generated_signing_key_is_not_readable_by_group_or_other() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("decern-key-{}-a", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.key");
        let _ = load_signing_key(Some(&path)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "signing key is readable beyond its owner: {mode:o}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Symmetric with the write side: a key placed by another tool, or opened up by a
    /// later chmod, must fail closed rather than keep signing quietly.
    #[cfg(unix)]
    #[test]
    fn a_world_readable_signing_key_is_refused_rather_than_loaded() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("decern-key-{}-b", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.key");
        let key = load_signing_key(Some(&path)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            load_signing_key(Some(&path)).is_err(),
            "a world-readable key must not load"
        );
        drop(key);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same key comes back across a restart, so a ledger keeps verifying under the key it
    /// was written with.
    #[test]
    fn a_configured_key_round_trips_across_restarts() {
        let dir = std::env::temp_dir().join(format!("decern-key-{}-c", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.key");
        let first = load_signing_key(Some(&path)).unwrap().verifying_key();
        let second = load_signing_key(Some(&path)).unwrap().verifying_key();
        assert_eq!(first, second);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every refusal a flag can cause comes before the first write: the key, the ledger and
    /// the registry all point into an empty directory, and it is still empty afterwards.
    #[tokio::test]
    async fn a_refused_boot_leaves_nothing_behind() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let taken = taken.local_addr().unwrap().to_string();
        let cases: [(&str, Vec<&str>); 5] = [
            ("public url", vec!["--public-url", "ftp://bad.example"]),
            ("standing key", vec!["--standing-issuer-key", "zz"]),
            (
                "type alias",
                vec!["--authzen-type-alias", "user=NoSuchType"],
            ),
            ("port taken", vec!["--addr", &taken]),
            (
                "sharded scheme",
                vec!["--sharded", "mysql://decern:s3cret@db/decern"],
            ),
        ];
        for (name, extra) in cases {
            let dir = std::env::temp_dir().join(format!(
                "decern-refused-boot-{}-{}",
                name.replace(' ', "-"),
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let key = dir.join("k");
            let ledger = dir.join("l.jsonl");
            let missions = dir.join("m.json");
            let mut argv = vec![
                "decern-serve",
                "--trust-proxy",
                "--key",
                key.to_str().unwrap(),
                "--missions",
                missions.to_str().unwrap(),
            ];
            if !extra.contains(&"--sharded") {
                argv.extend(["--ledger", ledger.to_str().unwrap()]);
            }
            if !extra.contains(&"--addr") {
                argv.extend(["--addr", "127.0.0.1:0"]);
            }
            argv.extend(extra.iter().copied());
            let result = serve_with(Args::try_parse_from(&argv).unwrap()).await;
            assert!(result.is_err(), "{name}: the boot was not refused");
            let left: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert!(left.is_empty(), "{name}: a refused boot left {left:?}");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
