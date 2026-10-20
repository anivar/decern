// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Starting the server and stopping it: the caller posture is settled before anything touches disk,
//! and the server stops on SIGINT or, on Unix, SIGTERM.

use crate::args::{Args, DEFAULT_LEDGER, caller_from, default_missions_path, parse_issuer_key};
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
/// This used to write the seed with `std::fs::write`, which creates at the process umask —
/// commonly `0644`. That is the key every record and every tree head is signed with, so a
/// world-readable copy is enough for anyone on the host to forge history that verifies.
/// `decern_crypto::save_signing_key` creates at `0600` and refuses to overwrite; its loader
/// refuses a key that is group- or other-readable, so a file later `chmod`ed open fails
/// closed instead of signing quietly. Both sides also zeroize the seed, which the local
/// buffer here did not.
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
    let args = Args::parse();
    // First, before anything touches disk: a server that cannot say how its callers are
    // established refuses to start, and that refusal leaves nothing behind. A refusal further
    // down (a bad `--public-url`, a malformed `--standing-issuer-key`) comes after the key, the
    // ledger and the Mission registry exist on disk.
    let caller = Arc::new(caller_from(&args)?);
    let caller_desc = match caller.as_ref() {
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

    let type_aliases = deployment::parse_type_aliases(&args.authzen_type_alias)?;
    deployment::check_type_aliases(&kernel, &type_aliases)?;
    let public_url = args
        .public_url
        .as_deref()
        .map(deployment::parse_public_url)
        .transpose()?
        .map(Arc::from);
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

    /// The ledger signing key authenticates every record and every tree head, so a
    /// world-readable copy is enough for anyone on the host to forge history that
    /// verifies. This used to be written at the process umask (commonly 0644).
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

    /// The same key comes back, so routing through the crypto crate did not change what a
    /// restart signs with — a ledger written before this change still verifies after it.
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
}
