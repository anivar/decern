// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Starting the server and stopping it: what a flag can get wrong is checked before anything is
//! written, so a boot refused there leaves nothing behind; opening the ledger, the head store or
//! the registry can still fail after the key exists. The server stops on SIGINT or, on Unix,
//! SIGTERM.

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
use decern_store::{FileLedgerHeadStore, FileMissionRegistry, LedgerHeadStore};
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

/// Start the server `args` describe.
pub(crate) async fn serve_with(args: Args) -> Result<()> {
    let boot = prepare(args).await?;
    println!("{}", boot.line);
    crate::serve::run(
        boot.listener,
        app(boot.state, boot.caller),
        crate::serve::LIMITS,
        shutdown_signal(),
    )
    .await;
    Ok(())
}

/// A boot that has done everything but serve: what `serve_with` hands to the server, and what
/// a test can drop.
pub(crate) struct Boot {
    pub(crate) listener: tokio::net::TcpListener,
    pub(crate) state: AppState,
    pub(crate) caller: Arc<caller::Caller>,
    pub(crate) line: String,
}

/// Check and open what `args` describe. What a flag can get wrong is checked before the first
/// write, so a boot refused there leaves no key, ledger or registry behind and a failed
/// deployment can be retried as it stands; what only opening a file or a store reveals is
/// refused after the key exists. The caller posture comes first of all.
pub(crate) async fn prepare(args: Args) -> Result<Boot> {
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
    let mut retired: Vec<ed25519_dalek::VerifyingKey> = Vec::new();
    for hex_key in &args.retired_keys {
        let k = parse_issuer_key(hex_key, "--retired-key")?;
        if retired.contains(&k) {
            anyhow::bail!("--retired-key {hex_key} is given twice");
        }
        retired.push(k);
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

    // The key a ledger was signed with is the key it keeps being signed with: a new key, or
    // an ephemeral one, would fork the signing identity, and the next restart under the old
    // key would read the fork as tampering. A ledger that exists is therefore extended only by
    // a key file that exists; whether that file holds the right key is checked against the
    // records once it is loaded, below. Checked here by presence alone, before anything is
    // written. A Postgres head store cannot be looked at before connecting, so a missing key
    // file is refused only after it is created when that store already holds shards.
    let ledger_path = args
        .ledger
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LEDGER));
    if sharded.is_some() && args.key.is_none() {
        anyhow::bail!(
            "--sharded needs --key: a shared head store is signed by one key across restarts \
             and replicas, and an ephemeral key would fork it"
        );
    }
    let existing = match &sharded {
        None if ledger_has_records(&ledger_path) => {
            Some(format!("ledger {}", ledger_path.display()))
        }
        Some(ShardedTarget::Dir(dir)) if dir.exists() => {
            let shards = FileLedgerHeadStore::new(dir)
                .with_context(|| format!("opening sharded head store at {}", dir.display()))?
                .list_shards()
                .map_err(|e| anyhow::anyhow!("listing shards at {}: {e}", dir.display()))?;
            (!shards.is_empty()).then(|| format!("sharded head store {}", dir.display()))
        }
        _ => None,
    };
    // clap's `requires` establishes this; the check stays so a later edit to the attribute
    // degrades to this error, not an ephemeral key booting beside retired ones.
    if !args.retired_keys.is_empty() && args.key.is_none() {
        anyhow::bail!("--retired-key requires --key");
    }
    // A rotation names a key made beforehand. Creating one here would give this process a key
    // no other replica holds, which a mistyped path would do without a word.
    if !args.retired_keys.is_empty()
        && let Some(p) = &args.key
        && !p.exists()
    {
        anyhow::bail!(
            "--key {} does not exist; with --retired-key, --key names a key file made beforehand",
            p.display()
        );
    }
    if let Some(what) = &existing {
        match &args.key {
            None => anyhow::bail!(
                "{what} exists and --key is not given; an ephemeral key cannot extend it. Point \
                 --key at the key it was signed with, or move it aside to start a new ledger"
            ),
            Some(p) if !p.exists() => anyhow::bail!(
                "{what} exists and --key {} does not; point --key at the key that signs it now, \
                 or at a new key file made beforehand with that key given as --retired-key, or \
                 move the ledger aside to start a new one",
                p.display()
            ),
            _ => {}
        }
    }

    // The files this boot writes, refused now if it could not: a registry or ledger path that
    // is a directory, a registry that is the shard directory or the ledger file, a ledger or
    // key path under a directory that does not exist, or a registry file that is not JSON. A
    // registry under a path that is a file is refused too; a registry's parent directory that
    // does not exist is created when it is opened, as it always was, and a
    // registry file that is JSON of another shape is refused only when opened, after the key
    // and the ledger exist.
    registry_path(&missions_path)?;
    match &sharded {
        Some(ShardedTarget::Dir(dir)) if same_path(&missions_path, dir) => {
            anyhow::bail!(
                "--missions {} is the shard directory",
                missions_path.display()
            )
        }
        None if same_path(&missions_path, &ledger_path) => {
            anyhow::bail!("--missions {} is the ledger", missions_path.display())
        }
        None => writable_path("--ledger", &ledger_path)?,
        _ => {}
    }
    if let Some(k) = &args.key {
        writable_path("--key", k)?;
        // The ledger opens its file for append and trims an unterminated last line, and a key
        // file has no newline: pointed at the key, the open would truncate it.
        if sharded.is_none() && same_path(k, &ledger_path) {
            anyhow::bail!("--ledger {} is the key file", ledger_path.display());
        }
        if same_path(k, &missions_path) {
            anyhow::bail!("--missions {} is the key file", missions_path.display());
        }
    }
    if missions_path.is_file() {
        let bytes = std::fs::read(&missions_path)
            .with_context(|| format!("reading --missions {}", missions_path.display()))?;
        if serde_json::from_slice::<serde_json::Value>(&bytes).is_err() {
            anyhow::bail!("--missions {} is not a JSON file", missions_path.display());
        }
    }

    // A port already taken is refused here too, before anything is written.
    let listener = tokio::net::TcpListener::bind(&args.addr)
        .await
        .with_context(|| format!("binding {}", args.addr))?;
    let bound = listener.local_addr().context("reading the bound address")?;

    // The writes, each after what it depends on: the key, the ledger it signs, the registry.
    let key = load_signing_key(args.key.as_ref())?;
    let pubkey = key.verifying_key();
    let kid = hex::encode(pubkey.to_bytes());
    // With --retired-key the key file already existed, so this refusal writes nothing.
    if retired.contains(&pubkey) {
        anyhow::bail!(
            "--retired-key {kid} is the public key of --key; a key signs or is retired, not both"
        );
    }
    let retired_desc: String = retired
        .iter()
        .map(|k| format!(", retired {}", hex::encode(k.to_bytes())))
        .collect();
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
            let sharded = ShardedLedger::new(store, key, retired.clone());
            // Opening a shard verifies nothing, unlike a single-file ledger, so each shard is
            // verified here under this key and the retired ones: the chain, and every record's
            // signature. A record that names a key in neither, one with no key id that none of
            // them verifies, or a retired key signing after its successor refuses the boot, and
            // so does a --key that another key has followed in any shard: its next record there
            // would not verify. Every record is read, as a single-file open reads its whole
            // file; a boot pays that once.
            for shard in sharded.list_shards()? {
                let report = sharded.self_verify(&shard).with_context(|| {
                    format!(
                        "shard {shard} does not verify under --key {kid}{retired_desc}; point \
                         --key at the key that signs it now and --retired-key at each key that \
                         signed it before, or move the store aside to start a new ledger"
                    )
                })?;
                if let Some(next) = report.superseded_by(&kid) {
                    anyhow::bail!(
                        "--key {kid} may not sign shard {shard}: key {} signed it after this \
                         one, from seq {}; point --key at that key or a later one",
                        next.kid,
                        next.first_seq
                    );
                }
            }
            (LedgerBackend::Sharded(sharded), desc)
        }
        None => {
            // Opening verifies the whole chain under this key and the retired ones; a record
            // signed by any other key is refused, and so is a --key another key has followed.
            // The context names the keys this boot holds beside the one the error names.
            let mut ledger = Ledger::open_with_verifiers(&ledger_path, key, retired.clone())
                .with_context(|| {
                    format!(
                        "opening ledger {} with key {kid}{retired_desc}",
                        ledger_path.display()
                    )
                })?;
            // Durable by default in the server: an append the PEP acks (and acts
            // on) must survive a crash — `sync_data` before `append` returns.
            ledger.set_sync(true);
            let desc = format!("ledger {}", ledger_path.display());
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
        retired_keys: Arc::new(retired),
        tree_head: Arc::default(),
        projection: Arc::default(),
        require_mission: args.require_mission,
        standing_issuers: Arc::new(standing_issuers),
        authority_digest,
        caller_disclosure: Arc::new(caller_disclosure(&caller)),
    };
    let line = format!(
        "decern-serve on {} — {}, missions {}, {}, kid {}{}{}",
        bound,
        backend_desc,
        missions_path.display(),
        caller_desc,
        kid,
        retired_desc,
        if args.key.is_none() {
            " (ephemeral)"
        } else {
            ""
        }
    );
    Ok(Boot {
        listener,
        state,
        caller,
        line,
    })
}

/// Whether two flags name one file: by device and inode when both exist, otherwise by their
/// absolute forms, so `./l` and `l`, or a link and what it points at, are not taken for two.
fn same_path(a: &std::path::Path, b: &std::path::Path) -> bool {
    #[cfg(unix)]
    if let (Ok(ma), Ok(mb)) = (std::fs::metadata(a), std::fs::metadata(b)) {
        use std::os::unix::fs::MetadataExt;
        return ma.dev() == mb.dev() && ma.ino() == mb.ino();
    }
    #[cfg(not(unix))]
    if let (Ok(ca), Ok(cb)) = (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        return ca == cb;
    }
    match (std::path::absolute(a), std::path::absolute(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// The registry path: not a directory, and not under a path that is a file. A parent that does
/// not exist is created when the registry opens, as it always was, since nothing can refuse the
/// boot after that point.
fn registry_path(path: &std::path::Path) -> Result<()> {
    if path.is_dir() {
        anyhow::bail!("--missions {} is a directory", path.display());
    }
    if let Some(parent) = path.parent()
        && parent.exists()
        && !parent.is_dir()
    {
        anyhow::bail!(
            "--missions {}: {} is not a directory",
            path.display(),
            parent.display()
        );
    }
    Ok(())
}

/// A path this boot will create or extend: not a directory, and under a directory that exists.
fn writable_path(flag: &str, path: &std::path::Path) -> Result<()> {
    if path.is_dir() {
        anyhow::bail!("{flag} {} is a directory", path.display());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.is_dir()
    {
        let what = if parent.exists() {
            "is not a directory"
        } else {
            "does not exist"
        };
        anyhow::bail!("{flag} {}: {} {what}", path.display(), parent.display());
    }
    Ok(())
}

/// A ledger file that holds anything. An empty file, such as the default ledger a checkout
/// carries, was signed by no key and is a new ledger.
fn ledger_has_records(path: &std::path::Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.len() > 0)
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
        let retired = hex::encode(
            decern_crypto::generate()
                .unwrap()
                .verifying_key()
                .to_bytes(),
        );
        let cases: [(&str, Vec<&str>); 7] = [
            ("public url", vec!["--public-url", "ftp://bad.example"]),
            ("standing key", vec!["--standing-issuer-key", "zz"]),
            ("retired key", vec!["--retired-key", "zz"]),
            (
                "retired key without a key file",
                vec!["--retired-key", &retired],
            ),
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
            // A boot that is not refused serves until stopped; the bound turns that into a
            // failure instead of a test that never ends.
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                serve_with(Args::try_parse_from(&argv).unwrap()),
            )
            .await
            .unwrap_or_else(|_| panic!("{name}: the boot was not refused"));
            assert!(result.is_err(), "{name}: the boot was not refused");
            let left: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert!(left.is_empty(), "{name}: a refused boot left {left:?}");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    fn entry() -> decern_ledger::Entry {
        decern_ledger::Entry {
            action: "Read".into(),
            subject_type: "Principal".into(),
            subject_id: "s".into(),
            resource_type: "R".into(),
            resource_id: "r".into(),
            context: serde_json::json!({"now": 1}),
            ..Default::default()
        }
    }

    fn kid_of(key_file: &std::path::Path) -> String {
        hex::encode(
            decern_crypto::load_signing_key(key_file)
                .unwrap()
                .verifying_key()
                .to_bytes(),
        )
    }

    fn fresh_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("decern-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A ledger is extended only by the key that signed it. A different existing key is
    /// refused naming both key ids; a key file that does not exist, or no key at all, is
    /// refused before anything is written; the same key boots again.
    #[tokio::test]
    async fn a_ledger_keeps_the_key_it_was_signed_with() {
        let dir = fresh_dir("ledger-key");
        let (k1, k2, k3) = (dir.join("k1"), dir.join("k2"), dir.join("k3"));
        decern_crypto::save_signing_key(&decern_crypto::generate().unwrap(), &k2).unwrap();
        let ledger = dir.join("l.jsonl");
        let missions = dir.join("m.json");
        let argv = |key: Option<&std::path::Path>| {
            let mut v: Vec<String> = ["decern-serve", "--trust-proxy", "--addr", "127.0.0.1:0"]
                .map(String::from)
                .to_vec();
            v.extend(["--ledger".into(), ledger.display().to_string()]);
            v.extend(["--missions".into(), missions.display().to_string()]);
            if let Some(k) = key {
                v.extend(["--key".into(), k.display().to_string()]);
            }
            Args::parse_from(v)
        };

        let boot = prepare(argv(Some(&k1))).await.unwrap();
        let LedgerBackend::Single(l) = &*boot.state.backend else {
            panic!("single-file backend expected");
        };
        l.lock().unwrap().append(entry()).unwrap();
        assert!(!boot.line.contains("(ephemeral)"));
        drop(boot);

        let e = prepare(argv(Some(&k2)))
            .await
            .err()
            .expect("the boot should have been refused");
        let msg = format!("{e:#}");
        assert!(
            msg.contains(&kid_of(&k1)) && msg.contains(&kid_of(&k2)),
            "{msg}"
        );

        let e = prepare(argv(None))
            .await
            .err()
            .expect("the boot should have been refused");
        assert!(e.to_string().contains("ephemeral"), "{e}");

        let e = prepare(argv(Some(&k3)))
            .await
            .err()
            .expect("the boot should have been refused");
        assert!(e.to_string().contains("does not"), "{e}");
        assert!(!k3.exists(), "a refused boot created the key file");

        prepare(argv(Some(&k1))).await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same rule for a sharded store, whose open verifies nothing on its own: each shard's
    /// last record is checked against the key, and `--sharded` without `--key` is refused.
    #[tokio::test]
    async fn a_sharded_ledger_keeps_the_key_it_was_signed_with() {
        let dir = fresh_dir("sharded-key");
        let (k1, k2, k3) = (dir.join("k1"), dir.join("k2"), dir.join("k3"));
        decern_crypto::save_signing_key(&decern_crypto::generate().unwrap(), &k2).unwrap();
        let heads = dir.join("heads");
        let missions = dir.join("m.json");
        let argv = |key: Option<&std::path::Path>| {
            let mut v: Vec<String> = ["decern-serve", "--trust-proxy", "--addr", "127.0.0.1:0"]
                .map(String::from)
                .to_vec();
            v.extend(["--sharded".into(), heads.display().to_string()]);
            v.extend(["--missions".into(), missions.display().to_string()]);
            if let Some(k) = key {
                v.extend(["--key".into(), k.display().to_string()]);
            }
            Args::parse_from(v)
        };

        let e = prepare(argv(None))
            .await
            .err()
            .expect("the boot should have been refused");
        assert!(e.to_string().contains("--sharded needs --key"), "{e}");
        assert!(!heads.exists(), "a refused boot created the head store");

        let boot = prepare(argv(Some(&k1))).await.unwrap();
        let LedgerBackend::Sharded(s) = &*boot.state.backend else {
            panic!("sharded backend expected");
        };
        s.append("t", entry()).unwrap();
        drop(boot);

        let e = prepare(argv(Some(&k2)))
            .await
            .err()
            .expect("the boot should have been refused");
        let msg = format!("{e:#}");
        assert!(
            msg.contains("shard t") && msg.contains(&kid_of(&k1)) && msg.contains(&kid_of(&k2)),
            "{msg}"
        );

        let e = prepare(argv(Some(&k3)))
            .await
            .err()
            .expect("the boot should have been refused");
        assert!(e.to_string().contains("does not"), "{e}");
        assert!(!k3.exists(), "a refused boot created the key file");

        prepare(argv(Some(&k1))).await.unwrap();

        // A head record a label comparison would pass is refused by verification. With its
        // key id stripped, as a legacy record has none, the other key does not verify the
        // signature and the signing key does; with its key id relabelled to the other key,
        // the signature does not match the key named.
        let kid2 = kid_of(&k2);
        edit_last_record(&heads, |r| {
            format!("{}}}", &r[..r.rfind(",\"kid\":\"").unwrap()])
        });
        let e = prepare(argv(Some(&k2)))
            .await
            .err()
            .expect("a record with no key id is still another key's record");
        assert!(format!("{e:#}").contains("does not verify under"), "{e:#}");
        prepare(argv(Some(&k1)))
            .await
            .expect("the signing key verifies a record with no key id");
        edit_last_record(&heads, |r| {
            format!("{},\"kid\":\"{kid2}\"}}", &r[..r.len() - 1])
        });
        let e = prepare(argv(Some(&k2)))
            .await
            .err()
            .expect("a relabelled key id is not a pass");
        assert!(format!("{e:#}").contains("does not verify under"), "{e:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ledger and the registry are files this boot writes, and the key file is the one it
    /// must never touch: naming the key as either is refused before anything is written, the
    /// same file reached by another spelling of its path included.
    #[tokio::test]
    async fn a_ledger_or_registry_that_is_the_key_file_is_refused() {
        let dir = fresh_dir("ledger-is-key");
        let key = dir.join("k");
        decern_crypto::save_signing_key(&decern_crypto::generate().unwrap(), &key).unwrap();
        let before = std::fs::read(&key).unwrap();
        let spelled = dir.join(".").join("k");

        let argv = |ledger: &std::path::Path, missions: &std::path::Path, key: &std::path::Path| {
            Args::parse_from([
                "decern-serve",
                "--trust-proxy",
                "--addr",
                "127.0.0.1:0",
                "--ledger",
                ledger.to_str().unwrap(),
                "--missions",
                missions.to_str().unwrap(),
                "--key",
                key.to_str().unwrap(),
            ])
        };
        let m = dir.join("m.json");
        let l = dir.join("l.jsonl");
        let mut cases = vec![
            (key.as_path(), m.as_path(), "is the key file"),
            (spelled.as_path(), m.as_path(), "is the key file"),
            (l.as_path(), key.as_path(), "is the key file"),
        ];
        #[cfg(unix)]
        let link = {
            let link = dir.join("link");
            std::os::unix::fs::symlink(&key, &link).unwrap();
            link
        };
        #[cfg(unix)]
        cases.push((link.as_path(), m.as_path(), "is the key file"));
        for (ledger, missions, needle) in cases {
            let e = prepare(argv(ledger, missions, &key))
                .await
                .err()
                .expect("the boot should have been refused");
            assert!(e.to_string().contains(needle), "{e}");
            assert_eq!(std::fs::read(&key).unwrap(), before, "the key file changed");
        }
        // Neither exists yet: refused on the absolute paths, and nothing is created.
        let fresh = dir.join("new");
        let e = prepare(argv(&fresh, &m, &fresh))
            .await
            .err()
            .expect("the boot should have been refused");
        assert!(e.to_string().contains("is the key file"), "{e}");
        assert!(
            !fresh.exists(),
            "a refused boot created {}",
            fresh.display()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A rotation of a single-file ledger: restarted on a new key with the old one retired, it
    /// keeps every record verifiable, publishes both keys, and refuses the old key as `--key`
    /// once the new one has signed.
    #[tokio::test]
    async fn a_ledger_rotates_to_a_new_key_with_the_old_one_retired() {
        let dir = fresh_dir("ledger-rotate");
        let (k1, k2) = (dir.join("k1"), dir.join("k2"));
        decern_crypto::save_signing_key(&decern_crypto::generate().unwrap(), &k2).unwrap();
        let ledger = dir.join("l.jsonl");
        let missions = dir.join("m.json");
        let argv = |key: &std::path::Path, retired: &[&str]| {
            let mut v: Vec<String> = ["decern-serve", "--trust-proxy", "--addr", "127.0.0.1:0"]
                .map(String::from)
                .to_vec();
            v.extend(["--ledger".into(), ledger.display().to_string()]);
            v.extend(["--missions".into(), missions.display().to_string()]);
            v.extend(["--key".into(), key.display().to_string()]);
            for r in retired {
                v.extend(["--retired-key".into(), (*r).to_owned()]);
            }
            Args::parse_from(v)
        };
        let append = |boot: &Boot| {
            let LedgerBackend::Single(l) = &*boot.state.backend else {
                panic!("single-file backend expected");
            };
            l.lock().unwrap().append(entry()).unwrap();
        };

        let boot = prepare(argv(&k1, &[])).await.unwrap();
        append(&boot);
        drop(boot);
        let (kid1, kid2) = (kid_of(&k1), kid_of(&k2));

        let e = prepare(argv(&k2, &[&kid2]))
            .await
            .err()
            .expect("a key that is both current and retired must be refused");
        assert!(e.to_string().contains("is the public key of --key"), "{e}");
        let e = prepare(argv(&k2, &[&kid1, &kid1]))
            .await
            .err()
            .expect("a retired key given twice must be refused");
        assert!(e.to_string().contains("given twice"), "{e}");

        let boot = prepare(argv(&k2, &[&kid1])).await.unwrap();
        assert!(
            boot.line.contains(&format!("kid {kid2}, retired {kid1}")),
            "{}",
            boot.line
        );
        let axum::Json(published) =
            crate::audit::pubkey(axum::extract::State(boot.state.clone())).await;
        assert_eq!(
            published,
            serde_json::json!({ "kid": kid2, "keys": [kid1, kid2] })
        );
        append(&boot);
        drop(boot);

        let pk = |k: &std::path::Path| decern_crypto::load_signing_key(k).unwrap().verifying_key();
        let report = decern_ledger::verify_with_keys(&ledger, &[pk(&k1), pk(&k2)]).unwrap();
        assert_eq!(report.entries, 2);
        assert_eq!(report.superseded_by(&kid1).map(|s| s.first_seq), Some(1));
        let e = decern_ledger::verify_with_keys(&ledger, &[pk(&k2)]).unwrap_err();
        assert!(e.to_string().contains(&kid1), "{e}");

        // Back to the old key once the new one has signed: refused, naming the successor.
        let e = prepare(argv(&k1, &[&kid2]))
            .await
            .err()
            .expect("a key another has followed must not sign again");
        let msg = format!("{e:#}");
        assert!(
            msg.contains(&kid1) && msg.contains(&kid2) && msg.contains("seq 1"),
            "{msg}"
        );
        // Without the retired key, the old records are another key's.
        let e = prepare(argv(&k2, &[]))
            .await
            .err()
            .expect("the old records need the retired key");
        assert!(format!("{e:#}").contains(&kid1), "{e:#}");

        prepare(argv(&k2, &[&kid1])).await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A rotation of a sharded store. A replica still on the old key refuses to extend a shard
    /// the new key has signed, rather than writing a record that would stop the shard
    /// verifying; a boot on the old key is refused once the new key has signed any shard.
    #[tokio::test]
    async fn a_sharded_ledger_rotates_with_every_replica_on_the_new_key() {
        let dir = fresh_dir("sharded-rotate");
        let (k1, k2) = (dir.join("k1"), dir.join("k2"));
        decern_crypto::save_signing_key(&decern_crypto::generate().unwrap(), &k2).unwrap();
        let heads = dir.join("heads");
        let missions = dir.join("m.json");
        let argv = |key: &std::path::Path, retired: &[&str]| {
            let mut v: Vec<String> = ["decern-serve", "--trust-proxy", "--addr", "127.0.0.1:0"]
                .map(String::from)
                .to_vec();
            v.extend(["--sharded".into(), heads.display().to_string()]);
            v.extend(["--missions".into(), missions.display().to_string()]);
            v.extend(["--key".into(), key.display().to_string()]);
            for r in retired {
                v.extend(["--retired-key".into(), (*r).to_owned()]);
            }
            Args::parse_from(v)
        };
        fn sharded(boot: &Boot) -> &ShardedLedger {
            let LedgerBackend::Sharded(s) = &*boot.state.backend else {
                panic!("sharded backend expected");
            };
            s
        }

        let old = prepare(argv(&k1, &[])).await.unwrap();
        sharded(&old).append("t", entry()).unwrap();
        let (kid1, kid2) = (kid_of(&k1), kid_of(&k2));

        let new = prepare(argv(&k2, &[&kid1])).await.unwrap();
        sharded(&new).append("t", entry()).unwrap();
        let e = sharded(&old).append("t", entry()).unwrap_err();
        assert!(
            matches!(e, decern_ledger::LedgerError::KeySuperseded { .. }),
            "{e}"
        );
        // A shard the new key has not signed still takes the old key's records.
        sharded(&old).append("u", entry()).unwrap();
        drop((old, new));

        let e = prepare(argv(&k1, &[&kid2]))
            .await
            .err()
            .expect("a key another has followed must not sign again");
        let msg = format!("{e:#}");
        assert!(msg.contains("shard t") && msg.contains(&kid2), "{msg}");

        let boot = prepare(argv(&k2, &[&kid1])).await.unwrap();
        sharded(&boot).append("u", entry()).unwrap();
        for shard in ["t", "u"] {
            sharded(&boot).self_verify(shard).unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rewrite the last record of the one shard under `heads`, the way an operator with the
    /// files could.
    fn edit_last_record(heads: &std::path::Path, edit: impl Fn(&str) -> String) {
        let shard = std::fs::read_dir(heads)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "shard"))
            .expect("a shard file");
        let mut state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&shard).unwrap()).unwrap();
        let last = state["records"].as_array_mut().unwrap().last_mut().unwrap();
        let edited = edit(last["record_json"].as_str().unwrap());
        last["record_json"] = serde_json::Value::String(edited);
        std::fs::write(&shard, serde_json::to_vec(&state).unwrap()).unwrap();
    }

    /// The Mission registry defaults into the shard directory. The boot-time key check lists
    /// shards there, and neither the registry nor its lock is one.
    #[tokio::test]
    async fn a_sharded_ledger_with_the_default_registry_path_boots_again() {
        let dir = fresh_dir("sharded-default-registry");
        let k1 = dir.join("k1");
        let heads = dir.join("heads");
        assert_eq!(
            default_missions_path(None, Some(&ShardedTarget::Dir(heads.clone()))),
            heads.join("decern-missions.json")
        );
        let argv = || {
            Args::parse_from([
                "decern-serve",
                "--trust-proxy",
                "--addr",
                "127.0.0.1:0",
                "--sharded",
                heads.to_str().unwrap(),
                "--key",
                k1.to_str().unwrap(),
            ])
        };
        let boot = prepare(argv()).await.unwrap();
        let LedgerBackend::Sharded(s) = &*boot.state.backend else {
            panic!("sharded backend expected");
        };
        s.append("t", entry()).unwrap();
        drop(boot);
        prepare(argv()).await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn listing(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// A path this boot could not write to is refused before anything is written: the
    /// directory holds afterwards exactly what it held before.
    #[tokio::test]
    async fn a_refused_boot_leaves_a_bad_path_alone() {
        let dir = fresh_dir("refused-paths");
        let nope = dir.join("nope");
        let bad = dir.join("bad.json");
        std::fs::write(&bad, "not json").unwrap();
        let before = listing(&dir);
        let (k, l, m) = (dir.join("k"), dir.join("l.jsonl"), dir.join("m.json"));
        let (k, l, m) = (
            k.to_str().unwrap(),
            l.to_str().unwrap(),
            m.to_str().unwrap(),
        );
        let (nl, nk, heads) = (nope.join("l.jsonl"), nope.join("k"), dir.join("heads"));
        let under_file = bad.join("m.json");
        let cases: [(&str, Vec<&str>); 7] = [
            (
                "registry is a directory",
                vec![
                    "--missions",
                    dir.to_str().unwrap(),
                    "--ledger",
                    l,
                    "--key",
                    k,
                ],
            ),
            (
                "registry is not JSON",
                vec![
                    "--missions",
                    bad.to_str().unwrap(),
                    "--ledger",
                    l,
                    "--key",
                    k,
                ],
            ),
            (
                "registry under a file",
                vec![
                    "--missions",
                    under_file.to_str().unwrap(),
                    "--ledger",
                    l,
                    "--key",
                    k,
                ],
            ),
            (
                "registry is the ledger",
                vec!["--missions", l, "--ledger", l, "--key", k],
            ),
            (
                "registry is the shard directory",
                vec![
                    "--sharded",
                    heads.to_str().unwrap(),
                    "--missions",
                    heads.to_str().unwrap(),
                    "--key",
                    k,
                ],
            ),
            (
                "ledger under a missing directory",
                vec![
                    "--ledger",
                    nl.to_str().unwrap(),
                    "--missions",
                    m,
                    "--key",
                    k,
                ],
            ),
            (
                "key under a missing directory",
                vec![
                    "--key",
                    nk.to_str().unwrap(),
                    "--ledger",
                    l,
                    "--missions",
                    m,
                ],
            ),
        ];
        for (name, extra) in cases {
            let mut argv = vec!["decern-serve", "--trust-proxy", "--addr", "127.0.0.1:0"];
            argv.extend(extra);
            let result = prepare(Args::try_parse_from(&argv).unwrap()).await;
            assert!(result.is_err(), "{name}: the boot was not refused");
            assert_eq!(
                listing(&dir),
                before,
                "{name}: a refused boot changed the directory"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An empty ledger file was signed by no key: it boots under an ephemeral key and under
    /// a key that does not exist yet, as a ledger that is not there does.
    #[tokio::test]
    async fn an_empty_ledger_file_is_a_new_ledger() {
        let dir = fresh_dir("empty-ledger");
        let ledger = dir.join("l.jsonl");
        std::fs::write(&ledger, b"").unwrap();
        let base = [
            "decern-serve",
            "--trust-proxy",
            "--addr",
            "127.0.0.1:0",
            "--ledger",
        ];
        let mut argv: Vec<&str> = base.to_vec();
        argv.push(ledger.to_str().unwrap());
        let m = dir.join("m.json");
        argv.extend(["--missions", m.to_str().unwrap()]);
        let boot = prepare(Args::parse_from(&argv)).await.unwrap();
        assert!(boot.line.contains("(ephemeral)"));
        drop(boot);
        let k = dir.join("k");
        argv.extend(["--key", k.to_str().unwrap()]);
        prepare(Args::parse_from(&argv)).await.unwrap();
        assert!(k.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The registry's parent directory is created when the registry is opened, as it always
    /// was, since nothing can refuse the boot after that point.
    #[tokio::test]
    async fn the_registry_directory_is_created_when_the_registry_is_opened() {
        let dir = fresh_dir("registry-parent");
        let m = dir.join("new").join("m.json");
        let (k, l) = (dir.join("k"), dir.join("l.jsonl"));
        let argv = [
            "decern-serve",
            "--trust-proxy",
            "--addr",
            "127.0.0.1:0",
            "--key",
            k.to_str().unwrap(),
            "--ledger",
            l.to_str().unwrap(),
            "--missions",
            m.to_str().unwrap(),
        ];
        prepare(Args::parse_from(argv)).await.unwrap();
        assert!(
            m.parent().unwrap().is_dir(),
            "the registry directory was not created"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
