// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! decern — prove your authorization holds over every input, decide, and verify the audit trail.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use decern_kernel::{EntityRef, Kernel, Model};

#[derive(Parser)]
#[command(
    name = "decern",
    version,
    about = "Proven authorization: prove, decide, verify"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Prove every safety invariant over the entire input space (cvc5).
    Prove {
        /// Model directory (authority.cedar, authority.cedarschema, entities.json). Omit for the built-in model.
        #[arg(long)]
        model: Option<PathBuf>,
        /// Path to the cvc5 solver, if not on PATH.
        #[arg(long)]
        cvc5: Option<PathBuf>,
        /// Per-suite timeout in seconds.
        #[arg(long, default_value_t = decern_proof::DEFAULT_PROVE_TIMEOUT_SECS)]
        timeout: u64,
    },
    /// Make one decision against the model.
    Decide {
        #[arg(long)]
        model: Option<PathBuf>,
        /// Subject as TYPE:ID (e.g. Principal:alice).
        #[arg(long)]
        subject: String,
        #[arg(long)]
        action: String,
        /// Resource as TYPE:ID (e.g. Resource:doc1).
        #[arg(long)]
        resource: String,
        /// Decision context as JSON; must carry `now` (epoch seconds).
        #[arg(long, default_value = "{\"now\":0}")]
        context: String,
    },
    /// Explain a recorded decision by sequence number — show why a decision
    /// came out as it did, reading only the record itself (no re-evaluation).
    Explain {
        /// Ledger file path (single file or segmented directory).
        #[arg(long)]
        ledger: PathBuf,
        /// Sequence number of the record to explain (0-based).
        #[arg(long)]
        seq: u64,
        /// Hex Ed25519 public key to verify the record's signature.
        #[arg(long)]
        pubkey: Option<String>,
        /// Output as JSON (machine-readable) instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Verify a tamper-evident ledger (hash chain always; signatures when a key is
    /// given). `--ledger` is a single file or a segmented directory; `--sharded` is a
    /// flock head-store directory, where every shard is verified.
    Verify {
        /// Single-file or segmented-directory ledger path.
        #[arg(long, conflicts_with = "sharded", required_unless_present = "sharded")]
        ledger: Option<PathBuf>,
        /// A flock `--sharded <dir>` head-store directory: verify every shard.
        #[arg(long)]
        sharded: Option<PathBuf>,
        /// Hex Ed25519 public key to check every record's signature.
        #[arg(long)]
        pubkey: Option<String>,
    },
}

fn load_model(dir: Option<PathBuf>) -> Result<Model> {
    match dir {
        Some(d) => {
            Model::from_dir(&d).with_context(|| format!("loading model from {}", d.display()))
        }
        None => Ok(Model::builtin()),
    }
}

fn parse_ref(s: &str) -> Result<EntityRef> {
    let (ty, id) = s
        .split_once(':')
        .with_context(|| format!("expected TYPE:ID, got {s:?}"))?;
    Ok(EntityRef {
        ty: ty.into(),
        id: id.into(),
    })
}

/// Explain a recorded decision by sequence number. Reads the record from the
/// ledger, verifies chain integrity, and outputs a faithful explanation of
/// what was recorded — not a re-derivation of policy.
fn explain(
    ledger_path: &std::path::Path,
    seq: u64,
    pubkey_hex: Option<&str>,
    json: bool,
) -> Result<ExitCode> {
    let key = pubkey_hex
        .map(|h| -> Result<_> {
            let bytes: [u8; 32] = hex::decode(h.trim())
                .context("decoding --pubkey hex")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("--pubkey must be 32 bytes"))?;
            ed25519_dalek::VerifyingKey::from_bytes(&bytes).context("invalid Ed25519 key")
        })
        .transpose()?;

    // Verify the whole chain: the offset includes seq, limit is 1 to materialize only that record.
    let (report, records) =
        decern_ledger::read_verified(ledger_path, key.as_ref(), seq as usize, 1)
            .context("reading ledger")?;

    if records.is_empty() {
        anyhow::bail!(
            "sequence {} is beyond the end of the ledger (contains {} records)",
            seq,
            report.entries
        );
    }

    let record_json = &records[0];
    let record: decern_ledger::Record =
        serde_json::from_value(record_json.clone()).context("parsing ledger record")?;

    if json {
        // Output the entry as-is (faithfully what was recorded)
        println!("{}", serde_json::to_string_pretty(&record.entry)?);
    } else {
        // Human-readable explanation
        let decision_str = if record.entry.decision {
            "ALLOW"
        } else {
            "DENY"
        };
        println!("seq:           {}", record.entry.seq);
        println!("timestamp:     {} (ms since epoch)", record.entry.ts_ms);
        println!(
            "subject:       {}:{}",
            record.entry.subject_type, record.entry.subject_id
        );
        println!("action:        {}", record.entry.action);
        println!(
            "resource:      {}:{}",
            record.entry.resource_type, record.entry.resource_id
        );
        println!("decision:      {}", decision_str);

        // Chain integrity
        println!();
        println!("chain:");
        println!("  prev:       {}", record.prev);
        println!("  hash:       {}", record.hash);
        println!(
            "  signature:  {} (verified)",
            if key.is_some() { "yes" } else { "not checked" }
        );
        if let Some(kid) = &record.kid {
            println!("  signed_by:  {}", kid);
        }

        // Decision metadata
        if !record.entry.reasons.is_empty() {
            println!();
            println!("reasoning:");
            for reason in &record.entry.reasons {
                println!("  - {}", reason);
            }
        }

        if let Some(digest) = &record.entry.parameter_digest {
            println!();
            println!(
                "parameter_digest: {} (binds to decision input, prevents TOCTOU)",
                digest
            );
        }

        if let Some(sponsor) = &record.entry.sponsor {
            println!();
            println!("accountable_owner: {}:{}", sponsor.kind, sponsor.id);
            if record.entry.sponsor_source == decern_ledger::SponsorSource::Explicit {
                println!("  (admin-set, not derived)");
            }
        }

        if let Some(mission) = &record.entry.mission {
            println!();
            println!("mission_justification:");
            println!("  approver:  {}", mission.approver);
            println!("  sha256:    {}", mission.s256);
        }

        if let Some(subject) = &record.entry.decision_subject {
            println!();
            println!("decision_affects:  {}:{}", subject.kind, subject.id);
        }

        println!();
        println!("note: This explanation is a faithful reading of the recorded entry.");
        println!("      It is NOT a re-derivation of policy, and NOT a claim about the present.");
        println!(
            "      The chain is verified intact; the signature is {}.",
            if key.is_some() {
                "verified"
            } else {
                "not checked"
            }
        );
    }

    Ok(ExitCode::SUCCESS)
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ExitCode> {
    match Cli::parse().cmd {
        Cmd::Explain {
            ledger,
            seq,
            pubkey,
            json,
        } => explain(&ledger, seq, pubkey.as_deref(), json),
        Cmd::Prove {
            model,
            cvc5,
            timeout,
        } => {
            let model = load_model(model)?;
            let outcomes =
                decern_proof::prove_all(&model, cvc5.as_deref(), Duration::from_secs(timeout))
                    .await?;
            let mut proven = 0usize;
            for o in &outcomes {
                if o.proven {
                    proven += 1;
                    println!("PASS  {:<18} {}", o.name, o.statement);
                } else {
                    println!("FAIL  {:<18} {}", o.name, o.statement);
                    if let Some(cx) = &o.counterexample {
                        println!("      counterexample: {cx}");
                    }
                }
            }
            println!("\n{proven}/{} invariants proven", outcomes.len());
            Ok(if proven == outcomes.len() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Cmd::Decide {
            model,
            subject,
            action,
            resource,
            context,
        } => {
            let model = load_model(model)?;
            let kernel = Kernel::new(&model)?;
            let ctx = serde_json::from_str(&context).context("parsing --context as JSON")?;
            let r = kernel.check(&parse_ref(&subject)?, &action, &parse_ref(&resource)?, &ctx);
            println!("{}", if r.decision { "ALLOW" } else { "DENY" });
            for reason in &r.reasons {
                println!("  reason: {reason}");
            }
            for err in &r.errors {
                println!("  cause: {err}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Verify {
            ledger,
            sharded,
            pubkey,
        } => {
            let key = pubkey
                .map(|h| -> Result<_> {
                    let bytes: [u8; 32] = hex::decode(h.trim())
                        .context("decoding --pubkey hex")?
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("--pubkey must be 32 bytes"))?;
                    ed25519_dalek::VerifyingKey::from_bytes(&bytes).context("invalid Ed25519 key")
                })
                .transpose()?;

            if let Some(dir) = sharded {
                return verify_sharded(&dir, key.as_ref());
            }

            // clap requires exactly one of --ledger / --sharded, so --ledger is set here.
            let ledger = ledger.expect("clap requires --ledger unless --sharded is given");
            // A flock head-store directory passed as --ledger would otherwise fall into
            // the segmented-ledger path and report a misleading "no manifest.json";
            // point the operator at --sharded, the mode that can actually verify it.
            if ledger.is_dir() && looks_like_sharded_dir(&ledger) {
                anyhow::bail!(
                    "{} looks like a flock sharded head-store directory; verify it with \
                     `decern verify --sharded {}`",
                    ledger.display(),
                    ledger.display()
                );
            }
            let report = decern_ledger::verify(&ledger, key.as_ref())?;
            if !report.signatures_checked {
                // Prominent, at the TOP: a chain-only pass is NOT a full verify — it does
                // not catch a record signed by nobody, so it is not "verify without trusting
                // the operator". Do not let it read as a clean pass.
                println!("NOTE: no --pubkey given — hash chain verified, signatures NOT checked.");
                println!("      This is a chain-only pass, not a full verify; pass --pubkey <kid>");
                println!("      to check every record's signature.");
            }
            println!("OK  {} entries", report.entries);
            println!("    root: {}", report.root.as_deref().unwrap_or("(empty)"));
            println!(
                "    signatures: {}",
                if report.signatures_checked {
                    "verified"
                } else {
                    "not checked (no key given)"
                }
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// True if `dir` holds any `*.shard` file — the flock head-store layout. Used only to
/// redirect an operator who passed such a directory to `--ledger` toward `--sharded`.
fn looks_like_sharded_dir(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("shard"))
        })
        .unwrap_or(false)
}

/// Verify every shard of a `--sharded <dir>` flock deployment: PASS/TAMPER per shard,
/// with a non-zero exit if any shard failed. Signatures are checked when a key is given
/// (same as single-file verify); the hash chain always is.
fn verify_sharded(
    dir: &std::path::Path,
    key: Option<&ed25519_dalek::VerifyingKey>,
) -> Result<ExitCode> {
    let results = decern_ledger::verify_sharded_dir(dir, key)?;
    if results.is_empty() {
        println!("no shards found to verify in {}", dir.display());
        return Ok(ExitCode::SUCCESS);
    }
    // Describe the mode BEFORE the per-shard results — it is what will be checked,
    // not a verdict. A failing shard aborts its own signature check, so printing
    // "verified" as a trailer after a TAMPER line would misread as a pass.
    if key.is_some() {
        println!("signatures: checked against --pubkey");
    } else {
        // Prominent, at the TOP: a chain-only pass is NOT a full verify.
        println!("NOTE: no --pubkey given — hash chains verified, signatures NOT checked.");
        println!("      This is a chain-only pass, not a full verify; pass --pubkey <kid>.");
    }
    let total = results.len();
    let mut failed = 0usize;
    for (shard, res) in &results {
        match res {
            Ok(r) => println!(
                "PASS   shard {shard}: {} entries  root {}",
                r.entries,
                r.root.as_deref().unwrap_or("(empty)")
            ),
            Err(e) => {
                failed += 1;
                println!("TAMPER shard {shard}: {e}");
            }
        }
    }
    if failed > 0 {
        println!("FAILED: {failed} of {total} shard(s) did not verify");
        Ok(ExitCode::FAILURE)
    } else {
        println!("OK: all {total} shard(s) verified");
        Ok(ExitCode::SUCCESS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ref_splits_type_and_id() {
        let r = parse_ref("Principal:alice").unwrap();
        assert_eq!(r.ty, "Principal");
        assert_eq!(r.id, "alice");
        assert!(parse_ref("noseparator").is_err());
    }
}
