// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! Verifying a ledger from its stored bytes: the chain, each record's signature when a keyring is
//! given, and the Merkle leaves the records commit to.

#[cfg(doc)]
use crate::Ledger;
use crate::checkpoint::{InclusionProof, key_fingerprint};
use crate::error::LedgerError;
use crate::merkle;
use crate::open::Location;
use crate::record::{Entry, GENESIS, RecordIn, chain_hash};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use decern_crypto::VerifyingKey;
use std::path::Path;

#[derive(Debug)]
pub struct VerifyReport {
    pub entries: u64,
    pub root: Option<String>,
    pub signatures_checked: bool,
}

/// Verify a ledger file: the hash chain always; every entry signature when a key is
/// supplied. Single-key convenience over [`verify_with_keys`] — for a key-ROTATED
/// log (entries under more than one key) use that with the full keyring.
#[must_use = "ledger verification failure must be checked"]
pub fn verify(path: &Path, pubkey: Option<&VerifyingKey>) -> Result<VerifyReport, LedgerError> {
    let loc = Location::detect(path);
    match pubkey {
        None => verify_inner(&loc, &[], None),
        Some(k) => verify_inner(&loc, std::slice::from_ref(k), None),
    }
}

/// Verify the whole chain (fail-closed on any tamper) AND return a window of the parsed
/// records — the OFFLINE auditor read: an auditor holds the ledger file and, out of band,
/// the public key, but not the private signing key `Ledger::open` demands. With `pubkey`
/// each record's signature is checked too; without it, only the hash chain (still
/// fail-closed). The whole log is scanned to verify integrity; only records in
/// `[offset, offset+limit)` are materialized (memory stays bounded to the window). The
/// records are the exact stored JSON (as `read_records` returns them), NOT verbatim bytes.
pub fn read_verified(
    path: &Path,
    pubkey: Option<&VerifyingKey>,
    offset: usize,
    limit: usize,
) -> Result<(VerifyReport, Vec<serde_json::Value>), LedgerError> {
    let loc = Location::detect(path);
    let mut window = ReadWindow {
        offset,
        end: offset.saturating_add(limit),
        records: Vec::new(),
    };
    let report = match pubkey {
        None => verify_inner(&loc, &[], Some(&mut window)),
        Some(k) => verify_inner(&loc, std::slice::from_ref(k), Some(&mut window)),
    }?;
    Ok((report, window.records))
}

/// A bounded collection window for [`read_verified`]: while the whole chain is scanned
/// for integrity, only records whose index falls in `[offset, end)` are materialized.
pub(crate) struct ReadWindow {
    offset: usize,
    end: usize,
    records: Vec<serde_json::Value>,
}

/// Verify a ledger file against a KEYRING — the rotation-aware form. Each record is
/// checked against the key its `kid` names; a legacy record with no `kid` (written
/// before rotation support) is accepted against any key in the ring. A record whose
/// `kid` names a key NOT in the ring is tamper (fail-closed: an unknown signer is
/// never trusted). An empty ring means "signatures not checked" (chain only), same
/// as [`verify`] with `None`.
#[must_use = "ledger verification failure must be checked"]
pub fn verify_with_keys(path: &Path, keys: &[VerifyingKey]) -> Result<VerifyReport, LedgerError> {
    verify_inner(&Location::detect(path), keys, None)
}

pub(crate) fn verify_inner(
    location: &Location,
    keys: &[VerifyingKey],
    sink: Option<&mut ReadWindow>,
) -> Result<VerifyReport, LedgerError> {
    let (lines, torn) = location.prefix_lines()?;
    // Verify the PREFIX (torn fragment already excluded). A failure here is a
    // fault in fully-terminated, acked history → genuine Tamper, propagated
    // as-is whether or not a torn fragment also exists.
    let report = verify_lines(lines, keys, sink)?;
    match torn {
        None => Ok(report),
        // Prefix is clean AND a torn fragment trails it → report it distinctly so
        // callers can tell a benign crash-mid-append from an attack. The open
        // path catches this and heals; read-only verifiers surface it.
        Some(t) => Err(LedgerError::TornTail {
            healed_entries: report.entries,
            healed_root: report.root,
            torn_path: t.path.display().to_string(),
            torn_from_offset: t.offset,
        }),
    }
}

/// The shared per-record verify core: hash-chain always, signatures when `keys` is
/// non-empty. `lines` yields each stored record's raw JSON text in seq order (an
/// `Err` propagates a read failure as-is) — the SAME logic verifies a File-backed
/// [`Ledger`]'s lines (via [`verify_inner`]) and a [`sharded::ShardedLedger`] shard's
/// stored records (via [`verify_stored_records`]), so the two can never diverge on
/// what counts as tamper.
fn verify_lines(
    lines: impl Iterator<Item = Result<String, LedgerError>>,
    keys: &[VerifyingKey],
    mut sink: Option<&mut ReadWindow>,
) -> Result<VerifyReport, LedgerError> {
    let check_sigs = !keys.is_empty();

    let mut prev = GENESIS.to_owned();
    let mut count: u64 = 0;

    for (i, line) in lines.enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: RecordIn = serde_json::from_str(&line).map_err(|e| LedgerError::Tamper {
            seq: i as u64,
            why: format!("unparseable record: {e}"),
        })?;

        // Hash the entry bytes EXACTLY as stored — no re-serialization.
        let entry_bytes = record.entry.get().as_bytes();
        let entry: Entry =
            serde_json::from_str(record.entry.get()).map_err(|e| LedgerError::Tamper {
                seq: count,
                why: format!("unparseable entry: {e}"),
            })?;

        if entry.seq != count {
            return Err(LedgerError::Tamper {
                seq: count,
                why: format!("sequence break (found seq {})", entry.seq),
            });
        }
        if record.prev != prev {
            return Err(LedgerError::Tamper {
                seq: count,
                why: "broken chain link (prev mismatch — record edited, moved or removed)".into(),
            });
        }

        let hash = chain_hash(entry_bytes, &record.prev);
        if hex::encode(hash) != record.hash {
            return Err(LedgerError::Tamper {
                seq: count,
                why: "entry altered (hash mismatch)".into(),
            });
        }

        if check_sigs {
            let sig_bytes: [u8; 64] = B64
                .decode(&record.sig_b64)
                .map_err(|_| LedgerError::Tamper {
                    seq: count,
                    why: "unparseable signature".into(),
                })?
                .try_into()
                .map_err(|_| LedgerError::Tamper {
                    seq: count,
                    why: "signature length".into(),
                })?;
            let sig = decern_crypto::Signature::from_bytes(&sig_bytes);

            // Pick the verifying key: the one this record's `kid` names, or — for a
            // legacy record with no `kid` — any key in the ring (a pre-rotation log
            // was signed by a single key that is in the ring).
            let verified = match &record.kid {
                Some(kid) => match keys.iter().find(|k| key_fingerprint(k) == *kid) {
                    Some(k) => k.verify_strict(&hash, &sig).is_ok(),
                    None => {
                        return Err(LedgerError::Tamper {
                            seq: count,
                            why: format!(
                                "record signed by key {kid}, which is not in the trusted keyring"
                            ),
                        });
                    }
                },
                None => keys.iter().any(|k| k.verify_strict(&hash, &sig).is_ok()),
            };
            if !verified {
                return Err(LedgerError::Tamper {
                    seq: count,
                    why: "signature invalid (chain rewritten with a different key?)".into(),
                });
            }
        }

        // Materialize into the read window only when in range — the whole chain is still
        // scanned for integrity, but memory stays bounded to `[offset, end)`. Push the
        // WHOLE stored line (same shape `read_records` returns: `entry` + envelope), so a
        // read_verified consumer sees exactly what the admin projection would, but only
        // after the chain (and, with a key, the signatures) checked out.
        if let Some(w) = sink.as_deref_mut() {
            let idx = count as usize;
            if idx >= w.offset && idx < w.end {
                let value: serde_json::Value =
                    serde_json::from_str(&line).map_err(|e| LedgerError::Serde(e.to_string()))?;
                w.records.push(value);
            }
        }

        prev = record.hash;
        count += 1;
    }

    Ok(VerifyReport {
        entries: count,
        root: if count > 0 { Some(prev) } else { None },
        signatures_checked: check_sigs,
    })
}

/// Verify one [`sharded::ShardedLedger`] shard's stored records — the hash-chain +
/// signature check [`sharded::ShardedLedger::self_verify`] runs, over the exact
/// byte-stable lines a [`decern_store::LedgerHeadStore`] persisted (never a
/// re-serialization — same byte-stability discipline as the File path). `records`
/// must already be in seq order (what `LedgerHeadStore::with_shard` hands back).
pub(crate) fn verify_stored_records(
    records: &[decern_store::StoredRecord],
    keys: &[VerifyingKey],
) -> Result<VerifyReport, LedgerError> {
    verify_lines(
        records.iter().map(|r| Ok(r.record_json.clone())),
        keys,
        None,
    )
}

/// Verify a checkpoint's own signature against a pinned key — does the ledger key
/// that signs entries also vouch for this commitment? Does not read the ledger.
/// The Merkle leaf data of each record, in order: the 32 raw bytes its `hash` hex encodes.
/// One definition, shared by the signing side and the read-only verifying side — a leaf that
/// meant two different things in two places would produce proofs that verify nowhere.
/// The Merkle leaf data of each stored line, in order — the record-form derivation, for a
/// caller holding raw lines from [`Ledger::raw_records`]. Only the `hash` field is
/// deserialized, and a line without a valid one fails closed exactly as the record
/// form does.
pub fn leaves_from_lines(lines: &[String]) -> Result<Vec<Vec<u8>>, LedgerError> {
    #[derive(serde::Deserialize)]
    struct HashOnly {
        hash: String,
    }
    let mut leaves = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        let h: HashOnly = serde_json::from_str(line).map_err(|_| LedgerError::Tamper {
            seq: i as u64,
            why: "record missing hash field".into(),
        })?;
        let bytes = hex::decode(&h.hash).map_err(|_| LedgerError::Tamper {
            seq: i as u64,
            why: "record hash is not valid hex".into(),
        })?;
        leaves.push(bytes);
    }
    Ok(leaves)
}

/// Inclusion proofs over already-derived leaves — the proving half of
/// [`Ledger::inclusion_proofs`], for a caller who took the leaves out from under the
/// lock. Returns proofs in the order the sequences were given; a sequence past the end
/// fails the whole call rather than being skipped.
pub fn inclusion_proofs_over(
    leaves: &[Vec<u8>],
    seqs: &[u64],
) -> Result<Vec<InclusionProof>, LedgerError> {
    let tree_size = leaves.len() as u64;
    seqs.iter()
        .map(|&seq| {
            let idx = seq as usize;
            let path = merkle::inclusion_proof(leaves, idx).ok_or_else(|| LedgerError::Tamper {
                seq,
                why: "inclusion index past the end of the log".into(),
            })?;
            Ok(InclusionProof {
                leaf_index: seq,
                tree_size,
                leaf_data: hex::encode(&leaves[idx]),
                audit_path: path.iter().map(hex::encode).collect(),
            })
        })
        .collect()
}

pub(crate) fn leaves_from_records(recs: &[serde_json::Value]) -> Result<Vec<Vec<u8>>, LedgerError> {
    let mut leaves = Vec::with_capacity(recs.len());
    for (i, r) in recs.iter().enumerate() {
        let hash_hex = r
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| LedgerError::Tamper {
                seq: i as u64,
                why: "record missing hash field".into(),
            })?;
        let bytes = hex::decode(hash_hex).map_err(|_| LedgerError::Tamper {
            seq: i as u64,
            why: "record hash is not valid hex".into(),
        })?;
        leaves.push(bytes);
    }
    Ok(leaves)
}

/// Merkle leaves of the ledger at `path`, read-only — no signing key required.
///
/// Producing a tree head needs the ledger key, because a commitment nobody signed commits
/// nobody. CHECKING one does not: an auditor holds the log and a public key, never the key
/// that wrote it. This is the path that makes an anchored commitment verifiable by someone
/// other than its author, which is the only thing that makes anchoring worth doing.
///
/// Verifies the whole chain on the way through, so leaves are never derived from records
/// that do not hold together.
pub fn merkle_leaves_at(
    path: &Path,
    pubkey: Option<&VerifyingKey>,
) -> Result<Vec<Vec<u8>>, LedgerError> {
    let (_report, records) = read_verified(path, pubkey, 0, usize::MAX)?;
    leaves_from_records(&records)
}
