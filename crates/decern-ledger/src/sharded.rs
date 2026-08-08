// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! `ShardedLedger` — the hosted-topology ledger: one hash chain per
//! authority-domain ("shard"), safely extendable by any number of concurrent
//! `decern-server` replicas via a [`decern_store::LedgerHeadStore`].
//!
//! This reuses the EXACT chain-hash/sign logic [`crate::Ledger::append`] uses —
//! `chain_hash`, `key_fingerprint`, the `RecordOut` wire
//! shape — only the storage/coordination layer differs (a `decern_store`-backed
//! per-shard critical section instead of one `std::fs::File` + in-process
//! fields). The sovereign single-file [`crate::Ledger`] is completely untouched and
//! remains the default; `ShardedLedger` is constructed only for the hosted
//! `decern-serve --sharded <dir>` mode (a per-shard `flock` head store shared
//! by several processes on one host), never otherwise.
//!
//! Why a `critical_section` primitive, not just an `append`: a caller that must
//! read a shard's accumulated state, decide against it, and append — ALL
//! atomically. Without that, two concurrent callers can both read the same
//! pre-append state and both act on it (e.g. two writers each read head=N and
//! both write N+1, forking the chain). See [`decern_store::LedgerHeadStore`]'s own
//! doc for the full reasoning — this is the SAME property a single-process
//! `Mutex<Ledger>` already gave every caller today, generalized across replicas.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use decern_crypto::{Signer, SigningKey, VerifyingKey};
use decern_store::{HeadCursor, LedgerHeadStore, StoreError};
use serde::Serialize;

use crate::{
    Checkpoint, Entry, GENESIS, LedgerError, Record, chain_hash, checkpoint_bytes, key_fingerprint,
};

/// The reserved shard for entries whose subject has no resolvable
/// authority-domain (an unprovisioned/foreign/denied caller, or a system
/// action not scoped to any one tenant). Fail-closed ledgering still demands
/// every entry land SOMEWHERE — this is that home. Never allocatable as a
/// REAL tenant id: `decern-server`'s shard-key resolver must reject a directory
/// tenant literally named `__system__` at directory-load time (mirroring how
/// the kernel already rejects an empty tenant), so a crafted tenant can never
/// alias this reserved shard.
pub const UNATTRIBUTED_SHARD: &str = "__system__";

/// Write-side record shape — copied from `lib.rs`'s private `RecordOut` (that
/// one borrows `&RawValue` for zero-copy on the single-file hot path; this
/// owns its `entry_json` since the value is scoped to the closure that builds
/// it, cheaper here than adding a lifetime through `LedgerHeadStore`'s
/// closure-based API for one string field).
#[derive(Serialize)]
struct ShardRecordOut<'a> {
    entry: &'a serde_json::value::RawValue,
    prev: &'a str,
    hash: &'a str,
    sig_b64: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
}

pub struct ShardedLedger {
    store: Arc<dyn LedgerHeadStore>,
    key: SigningKey,
    /// Every key trusted to have signed this ledger's records (current +
    /// retired) — mirrors `Ledger`'s own keyring. Used by [`Self::self_verify`].
    verifiers: Vec<VerifyingKey>,
}

fn store_to_ledger_err(e: StoreError) -> LedgerError {
    LedgerError::Io {
        path: "<sharded ledger store>".into(),
        err: e.to_string(),
    }
}

impl ShardedLedger {
    pub fn new(
        store: Arc<dyn LedgerHeadStore>,
        key: SigningKey,
        retired: Vec<VerifyingKey>,
    ) -> Self {
        let mut verifiers = retired;
        let current = key.verifying_key();
        if !verifiers.iter().any(|v| v.to_bytes() == current.to_bytes()) {
            verifiers.push(current);
        }
        Self {
            store,
            key,
            verifiers,
        }
    }

    /// The signing key's public fingerprint — ONE key across every shard (a
    /// `decern-server` deployment has one ledger signing identity; sharding only
    /// splits WRITE coordination, never the signer), so unlike a chain-verify
    /// or a bare-seq lookup this needs no shard argument and is never
    /// cross-shard-ambiguous. Mirrors `Ledger::pubkey_hex`.
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    /// Every shard the underlying store has ever seen a head cursor for —
    /// store ground truth (never derived from the live Directory) — a
    /// distinction that matters for shard verification. Public so callers outside this crate (the
    /// event forwarder — "which shards exist to sweep") can enumerate shards
    /// without reaching into the private `store` field themselves.
    pub fn list_shards(&self) -> Result<Vec<String>, LedgerError> {
        self.store.list_shards().map_err(store_to_ledger_err)
    }

    /// Append `entry` to `shard`'s chain — the sharded analog of
    /// `Ledger::append`, held under `shard`'s exclusive lock for the write.
    pub fn append(&self, shard: &str, entry: Entry) -> Result<Record, LedgerError> {
        let (record, _) = self.critical_section(shard, move |_existing| Ok((Some(entry), ())))?;
        // `critical_section`'s closure above always returns `Some(entry)`, so
        // `append` never legitimately produces `None` — a `None` here would
        // mean the store silently dropped a write, which is exactly the
        // fail-closed condition callers must see as an error, not a quiet Ok.
        record.ok_or_else(|| LedgerError::Io {
            path: format!("<sharded ledger, shard {shard}>"),
            err: "append produced no record (store did not commit)".into(),
        })
    }

    /// The general primitive: run `f` with the shard's existing records (each
    /// the same `Value`-parsed shape `Ledger::read_records` produces — an
    /// object with `entry`/`prev`/`hash`/`sig_b64`/`kid`), under the shard's
    /// EXCLUSIVE lock, and optionally append one new entry it decides on. This
    /// is what lets a caller read the shard's accumulated state and append
    /// atomically — see this module's top doc.
    ///
    /// `f`'s `T` is returned alongside the `Record` (if one was appended) — the
    /// caller's own decision value plus whatever else it needs, so this one call
    /// replaces "read, decide, append" with no gap a concurrent replica could land
    /// in between.
    pub fn critical_section<T>(
        &self,
        shard: &str,
        f: impl FnOnce(&[serde_json::Value]) -> Result<(Option<Entry>, T), LedgerError>,
    ) -> Result<(Option<Record>, T), LedgerError>
    where
        T: Default,
    {
        let mut inner_err: Option<LedgerError> = None;
        let mut out_record: Option<Record> = None;
        let mut out_value: T = T::default();
        // `LedgerHeadStore::with_shard` requires an `FnMut` (the trait can't
        // express "called at most once" through `dyn`) even though every real
        // implementation calls it exactly once per `with_shard` call. Wrap the
        // caller's true `FnOnce` in an `Option` so it type-checks as `FnMut`
        // while still only ever running once — `.take()` yields `None` on any
        // hypothetical second call, which would be a store bug, not ours.
        let mut f = Some(f);

        self.store
            .with_shard(shard, &mut |cursor, existing| {
                let f = f
                    .take()
                    .expect("LedgerHeadStore::with_shard invoked its callback more than once");
                let parsed: Result<Vec<serde_json::Value>, _> = existing
                    .iter()
                    .map(|r| serde_json::from_str(&r.record_json))
                    .collect();
                let parsed = match parsed {
                    Ok(p) => p,
                    Err(e) => {
                        inner_err = Some(LedgerError::Serde(e.to_string()));
                        return Ok(None);
                    }
                };

                let (maybe_entry, value) = match f(&parsed) {
                    Ok(x) => x,
                    Err(e) => {
                        inner_err = Some(e);
                        return Ok(None);
                    }
                };
                out_value = value;

                let Some(mut entry) = maybe_entry else {
                    return Ok(None); // f decided nothing appends (e.g. a deny).
                };

                let next_seq = cursor.map(|c| c.next_seq).unwrap_or(0);
                let prev_hash = cursor
                    .map(|c| c.last_hash.clone())
                    .unwrap_or_else(|| GENESIS.to_owned());
                entry.seq = next_seq;

                let entry_json = match serde_json::to_string(&entry) {
                    Ok(s) => s,
                    Err(e) => {
                        inner_err = Some(LedgerError::Serde(e.to_string()));
                        return Ok(None);
                    }
                };
                let hash = chain_hash(entry_json.as_bytes(), &prev_hash);
                let sig = self.key.sign(&hash);
                let hash_hex = hex::encode(hash);
                let sig_b64 = B64.encode(sig.to_bytes());
                let kid = key_fingerprint(&self.key.verifying_key());

                let raw_entry = match serde_json::value::RawValue::from_string(entry_json) {
                    Ok(r) => r,
                    Err(e) => {
                        inner_err = Some(LedgerError::Serde(e.to_string()));
                        return Ok(None);
                    }
                };
                let line = match serde_json::to_string(&ShardRecordOut {
                    entry: &raw_entry,
                    prev: &prev_hash,
                    hash: &hash_hex,
                    sig_b64: &sig_b64,
                    kid: Some(&kid),
                }) {
                    Ok(l) => l,
                    Err(e) => {
                        inner_err = Some(LedgerError::Serde(e.to_string()));
                        return Ok(None);
                    }
                };

                out_record = Some(Record {
                    entry,
                    prev: prev_hash,
                    hash: hash_hex.clone(),
                    sig_b64,
                    kid: Some(kid),
                });

                Ok(Some((
                    HeadCursor {
                        next_seq: next_seq + 1,
                        last_hash: hash_hex,
                    },
                    line,
                )))
            })
            .map_err(store_to_ledger_err)?;

        if let Some(e) = inner_err {
            return Err(e);
        }
        Ok((out_record, out_value))
    }

    /// A per-shard analog of `Ledger::checkpoint`: the shard's current head
    /// (root = last_hash, count = next_seq), signed with this ledger's key.
    /// A never-written shard checkpoints at genesis (root =
    /// `GENESIS`, count = 0) — the same "shard exists with zero history"
    /// state `append`'s first call on it would extend, not an error.
    ///
    /// Reads the cursor directly via `LedgerHeadStore::with_shard` rather
    /// than going through `critical_section` (which also parses every
    /// record's JSON to hand the caller a full read) — a checkpoint only
    /// needs the cursor, so this skips that work entirely.
    pub fn checkpoint(&self, shard: &str, ts_ms: u64) -> Result<Checkpoint, LedgerError> {
        let mut cursor_out: Option<HeadCursor> = None;
        self.store
            .with_shard(shard, &mut |cursor, _existing| {
                cursor_out = cursor.cloned();
                Ok(None)
            })
            .map_err(store_to_ledger_err)?;
        let (root, count) = match cursor_out {
            Some(c) => (c.last_hash, c.next_seq),
            None => (GENESIS.to_owned(), 0),
        };
        let sig = self.key.sign(&checkpoint_bytes(&root, count, ts_ms));
        Ok(Checkpoint {
            root,
            count,
            ts_ms,
            pubkey_hex: self.pubkey_hex(),
            sig_b64: B64.encode(sig.to_bytes()),
        })
    }

    /// A shard's records as `Value`s (mirrors `Ledger::read_records`) — for
    /// callers that just need to read (e.g. an admin-plane ledger browser),
    /// not run a critical section. NOT locked across a subsequent write: two
    /// calls (`read_records` then `append`) are NOT atomic — use
    /// `critical_section` when the read must gate the write.
    pub fn read_records(
        &self,
        shard: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>, LedgerError> {
        let (_, records) = self.critical_section(shard, |existing| {
            Ok::<_, LedgerError>((None, existing.to_vec()))
        })?;
        Ok(records.into_iter().skip(offset).take(limit).collect())
    }

    /// `shard`'s stored records EXACTLY as persisted (byte-stable `record_json`
    /// lines) — unlike [`Self::read_records`] (which reparses to `Value` for a
    /// browser view), verification must hash the bytes actually stored, never a
    /// re-serialization. Reads the cursor's record list directly via
    /// `LedgerHeadStore::with_shard` rather than `critical_section` (which also
    /// eagerly parses every record to `Value` for callers that want that) — a
    /// pure read like this needs neither.
    fn raw_stored_records(
        &self,
        shard: &str,
    ) -> Result<Vec<decern_store::StoredRecord>, LedgerError> {
        let mut out = Vec::new();
        self.store
            .with_shard(shard, &mut |_cursor, existing| {
                out = existing.to_vec();
                Ok(None)
            })
            .map_err(store_to_ledger_err)?;
        Ok(out)
    }

    /// Re-read and verify `shard`'s own stored records against this ledger's whole
    /// keyring (current + retired), so a rotated log verifies end-to-end — the
    /// [`ShardedLedger`] analog of `Ledger::self_verify`. A never-written
    /// shard verifies as the degenerate empty case (`entries: 0, root: None`), not
    /// an error — mirrors `checkpoint`'s genesis state for the same shard. O(shard's
    /// entries); audit path, never the decision hot path.
    pub fn self_verify(&self, shard: &str) -> Result<crate::VerifyReport, LedgerError> {
        let records = self.raw_stored_records(shard)?;
        crate::verify_stored_records(&records, &self.verifiers)
    }

    /// `shard`'s records as VERBATIM stored bytes (`RawValue`, no reparse) — the
    /// sharded analog of `Ledger::read_raw_records`, what a per-tenant evidence
    /// bundle must ship (the hash chain commits to these exact bytes).
    pub fn read_raw_records(
        &self,
        shard: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<Box<serde_json::value::RawValue>>, LedgerError> {
        self.raw_stored_records(shard)?
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|r| {
                serde_json::value::RawValue::from_string(r.record_json)
                    .map_err(|e| LedgerError::Serde(e.to_string()))
            })
            .collect()
    }

    /// Read every stored record's chain hash, in order, as the Merkle LEAF DATA —
    /// the sharded analog of `Ledger::merkle_leaves`. Fails closed on a record with
    /// a missing or non-hex `hash`.
    fn merkle_leaves(&self, shard: &str) -> Result<Vec<Vec<u8>>, LedgerError> {
        let stored = self.raw_stored_records(shard)?;
        let mut leaves = Vec::with_capacity(stored.len());
        for (i, r) in stored.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(&r.record_json)
                .map_err(|e| LedgerError::Serde(e.to_string()))?;
            let hash_hex = v
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

    /// A single-snapshot read for an evidence bundle: the shard's cursor and full
    /// stored record set are read via ONE `with_shard` call, and
    /// count/records/checkpoint/tree_head are ALL derived from that one snapshot —
    /// unlike calling `checkpoint`/`read_raw_records`/`tree_head` separately (each
    /// its own store round trip), which lets a concurrent append land between
    /// calls and make the four mutually inconsistent (a bundle that fails its own
    /// verification: `records.last().hash != checkpoint.root`, or `tree_head`
    /// computed over a different record set than `records`). Read-only
    /// (`with_shard`'s callback returns `Ok(None)`, nothing is appended).
    pub fn evidence_snapshot(
        &self,
        shard: &str,
        ts_ms: u64,
    ) -> Result<
        (
            u64,
            Vec<decern_store::StoredRecord>,
            Checkpoint,
            crate::TreeHead,
        ),
        LedgerError,
    > {
        let mut cursor_out: Option<HeadCursor> = None;
        let mut existing_out: Vec<decern_store::StoredRecord> = Vec::new();
        self.store
            .with_shard(shard, &mut |cursor, existing| {
                cursor_out = cursor.cloned();
                existing_out = existing.to_vec();
                Ok(None)
            })
            .map_err(store_to_ledger_err)?;
        let (root, count) = match &cursor_out {
            Some(c) => (c.last_hash.clone(), c.next_seq),
            None => (GENESIS.to_owned(), 0),
        };
        let cp_sig = self.key.sign(&checkpoint_bytes(&root, count, ts_ms));
        let checkpoint = Checkpoint {
            root,
            count,
            ts_ms,
            pubkey_hex: self.pubkey_hex(),
            sig_b64: B64.encode(cp_sig.to_bytes()),
        };
        // Merkle leaves from the SAME snapshot (`existing_out`), not a fresh
        // `merkle_leaves` call that could race a concurrent append.
        let mut leaves = Vec::with_capacity(existing_out.len());
        for (i, r) in existing_out.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(&r.record_json)
                .map_err(|e| LedgerError::Serde(e.to_string()))?;
            let hash_hex = v
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
        let root_hex = hex::encode(crate::merkle::tree_hash(&leaves));
        let tree_size = leaves.len() as u64;
        let th_sig = self
            .key
            .sign(&crate::tree_head_bytes(&root_hex, tree_size, ts_ms));
        let tree_head = crate::TreeHead {
            merkle_root: root_hex,
            tree_size,
            ts_ms,
            pubkey_hex: self.pubkey_hex(),
            sig_b64: B64.encode(th_sig.to_bytes()),
        };
        Ok((count, existing_out, checkpoint, tree_head))
    }

    /// Sign `shard`'s current Merkle tree head — the RFC 9162 root over the
    /// shard's own record hashes, enabling compact per-tenant inclusion proofs.
    /// The sharded analog of `Ledger::tree_head`; `tree_size == shard's count`.
    pub fn tree_head(&self, shard: &str, ts_ms: u64) -> Result<crate::TreeHead, LedgerError> {
        let leaves = self.merkle_leaves(shard)?;
        let root_hex = hex::encode(crate::merkle::tree_hash(&leaves));
        let tree_size = leaves.len() as u64;
        let sig = self
            .key
            .sign(&crate::tree_head_bytes(&root_hex, tree_size, ts_ms));
        Ok(crate::TreeHead {
            merkle_root: root_hex,
            tree_size,
            ts_ms,
            pubkey_hex: self.pubkey_hex(),
            sig_b64: B64.encode(sig.to_bytes()),
        })
    }
}

/// One shard's verification outcome from [`verify_sharded_dir`]: the shard name paired
/// with either its [`crate::VerifyReport`] or the tamper/read error it failed with.
pub type ShardVerification = (String, Result<crate::VerifyReport, LedgerError>);

/// Audit every shard of a flock (`FileLedgerHeadStore`) sharded ledger rooted at
/// `dir` — the operator-facing verification of a `decern-serve --sharded <dir>`
/// deployment, the sharded counterpart of the single-file [`crate::verify`]. Opens
/// the head store read-only, enumerates its committed shards
/// ([`decern_store::LedgerHeadStore::list_shards`]), and runs over each shard's
/// byte-stable stored records the SAME hash-chain + signature check
/// [`ShardedLedger::self_verify`] runs (via the shared `verify_stored_records`
/// core). With `pubkey` every record's signature is checked; without it, only the
/// hash chain (still fail-closed) — exactly matching [`crate::verify`]'s single-key
/// behavior.
///
/// Returns one `(shard, result)` per shard in `list_shards` order, each result the
/// shard's own [`crate::VerifyReport`] or the tamper/read error it failed with — so a
/// caller reports every shard's PASS/TAMPER and fails overall if any shard failed,
/// rather than stopping at the first. `dir` must be an existing directory: unlike
/// `FileLedgerHeadStore::new` (which would create it), a verify of a path that is not
/// a directory is a hard error, never a clean "zero shards" verdict on a ledger that
/// is not there.
pub fn verify_sharded_dir(
    dir: &std::path::Path,
    pubkey: Option<&VerifyingKey>,
) -> Result<Vec<ShardVerification>, LedgerError> {
    if !dir.is_dir() {
        return Err(LedgerError::Io {
            path: dir.display().to_string(),
            err: "not a sharded head-store directory (path is missing or not a directory)".into(),
        });
    }
    let store = decern_store::FileLedgerHeadStore::new(dir).map_err(|e| LedgerError::Io {
        path: dir.display().to_string(),
        err: e.to_string(),
    })?;
    // Empty keyring => chain-only (signatures not checked), same as `verify(_, None)`.
    let keys: Vec<VerifyingKey> = pubkey.into_iter().copied().collect();

    let shards = store.list_shards().map_err(store_to_ledger_err)?;
    let mut out = Vec::with_capacity(shards.len());
    for shard in shards {
        out.push((shard.clone(), verify_one_shard(&store, &shard, &keys)));
    }
    Ok(out)
}

/// Read one shard's stored records under its lock (read-only — appends nothing) and
/// verify them against `keys`. A store/read failure and a tamper both surface as this
/// shard's `Err`, so [`verify_sharded_dir`] can attribute either to the exact shard.
fn verify_one_shard(
    store: &dyn LedgerHeadStore,
    shard: &str,
    keys: &[VerifyingKey],
) -> Result<crate::VerifyReport, LedgerError> {
    let mut records: Vec<decern_store::StoredRecord> = Vec::new();
    store
        .with_shard(shard, &mut |_cursor, existing| {
            records = existing.to_vec();
            Ok(None)
        })
        .map_err(store_to_ledger_err)?;
    crate::verify_stored_records(&records, keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use decern_store::MemoryLedgerHeadStore;
    use serde_json::json;

    fn entry(action: &str, resource_id: &str) -> Entry {
        Entry {
            seq: 0, // assigned by append
            ts_ms: 1234,
            subject_type: "Principal".into(),
            subject_id: "agent1".into(),
            action: action.into(),
            resource_type: "Resource".into(),
            resource_id: resource_id.into(),
            context: json!({"now": 100}),
            decision: true,
            reasons: vec![],
            ..Default::default()
        }
    }

    fn ledger() -> ShardedLedger {
        let key = decern_crypto::generate().unwrap();
        ShardedLedger::new(Arc::new(MemoryLedgerHeadStore::new()), key, Vec::new())
    }

    #[test]
    fn append_assigns_sequential_seq_and_chains_the_hash() {
        let l = ledger();
        let r0 = l.append("acme", entry("Read", "r1")).unwrap();
        assert_eq!(r0.entry.seq, 0);
        assert_eq!(r0.prev, GENESIS);

        let r1 = l.append("acme", entry("Read", "r2")).unwrap();
        assert_eq!(r1.entry.seq, 1);
        // The chain: record 1's `prev` is record 0's `hash`, not genesis again —
        // this IS the tamper-evidence property, so it's worth asserting directly
        // rather than trusting `append` "worked" from seq alone.
        assert_eq!(r1.prev, r0.hash);
        assert_ne!(r0.hash, r1.hash);
    }

    #[test]
    fn read_records_returns_entries_in_append_order() {
        let l = ledger();
        l.append("acme", entry("Read", "r1")).unwrap();
        l.append("acme", entry("Write", "r2")).unwrap();
        let records = l.read_records("acme", 0, 10).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["entry"]["action"], "Read");
        assert_eq!(records[1]["entry"]["action"], "Write");
    }

    #[test]
    fn shards_hold_independent_chains() {
        let l = ledger();
        let acme0 = l.append("acme", entry("Read", "r1")).unwrap();
        let other0 = l.append("other-tenant", entry("Read", "r1")).unwrap();
        // Both are the FIRST entry of their own chain — genesis-chained
        // independently, not sharing one global sequence.
        assert_eq!(acme0.entry.seq, 0);
        assert_eq!(other0.entry.seq, 0);
        assert_eq!(acme0.prev, GENESIS);
        assert_eq!(other0.prev, GENESIS);
        assert_eq!(l.read_records("acme", 0, 10).unwrap().len(), 1);
        assert_eq!(l.read_records("other-tenant", 0, 10).unwrap().len(), 1);
    }

    #[test]
    fn critical_section_appends_nothing_when_f_declines() {
        let l = ledger();
        let (record, decision) = l
            .critical_section("acme", |_existing| Ok::<_, LedgerError>((None, "denied")))
            .unwrap();
        assert!(record.is_none());
        assert_eq!(decision, "denied");
        assert_eq!(l.read_records("acme", 0, 10).unwrap().len(), 0);
    }

    #[test]
    fn critical_section_propagates_a_gate_error_and_writes_nothing() {
        let l = ledger();
        let err = l.critical_section("acme", |_existing: &[serde_json::Value]| {
            Err::<(Option<Entry>, ()), _>(LedgerError::Serde("boom".into()))
        });
        assert!(err.is_err());
        assert_eq!(l.read_records("acme", 0, 10).unwrap().len(), 0);
    }

    /// The property this whole redesign exists to prove, exercised through the
    /// REAL `ShardedLedger` API a caller would use — not just the underlying trait
    /// in isolation (already covered in `decern-store`'s own tests). Exercises a
    /// read-then-decide-then-append critical section: read a shard's accumulated
    /// amount, gate against a ceiling, append only if under it. A ceiling of 100
    /// with 10 threads each trying to add 15 permits AT MOST 6 successful appends
    /// (90) — a 7th would exceed 100. If the read-then-gate-then-append weren't
    /// atomic across threads, more than 6 could read the same stale "0 so far" and
    /// all pass.
    #[test]
    fn concurrent_critical_sections_on_one_shard_respect_the_accumulated_ceiling() {
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        const CEILING: u64 = 100;
        const PER_OP: u64 = 15;

        let l = StdArc::new(ledger());
        let allowed = StdArc::new(AtomicUsize::new(0));

        let threads: Vec<_> = (0..10)
            .map(|i| {
                let l = l.clone();
                let allowed = allowed.clone();
                thread::spawn(move || {
                    let (record, _) = l
                        .critical_section("acme", move |existing| {
                            let spent: u64 = existing
                                .iter()
                                .filter_map(|r| r["entry"]["context"]["amount"].as_u64())
                                .sum();
                            // Widen the race window the same way the decern-store
                            // test does — if the lock only covered the WRITE,
                            // every thread would see `spent == 0` here.
                            thread::sleep(std::time::Duration::from_micros(200));
                            if spent + PER_OP > CEILING {
                                return Ok::<_, LedgerError>((None, ()));
                            }
                            let mut e = entry("MoveMoney", &format!("op-{i}"));
                            e.context = json!({"now": 100, "amount": PER_OP});
                            Ok((Some(e), ()))
                        })
                        .unwrap();
                    if record.is_some() {
                        allowed.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        let allowed_count = allowed.load(Ordering::SeqCst);
        assert!(
            allowed_count <= 6,
            "ceiling exceeded: {allowed_count} appends of {PER_OP} \
             against a ceiling of {CEILING} (amount {})",
            allowed_count as u64 * PER_OP
        );
        let total_spent: u64 = l
            .read_records("acme", 0, 100)
            .unwrap()
            .iter()
            .filter_map(|r| r["entry"]["context"]["amount"].as_u64())
            .sum();
        assert!(
            total_spent <= CEILING,
            "recorded spend {total_spent} exceeds ceiling {CEILING}"
        );
    }

    #[test]
    fn checkpoint_reflects_the_shards_current_head_and_a_never_written_shard_checkpoints_at_genesis()
     {
        let l = ledger();
        let empty = l.checkpoint("never-written", 1000).unwrap();
        assert_eq!(empty.root, GENESIS);
        assert_eq!(empty.count, 0);

        l.append("acme", entry("Read", "r1")).unwrap();
        let r1 = l.append("acme", entry("Read", "r2")).unwrap();
        let cp = l.checkpoint("acme", 2000).unwrap();
        assert_eq!(cp.root, r1.hash);
        assert_eq!(cp.count, 2);
        assert_eq!(cp.ts_ms, 2000);
        assert_eq!(cp.pubkey_hex, l.pubkey_hex());
    }

    #[test]
    fn self_verify_passes_for_a_healthy_shard_and_never_written_verifies_empty() {
        let l = ledger();
        l.append("acme", entry("Read", "r1")).unwrap();
        let r2 = l.append("acme", entry("Read", "r2")).unwrap();
        // A second, unrelated shard must not leak into "acme"'s report.
        l.append("other-tenant", entry("Read", "r1")).unwrap();

        let report = l.self_verify("acme").unwrap();
        assert_eq!(report.entries, 2);
        assert!(report.signatures_checked);
        assert_eq!(report.root.as_deref(), Some(r2.hash.as_str()));

        // A never-written shard verifies as the degenerate empty case, not an
        // error — mirrors `checkpoint`'s genesis state for the same shard.
        let empty = l.self_verify("never-written").unwrap();
        assert_eq!(empty.entries, 0);
        assert_eq!(empty.root, None);
    }

    #[test]
    fn self_verify_detects_a_tampered_entry() {
        let store: Arc<dyn LedgerHeadStore> = Arc::new(MemoryLedgerHeadStore::new());
        let key = decern_crypto::generate().unwrap();
        let l = ShardedLedger::new(store.clone(), key, Vec::new());
        l.append("acme", entry("Read", "r1")).unwrap();
        let r1 = l.append("acme", entry("Read", "r2")).unwrap();
        assert!(l.self_verify("acme").unwrap().signatures_checked);

        // Append a THIRD record directly through the store with a hash that does
        // NOT match its entry bytes. `LedgerHeadStore::with_shard` trusts its
        // caller's `record_json` verbatim (`ShardedLedger::append` never produces
        // this itself) — this simulates the corruption `self_verify` exists to
        // catch, e.g. a row edited directly in Postgres.
        let mut e3 = entry("Read", "r3");
        e3.seq = 2;
        let entry_json = serde_json::to_string(&e3).unwrap();
        let wrong_hash = "0".repeat(64);
        let line = format!(
            r#"{{"entry":{entry_json},"prev":"{}","hash":"{wrong_hash}","sig_b64":"","kid":null}}"#,
            r1.hash
        );
        store
            .with_shard("acme", &mut |cursor, _existing| {
                let c = cursor.unwrap().clone();
                Ok(Some((
                    HeadCursor {
                        next_seq: c.next_seq + 1,
                        last_hash: wrong_hash.clone(),
                    },
                    line.clone(),
                )))
            })
            .unwrap();

        let err = l.self_verify("acme").unwrap_err();
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "expected Tamper, got {err:?}"
        );
    }

    /// A unique, self-cleaning temp directory for an on-disk flock head store.
    fn temp_store_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "decern-verify-sharded-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Look up one shard's result in a `verify_sharded_dir` return by shard name.
    fn shard_result<'a>(
        results: &'a [crate::ShardVerification],
        shard: &str,
    ) -> &'a Result<crate::VerifyReport, LedgerError> {
        &results
            .iter()
            .find(|(s, _)| s == shard)
            .unwrap_or_else(|| panic!("shard {shard} not in results"))
            .1
    }

    /// `verify_sharded_dir` over a REAL on-disk flock store: every shard verifies
    /// clean (with and without a pubkey), and after a single byte is flipped inside
    /// one shard's stored record the tamper is pinned to THAT shard while the other
    /// still verifies — the property that justifies returning a per-shard result Vec.
    #[test]
    fn verify_sharded_dir_passes_clean_then_pins_a_tamper_to_its_shard() {
        let dir = temp_store_dir("tamper");
        let key = decern_crypto::generate().unwrap();
        let pubkey = key.verifying_key();
        let store: Arc<dyn LedgerHeadStore> =
            Arc::new(decern_store::FileLedgerHeadStore::new(&dir).unwrap());
        let l = ShardedLedger::new(store, key, Vec::new());
        l.append("acme", entry("Read", "acme-r0")).unwrap();
        l.append("acme", entry("Read", "acme-r1")).unwrap();
        l.append("beta", entry("Read", "beta-r0")).unwrap();

        // Clean, signatures checked (pubkey supplied).
        let clean = crate::verify_sharded_dir(&dir, Some(&pubkey)).unwrap();
        assert_eq!(clean.len(), 2, "two committed shards");
        let acme = shard_result(&clean, "acme").as_ref().unwrap();
        assert_eq!(acme.entries, 2);
        assert!(acme.signatures_checked);
        assert_eq!(shard_result(&clean, "beta").as_ref().unwrap().entries, 1);

        // Clean, chain-only (no pubkey) — mirrors `verify(_, None)`.
        let chain_only = crate::verify_sharded_dir(&dir, None).unwrap();
        assert!(
            !shard_result(&chain_only, "acme")
                .as_ref()
                .unwrap()
                .signatures_checked
        );

        // Flip a byte INSIDE acme's stored record (resource id text, kept the same
        // length so the outer `{cursor,records}` JSON still parses) — the store reads
        // it back fine; the hash recompute is what must fire.
        let shard_file = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p| {
                p.extension().and_then(|e| e.to_str()) == Some("shard")
                    && std::fs::read_to_string(p)
                        .map(|s| s.contains("acme-r1"))
                        .unwrap_or(false)
            })
            .expect("acme's .shard file");
        let corrupted = std::fs::read_to_string(&shard_file)
            .unwrap()
            .replace("acme-r1", "acme-rX");
        std::fs::write(&shard_file, corrupted).unwrap();

        let after = crate::verify_sharded_dir(&dir, Some(&pubkey)).unwrap();
        assert!(
            matches!(
                shard_result(&after, "acme"),
                Err(LedgerError::Tamper { .. })
            ),
            "acme must fail as Tamper, got {:?}",
            shard_result(&after, "acme")
        );
        assert!(
            shard_result(&after, "beta").is_ok(),
            "an untouched shard still verifies clean"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A path that is not an existing directory is a hard error, never a clean
    /// "zero shards" verdict — and the store must NOT create it as a side effect.
    #[test]
    fn verify_sharded_dir_errors_on_a_missing_directory() {
        let missing = temp_store_dir("missing").join("does-not-exist");
        assert!(!missing.exists());
        assert!(matches!(
            crate::verify_sharded_dir(&missing, None),
            Err(LedgerError::Io { .. })
        ));
        assert!(!missing.exists(), "verify must not create the directory");
    }

    #[test]
    fn read_raw_records_are_verbatim_and_tree_head_matches_a_fresh_merkle_computation() {
        let l = ledger();
        let r1 = l.append("acme", entry("Read", "r1")).unwrap();
        let r2 = l.append("acme", entry("Read", "r2")).unwrap();

        let raw = l.read_raw_records("acme", 0, 10).unwrap();
        assert_eq!(raw.len(), 2);
        let last: serde_json::Value = serde_json::from_str(raw[1].get()).unwrap();
        assert_eq!(last["hash"], json!(r2.hash));

        let th = l.tree_head("acme", 5000).unwrap();
        assert_eq!(th.tree_size, 2);
        assert_eq!(th.pubkey_hex, l.pubkey_hex());
        let leaves = vec![
            hex::decode(&r1.hash).unwrap(),
            hex::decode(&r2.hash).unwrap(),
        ];
        assert_eq!(
            th.merkle_root,
            hex::encode(crate::merkle::tree_hash(&leaves))
        );

        // A never-written shard's tree head is the degenerate empty-tree case.
        let empty = l.tree_head("never-written", 5000).unwrap();
        assert_eq!(empty.tree_size, 0);
    }
}
