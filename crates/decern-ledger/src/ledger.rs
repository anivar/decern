// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The append-only, signed, hash-chained ledger: opening a file or a segmented directory,
//! appending, key rotation, segment rollover, and the checkpoints, tree heads, proofs and anchors
//! it issues over its own records.

use crate::checkpoint::key_fingerprint;
use crate::error::{LedgerError, io_err};
use crate::open::{Location, lock_single_writer, open_append_owner_only, resolve_open_head};
use crate::record::{Entry, GENESIS, Record, RecordOut, chain_hash};
use crate::segment::{self, RolloverPolicy};
use crate::verify::{SignerSpan, VerifyReport, verify_inner};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use decern_crypto::{Signer, SigningKey, VerifyingKey};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

mod commitments;
#[cfg(test)]
mod tests;

/// Append-only writer. Opening an existing ledger verifies the whole chain
/// (and, with this key, every signature) before accepting new entries —
/// fail-closed: a corrupt audit trail refuses further writes.
pub struct Ledger {
    location: Location,
    /// The path `file` is currently open on: the single file's path in
    /// unsegmented mode, or the active segment's path in segmented mode. Used
    /// only for error messages on the write path — reads always go through
    /// `location`, never this field.
    active_path: PathBuf,
    key: SigningKey,
    file: File,
    last_hash: String,
    next_seq: u64,
    /// The full set of keys trusted to have signed this log: every RETIRED key plus
    /// the CURRENT signing key. A key-rotated log has entries under more than one
    /// key; verification (open, [`self_verify`](Ledger::self_verify)) checks each
    /// record against the key its `kid` names, drawn from this ring — so rotation
    /// never bricks a long-lived log.
    verifiers: Vec<VerifyingKey>,
    /// Each key that has signed this log, in the order it took over. A key that another
    /// has followed may not sign again, so [`rotate`](Ledger::rotate) refuses it.
    signers: Vec<SignerSpan>,
    /// When true, every append `sync_data()`s to disk before returning — crash-DURABLE
    /// (a "complete" log cannot lose its tail on power loss), at a per-append fsync cost.
    /// Off by default (crash-consistent, fast); opt in via [`Ledger::set_sync`] for a
    /// regulated deployment that must not lose a recorded decision.
    sync: bool,
    /// `Some` only for a segmented ledger (opened via
    /// [`Ledger::open_segmented`]) — the rollover trigger policy plus the
    /// in-memory manifest state `append` consults/updates. `None` for every
    /// single-file ledger, the overwhelming majority, which never rolls over.
    rollover: Option<RolloverState>,
    /// Set once a write failed after bytes may have reached the file. The file can then
    /// end in part of a record, and a record appended after it would be unreadable
    /// behind it, so every later append is refused until the ledger is reopened, which
    /// trims an unterminated tail.
    failed: bool,
    /// The single-file ledger's writer lock, released when the ledger is dropped. `None` for
    /// a segmented ledger, which takes no lock: neither binary writes one.
    _writer_lock: Option<crate::open::WriterLock>,
}

/// The first [`count`](Prefix::count) records of a ledger, readable without holding it.
/// See [`Ledger::prefix`].
pub struct Prefix {
    location: Location,
    count: u64,
}

impl Prefix {
    /// How many records the prefix holds.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The prefix's records exactly as stored, one string per line. Lines past the prefix,
    /// including one being appended now, are not read.
    pub fn lines(&self) -> Result<Vec<String>, LedgerError> {
        let (lines, _torn) = self.location.prefix_lines()?;
        let mut out = Vec::new();
        for line in lines {
            if out.len() as u64 == self.count {
                break;
            }
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            out.push(line);
        }
        if (out.len() as u64) < self.count {
            return Err(LedgerError::Tamper {
                seq: out.len() as u64,
                why: format!(
                    "{} records on disk where {} were written",
                    out.len(),
                    self.count
                ),
            });
        }
        Ok(out)
    }
}

struct RolloverState {
    policy: RolloverPolicy,
    manifest: segment::Manifest,
}

impl Ledger {
    /// Open a single-key ledger (the common case). Equivalent to
    /// [`open_with_verifiers`](Ledger::open_with_verifiers) with no retired keys.
    pub fn open(path: &Path, key: SigningKey) -> Result<Self, LedgerError> {
        Self::open_with_verifiers(path, key, Vec::new())
    }

    /// Open a ledger that may have been KEY-ROTATED: `key` is the current signing
    /// key, `retired` the public keys of every previously-active signing key. The
    /// existing chain is verified against the whole keyring (each record by the key
    /// its `kid` names; legacy kid-less records against any trusted key), so a
    /// rotated log reopens cleanly. Fail-closed: a record signed by a key NOT in the
    /// ring is tamper, and a `key` that another key has followed in the log is refused
    /// with [`LedgerError::KeySuperseded`] before anything is written.
    pub fn open_with_verifiers(
        path: &Path,
        key: SigningKey,
        retired: Vec<VerifyingKey>,
    ) -> Result<Self, LedgerError> {
        Self::open_single_inner(path, key, retired, None)
    }

    /// Shared single-file open. `anchor` is passed through to
    /// [`resolve_open_head`] so that, when a torn tail is found, the committed
    /// height is consulted BEFORE the torn fragment is truncated — a ragged
    /// truncation of acked history is rejected as tamper without ever mutating
    /// the file.
    fn open_single_inner(
        path: &Path,
        key: SigningKey,
        retired: Vec<VerifyingKey>,
        anchor: Option<&Path>,
    ) -> Result<Self, LedgerError> {
        if path.is_dir() {
            return Err(LedgerError::Io {
                path: path.display().to_string(),
                err: "this path is a segmented ledger directory — use Ledger::open_segmented \
                      instead of open/open_with_verifiers"
                    .into(),
            });
        }
        // Before anything reads the log: a second writer must not judge, or trim, a tail the
        // first is still writing.
        let writer_lock = lock_single_writer(path)?;
        let mut verifiers = retired;
        let current = key.verifying_key();
        if !verifiers.iter().any(|v| v.to_bytes() == current.to_bytes()) {
            verifiers.push(current);
        }
        let location = Location::Single(path.to_owned());
        // A ledger the lock just created, still empty, is a new one, as an absent file was
        // before the lock existed; one that was there is verified, empty or not.
        let fresh = !path.exists()
            || (writer_lock.created && fs::metadata(path).is_ok_and(|m| m.len() == 0));
        let (last_hash, next_seq, signers) = if !fresh {
            let report = resolve_open_head(&location, &verifiers, &current, anchor)?;
            (
                report.root.unwrap_or_else(|| GENESIS.to_owned()),
                report.entries,
                report.signers,
            )
        } else {
            (GENESIS.to_owned(), 0, Vec::new())
        };
        let file = open_append_owner_only(path)?;
        Ok(Ledger {
            location,
            active_path: path.to_owned(),
            key,
            file,
            last_hash,
            next_seq,
            verifiers,
            signers,
            sync: false,
            rollover: None,
            failed: false,
            _writer_lock: Some(writer_lock),
        })
    }

    /// Open a ledger AND fail-closed check it against its persisted anchor in one
    /// step — the constructor a server's startup uses. Equivalent to
    /// [`open_with_verifiers`](Ledger::open_with_verifiers) followed by
    /// [`verify_against_anchor`](Ledger::verify_against_anchor): the log must be
    /// internally consistent under the keyring AND still extend its last committed
    /// height, so a truncation across a restart refuses the open rather than silently
    /// serving a shortened audit trail.
    pub fn open_anchored(
        path: &Path,
        key: SigningKey,
        retired: Vec<VerifyingKey>,
        anchor_path: &Path,
    ) -> Result<Self, LedgerError> {
        // The open consults the anchor before it heals a torn tail or judges the key, so a
        // truncation refuses it as tamper whether or not it left a torn tail.
        Self::open_single_inner(path, key, retired, Some(anchor_path))
    }

    /// Open (or create) a SEGMENTED ledger at `dir` — the opt-in alternative
    /// to the single ever-growing file, for a long-lived sovereign deployment.
    /// `dir` becomes a directory of numbered segment files plus a
    /// `manifest.json`; `policy` controls when `append` rolls the active
    /// segment over to a new one. An existing single-file ledger is never
    /// silently upgraded — this only ever creates or reopens a directory, and
    /// [`open_with_verifiers`](Ledger::open_with_verifiers) refuses to open a
    /// directory in the other direction, so the two modes can't be confused
    /// for each other by accident.
    ///
    /// Reopen is fail-closed exactly like the single-file constructors: the
    /// whole chain (every segment, in order) is re-verified against the
    /// keyring before any further append is accepted. Every SEALED segment is
    /// (re-)marked read-only (0400 on Unix) on open — self-healing after a
    /// crash that landed between committing the manifest and applying that
    /// permission, since the permission bit is defense-in-depth only, never
    /// the source of truth (see the `segment` module).
    pub fn open_segmented(
        dir: &Path,
        key: SigningKey,
        retired: Vec<VerifyingKey>,
        policy: RolloverPolicy,
    ) -> Result<Self, LedgerError> {
        Self::open_segmented_inner(dir, key, retired, policy, None)
    }

    /// Shared segmented open — the multi-file analogue of
    /// [`open_single_inner`](Ledger::open_single_inner). A torn tail can only
    /// ever be in the ACTIVE (last) segment, since every sealed segment ended on
    /// a committed boundary; `anchor` gates the heal against the committed height
    /// exactly as in the single-file case.
    fn open_segmented_inner(
        dir: &Path,
        key: SigningKey,
        retired: Vec<VerifyingKey>,
        policy: RolloverPolicy,
        anchor: Option<&Path>,
    ) -> Result<Self, LedgerError> {
        let mut verifiers = retired;
        let current = key.verifying_key();
        if !verifiers.iter().any(|v| v.to_bytes() == current.to_bytes()) {
            verifiers.push(current);
        }
        fs::create_dir_all(dir).map_err(|e| io_err(dir, e))?;
        let manifest = match segment::load_manifest(dir)? {
            Some(m) => m,
            None => segment::initialize(dir)?,
        };
        let location = Location::Segmented(dir.to_owned());

        // Reassert permissions BEFORE verify/heal: seal every sealed segment,
        // and — crucially — UNSEAL the active segment first, so that if a torn
        // tail lands in it, `resolve_open_head`'s `heal_torn_tail` (which opens
        // the file `write(true)`) can truncate the fragment even when a prior
        // crash left the active segment defensively 0400. Healing a torn tail is
        // a write; it must never be blocked by the very permission bit the open
        // path exists to self-heal.
        for seg in manifest.segments.iter().filter(|s| s.end_seq.is_some()) {
            segment::seal_file_permissions(&dir.join(&seg.file));
        }
        let active = manifest
            .active()
            .ok_or_else(|| LedgerError::Io {
                path: dir.display().to_string(),
                err: "segmented ledger manifest has no active (unsealed) segment".into(),
            })?
            .clone();
        let active_path = dir.join(&active.file);
        segment::unseal_file_permissions(&active_path);

        let report = resolve_open_head(&location, &verifiers, &current, anchor)?;

        let file = open_append_owner_only(&active_path)?;
        Ok(Ledger {
            location,
            active_path,
            key,
            file,
            last_hash: report.root.unwrap_or_else(|| GENESIS.to_owned()),
            next_seq: report.entries,
            verifiers,
            signers: report.signers,
            sync: false,
            rollover: Some(RolloverState { policy, manifest }),
            failed: false,
            _writer_lock: None,
        })
    }

    /// [`open_segmented`](Ledger::open_segmented) plus the same fail-closed
    /// anchor check [`open_anchored`](Ledger::open_anchored) applies — a
    /// segmented ledger's committed height is anchored exactly the same way
    /// as a single-file one's (root+count don't care how many files the bytes
    /// span).
    pub fn open_segmented_anchored(
        dir: &Path,
        key: SigningKey,
        retired: Vec<VerifyingKey>,
        policy: RolloverPolicy,
        anchor_path: &Path,
    ) -> Result<Self, LedgerError> {
        Self::open_segmented_inner(dir, key, retired, policy, Some(anchor_path))
    }

    /// Rotate the signing key. Entries already written stay verifiable under the
    /// retired key (kept in the keyring); every subsequent entry is signed by
    /// `new_key` and carries its `kid`. The chain is uninterrupted — no re-signing of
    /// the past, and no republish. On the next restart, pass the retired public key
    /// to [`open_with_verifiers`](Ledger::open_with_verifiers) so the whole log still
    /// verifies.
    ///
    /// Once the new key has signed, the retired one may not sign this log again:
    /// verification refuses a record under it. Rotating back to a key another key has
    /// already followed is refused here with [`LedgerError::KeySuperseded`].
    pub fn rotate(&mut self, new_key: SigningKey) -> Result<(), LedgerError> {
        let current = new_key.verifying_key();
        let kid = key_fingerprint(&current);
        if let Some(next) = crate::verify::successor(&self.signers, &kid) {
            return Err(LedgerError::KeySuperseded {
                why: format!(
                    "key {} signed after it, from seq {}",
                    next.kid, next.first_seq
                ),
                kid,
            });
        }
        if !self
            .verifiers
            .iter()
            .any(|v| v.to_bytes() == current.to_bytes())
        {
            self.verifiers.push(current);
        }
        self.key = new_key;
        Ok(())
    }

    /// The public keys of every key trusted to have signed this log (retired +
    /// current), as hex fingerprints — what an auditor pins across a rotation.
    pub fn verifier_fingerprints(&self) -> Vec<String> {
        self.verifiers.iter().map(key_fingerprint).collect()
    }

    /// Whether a write error has stopped this ledger. It refuses every append until it is
    /// reopened, so a process holding it needs a restart to record again.
    pub fn has_failed(&self) -> bool {
        self.failed
    }

    /// Enable/disable fsync-per-append (see the `sync` field). Returns self for
    /// builder-style config right after `open`.
    pub fn set_sync(&mut self, sync: bool) -> &mut Self {
        self.sync = sync;
        self
    }

    /// Append `entry` to the log. `entry.seq` is assigned here; the serialized
    /// bytes are hashed into the chain, signed, and written verbatim, so an
    /// external verifier recomputes the exact same hash from what is on disk.
    pub fn append(&mut self, mut entry: Entry) -> Result<Record, LedgerError> {
        if self.failed {
            return Err(self.failed_err());
        }
        if let Some(state) = &self.rollover {
            let current_bytes = self.file.metadata().map(|m| m.len()).unwrap_or(0);
            if Self::should_roll_over(state, self.next_seq, current_bytes, entry.ts_ms) {
                self.roll_over(entry.ts_ms)?;
            }
        }
        // If this append is the active segment's first-ever record, rebase its
        // `opened_ms` to this entry's real `ts_ms`. Every segment `roll_over`
        // creates is already seeded correctly (its `opened_ms` IS the
        // triggering entry's `ts_ms`, so this is a no-op there); the one case
        // that needs it is segment 1 of a fresh ledger, whose `opened_ms`
        // `segment::initialize` hardcodes to 0 before any real entry exists to
        // read a timestamp from. Left unrebased, EVERY append after the first
        // would compare a real ts_ms against that stale 0 — landing in a
        // different epoch bucket almost every time and rolling over one record
        // after the first no matter how close in time the two really are.
        let this_seq = self.next_seq;
        if let Some(state) = &self.rollover {
            let needs_rebase = state
                .manifest
                .active()
                .is_some_and(|s| s.start_seq == this_seq && s.opened_ms != entry.ts_ms);
            if needs_rebase {
                // Mutate a CLONE and only commit it to `self.rollover.manifest`
                // after the persist below succeeds (mirroring `roll_over`'s own
                // clone-then-commit-on-success discipline a few lines down) — a
                // transient `save_manifest` failure (disk full, permission
                // blip) must not leave the in-memory manifest disagreeing with
                // what's actually on disk, which would otherwise let a
                // same-timestamp retry see `opened_ms` already "correct" in
                // memory and silently skip persisting it forever.
                let mut rebased = state.manifest.clone();
                if let Some(active) = rebased.active_mut() {
                    active.opened_ms = entry.ts_ms;
                }
                if let Location::Segmented(dir) = &self.location {
                    segment::save_manifest(dir, &rebased)?;
                }
                if let Some(state) = &mut self.rollover {
                    state.manifest = rebased;
                }
            }
        }
        entry.seq = self.next_seq;
        // Serialize the entry ONCE; these exact bytes are hashed, signed,
        // and written. Nothing downstream re-serializes.
        let entry_json =
            serde_json::to_string(&entry).map_err(|e| LedgerError::Serde(e.to_string()))?;
        let hash = chain_hash(entry_json.as_bytes(), &self.last_hash);
        let sig = self.key.sign(&hash);
        let hash_hex = hex::encode(hash);
        let sig_b64 = B64.encode(sig.to_bytes());
        // Stamp the signing key's fingerprint so a key-rotated log stays verifiable:
        // this record names which key signed it. Envelope-only, not hashed.
        let kid = key_fingerprint(&self.key.verifying_key());

        let raw_entry = serde_json::value::RawValue::from_string(entry_json)
            .map_err(|e| LedgerError::Serde(e.to_string()))?;
        let mut line = serde_json::to_string(&RecordOut {
            entry: &raw_entry,
            prev: &self.last_hash,
            hash: &hash_hex,
            sig_b64: &sig_b64,
            kid: Some(&kid),
        })
        .map_err(|e| LedgerError::Serde(e.to_string()))?;
        // Terminate IN the same buffer and write it in ONE `write_all`, so the
        // newline is never a separate syscall from the record it terminates.
        // This shrinks the partial-write window and makes newline-termination the
        // single, reliable signal the reopen path keys torn-tail detection on: a
        // present `\n` proves the whole record landed, its absence proves a torn
        // (never-acked) tail. (`write_all` may still short-write on a crash, but
        // it can no longer succeed at the record yet skip a separate terminator.)
        line.push('\n');
        self.write_line(&line)?;

        if self.signers.last().is_none_or(|s| s.kid != kid) {
            self.signers.push(SignerSpan {
                kid: kid.clone(),
                first_seq: self.next_seq,
            });
        }
        let record = Record {
            entry,
            prev: std::mem::replace(&mut self.last_hash, hash_hex.clone()),
            hash: hash_hex,
            sig_b64,
            kid: Some(kid),
        };
        self.next_seq += 1;
        Ok(record)
    }

    /// Append several entries as one durable step. Each is chained, signed and written
    /// exactly as [`Ledger::append`] writes it; when sync is on, the file is synced once
    /// at the end rather than once per entry, and what landed before a failure is synced
    /// before the error is returned — a record this call reported written is as durable
    /// as any other.
    pub fn append_all(&mut self, entries: Vec<Entry>) -> Result<Vec<Record>, LedgerError> {
        let sync = self.sync;
        self.sync = false;
        let mut records = Vec::with_capacity(entries.len());
        let mut outcome = Ok(());
        for entry in entries {
            match self.append(entry) {
                Ok(record) => records.push(record),
                Err(e) => {
                    outcome = Err(e);
                    break;
                }
            }
        }
        self.sync = sync;
        if sync {
            self.file.sync_data().map_err(|e| self.write_failed(e))?;
        }
        outcome?;
        Ok(records)
    }

    /// Write one newline-terminated record, and force it to disk when sync is on. This is
    /// the only place a record's bytes reach the file, so a failure here marks the ledger
    /// failed: part of the record may be in the file.
    fn write_line(&mut self, line: &str) -> Result<(), LedgerError> {
        self.file
            .write_all(line.as_bytes())
            .and_then(|_| self.file.flush())
            // Crash-DURABLE when enabled: force the bytes to disk before we return the
            // record, so a power loss cannot drop the tail of a log the caller was told
            // was written. Off by default (fast, crash-consistent).
            .and_then(|_| {
                if self.sync {
                    self.file.sync_data()
                } else {
                    Ok(())
                }
            })
            .map_err(|e| self.write_failed(e))
    }

    /// A write error after bytes may have reached the file: mark the ledger failed, so
    /// nothing is appended behind what may be part of a record.
    fn write_failed(&mut self, e: std::io::Error) -> LedgerError {
        self.failed = true;
        io_err(&self.active_path, e)
    }

    /// The refusal every append returns once a write has failed part-way.
    fn failed_err(&self) -> LedgerError {
        io_err(
            &self.active_path,
            "an earlier write to this ledger failed part-way; reopen it before appending",
        )
    }

    /// Whether the NEXT append (which will carry `next_ts_ms`, on top of
    /// `current_bytes` already written to the active segment) should roll
    /// over first. `epoch_ms` compares `next_ts_ms` against the active
    /// segment's own `opened_ms` — the CALLER-SUPPLIED entry timestamp, never
    /// wall-clock time (this crate makes no wall-clock call of its own, so
    /// the decision stays deterministic and testable, matching the
    /// caller-supplied-time convention used throughout `decern-cli`).
    fn should_roll_over(
        state: &RolloverState,
        current_seq: u64,
        current_bytes: u64,
        next_ts_ms: u64,
    ) -> bool {
        // Never roll over a segment holding zero records yet. Without this,
        // the very first append into a fresh epoch-policy ledger rolls over
        // before writing anything: `segment::initialize` hardcodes the first
        // segment's `opened_ms` to 0 (it's created before any entry exists to
        // read a timestamp from), so a real ts_ms (~10^12) almost always
        // lands in a different epoch bucket than bucket 0 — producing a
        // permanently wasted, empty, sealed segment for no benefit. A segment
        // can only ever hold MORE by staying active until its first record.
        let active_is_empty = state
            .manifest
            .active()
            .is_some_and(|s| s.start_seq == current_seq);
        if active_is_empty {
            return false;
        }
        if let Some(max) = state.policy.max_bytes
            && current_bytes >= max
        {
            return true;
        }
        if let Some(epoch) = state.policy.epoch_ms {
            let opened = state
                .manifest
                .active()
                .map(|s| s.opened_ms)
                .unwrap_or(next_ts_ms);
            if epoch > 0 && next_ts_ms / epoch != opened / epoch {
                return true;
            }
        }
        false
    }

    /// Seal the active segment and switch to a fresh one. Only ever called
    /// (from `append`) when `self.rollover` is `Some`, i.e. only for a
    /// segmented ledger — see [`segment::roll_over`] for the crash-safety
    /// argument (the manifest rename is the single atomic commit point).
    fn roll_over(&mut self, next_ts_ms: u64) -> Result<(), LedgerError> {
        let Location::Segmented(dir) = &self.location else {
            return Err(LedgerError::Io {
                path: self.active_path.display().to_string(),
                err: "internal error: roll_over called on a non-segmented ledger".into(),
            });
        };
        let dir = dir.clone();
        let state = self.rollover.as_ref().ok_or_else(|| LedgerError::Io {
            path: dir.display().to_string(),
            err: "internal error: roll_over called with no rollover state".into(),
        })?;
        let (new_manifest, new_path) =
            segment::roll_over(&dir, &state.manifest, self.next_seq, next_ts_ms)?;
        self.file = OpenOptions::new()
            .append(true)
            .open(&new_path)
            .map_err(|e| io_err(&new_path, e))?;
        self.active_path = new_path;
        if let Some(state) = self.rollover.as_mut() {
            state.manifest = new_manifest;
        }
        Ok(())
    }

    /// The current head hash — export and anchor this externally.
    pub fn root(&self) -> &str {
        &self.last_hash
    }

    /// Number of entries appended so far (the next sequence number).
    pub fn count(&self) -> u64 {
        self.next_seq
    }

    /// Re-read and verify this ledger's own file against its whole keyring (every
    /// retired key plus the current one), so a rotated log verifies end-to-end. Used
    /// by the admin summary; O(entries), so not for the request hot path.
    pub fn self_verify(&self) -> Result<VerifyReport, LedgerError> {
        verify_inner(&self.location, &self.verifiers, None)
    }

    /// Hex of the Ed25519 public key that signs this ledger's entries — the
    /// fingerprint an auditor pins.
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    /// Every stored line, verbatim and unparsed — for a caller who must hold this
    /// ledger's lock as briefly as possible. The audit projection copies the bytes out
    /// under the lock and does every parse, match and proof after releasing it; what
    /// stays under the lock is one sequential read, not three parsing passes.
    pub fn raw_records(&self) -> Result<Vec<String>, LedgerError> {
        let mut out = Vec::new();
        for line in self.location.lines()? {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            out.push(line);
        }
        Ok(out)
    }

    /// The records written so far, as a handle that reads them without this ledger: records
    /// already written are never rewritten, so a caller can take this under a lock, release
    /// it, and read the prefix while later appends land after it.
    pub fn prefix(&self) -> Prefix {
        Prefix {
            location: self.location.clone(),
            count: self.next_seq,
        }
    }

    /// A window of records for the admin ledger browser: skip `offset`, take up
    /// to `limit`, each as its stored JSON object. Reads the file, so it's an
    /// admin/audit path, never the decision hot path.
    pub fn read_records(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>, LedgerError> {
        // `skip(offset)` and the `limit` break apply to ONE chained iterator
        // across every segment (single-file mode: trivially one file) — a
        // GLOBAL record index, never a per-segment one. Wrapping this loop
        // per-segment instead would re-apply both per file, which is wrong on
        // both counts for a window that straddles a segment boundary.
        let mut out = Vec::new();
        for line in self.location.lines()?.skip(offset) {
            if out.len() >= limit {
                break;
            }
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let v = serde_json::from_str(&line).map_err(|e| LedgerError::Serde(e.to_string()))?;
            out.push(v);
        }
        Ok(out)
    }

    /// A window of records as their VERBATIM stored bytes — the exact line each
    /// record was written as, preserved byte-for-byte (`RawValue`, no reparse).
    /// This is what an EXTERNALLY-VERIFIABLE evidence bundle must ship: the hash
    /// chain commits to the entry's stored bytes (`chain_hash(entry_bytes, prev)`),
    /// so a third party can only reproduce a record's hash from those exact bytes.
    /// `read_records` (which parses to `Value`) would re-serialize and reorder keys,
    /// breaking the hash — use this whenever the bytes are the proof, not the data.
    pub fn read_raw_records(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<Box<serde_json::value::RawValue>>, LedgerError> {
        // Same global-index discipline as `read_records` — see its comment.
        // This is the primitive an evidence bundle's span is built from, so a
        // span crossing a segment boundary must come out byte-identical to
        // requesting the same span from an equivalent single-file log.
        let mut out = Vec::new();
        for line in self.location.lines()?.skip(offset) {
            if out.len() >= limit {
                break;
            }
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let v: Box<serde_json::value::RawValue> =
                serde_json::from_str(&line).map_err(|e| LedgerError::Serde(e.to_string()))?;
            out.push(v);
        }
        Ok(out)
    }
}
