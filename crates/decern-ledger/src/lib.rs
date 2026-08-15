// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
#![forbid(unsafe_code)]
//! decern-ledger — the tamper-evident decision ledger (the audit column).
//!
//! Every authority decision is appended as a hash-chained, Ed25519-signed
//! record: `hash = SHA-256(entry_bytes ‖ prev_hash)`, signature over `hash`.
//! Any edit, reorder or in-place deletion breaks the chain; a wholesale
//! rewrite fails signature verification against the ledger key. What the
//! chain alone cannot detect is truncation of the *tail* — that is what
//! `root()` is for: export the head hash and anchor it externally (a
//! regulator, a notary, another system). Anchored root + intact chain =
//! complete, unmodified history.
//!
//! The chain hash covers the EXACT entry bytes as stored on disk (captured
//! via serde_json's RawValue at verify time), never a re-serialization — so
//! byte-stability is structural, not an assumption about JSON round-trips.
//! (Float round-tripping is NOT stable in serde_json without the
//! `float_roundtrip` feature; hashing re-serialized bytes was a confirmed
//! false-tamper bug that could brick an honest ledger.)

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use decern_crypto::{Signer, SigningKey, VerifyingKey};
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod jcs;
pub mod merkle;
mod segment;
pub mod sharded;
pub use jcs::{canonicalize, digest};
pub use segment::RolloverPolicy;
pub use sharded::{ShardVerification, ShardedLedger, UNATTRIBUTED_SHARD, verify_sharded_dir};

/// Where a [`Ledger`]'s bytes live: a single append-only file (the default)
/// or a segmented directory (opt-in, see
/// [`Ledger::open_segmented`]). `detect` is used ONLY by the path-taking free
/// functions (`verify`, `verify_with_keys`, `read_verified`,
/// `ledger_extends_checkpoint`) so they stay
/// segmentation-transparent for external callers with zero signature changes;
/// a `Ledger`'s own methods already know their kind from how they were
/// opened and never need to re-detect it.
enum Location {
    Single(PathBuf),
    Segmented(PathBuf),
}

impl Location {
    fn detect(path: &Path) -> Self {
        if path.is_dir() {
            Location::Segmented(path.to_path_buf())
        } else {
            Location::Single(path.to_path_buf())
        }
    }

    /// Every file this location's bytes live in, in seq order. `Single` is
    /// always exactly one path (even if it doesn't exist yet — the same
    /// "doesn't exist" a plain `File::open` would report); `Segmented` reads
    /// the manifest and fails closed if a listed segment is missing from
    /// disk.
    fn resolved_paths(&self) -> Result<Vec<PathBuf>, LedgerError> {
        match self {
            Location::Single(p) => Ok(vec![p.clone()]),
            Location::Segmented(dir) => segment::segment_paths(dir),
        }
    }

    fn lines(&self) -> Result<segment::ChainedLines, LedgerError> {
        Ok(segment::chained_lines(self.resolved_paths()?))
    }

    /// The lines of this location's PREFIX — every fully `\n`-terminated line —
    /// with any crash-torn trailing fragment (bytes after the final newline of
    /// the last file) excluded. Returns the iterator plus `Some(TornFragment)` when
    /// such a fragment exists, or `None` when the last file ends cleanly (the
    /// normal case). Verification and root re-derivation both consume THIS, so a
    /// torn fragment is never mistaken for a corrupt record.
    fn prefix_lines(&self) -> Result<(segment::ChainedLines, Option<TornFragment>), LedgerError> {
        let paths = self.resolved_paths()?;
        let torn = match paths.last() {
            Some(last) => scan_torn_tail(last)?,
            None => None,
        };
        let limit = torn.as_ref().map(|t| t.offset).unwrap_or(u64::MAX);
        Ok((segment::chained_lines_bounded(paths, limit), torn))
    }
}

/// A crash-torn trailing fragment discovered on the last file: the file does
/// not end in `\n`, so everything from `offset` (the byte just past the final
/// newline, or 0 if the file has no newline at all) to EOF was only partially
/// written and must be discarded to recover the verified prefix.
struct TornFragment {
    path: PathBuf,
    offset: u64,
}

/// Inspect `path`'s LAST byte. Returns `None` (no torn tail) when the file is
/// missing, empty, or already ends in `\n`. Otherwise the file's final record
/// was not newline-terminated → returns the offset just past its last `\n` (0
/// if none), i.e. where the log must be truncated to drop the torn fragment.
/// Keyed purely on newline-termination: given `append` writes `line + "\n"` in a
/// single `write_all`, a present terminator proves the whole record reached the
/// file, and its absence proves a partial write — so a terminated line is never
/// a torn tail (a terminated-but-corrupt final record stays `Tamper`), and an
/// unterminated one always is (even if its bytes happen to parse — it was never
/// acked, and keeping it would fuse onto the next append on one physical line).
fn scan_torn_tail(path: &Path) -> Result<Option<TornFragment>, LedgerError> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err(path, e)),
    };
    let len = f.metadata().map_err(|e| io_err(path, e))?.len();
    if len == 0 {
        return Ok(None);
    }
    // Cheap last-byte check first: a clean, newline-terminated file (the common
    // case) costs one seek + one byte read and exits here.
    f.seek(SeekFrom::End(-1)).map_err(|e| io_err(path, e))?;
    let mut last = [0u8; 1];
    f.read_exact(&mut last).map_err(|e| io_err(path, e))?;
    if last[0] == b'\n' {
        return Ok(None);
    }
    // Unterminated: scan backward in chunks for the final newline. The torn
    // fragment is a single partially-written record, but records can be large,
    // so loop rather than assume it fits one chunk.
    const CHUNK: u64 = 64 * 1024;
    let mut pos = len;
    let mut buf = vec![0u8; CHUNK as usize];
    while pos > 0 {
        let read_len = CHUNK.min(pos);
        let start = pos - read_len;
        f.seek(SeekFrom::Start(start))
            .map_err(|e| io_err(path, e))?;
        let slice = &mut buf[..read_len as usize];
        f.read_exact(slice).map_err(|e| io_err(path, e))?;
        if let Some(idx) = slice.iter().rposition(|&b| b == b'\n') {
            // Byte just past this newline, in absolute file coordinates.
            return Ok(Some(TornFragment {
                path: path.to_path_buf(),
                offset: start + idx as u64 + 1,
            }));
        }
        pos = start;
    }
    // No newline anywhere: the whole file is one torn (never-acked) record.
    Ok(Some(TornFragment {
        path: path.to_path_buf(),
        offset: 0,
    }))
}

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One record in the ledger: a decision — "what happened, with everything needed
/// to replay it". Several fields below are reserved and inert (see
/// each field's note): no shipped path sets them, they are retained only for
/// struct/type stability, and a plain decision leaves them at their defaults, which
/// serialize to no bytes — so every existing writer and stored line is unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub ts_ms: u64,
    pub subject_type: String,
    pub subject_id: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub context: serde_json::Value,
    pub decision: bool,
    pub reasons: Vec<String>,
    /// RFC 8785 SHA-256 digest of the parameters a decision was made over — binds a
    /// record to the EXACT arguments, closing the TOCTOU gap between "authorized"
    /// and "executed". Set by `decern-serve` on decide / mission transitions.

    /// The authority-graph edge type: `Attenuate` (default, omitted) = offline
    /// narrowing WITHIN the delegator's namespace (a decern tenant); `Mint` = a
    /// trusted-issuer crossing that no offline delegate can produce. Reserved and
    /// inert: never set by any shipped path, defaulted and
    /// skipped-when-default, so existing records' bytes and hashes are unchanged.
    #[serde(default, skip_serializing_if = "edge_is_attenuate")]
    pub edge: EdgeType,
    /// The accountable-owner — who stands behind `subject_id` existing and
    /// acting AT ALL. Resolved server-side from the directory's delegation chain —
    /// never a decision input (stripped before the kernel) and safe to store in the
    /// clear: it names a principal already visible elsewhere in the same tenant's
    /// directory, not third-party PII — EXCEPT for a self-sponsored root principal,
    /// where this equals `subject_id` verbatim. `None` on every record before this
    /// field existed, and on any subject the directory doesn't recognize (e.g. a
    /// global/static-token caller) — existing bytes and hashes are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sponsor: Option<Party>,
    /// Whether `sponsor` above was computed (`Derived`, the default — the pure
    /// root of the delegation chain) or set by an admin override, constrained
    /// to that same chain. Lets an auditor tell asserted from computed without
    /// re-deriving it. Default + skipped-when-default, so existing records'
    /// bytes and hashes are unchanged.
    #[serde(default, skip_serializing_if = "is_derived_sponsor")]
    pub sponsor_source: SponsorSource,
    /// The Mission that justified this decision, when decide ran under a live
    /// approval. `None` when no mission was bound (or on pre-mission records).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mission: Option<MissionRef>,
    /// The party the decision is *about* — the one it is taken upon, distinct
    /// from the acting `subject_id` and from the accountable `sponsor`.
    /// Descriptive, never an authorization input. Present only when that party
    /// is a third party: a decision about the requester, or about the owner of
    /// the resource named, carries none, because the record already says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_subject: Option<DecisionSubject>,
    /// The caller the server verified when it took this request — who ASSERTED the
    /// subject, distinct from the subject itself and from the accountable sponsor.
    /// Present only under bearer validation, where it is what the token proved, on
    /// decision records and mission lifecycle records (`Mission.Approve`, `Mission.Terminate`).
    /// Absent under a trusted front: an assertion the server did not verify itself does not
    /// belong on a permanent record. Descriptive, never a decision input.
    ///
    /// The token's `sub` is written verbatim, permanently, and the subject-side
    /// projection returns whole records — so front service identities here, not
    /// end-user tokens: a person's identifier in `sub` becomes visible to anyone
    /// holding a decision-subject handle on the same record, and cannot be redacted
    /// after the fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asserted_by: Option<AssertedBy>,
    /// Whether this decision is one an affected party should be told about. Recorded, not
    /// acted on: telling them is the job of whoever enforces the decision, and this server
    /// does not enforce. Recording it is what makes a notice that never went out a gap
    /// someone can point at rather than a thing nobody can prove either way.
    #[serde(default, skip_serializing_if = "is_false")]
    pub notice_required: bool,
    /// A challenge from the party this decision was about, and how it was answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<ChallengeRecord>,
    /// Digests of the things this record was bound to, by name.
    ///
    /// [`DIGEST_PARAMETERS`] binds the arguments a decision authorized. This binds
    /// everything else worth pinning, without a new column each time something is: a
    /// consumer of this crate records what its own decisions depend on under names it
    /// chooses, and a reader who does not know a name can still see that something was
    /// pinned and that it does not match.
    ///
    /// `decern-serve` writes [`DIGEST_AUTHORITY`]. The chain already proves a record was
    /// not altered afterwards; it says nothing about what the record was decided
    /// *against*, and that moves. Revoke a delegation tomorrow and an allow recorded today
    /// still reads as an allow, with nothing to say what was true when — the trail is
    /// immutable while the thing it refers to is not. A digest of the authority state
    /// makes the decision addressable: a later reading can tell whether the authority it
    /// was taken against is still the same one.
    ///
    /// Ordered, so the serialization is deterministic — this is inside the bytes the chain
    /// hashes, and a map that serialized in a different order each time would break it.
    /// Values are digests, not content: whatever is being pinned may be large, may be
    /// about a person, and cannot be taken back out of an append-only log.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub digests: BTreeMap<String, String>,
}

/// The exact arguments a decision authorized — what it was asked, not what it knew.
/// Binding them means a later reading can tell that the thing authorized is the thing
/// that was requested, rather than something substituted after the check.
pub const DIGEST_PARAMETERS: &str = "parameters";

/// The authority a decision was taken against — policy, schema and entity graph.
pub const DIGEST_AUTHORITY: &str = "authority";

fn is_false(b: &bool) -> bool {
    !*b
}

/// The verified caller of the request that produced a record: the token's subject, the
/// client acting for it, and the issuer that vouched — enough for a reader to ask the
/// right party why this request was made, and nothing a caller can write for itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertedBy {
    /// The token's `sub` — the party the issuer authenticated.
    pub sub: String,
    /// The token's `client_id` — the client acting for that party.
    pub client_id: String,
    /// The issuer whose signature the server verified.
    pub iss: String,
}

/// A challenge and its answer, on the record.
///
/// Written here rather than kept beside the log because a challenge nobody can find later
/// is the same as one that was never made — and because the point of answering is that the
/// answer, and its reason, are as durable as the decision they concern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRecord {
    /// The decision that was challenged.
    pub decision_ref: String,
    /// The handle the challenger proved standing as.
    pub decision_subject: String,
    /// The grounds given.
    pub basis: Vec<String>,
    /// What the challenger asked for, which is not what they necessarily got.
    pub requested_effect: String,
    /// What was done: the decision stood, or it was made again with the challenge in view.
    pub outcome: String,
    /// Why. An answer without a reason is a dismissal.
    pub outcome_basis: String,
    /// A digest of the evidence submitted, when any was — not the evidence itself.
    /// Whatever a party sends to argue their case is likely to be about them, and this
    /// log is append-only and signed: what lands here cannot be taken back. The digest
    /// is enough to show later that what was weighed is what was sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
}

/// The party a decision is about, as a pseudonymous reference.
///
/// A handle, not an identity: it addresses a party without naming one, so a
/// record can say who a decision concerned without becoming a place personal
/// data accumulates. Resolving it back to a person is a separate authority's
/// job, and deliberately not this one's.
///
/// Its integrity comes from the record that carries it — every entry here is
/// signed and chained — so a handle read out of a verified record is as
/// trustworthy as the record, and one read anywhere else is not trustworthy at
/// all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DecisionSubject {
    /// The pseudonymous reference itself.
    pub handle: String,
    /// The namespace the handle belongs to, and so how it could be resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// What the handle was minted for. Pairwise per purpose, so the same party
    /// is not linkable across two of them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

impl<'de> Deserialize<'de> for DecisionSubject {
    /// Accepts a bare handle or the full object, since a caller with nothing to
    /// say about scheme or purpose should not have to write an object to say it.
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Handle(String),
            Full {
                handle: String,
                #[serde(default)]
                scheme: Option<String>,
                #[serde(default)]
                purpose: Option<String>,
            },
        }
        Ok(match Wire::deserialize(d)? {
            Wire::Handle(handle) => DecisionSubject {
                handle,
                scheme: None,
                purpose: None,
            },
            Wire::Full {
                handle,
                scheme,
                purpose,
            } => DecisionSubject {
                handle,
                scheme,
                purpose,
            },
        })
    }
}

/// A Mission reference recorded on a decision Entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionRef {
    pub approver: String,
    pub s256: String,
}

/// A party referenced by a record — the accountable owner named by `sponsor`,
/// or the `decision_subject`. The acting subject is `subject_id` on the entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Party {
    pub kind: String,
    pub id: String,
}

/// How an authority-graph edge came to be — the attenuate-vs-mint distinction.
/// Typing every issuance edge lets the record tell offline narrowing apart from a
/// trusted-issuer crossing; the two carry different safety properties (only the
/// former is safe to delegate offline). Only `Attenuate` is used;
/// `Mint` is reserved and inert, retained so the enum stays stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EdgeType {
    /// Narrowing WITHIN a subject namespace (a decern tenant): child scopes ⊆ delegator,
    /// same tenant. Offline-delegable — an intermediate delegate produces it with no
    /// issuer. The default and overwhelmingly common edge.
    #[default]
    Attenuate,
    /// CROSSING a subject namespace: a fresh trusted-issuer binding (an external
    /// token verified against its JWKS, or a redeemed cross-app assertion). NEVER
    /// offline-delegable — "you cannot narrow your way into a subject you were never
    /// given." Reserved and inert: no shipped path emits it.
    Mint,
}

fn edge_is_attenuate(e: &EdgeType) -> bool {
    matches!(e, EdgeType::Attenuate)
}

/// How `Entry::sponsor` was determined (see [`Entry::sponsor`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SponsorSource {
    /// The pure root of `subject_id`'s delegation chain — no admin override.
    #[default]
    Derived,
    /// An admin explicitly set this sponsor, constrained at write time to
    /// `subject_id`'s own delegation chain (never a genuine outsider).
    Explicit,
}

fn is_derived_sponsor(s: &SponsorSource) -> bool {
    matches!(s, SponsorSource::Derived)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub entry: Entry,
    pub prev: String,
    pub hash: String,
    pub sig_b64: String,
    /// The fingerprint (hex Ed25519 public key) of the key that signed this record —
    /// so a KEY-ROTATED log stays verifiable: each record names which key to check
    /// it against, and a keyring verify picks that key. `None` on legacy records
    /// written before rotation support (they are all signed by the ledger's original
    /// key). Envelope-only — NOT part of the hashed entry, so adding it left every
    /// existing record's hash and signature unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// Write-side record: `entry` is pre-serialized text, inlined verbatim, so
/// the bytes we hash are exactly the bytes that land on disk.
#[derive(Serialize)]
struct RecordOut<'a> {
    entry: &'a serde_json::value::RawValue,
    prev: &'a str,
    hash: &'a str,
    sig_b64: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
}

/// Read-side record: `entry` captures the exact byte span from the line, so
/// verification hashes what is actually stored, not a re-serialization.
#[derive(Deserialize)]
struct RecordIn {
    entry: Box<serde_json::value::RawValue>,
    prev: String,
    hash: String,
    sig_b64: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LedgerError {
    #[error("ledger I/O error at {path}: {err}")]
    Io { path: String, err: String },
    #[error("ledger serialization error: {0}")]
    Serde(String),
    #[error("TAMPER at seq {seq}: {why}")]
    Tamper { seq: u64, why: String },
    /// The log's FINAL physical line is structurally incomplete — the file does
    /// not end in a newline, so the trailing record was only partially written
    /// (a crash between/mid the single `append` write and its `flush`/`sync`).
    /// DISTINCT from [`Tamper`](LedgerError::Tamper) on purpose: a benign
    /// crash-during-append must never be reported as an attack. The verified
    /// PREFIX — every fully-terminated, chain-valid, signature-valid record —
    /// is intact and is the ledger; `healed_entries` is its length and
    /// `healed_root` its head hash. The open path HEALS this (truncates the torn
    /// fragment at `torn_from_offset` in `torn_path`) after first confirming the
    /// prefix still extends any persisted anchor — because a crash can only ever
    /// drop an un-acked tail, whereas a shorter-than-anchor prefix means acked
    /// history was deleted and stays [`Tamper`](LedgerError::Tamper). The
    /// read-only `verify*` entry points surface this variant rather than healing.
    #[error(
        "TORN TAIL: unterminated trailing record (crash mid-append); \
         {healed_entries} verified records intact before it"
    )]
    TornTail {
        healed_entries: u64,
        healed_root: Option<String>,
        torn_path: String,
        torn_from_offset: u64,
    },
}

/// A record's signature is over this 32-byte hash and nothing else. That is what keeps it
/// out of [`commitment_bytes`]'s space without a tag of its own: every commitment is a
/// tagged string far longer than 32 bytes, so no record signature can be replayed as one.
/// Anything else signed by a ledger key must keep that property or take a tag.
fn chain_hash(entry_bytes: &[u8], prev_hex: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(entry_bytes);
    h.update(prev_hex.as_bytes());
    h.finalize().into()
}

fn io_err(path: &Path, e: impl std::fmt::Display) -> LedgerError {
    LedgerError::Io {
        path: path.display().to_string(),
        err: e.to_string(),
    }
}

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
}

struct RolloverState {
    policy: RolloverPolicy,
    manifest: segment::Manifest,
}

/// Resolve the head `(last_hash, next_seq)` an open should start appending from,
/// healing a crash-torn tail iff it does not erase acked history.
///
/// This is the code that implements the task's core distinction: the anchor is
/// the line between "a crash dropped an un-acked tail" (heal) and "someone
/// deleted acked records" (tamper). On [`LedgerError::TornTail`] the persisted
/// anchor is consulted BEFORE the file is mutated — if the verified prefix no
/// longer extends the last committed height, the torn tail is really a ragged
/// truncation of acked history and stays [`LedgerError::Tamper`], with the file
/// left untouched. Only once the prefix is proven to still cover the anchor is
/// the torn fragment physically discarded.
fn resolve_open_head(
    location: &Location,
    verifiers: &[VerifyingKey],
    anchor: Option<&Path>,
) -> Result<(String, u64), LedgerError> {
    match verify_inner(location, verifiers, None) {
        Ok(report) => Ok((
            report.root.unwrap_or_else(|| GENESIS.to_owned()),
            report.entries,
        )),
        Err(LedgerError::TornTail {
            healed_entries,
            healed_root,
            torn_path,
            torn_from_offset,
        }) => {
            // Consult the anchor BEFORE any mutation.
            if let Some(anchor_path) = anchor
                && let Some(cp) = load_anchor(anchor_path)?
            {
                if !verifiers.iter().any(|k| verify_checkpoint_sig(&cp, k)) {
                    return Err(LedgerError::Tamper {
                        seq: cp.count,
                        why: "anchor signature is not from a trusted ledger key \
                                  (forged or wrong-key anchor)"
                            .into(),
                    });
                }
                // `ledger_extends_checkpoint_at` re-derives the head over the
                // PREFIX only (torn fragment excluded), so a prefix shorter
                // than the committed height reports `false` here.
                if !ledger_extends_checkpoint_at(location, &cp)? {
                    return Err(LedgerError::Tamper {
                        seq: cp.count,
                        why: format!(
                            "ledger no longer extends its anchor at count {} — the trailing \
                                 record is unterminated AND the verified prefix is below the last \
                                 committed height (acked history truncated, not a crash tail)",
                            cp.count
                        ),
                    });
                }
            }
            // Prefix covers the anchor (or there is none): the torn fragment was
            // never acked. Discard it durably, then adopt the healed head.
            heal_torn_tail(Path::new(&torn_path), torn_from_offset)?;
            Ok((
                healed_root.unwrap_or_else(|| GENESIS.to_owned()),
                healed_entries,
            ))
        }
        Err(e) => Err(e),
    }
}

/// Physically discard a crash-torn trailing fragment by truncating `path` to
/// `offset` (the byte just past the log's final newline). fsync'd so the
/// recovery is itself durable — a second crash cannot resurrect the fragment.
/// Called only after [`resolve_open_head`] has proven the prefix still covers
/// any anchor, so this never deletes acked history.
fn heal_torn_tail(path: &Path, offset: u64) -> Result<(), LedgerError> {
    let f = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| io_err(path, e))?;
    f.set_len(offset).map_err(|e| io_err(path, e))?;
    f.sync_all().map_err(|e| io_err(path, e))?;
    Ok(())
}

/// Open the ledger for append, owner-only.
///
/// The record holds decision subjects and the pseudonymous handles the subject-side audit
/// route is keyed by. It was being created at the process umask — commonly `0644` — while
/// the signing key and the mission registry beside it are `0600`, which made the audit log
/// the readable one. `.mode()` applies only when the file is created, so an existing file
/// is corrected too; both are needed, the same reasoning `decern-store` documents for the
/// mission registry.
///
/// Unlike the signing key this does not refuse a group- or other-readable file: a ledger
/// is not a secret in the way a key is, existing deployments have readable ones, and
/// failing their next append would be a worse outcome than tightening it in place.
fn open_append_owner_only(path: &Path) -> Result<File, LedgerError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| io_err(path, e))?;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| io_err(path, e))
    }
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
    /// ring is tamper.
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
        let mut verifiers = retired;
        let current = key.verifying_key();
        if !verifiers.iter().any(|v| v.to_bytes() == current.to_bytes()) {
            verifiers.push(current);
        }
        let location = Location::Single(path.to_owned());
        let (last_hash, next_seq) = if path.exists() {
            resolve_open_head(&location, &verifiers, anchor)?
        } else {
            (GENESIS.to_owned(), 0)
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
            sync: false,
            rollover: None,
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
        // Pass the anchor INTO the open so a torn tail is classified against the
        // committed height before any heal; the post-open check then also covers
        // the non-torn truncation (records dropped at a clean line boundary, file
        // still newline-terminated, so no torn tail was raised).
        let ledger = Self::open_single_inner(path, key, retired, Some(anchor_path))?;
        ledger.verify_against_anchor(anchor_path)?;
        Ok(ledger)
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
    /// (re-)marked read-only (0444 on Unix) on open — self-healing after a
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
        // crash left the active segment defensively 0444. Healing a torn tail is
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

        let (last_hash, next_seq) = resolve_open_head(&location, &verifiers, anchor)?;

        let file = open_append_owner_only(&active_path)?;
        Ok(Ledger {
            location,
            active_path,
            key,
            file,
            last_hash,
            next_seq,
            verifiers,
            sync: false,
            rollover: Some(RolloverState { policy, manifest }),
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
        let ledger = Self::open_segmented_inner(dir, key, retired, policy, Some(anchor_path))?;
        ledger.verify_against_anchor(anchor_path)?;
        Ok(ledger)
    }

    /// Rotate the signing key. Entries already written stay verifiable under the
    /// retired key (kept in the keyring); every subsequent entry is signed by
    /// `new_key` and carries its `kid`. The chain is uninterrupted — no re-signing of
    /// the past, and no republish. On the next restart, pass the retired public key
    /// to [`open_with_verifiers`](Ledger::open_with_verifiers) so the whole log still
    /// verifies.
    pub fn rotate(&mut self, new_key: SigningKey) {
        let current = new_key.verifying_key();
        if !self
            .verifiers
            .iter()
            .any(|v| v.to_bytes() == current.to_bytes())
        {
            self.verifiers.push(current);
        }
        self.key = new_key;
    }

    /// The public keys of every key trusted to have signed this log (retired +
    /// current), as hex fingerprints — what an auditor pins across a rotation.
    pub fn verifier_fingerprints(&self) -> Vec<String> {
        self.verifiers.iter().map(key_fingerprint).collect()
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
            .map_err(|e| io_err(&self.active_path, e))?;

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

    /// Sign the current head into a [`Checkpoint`] for external anchoring — the
    /// operator-independent half of the audit story. Hand it to a notary / SCITT
    /// transparency service / another party; they can later prove the log was not
    /// rewritten below this point without trusting the operator.
    pub fn checkpoint(&self, ts_ms: u64) -> Checkpoint {
        let root = self.last_hash.clone();
        let count = self.next_seq;
        let sig = self.key.sign(&checkpoint_bytes(&root, count, ts_ms));
        Checkpoint {
            root,
            count,
            ts_ms,
            pubkey_hex: self.pubkey_hex(),
            sig_b64: B64.encode(sig.to_bytes()),
        }
    }

    /// Read every record's chain hash, in order, as the Merkle LEAF DATA (the 32 raw bytes
    /// each record's `hash` hex encodes). The RFC 9162 tree is built over these, so a leaf
    /// is exactly what the chain already commits to — a verifier who checks the chain has
    /// already derived every leaf. Audit/export path only (scans the whole file). Fails
    /// closed on a record with a missing or non-hex `hash`.
    fn merkle_leaves(&self) -> Result<Vec<Vec<u8>>, LedgerError> {
        let count = self.next_seq as usize;
        leaves_from_records(&self.read_records(0, count)?)
    }

    /// Sign the current MERKLE tree head — the RFC 9162 root over all record hashes,
    /// externally anchorable like [`checkpoint`](Ledger::checkpoint) but enabling COMPACT
    /// third-party inclusion/consistency proofs. `tree_size == count`. Signs through the
    /// ledger key (a keyless hash committed by a key, same as a checkpoint).
    pub fn tree_head(&self, ts_ms: u64) -> Result<TreeHead, LedgerError> {
        let leaves = self.merkle_leaves()?;
        let root_hex = hex::encode(merkle::tree_hash(&leaves));
        Ok(self.sign_tree_head(root_hex, leaves.len() as u64, ts_ms))
    }

    /// Sign a tree head over an already-computed root — the signing half of
    /// [`tree_head`](Ledger::tree_head), for a caller who derived the leaves outside the
    /// lock. Signs exactly what it is given: a root computed from a prefix that has since
    /// been appended past is still a consistent commitment to that prefix, the same answer
    /// the caller would have gotten before the append.
    pub fn sign_tree_head(&self, merkle_root: String, tree_size: u64, ts_ms: u64) -> TreeHead {
        let sig = self
            .key
            .sign(&tree_head_bytes(&merkle_root, tree_size, ts_ms));
        TreeHead {
            merkle_root,
            tree_size,
            ts_ms,
            pubkey_hex: self.pubkey_hex(),
            sig_b64: B64.encode(sig.to_bytes()),
        }
    }

    /// A compact RFC 9162 inclusion proof that the record at `seq` (0-based) is committed
    /// by the current tree head's root. `Err` if `seq` is past the end of the log.
    pub fn inclusion_proof(&self, seq: u64) -> Result<InclusionProof, LedgerError> {
        let leaves = self.merkle_leaves()?;
        let idx = seq as usize;
        let path = merkle::inclusion_proof(&leaves, idx).ok_or_else(|| LedgerError::Tamper {
            seq,
            why: "inclusion index past the end of the log".into(),
        })?;
        Ok(InclusionProof {
            leaf_index: seq,
            tree_size: leaves.len() as u64,
            leaf_data: hex::encode(&leaves[idx]),
            audit_path: path.iter().map(hex::encode).collect(),
        })
    }

    /// Inclusion proofs for several records, over one pass of the log.
    ///
    /// [`inclusion_proof`](Ledger::inclusion_proof) derives every leaf in the log to prove
    /// one record is in it, which is the right shape for one proof and the wrong shape for
    /// a page of them: asking for `m` proofs that way reads and parses the whole log `m`
    /// times, and does it holding the lock an append needs. This derives the leaves once.
    ///
    /// Returns proofs in the order the sequences were given. A sequence past the end of the
    /// log fails the whole call rather than being skipped — a page of proofs with a hole in
    /// it, where the hole is silent, is worse than no page.
    pub fn inclusion_proofs(&self, seqs: &[u64]) -> Result<Vec<InclusionProof>, LedgerError> {
        inclusion_proofs_over(&self.merkle_leaves()?, seqs)
    }

    /// A compact RFC 9162 consistency proof that the log of the first `first_size` records
    /// is an exact prefix of the current log — the operator-independent equivocation /
    /// truncation check against an EARLIER anchored tree head. `1 <= first_size <= count`.
    pub fn consistency_proof(&self, first_size: u64) -> Result<ConsistencyProof, LedgerError> {
        let leaves = self.merkle_leaves()?;
        let path = merkle::consistency_proof(&leaves, first_size as usize).ok_or_else(|| {
            LedgerError::Tamper {
                seq: first_size,
                why: "consistency first_size out of range (need 1..=count)".into(),
            }
        })?;
        Ok(ConsistencyProof {
            first_size,
            second_size: leaves.len() as u64,
            proof: path.iter().map(hex::encode).collect(),
        })
    }

    /// A single-snapshot read for an evidence bundle: checkpoint, tree_head, and raw records
    /// are ALL derived from the SAME in-memory (self.last_hash, self.next_seq) state captured
    /// at one moment — unlike calling `checkpoint()`/`tree_head()`/`read_raw_records()` separately
    /// (which lets an `append()` land between calls and make the three mutually inconsistent:
    /// `checkpoint.count != tree_head.tree_size` or `checkpoint.root` computed over different
    /// records than `tree_head`).
    ///
    /// This is the single-file analog of [`ShardedLedger::evidence_snapshot`](crate::sharded::ShardedLedger::evidence_snapshot).
    /// The snapshot captures the log's state at call time; a concurrent `append()` does not
    /// change the returned values. Returns `(count, raw_records, checkpoint, tree_head)`.
    pub fn snapshot_for_bundle(&self, ts_ms: u64) -> Result<EvidenceSnapshot, LedgerError> {
        // Capture the head state once — this is the "snapshot" that all derived values build from.
        let count = self.next_seq;
        let root = self.last_hash.clone();

        // All three outputs are now derived from this same (root, count) pair, so they are
        // mutually consistent even if an append happens after this point.
        let raw_records = self.read_raw_records(0, count as usize)?;

        let cp_sig = self.key.sign(&checkpoint_bytes(&root, count, ts_ms));
        let checkpoint = Checkpoint {
            root,
            count,
            ts_ms,
            pubkey_hex: self.pubkey_hex(),
            sig_b64: B64.encode(cp_sig.to_bytes()),
        };

        let leaves = leaves_from_records(&self.read_records(0, count as usize)?)?;
        let merkle_root = hex::encode(merkle::tree_hash(&leaves));
        let tree_size = leaves.len() as u64;
        let th_sig = self
            .key
            .sign(&tree_head_bytes(&merkle_root, tree_size, ts_ms));
        let tree_head = TreeHead {
            merkle_root,
            tree_size,
            ts_ms,
            pubkey_hex: self.pubkey_hex(),
            sig_b64: B64.encode(th_sig.to_bytes()),
        };

        Ok((count, raw_records, checkpoint, tree_head))
    }

    /// Seal the current head into the persisted ANCHOR file — the last committed
    /// height, durably recorded on THIS node (not only handed to an external notary).
    /// On the next [`open_anchored`](Ledger::open_anchored) /
    /// [`verify_against_anchor`](Ledger::verify_against_anchor) the log must still
    /// extend it, which is what makes a tail-truncation across a restart detectable
    /// — a plain reopen accepts any internally-consistent shorter chain and cannot.
    pub fn seal_anchor(&self, anchor_path: &Path, ts_ms: u64) -> Result<Checkpoint, LedgerError> {
        let cp = self.checkpoint(ts_ms);
        save_anchor(anchor_path, &cp)?;
        Ok(cp)
    }

    /// Fail-closed truncation/rewrite check against the persisted anchor. Call it
    /// right after opening (or use [`open_anchored`](Ledger::open_anchored)): if an
    /// anchor exists it must (a) be signed by a key in this ledger's keyring — a
    /// forged anchor cannot be used to downgrade the committed height — and (b) still
    /// be extended by the log (at least `count` records that re-derive `root`). Any
    /// failure is `Tamper`: the log was truncated below, or rewritten at/below, its
    /// last committed height. No anchor file ⇒ `Ok` (nothing committed yet).
    pub fn verify_against_anchor(&self, anchor_path: &Path) -> Result<(), LedgerError> {
        let Some(cp) = load_anchor(anchor_path)? else {
            return Ok(());
        };
        // (a) The anchor must be vouched by a trusted ledger key (current or retired),
        // else an attacker could drop a self-signed anchor at a lower count to mask a
        // truncation.
        if !self.verifiers.iter().any(|k| verify_checkpoint_sig(&cp, k)) {
            return Err(LedgerError::Tamper {
                seq: cp.count,
                why:
                    "anchor signature is not from a trusted ledger key (forged or wrong-key anchor)"
                        .into(),
            });
        }
        // (b) The log must still extend the anchor's committed height.
        if !ledger_extends_checkpoint_at(&self.location, &cp)? {
            return Err(LedgerError::Tamper {
                seq: cp.count,
                why: format!(
                    "ledger no longer extends its anchor at count {} — truncated or rewritten \
                     below the last committed height",
                    cp.count
                ),
            });
        }
        Ok(())
    }
}

/// A signed, externally-anchorable commitment to the ledger's state at a moment:
/// the head `root` over the first `count` entries, timestamped and signed by the
/// ledger key. It leaks no entry content — only a hash, a count, and a signature —
/// so it is safe to publish, hand to a notary, or submit to a SCITT transparency
/// service. Because the log is append-only, the root over the first `count` entries
/// is fixed forever; an external party holding a checkpoint can re-derive that root
/// from the file and, if it disagrees, prove the operator rewrote history — the
/// operator-INDEPENDENT verification a log inside the operator's own stack lacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub root: String,
    pub count: u64,
    pub ts_ms: u64,
    /// Hex of the Ed25519 ledger key that signed both the entries and this commitment.
    pub pubkey_hex: String,
    /// Ed25519 signature over the canonical commitment bytes.
    pub sig_b64: String,
}

/// A signed, externally-anchorable commitment to the ledger's MERKLE state: the RFC 9162
/// tree root over the first `tree_size` record hashes, timestamped and signed by the ledger
/// key. Parallel to [`Checkpoint`] (the linear-chain head): a `TreeHead` enables COMPACT
/// third-party proofs — an inclusion proof shows one record is in the log without shipping
/// the whole tail, and a consistency proof between an anchored earlier `TreeHead` and a
/// later one proves nothing below the earlier size was rewritten or dropped (closing
/// equivocation). Leaks no entry content — only a root, a size, and a signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeHead {
    /// Hex of the RFC 9162 Merkle Tree Hash over the first `tree_size` record hashes.
    pub merkle_root: String,
    pub tree_size: u64,
    pub ts_ms: u64,
    /// Hex of the Ed25519 ledger key that signed this commitment.
    pub pubkey_hex: String,
    /// Ed25519 signature over the `decern-ledger-tree-head` domain-separated bytes.
    pub sig_b64: String,
}

/// A single-snapshot evidence bundle: record count, raw bytes, and signed commitments
/// (checkpoint and merkle tree head) all derived from the same log state at one moment.
/// This is the return type of [`Ledger::snapshot_for_bundle`] and
/// [`ShardedLedger::evidence_snapshot`](sharded::ShardedLedger::evidence_snapshot).
pub type EvidenceSnapshot = (
    u64,                                   // record count
    Vec<Box<serde_json::value::RawValue>>, // raw record bytes
    Checkpoint,                            // signed linear-chain commitment
    TreeHead,                              // signed merkle-tree commitment
);

/// A compact RFC 9162 inclusion proof (hex-encoded): the record at `leaf_index` in a tree
/// of `tree_size` leaves is committed by a [`TreeHead`]'s root. `leaf_data` is the record's
/// chain hash (the Merkle leaf data — a verifier hashes it with the `0x00` leaf prefix);
/// `audit_path` is the sibling hashes bottom-up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub leaf_data: String,
    pub audit_path: Vec<String>,
}

/// A compact RFC 9162 consistency proof (hex-encoded) that the tree of the first
/// `first_size` leaves is an exact prefix of the tree of `second_size` leaves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub first_size: u64,
    pub second_size: u64,
    pub proof: Vec<String>,
}

/// Domain-separated commitment bytes: a fixed `tag` plus a hex field and two decimal
/// integers joined by a unit-separator byte (0x1F) that appears in neither hex nor a
/// decimal, so no two distinct field tuples collide AND no two tags cross-verify (a
/// checkpoint signature can never be replayed as a tree-head signature, or vice versa).
/// Shared by [`checkpoint_bytes`] and [`tree_head_bytes`] so the signing convention lives
/// in one place.
fn commitment_bytes(tag: &str, hex_field: &str, a: u64, b: u64) -> Vec<u8> {
    format!("{tag}\x1f{hex_field}\x1f{a}\x1f{b}").into_bytes()
}

/// The chain-head commitment (linear hash-chain root over `count` entries).
fn checkpoint_bytes(root: &str, count: u64, ts_ms: u64) -> Vec<u8> {
    commitment_bytes("decern-ledger-checkpoint", root, count, ts_ms)
}

/// The Merkle-tree-head commitment (RFC 9162 root over `tree_size` record hashes).
fn tree_head_bytes(merkle_root: &str, tree_size: u64, ts_ms: u64) -> Vec<u8> {
    commitment_bytes("decern-ledger-tree-head", merkle_root, tree_size, ts_ms)
}

#[derive(Debug)]
pub struct VerifyReport {
    pub entries: u64,
    pub root: Option<String>,
    pub signatures_checked: bool,
}

/// Hex of an Ed25519 public key — the `kid` fingerprint stamped on each record and
/// the id an auditor pins.
fn key_fingerprint(vk: &VerifyingKey) -> String {
    hex::encode(vk.to_bytes())
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
struct ReadWindow {
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

fn verify_inner(
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

fn leaves_from_records(recs: &[serde_json::Value]) -> Result<Vec<Vec<u8>>, LedgerError> {
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

#[must_use = "signature verification result must be checked"]
pub fn verify_checkpoint_sig(cp: &Checkpoint, pubkey: &VerifyingKey) -> bool {
    let Ok(bytes) = B64.decode(&cp.sig_b64) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = bytes.try_into() else {
        return false;
    };
    let sig = decern_crypto::Signature::from_bytes(&sig_arr);
    pubkey
        .verify_strict(&checkpoint_bytes(&cp.root, cp.count, cp.ts_ms), &sig)
        .is_ok()
}

/// Verify a tree head's own signature against a pinned key — the Merkle counterpart of
/// [`verify_checkpoint_sig`]. The domain-separated `decern-ledger-tree-head` tag means this
/// never cross-verifies a checkpoint signature. Does not read the ledger.
#[must_use = "signature verification result must be checked"]
pub fn verify_tree_head_sig(th: &TreeHead, pubkey: &VerifyingKey) -> bool {
    let Ok(bytes) = B64.decode(&th.sig_b64) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = bytes.try_into() else {
        return false;
    };
    let sig = decern_crypto::Signature::from_bytes(&sig_arr);
    pubkey
        .verify_strict(
            &tree_head_bytes(&th.merkle_root, th.tree_size, th.ts_ms),
            &sig,
        )
        .is_ok()
}

/// The per-check result of verifying an exported evidence bundle offline. `accepted` is
/// the AND of every APPLICABLE check (an `Option` check that is `None` did not apply and
/// does not gate acceptance). Serializable so a CLI can emit it as `--json` verbatim.
#[derive(Debug, Clone, Serialize)]
pub struct BundleVerdict {
    pub accepted: bool,
    pub format: String,
    pub records: usize,
    pub from: u64,
    /// True when the bundle is a full tail from genesis (`from == 0`) — only then can a
    /// verifier recompute the Merkle root and a consistency proof from the records alone.
    pub full_tail: bool,
    pub chain_ok: bool,
    pub record_sigs_ok: bool,
    pub checkpoint_sig_ok: bool,
    pub tree_head_present: bool,
    pub tree_head_sig_ok: bool,
    /// `Some(ok)` when recomputed from a full tail; `None` for a partial tail.
    pub merkle_root_ok: Option<bool>,
    pub anchor_ok: bool,
    /// `Some(ok)` when an `--against` earlier tree head was supplied AND checkable.
    pub consistency_ok: Option<bool>,
    pub errors: Vec<String>,
}

#[derive(Deserialize)]
struct BundleIn {
    #[serde(default)]
    format: String,
    #[serde(default)]
    span: SpanIn,
    checkpoint: Checkpoint,
    #[serde(default)]
    tree_head: Option<TreeHead>,
    #[serde(default)]
    records: Vec<RecordIn>,
}

#[derive(Deserialize, Default)]
struct SpanIn {
    #[serde(default)]
    from: u64,
}

/// Does any key in `keys` verify `sig_b64` over `msg`? (Keyring-aware: a rotated log's
/// records are signed by different keys; a verifier holds the current + retired public
/// keys.) Fail-closed on a malformed signature.
fn any_key_verifies(msg: &[u8], sig_b64: &str, keys: &[VerifyingKey]) -> bool {
    let Ok(bytes) = B64.decode(sig_b64) else {
        return false;
    };
    let Ok(arr): Result<[u8; 64], _> = bytes.try_into() else {
        return false;
    };
    let sig = decern_crypto::Signature::from_bytes(&arr);
    keys.iter().any(|k| k.verify_strict(msg, &sig).is_ok())
}

/// Verify an exported `decern-evidence-bundle` OFFLINE against a PINNED keyring — the standalone
/// third-party check with no call back to the server. `bundle_json` is the RAW bundle file
/// text (NOT a re-serialized `Value`): each record's `entry` is captured as verbatim bytes,
/// because the chain commits to those exact bytes. `keys` is the pinned current + retired
/// public keys (obtained OUT OF BAND — never from the bundle). `against`, if given, is an
/// independently-anchored EARLIER tree head; a consistency check then proves the bundle did
/// not rewrite or drop anything below that earlier size (equivocation/truncation).
///
/// Checks (all fail-closed): every record hash re-derives from its verbatim bytes; the chain
/// links (genesis when `from == 0`); every record signature; the checkpoint signature; the
/// tree-head signature; the anchor (last hash == checkpoint root, positions match count ==
/// tree_size); and — for a full tail — the recomputed Merkle root equals the signed tree
/// head, plus any requested consistency proof against the anchored earlier head.
pub fn verify_evidence_bundle(
    bundle_json: &str,
    keys: &[VerifyingKey],
    against: Option<&TreeHead>,
) -> BundleVerdict {
    let mut errors: Vec<String> = Vec::new();
    let b: BundleIn = match serde_json::from_str(bundle_json) {
        Ok(b) => b,
        Err(e) => {
            return BundleVerdict {
                accepted: false,
                format: String::new(),
                records: 0,
                from: 0,
                full_tail: false,
                chain_ok: false,
                record_sigs_ok: false,
                checkpoint_sig_ok: false,
                tree_head_present: false,
                tree_head_sig_ok: false,
                merkle_root_ok: None,
                anchor_ok: false,
                consistency_ok: None,
                errors: vec![format!("bundle does not parse: {e}")],
            };
        }
    };

    let from = b.span.from;
    let full_tail = from == 0;
    let n = b.records.len();

    // 1) Per-record hash re-derivation + 2) chain links.
    let mut chain_ok = true;
    let mut leaves: Vec<Vec<u8>> = Vec::with_capacity(n);
    for (i, r) in b.records.iter().enumerate() {
        let want = hex::encode(chain_hash(r.entry.get().as_bytes(), &r.prev));
        if want != r.hash {
            chain_ok = false;
            errors.push(format!(
                "record {i}: hash does not re-derive from its bytes"
            ));
        }
        let expected_prev = if i == 0 {
            if full_tail {
                GENESIS.to_owned()
            } else {
                r.prev.clone() // no genesis anchor for a partial tail; link-only below
            }
        } else {
            b.records[i - 1].hash.clone()
        };
        if r.prev != expected_prev {
            chain_ok = false;
            errors.push(format!(
                "record {i}: prev does not link to the previous record"
            ));
        }
        match hex::decode(&r.hash) {
            Ok(bytes) => leaves.push(bytes),
            Err(_) => {
                chain_ok = false;
                errors.push(format!("record {i}: hash is not valid hex"));
            }
        }
    }

    // 3) Every record signature against the pinned keyring.
    let mut record_sigs_ok = true;
    for (i, r) in b.records.iter().enumerate() {
        let Ok(msg) = hex::decode(&r.hash) else {
            record_sigs_ok = false;
            continue;
        };
        if !any_key_verifies(&msg, &r.sig_b64, keys) {
            record_sigs_ok = false;
            errors.push(format!(
                "record {i}: signature not verified by any pinned key"
            ));
        }
    }

    // 4) Checkpoint + 5) tree-head signatures.
    let checkpoint_sig_ok = keys.iter().any(|k| verify_checkpoint_sig(&b.checkpoint, k));
    if !checkpoint_sig_ok {
        errors.push("checkpoint signature not verified by any pinned key".into());
    }
    let tree_head_present = b.tree_head.is_some();
    let tree_head_sig_ok = match &b.tree_head {
        Some(th) => {
            let ok = keys.iter().any(|k| verify_tree_head_sig(th, k));
            if !ok {
                errors.push("tree-head signature not verified by any pinned key".into());
            }
            ok
        }
        None => {
            // Fail-closed: this verifier attests the UPGRADED bundle (the server always
            // emits a signed Merkle tree head). A bundle without one gets no Merkle
            // commitment, so it is rejected with a legible reason rather than a silent
            // acceptance that overstates what was checked.
            errors.push(
                "bundle has no tree_head (Merkle commitment); this verifier requires the \
                 upgraded decern-evidence-bundle shape"
                    .into(),
            );
            false
        }
    };

    // 6) Anchor: the tail terminates at the signed head and positions line up.
    let mut anchor_ok = true;
    match b.records.last() {
        Some(last) if last.hash == b.checkpoint.root => {}
        Some(_) => {
            anchor_ok = false;
            errors.push("last record hash != checkpoint root".into());
        }
        None => {
            // Empty tail: the checkpoint alone attests the head; only valid when from==count.
            if from != b.checkpoint.count {
                anchor_ok = false;
                errors.push("empty tail but from != checkpoint count".into());
            }
        }
    }
    if from + n as u64 != b.checkpoint.count {
        anchor_ok = false;
        errors.push("from + record count != checkpoint count".into());
    }
    if let Some(th) = &b.tree_head
        && th.tree_size != b.checkpoint.count
    {
        anchor_ok = false;
        errors.push("tree_head size != checkpoint count".into());
    }

    // 7) Full-tail Merkle root recomputation.
    let merkle_root_ok = match (&b.tree_head, full_tail && chain_ok) {
        (Some(th), true) => {
            let recomputed = hex::encode(merkle::tree_hash(&leaves));
            let ok = recomputed == th.merkle_root;
            if !ok {
                errors.push("recomputed Merkle root != signed tree head".into());
            }
            Some(ok)
        }
        _ => None,
    };

    // 8) Optional consistency against an anchored earlier tree head (full tail only).
    let consistency_ok = match (against, &b.tree_head, full_tail && chain_ok) {
        (Some(earlier), Some(current), true) => {
            // The earlier head must itself be pinned-key-signed, else it anchors nothing.
            let earlier_sig = keys.iter().any(|k| verify_tree_head_sig(earlier, k));
            let first = earlier.tree_size as usize;
            let ok = earlier_sig
                && first <= leaves.len()
                && merkle::consistency_proof(&leaves, first).is_some_and(|path| {
                    match (
                        hex_to_32(&earlier.merkle_root),
                        hex_to_32(&current.merkle_root),
                    ) {
                        (Some(fr), Some(sr)) => merkle::verify_consistency(
                            earlier.tree_size,
                            current.tree_size,
                            &fr,
                            &sr,
                            &path,
                        ),
                        _ => false,
                    }
                });
            if !ok {
                errors.push(
                    "consistency proof against the earlier anchored tree head FAILED \
                     (possible equivocation/truncation, or the earlier head is unsigned)"
                        .into(),
                );
            }
            Some(ok)
        }
        (Some(_), _, false) => {
            errors
                .push("consistency check needs a full tail (from==0) to recompute; skipped".into());
            Some(false)
        }
        _ => None,
    };

    let accepted = chain_ok
        && record_sigs_ok
        && checkpoint_sig_ok
        && tree_head_sig_ok
        && anchor_ok
        && merkle_root_ok.unwrap_or(true)
        && consistency_ok.unwrap_or(true);

    BundleVerdict {
        accepted,
        format: b.format,
        records: n,
        from,
        full_tail,
        chain_ok,
        record_sigs_ok,
        checkpoint_sig_ok,
        tree_head_present,
        tree_head_sig_ok,
        merkle_root_ok,
        anchor_ok,
        consistency_ok,
        errors,
    }
}

/// Decode a 64-hex-char string into 32 bytes, or `None`.
fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

/// The operator-independent tamper check: does the ledger at `path` still extend a
/// previously issued `cp`? Re-derives the head over the first `cp.count` records
/// from the stored bytes and confirms it equals `cp.root`. If the operator edited,
/// reordered, or truncated any entry at or before `count`, the re-derived root
/// diverges and this returns `Ok(false)` — caught by anyone holding the old
/// checkpoint, without trusting the operator. A well-behaved append-only log always
/// extends its past checkpoints.
pub fn ledger_extends_checkpoint(path: &Path, cp: &Checkpoint) -> Result<bool, LedgerError> {
    ledger_extends_checkpoint_at(&Location::detect(path), cp)
}

fn ledger_extends_checkpoint_at(location: &Location, cp: &Checkpoint) -> Result<bool, LedgerError> {
    Ok(root_at_count(location, cp.count)?.as_deref() == Some(cp.root.as_str()))
}

/// Persist a checkpoint as the ledger's anchor file, atomically (temp + fsync +
/// rename + parent-dir fsync) so a crash cannot leave a half-written or non-durable
/// anchor — a lost anchor write would silently lower the height truncation is checked
/// against. See [`Ledger::seal_anchor`].
pub fn save_anchor(anchor_path: &Path, cp: &Checkpoint) -> Result<(), LedgerError> {
    let bytes = serde_json::to_vec_pretty(cp).map_err(|e| LedgerError::Serde(e.to_string()))?;
    let tmp = anchor_path.with_extension("anchor-tmp");
    {
        let mut f = File::create(&tmp).map_err(|e| io_err(&tmp, e))?;
        f.write_all(&bytes).map_err(|e| io_err(&tmp, e))?;
        f.sync_all().map_err(|e| io_err(&tmp, e))?;
    }
    std::fs::rename(&tmp, anchor_path).map_err(|e| io_err(anchor_path, e))?;
    // fsync the parent dir so the rename (the anchor's new directory entry) is durable.
    if let Some(parent) = anchor_path.parent().filter(|p| !p.as_os_str().is_empty())
        && let Ok(dir) = File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Load the persisted anchor, or `None` if no anchor file exists yet. A present but
/// unparseable anchor is a hard error (fail-closed — a corrupt anchor is never
/// silently treated as "no committed height").
pub fn load_anchor(anchor_path: &Path) -> Result<Option<Checkpoint>, LedgerError> {
    match std::fs::read(anchor_path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).map_err(|e| LedgerError::Serde(e.to_string()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(anchor_path, e)),
    }
}

/// Re-derive the hash-chain head after exactly the first `count` records. Mirrors
/// [`verify`]'s per-record hashing (stored bytes + prev), independently, so any
/// rewrite below `count` changes the result. `None` if the file holds fewer than
/// `count` records (truncated below the checkpoint).
fn root_at_count(location: &Location, count: u64) -> Result<Option<String>, LedgerError> {
    if count == 0 {
        return Ok(Some(GENESIS.to_owned()));
    }
    let mut prev = GENESIS.to_owned();
    let mut seen: u64 = 0;
    // Consume the PREFIX (any crash-torn trailing fragment excluded), so the
    // anchor/truncation check derives the head over ACKED history only and a
    // half-written tail can neither spoof a match nor spuriously error. A prefix
    // shorter than `count` still yields `None` — the truncation-below-anchor
    // signal, which is exactly how a ragged attacker truncation stays Tamper.
    let (lines, _torn) = location.prefix_lines()?;
    for line in lines {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: RecordIn = serde_json::from_str(&line).map_err(|e| LedgerError::Tamper {
            seq: seen,
            why: format!("unparseable record: {e}"),
        })?;
        if record.prev != prev {
            return Err(LedgerError::Tamper {
                seq: seen,
                why: "broken chain link (prev mismatch)".into(),
            });
        }
        let hash = hex::encode(chain_hash(record.entry.get().as_bytes(), &record.prev));
        if hash != record.hash {
            return Err(LedgerError::Tamper {
                seq: seen,
                why: "entry altered (hash mismatch)".into(),
            });
        }
        prev = record.hash;
        seen += 1;
        if seen == count {
            return Ok(Some(prev));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use decern_crypto::Verifier;
    use serde_json::json;

    fn entry(action: &str, decision: bool) -> Entry {
        Entry {
            seq: 0, // assigned by append
            ts_ms: 1234,
            subject_type: "Principal".into(),
            subject_id: "agent1".into(),
            action: action.into(),
            resource_type: "Resource".into(),
            resource_id: "claim1".into(),
            context: json!({"now": 100}),
            decision,
            reasons: vec![],
            ..Default::default()
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("decern-ledger-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn h32(hex_str: &str) -> [u8; 32] {
        <[u8; 32]>::try_from(hex::decode(hex_str).unwrap()).unwrap()
    }

    /// The unlocked path is the locked path: raw lines yield the same leaves, the same
    /// proofs, and a head that verifies — one definition of a leaf, reachable two ways.

    #[test]
    fn the_out_of_lock_projection_path_equals_the_in_lock_one() {
        let key = decern_crypto::generate().unwrap();
        let vk = key.verifying_key();
        let path = tmp("raw-lines.ledger");
        let _ = std::fs::remove_file(&path);
        let mut l = Ledger::open(&path, key).unwrap();
        for i in 0..5 {
            l.append(entry(&format!("a{i}"), i % 2 == 0)).unwrap();
        }

        let lines = l.raw_records().unwrap();
        assert_eq!(lines.len(), 5);
        let from_lines = leaves_from_lines(&lines).unwrap();
        let from_records = l.merkle_leaves().unwrap();
        assert_eq!(from_lines, from_records);

        let seqs = [0u64, 3, 4];
        let over = inclusion_proofs_over(&from_lines, &seqs).unwrap();
        let method = l.inclusion_proofs(&seqs).unwrap();
        for (a, b) in over.iter().zip(&method) {
            assert_eq!(a.leaf_index, b.leaf_index);
            assert_eq!(a.tree_size, b.tree_size);
            assert_eq!(a.leaf_data, b.leaf_data);
            assert_eq!(a.audit_path, b.audit_path);
        }

        let root_hex = hex::encode(merkle::tree_hash(&from_lines));
        let signed = l.sign_tree_head(root_hex, from_lines.len() as u64, 2_000);
        let direct = l.tree_head(2_000).unwrap();
        assert_eq!(signed.merkle_root, direct.merkle_root);
        assert_eq!(signed.tree_size, direct.tree_size);
        assert!(verify_tree_head_sig(&signed, &vk));
    }

    /// A line without a decodable hash fails the whole derivation, exactly as the
    /// record form does — a leaf set with a silent hole would prove the wrong tree.
    #[test]
    fn a_line_without_a_hash_fails_leaf_derivation_closed() {
        let lines = vec![r#"{"entry":{}}"#.to_owned()];
        assert!(leaves_from_lines(&lines).is_err());
        let lines = vec![r#"{"hash":"zz"}"#.to_owned()];
        assert!(leaves_from_lines(&lines).is_err());
    }

    #[test]
    fn merkle_tree_head_and_proofs_verify_against_a_real_ledger() {
        let key = decern_crypto::generate().unwrap();
        let vk = key.verifying_key();
        let path = tmp("merkle-th.ledger");
        let _ = std::fs::remove_file(&path);
        let mut l = Ledger::open(&path, key.clone()).unwrap();

        // Grow to 4 records and anchor an EARLIER tree head.
        for i in 0..4 {
            l.append(entry(&format!("a{i}"), true)).unwrap();
        }
        let th4 = l.tree_head(1_000).unwrap();
        assert_eq!(th4.tree_size, 4);
        assert!(verify_tree_head_sig(&th4, &vk));

        // Grow to 7 records; a NEW tree head over the whole log.
        for i in 0..3 {
            l.append(entry(&format!("b{i}"), false)).unwrap();
        }
        let th7 = l.tree_head(2_000).unwrap();
        assert_eq!(th7.tree_size, 7);
        assert!(verify_tree_head_sig(&th7, &vk));

        // The tree-head signature is pinned to the ledger key AND domain-separated: a
        // wrong key or a tampered root does not verify.
        let other = decern_crypto::generate().unwrap().verifying_key();
        assert!(
            !verify_tree_head_sig(&th7, &other),
            "wrong key must not verify"
        );
        let mut tampered = th7.clone();
        tampered.merkle_root = "00".repeat(32);
        assert!(
            !verify_tree_head_sig(&tampered, &vk),
            "tampered root rejected"
        );
        // A checkpoint signature must NOT cross-verify as a tree head (distinct domain tag).
        let cp = l.checkpoint(2_000);
        let cross = TreeHead {
            merkle_root: cp.root.clone(),
            tree_size: cp.count,
            ts_ms: cp.ts_ms,
            pubkey_hex: cp.pubkey_hex.clone(),
            sig_b64: cp.sig_b64.clone(),
        };
        assert!(
            !verify_tree_head_sig(&cross, &vk),
            "a checkpoint sig must not verify as a tree head"
        );

        // Inclusion: every record is provably in the size-7 tree under th7's root.
        let root7 = h32(&th7.merkle_root);
        for seq in 0..7u64 {
            let ip = l.inclusion_proof(seq).unwrap();
            assert_eq!(ip.tree_size, 7);
            let leaf_hash = merkle::hash_leaf(&hex::decode(&ip.leaf_data).unwrap());
            let audit: Vec<[u8; 32]> = ip.audit_path.iter().map(|h| h32(h)).collect();
            assert!(
                merkle::verify_inclusion(seq, 7, &leaf_hash, &root7, &audit),
                "record {seq} must prove included"
            );
        }
        assert!(
            l.inclusion_proof(7).is_err(),
            "out-of-range inclusion rejected"
        );

        // Consistency: the anchored size-4 tree is an exact prefix of the size-7 head —
        // the operator cannot have rewritten or dropped anything below seq 4.
        let root4 = h32(&th4.merkle_root);
        let consist = l.consistency_proof(4).unwrap();
        assert_eq!((consist.first_size, consist.second_size), (4, 7));
        let cpath: Vec<[u8; 32]> = consist.proof.iter().map(|h| h32(h)).collect();
        assert!(
            merkle::verify_consistency(4, 7, &root4, &root7, &cpath),
            "size-4 prefix must reconcile with the size-7 head"
        );
        // A forged earlier root (equivocation) does NOT reconcile.
        let mut forged = root4;
        forged[0] ^= 0xFF;
        assert!(!merkle::verify_consistency(4, 7, &forged, &root7, &cpath));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn evidence_bundle_verifies_offline_and_catches_tamper() {
        let key = decern_crypto::generate().unwrap();
        let vk = key.verifying_key();
        let path = tmp("bundle-verify.ledger");
        let _ = std::fs::remove_file(&path);
        let mut l = Ledger::open(&path, key.clone()).unwrap();
        for i in 0..5 {
            l.append(entry(&format!("e{i}"), true)).unwrap();
        }
        let earlier = l.tree_head(500).unwrap(); // size 5 — an externally-anchored head
        for i in 0..3 {
            l.append(entry(&format!("f{i}"), false)).unwrap();
        }
        let count = l.count() as usize; // 8

        // Assemble the bundle from VERBATIM record bytes (`RawValue::get()`), exactly as
        // the server ships them — routing records through json!/Value would reorder the
        // entry keys (no preserve_order here) and break the very hashes we verify.
        let make_bundle = |from: usize| -> String {
            let recs = l.read_raw_records(from, count - from).unwrap();
            let records_arr = format!(
                "[{}]",
                recs.iter().map(|r| r.get()).collect::<Vec<_>>().join(",")
            );
            format!(
                "{{\"format\":\"decern-evidence-bundle/1\",\"span\":{{\"from\":{from}}},\
                 \"checkpoint\":{cp},\"tree_head\":{th},\"records\":{records_arr}}}",
                cp = serde_json::to_string(&l.checkpoint(900)).unwrap(),
                th = serde_json::to_string(&l.tree_head(900).unwrap()).unwrap(),
            )
        };

        // Full tail: everything verifies, the Merkle root recomputes, and the size-5
        // anchored head is a proven prefix of the size-8 head.
        let full = make_bundle(0);
        let v = verify_evidence_bundle(&full, &[vk], Some(&earlier));
        assert!(v.accepted, "full bundle must verify: {:?}", v.errors);
        assert_eq!(v.merkle_root_ok, Some(true));
        assert_eq!(v.consistency_ok, Some(true));

        // Wrong pinned key → rejected (record + checkpoint + tree-head sigs all fail).
        let other = decern_crypto::generate().unwrap().verifying_key();
        assert!(!verify_evidence_bundle(&full, &[other], None).accepted);

        // Tampered record entry → its hash no longer re-derives → rejected.
        let tampered = full.replacen("\"e0\"", "\"e0X\"", 1);
        let vt = verify_evidence_bundle(&tampered, &[vk], None);
        assert!(
            !vt.accepted && !vt.chain_ok,
            "tamper caught: {:?}",
            vt.errors
        );

        // Partial tail (from=3): the Merkle root can't be recomputed (None) but every other
        // check still passes, so the bundle is accepted.
        let partial = make_bundle(3);
        let vp = verify_evidence_bundle(&partial, &[vk], None);
        assert!(vp.accepted, "partial tail verifies: {:?}", vp.errors);
        assert_eq!(vp.merkle_root_ok, None);

        // Equivocation: an earlier head with a forged (unsigned) root fails consistency.
        let mut forged = earlier.clone();
        forged.merkle_root = "11".repeat(32);
        let vf = verify_evidence_bundle(&full, &[vk], Some(&forged));
        assert_eq!(vf.consistency_ok, Some(false));
        assert!(!vf.accepted);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn edge_type_omitted_when_attenuate_recorded_when_mint() {
        // Attenuate (the default) is skipped → existing records are byte-identical,
        // so their hashes and signatures are unaffected.
        let att = serde_json::to_string(&entry("issue_token", true)).unwrap();
        assert!(
            !att.contains("\"edge\""),
            "attenuate edge must be omitted: {att}"
        );

        // A mint (trusted-issuer crossing) is recorded explicitly.
        let mut e = entry("issue_token", true);
        e.edge = EdgeType::Mint;
        let mint = serde_json::to_string(&e).unwrap();
        assert!(
            mint.contains("\"edge\":\"Mint\""),
            "mint edge recorded: {mint}"
        );

        // Both round-trip; a record with no `edge` deserializes as Attenuate.
        assert_eq!(
            serde_json::from_str::<Entry>(&mint).unwrap().edge,
            EdgeType::Mint
        );
        assert_eq!(
            serde_json::from_str::<Entry>(&att).unwrap().edge,
            EdgeType::Attenuate
        );
    }

    #[test]
    fn append_verify_resume() {
        let path = tmp("ok.ledger");
        std::fs::remove_file(&path).ok();
        let key = decern_crypto::generate().unwrap();

        let mut l = Ledger::open(&path, key.clone()).unwrap();
        l.append(entry("Read", true)).unwrap();
        l.append(entry("MoveMoney", false)).unwrap();
        drop(l);

        // resume with the same key: chain verifies, seq continues
        let mut l = Ledger::open(&path, key.clone()).unwrap();
        let rec = l.append(entry("Read", true)).unwrap();
        assert_eq!(rec.entry.seq, 2);

        let report = verify(&path, Some(&key.verifying_key())).unwrap();
        assert_eq!(report.entries, 3);
        assert!(report.root.is_some());
    }

    #[test]
    fn sync_enabled_ledger_appends_and_verifies() {
        // fsync-per-append must be transparent to correctness: same chain, same verify.
        let path = tmp("synced.ledger");
        std::fs::remove_file(&path).ok();
        let key = decern_crypto::generate().unwrap();
        let mut l = Ledger::open(&path, key.clone()).unwrap();
        l.set_sync(true);
        l.append(entry("Read", true)).unwrap();
        l.append(entry("MoveMoney", false)).unwrap();
        drop(l);
        let report = verify(&path, Some(&key.verifying_key())).unwrap();
        assert_eq!(report.entries, 2);
        assert!(report.signatures_checked);
    }

    #[test]
    fn read_raw_records_bytes_reproduce_the_stored_hash() {
        // The evidence-bundle contract: the VERBATIM bytes read back must let an
        // external party recompute each record's hash. `read_records` (parse→Value)
        // would reorder keys and break this; `read_raw_records` must not.
        let path = tmp("raw.ledger");
        std::fs::remove_file(&path).ok();
        let key = decern_crypto::generate().unwrap();
        let mut l = Ledger::open(&path, key.clone()).unwrap();
        // A context with several keys — reserialization would reorder them.
        let mut e = entry("Pay", true);
        e.context = json!({"z": 1, "a": 2, "m": 3, "amount_minor": 500});
        l.append(e).unwrap();
        l.append(entry("Read", true)).unwrap();

        let raw = l.read_raw_records(0, 100).unwrap();
        assert_eq!(raw.len(), 2);

        // Recompute the chain exactly as an external verifier would.
        #[derive(serde::Deserialize)]
        struct Rec {
            entry: Box<serde_json::value::RawValue>,
            prev: String,
            hash: String,
        }
        let mut prev = GENESIS.to_owned();
        for line in &raw {
            let r: Rec = serde_json::from_str(line.get()).unwrap();
            let got = hex::encode(chain_hash(r.entry.get().as_bytes(), &prev));
            assert_eq!(got, r.hash, "verbatim bytes reproduce the stored hash");
            assert_eq!(r.prev, prev, "chain link continuous");
            prev = r.hash;
        }
        assert_eq!(prev, *l.root(), "final recomputed hash == head");
    }

    #[test]
    fn read_verified_returns_a_verified_window_and_fails_closed_on_tamper() {
        let path = tmp("readv.ledger");
        std::fs::remove_file(&path).ok();
        let key = decern_crypto::generate().unwrap();
        let mut l = Ledger::open(&path, key.clone()).unwrap();
        l.append(entry("Read", true)).unwrap();
        l.append(entry("MoveMoney", false)).unwrap();
        l.append(entry("Read", true)).unwrap();
        drop(l);

        // Full read with the public key: chain + signatures verified, all 3 records back,
        // each carrying its `entry` (with the seq inside), same shape read_records returns.
        let (report, recs) = read_verified(&path, Some(&key.verifying_key()), 0, 100).unwrap();
        assert_eq!(report.entries, 3);
        assert!(report.signatures_checked);
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0]["entry"]["seq"], json!(0));
        assert_eq!(recs[2]["entry"]["action"], json!("Read"));

        // Windowed (offset 1, limit 1): whole chain still verified, only the 2nd record
        // materialized.
        let (report, recs) = read_verified(&path, None, 1, 1).unwrap();
        assert_eq!(report.entries, 3, "whole chain scanned for integrity");
        assert!(!report.signatures_checked, "no key → chain-only");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["entry"]["seq"], json!(1));
        assert_eq!(recs[0]["entry"]["action"], json!("MoveMoney"));

        // Tamper: flip the deny to allow without re-chaining → a READ must refuse, never
        // hand back the altered record as if it were sound.
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        let mut rec: Record = serde_json::from_str(&lines[1]).unwrap();
        rec.entry.decision = true;
        lines[1] = serde_json::to_string(&rec).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        let err = read_verified(&path, Some(&key.verifying_key()), 0, 100).unwrap_err();
        assert!(matches!(err, LedgerError::Tamper { seq: 1, .. }), "{err}");
    }

    #[test]
    fn flipped_decision_detected() {
        let path = tmp("tamper.ledger");
        std::fs::remove_file(&path).ok();
        let key = decern_crypto::generate().unwrap();
        let mut l = Ledger::open(&path, key.clone()).unwrap();
        l.append(entry("Read", true)).unwrap();
        l.append(entry("MoveMoney", false)).unwrap();
        l.append(entry("Read", true)).unwrap();
        drop(l);

        // flip the deny to an allow without re-chaining
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        let mut rec: Record = serde_json::from_str(&lines[1]).unwrap();
        rec.entry.decision = true;
        lines[1] = serde_json::to_string(&rec).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let err = verify(&path, Some(&key.verifying_key())).unwrap_err();
        assert!(matches!(err, LedgerError::Tamper { seq: 1, .. }), "{err}");
    }

    #[test]
    fn rewrite_with_other_key_detected() {
        let path = tmp("rewrite.ledger");
        std::fs::remove_file(&path).ok();
        let honest = decern_crypto::generate().unwrap();
        let insider = decern_crypto::generate().unwrap();

        // insider fabricates a perfectly self-consistent chain with their own key
        let mut l = Ledger::open(&path, insider).unwrap();
        l.append(entry("MoveMoney", true)).unwrap();
        drop(l);

        // chain alone verifies...
        assert!(verify(&path, None).is_ok());
        // ...but not against the honest ledger key
        let err = verify(&path, Some(&honest.verifying_key())).unwrap_err();
        assert!(matches!(err, LedgerError::Tamper { .. }));
    }

    #[test]
    fn hostile_float_context_cannot_false_tamper() {
        // Regression: serde_json float round-trips are NOT byte-stable
        // without the float_roundtrip feature. These exact values used to
        // brick an honest ledger. The hash must cover stored bytes, so
        // append -> verify -> reopen must all succeed.
        let path = tmp("floats.ledger");
        std::fs::remove_file(&path).ok();
        let key = decern_crypto::generate().unwrap();
        let mut l = Ledger::open(&path, key.clone()).unwrap();

        for ctx in [
            json!({"now": 100, "z": 1.0715660391465826e-75}),
            json!({"v": 2.291712365432881e-9}),
            json!({"now": 100, "a": 0.1, "b": 1e308, "c": -5.5e-324}),
        ] {
            let mut e = entry("Read", false);
            e.context = ctx;
            l.append(e).unwrap();
        }
        drop(l);

        let report = verify(&path, Some(&key.verifying_key())).expect("honest ledger must verify");
        assert_eq!(report.entries, 3);
        // and it must reopen for new writes
        let mut l = Ledger::open(&path, key).expect("honest ledger must reopen");
        l.append(entry("Read", true)).unwrap();
    }

    #[test]
    fn corrupt_ledger_refuses_new_writes() {
        let path = tmp("refuse.ledger");
        std::fs::remove_file(&path).ok();
        let key = decern_crypto::generate().unwrap();
        let mut l = Ledger::open(&path, key.clone()).unwrap();
        l.append(entry("Read", true)).unwrap();
        drop(l);

        // corrupt it
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("Read", "Raid")).unwrap();

        assert!(Ledger::open(&path, key).is_err());
    }

    #[test]
    fn checkpoint_signs_and_verifies() {
        let path = tmp("cp-sig.ledger");
        std::fs::remove_file(&path).ok();
        let key = decern_crypto::generate().unwrap();
        let other = decern_crypto::generate().unwrap();
        let mut l = Ledger::open(&path, key.clone()).unwrap();
        l.append(entry("Read", true)).unwrap();
        l.append(entry("MoveMoney", false)).unwrap();

        let cp = l.checkpoint(9_999);
        assert_eq!(cp.count, 2);
        assert_eq!(cp.root, l.root());
        assert_eq!(cp.pubkey_hex, l.pubkey_hex());
        // the ledger key vouches for the commitment; a different key does not
        assert!(verify_checkpoint_sig(&cp, &key.verifying_key()));
        assert!(!verify_checkpoint_sig(&cp, &other.verifying_key()));
        // and a forged field is rejected (signature covers root+count+ts)
        let mut forged = cp.clone();
        forged.count = 3;
        assert!(!verify_checkpoint_sig(&forged, &key.verifying_key()));
    }

    #[test]
    fn append_only_log_extends_its_own_checkpoint() {
        let path = tmp("cp-extend.ledger");
        std::fs::remove_file(&path).ok();
        let key = decern_crypto::generate().unwrap();
        let mut l = Ledger::open(&path, key).unwrap();
        l.append(entry("Read", true)).unwrap();
        l.append(entry("MoveMoney", false)).unwrap();
        let cp = l.checkpoint(1); // an external party holds this
        // more activity happens afterwards
        l.append(entry("Read", true)).unwrap();
        drop(l);
        // the honest, append-only log still extends the held checkpoint
        assert!(ledger_extends_checkpoint(&path, &cp).unwrap());
    }

    #[test]
    fn rewrite_below_a_held_checkpoint_is_caught() {
        let path = tmp("cp-rewrite.ledger");
        std::fs::remove_file(&path).ok();
        let key = decern_crypto::generate().unwrap();
        let mut l = Ledger::open(&path, key).unwrap();
        l.append(entry("Read", true)).unwrap();
        l.append(entry("MoveMoney", false)).unwrap();
        l.append(entry("Read", true)).unwrap();
        let cp = l.checkpoint(1);
        drop(l);

        // operator flips the recorded deny to an allow (without re-chaining)
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        let mut rec: Record = serde_json::from_str(&lines[1]).unwrap();
        rec.entry.decision = true;
        lines[1] = serde_json::to_string(&rec).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        // the external holder's re-derivation refuses to confirm the checkpoint
        let r = ledger_extends_checkpoint(&path, &cp);
        assert!(
            matches!(r, Err(LedgerError::Tamper { .. })) || matches!(r, Ok(false)),
            "rewrite below a checkpoint must break extension: {r:?}"
        );
    }

    #[test]
    fn truncation_below_a_held_checkpoint_is_caught() {
        let path = tmp("cp-truncate.ledger");
        std::fs::remove_file(&path).ok();
        let key = decern_crypto::generate().unwrap();
        let mut l = Ledger::open(&path, key).unwrap();
        l.append(entry("Read", true)).unwrap();
        l.append(entry("MoveMoney", false)).unwrap();
        l.append(entry("Read", true)).unwrap();
        let cp = l.checkpoint(1); // commits to 3 entries
        drop(l);

        // operator drops the last recorded entry
        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().take(2).collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();

        // fewer records than the checkpoint committed to → does not extend
        assert!(!ledger_extends_checkpoint(&path, &cp).unwrap());
    }

    #[test]
    fn decision_entry_serialization_is_stable() {
        // Golden serialization + chain hash for a plain Decision entry. The chain
        // commits to these exact bytes, so if field order or naming drifts, every
        // existing ledger stops verifying.
        let js = serde_json::to_string(&entry("Read", true)).unwrap();
        assert_eq!(
            js,
            r#"{"seq":0,"ts_ms":1234,"subject_type":"Principal","subject_id":"agent1","action":"Read","resource_type":"Resource","resource_id":"claim1","context":{"now":100},"decision":true,"reasons":[]}"#,
            "Decision entry serialization drifted from the golden value"
        );
        assert_eq!(
            hex::encode(chain_hash(js.as_bytes(), GENESIS)),
            "7b53ca2b3294bd92166dc254d1b56ee12a2a95b76807c08867147729405f8194",
            "Decision entry chain hash drifted from the golden value"
        );
    }

    // ------------------------------- key rotation -------------------------------

    #[test]
    fn rotation_keeps_the_whole_chain_verifiable() {
        // The core: rotating the signing key must NOT brick a long-lived log.
        let path = tmp("rotate.ledger");
        std::fs::remove_file(&path).ok();
        let old = decern_crypto::generate().unwrap();
        let new = decern_crypto::generate().unwrap();

        let mut l = Ledger::open(&path, old.clone()).unwrap();
        l.append(entry("Read", true)).unwrap(); // signed by old
        l.append(entry("Write", true)).unwrap(); // signed by old
        l.rotate(new.clone());
        l.append(entry("MoveMoney", false)).unwrap(); // signed by new
        drop(l);

        // The whole chain verifies under the keyring (old + new)...
        let report = verify_with_keys(&path, &[old.verifying_key(), new.verifying_key()]).unwrap();
        assert_eq!(report.entries, 3);
        assert!(report.signatures_checked);

        // ...but NOT under either key alone: the pre-rotation records need `old`, the
        // post-rotation record needs `new`.
        assert!(
            verify(&path, Some(&old.verifying_key())).is_err(),
            "old key alone cannot verify the post-rotation tail"
        );
        assert!(
            verify(&path, Some(&new.verifying_key())).is_err(),
            "new key alone cannot verify the pre-rotation head"
        );
    }

    #[test]
    fn rotated_ledger_reopens_with_retired_verifiers() {
        let path = tmp("rotate-reopen.ledger");
        std::fs::remove_file(&path).ok();
        let old = decern_crypto::generate().unwrap();
        let new = decern_crypto::generate().unwrap();

        let mut l = Ledger::open(&path, old.clone()).unwrap();
        l.append(entry("Read", true)).unwrap();
        l.rotate(new.clone());
        l.append(entry("Write", true)).unwrap();
        drop(l);

        // Reopening with the CURRENT key alone fails (the head was signed by `old`)...
        assert!(
            Ledger::open(&path, new.clone()).is_err(),
            "reopen without the retired key must fail on the old-signed head"
        );
        // ...but succeeds when the retired public key is supplied, and can append more.
        let mut l =
            Ledger::open_with_verifiers(&path, new.clone(), vec![old.verifying_key()]).unwrap();
        assert_eq!(l.count(), 2);
        l.append(entry("MoveMoney", true)).unwrap(); // signed by new, seq 2
        assert!(l.self_verify().is_ok());
        // the keyring an auditor pins spans both keys
        let fps = l.verifier_fingerprints();
        assert!(fps.contains(&key_fingerprint(&old.verifying_key())));
        assert!(fps.contains(&key_fingerprint(&new.verifying_key())));
    }

    #[test]
    fn a_record_signed_by_an_untrusted_key_is_tamper() {
        // A record whose kid names a key NOT in the ring must be rejected — an
        // auditor cannot be fooled into trusting a signer of the attacker's choosing.
        let path = tmp("rotate-untrusted.ledger");
        std::fs::remove_file(&path).ok();
        let honest = decern_crypto::generate().unwrap();
        let attacker = decern_crypto::generate().unwrap();

        let mut l = Ledger::open(&path, honest.clone()).unwrap();
        l.append(entry("Read", true)).unwrap(); // kid = honest fingerprint
        drop(l);

        // A ring that does NOT contain the record's signing key: its kid names a key
        // not in the ring → tamper (fail-closed on an unknown signer), NOT skipped.
        let err = verify_with_keys(&path, &[attacker.verifying_key()]).unwrap_err();
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "a record whose kid is not in the ring must be tamper: {err}"
        );
        // The honest ring verifies fine.
        assert!(verify_with_keys(&path, &[honest.verifying_key()]).is_ok());
    }

    // ------------------------------ persisted anchor ------------------------------

    #[test]
    fn anchor_catches_truncation_across_a_reopen() {
        // The core: a plain reopen accepts a truncated (still internally
        // consistent) log; the persisted anchor makes the truncation fail-closed.
        let path = tmp("anchor-truncate.ledger");
        let anchor = tmp("anchor-truncate.anchor");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&anchor).ok();
        let key = decern_crypto::generate().unwrap();

        let mut l = Ledger::open(&path, key.clone()).unwrap();
        l.append(entry("Read", true)).unwrap();
        l.append(entry("Write", true)).unwrap();
        l.append(entry("MoveMoney", false)).unwrap();
        l.seal_anchor(&anchor, 1).unwrap(); // committed height = 3
        drop(l);

        // an insider truncates the last recorded decision
        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().take(2).collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();

        // a plain reopen is fooled — the 2-record log is internally consistent...
        assert!(
            Ledger::open(&path, key.clone()).is_ok(),
            "plain reopen cannot see the truncation"
        );
        // ...but open_anchored refuses: the log no longer extends its committed height.
        let err = match Ledger::open_anchored(&path, key.clone(), Vec::new(), &anchor) {
            Ok(_) => panic!("open_anchored must catch the truncation"),
            Err(e) => e,
        };
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "anchor must catch the truncation: {err}"
        );
    }

    #[test]
    fn anchor_accepts_a_legit_append_only_extension() {
        let path = tmp("anchor-extend.ledger");
        let anchor = tmp("anchor-extend.anchor");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&anchor).ok();
        let key = decern_crypto::generate().unwrap();

        let mut l = Ledger::open(&path, key.clone()).unwrap();
        l.append(entry("Read", true)).unwrap();
        l.seal_anchor(&anchor, 1).unwrap(); // committed height = 1
        l.append(entry("Write", true)).unwrap(); // honest append-only growth
        drop(l);

        // reopening against the anchor succeeds — the log still extends height 1
        let l = Ledger::open_anchored(&path, key, Vec::new(), &anchor).unwrap();
        assert_eq!(l.count(), 2);
        // no anchor file at all is also fine (nothing committed yet)
        let missing = tmp("anchor-missing.anchor");
        std::fs::remove_file(&missing).ok();
        assert!(l.verify_against_anchor(&missing).is_ok());
    }

    /// The Ed25519 identity point is a valid encoding of a key of order 1. Under the
    /// cofactorless verification equation, the signature `R = identity, S = 0` satisfies
    /// it for EVERY message — so an operator who hands an auditor this public key can
    /// hand them any log at all and have every record "verify". RFC 8032 §5.1.7 permits
    /// the cofactorless check; rejecting a small-order key is what makes verification
    /// mean something to a party who did not write the log.
    fn small_order_key_and_universal_forgery() -> (VerifyingKey, decern_crypto::Signature) {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0] = 1; // R = identity, S = 0
        (
            VerifyingKey::from_bytes(&identity).expect("identity is a valid encoding"),
            decern_crypto::Signature::from_bytes(&sig_bytes),
        )
    }

    #[test]
    fn a_small_order_key_cannot_verify_a_signature_it_never_made() {
        let (key, forgery) = small_order_key_and_universal_forgery();
        // The premise: this pair really does satisfy the permissive equation.
        assert!(
            key.verify(b"any message at all", &forgery).is_ok(),
            "the forgery must pass the cofactorless check, or this test proves nothing"
        );
        for msg in [&b"any message at all"[..], b"a fabricated record"] {
            assert!(
                key.verify_strict(msg, &forgery).is_err(),
                "a small-order key must not verify {}",
                String::from_utf8_lossy(msg)
            );
        }
    }

    #[test]
    fn a_fabricated_anchor_under_a_small_order_key_is_refused() {
        let (key, forgery) = small_order_key_and_universal_forgery();
        let cp = Checkpoint {
            root: "00".repeat(32),
            count: 9999,
            ts_ms: 1,
            pubkey_hex: hex::encode(key.to_bytes()),
            sig_b64: B64.encode(forgery.to_bytes()),
        };
        assert!(
            !verify_checkpoint_sig(&cp, &key),
            "an anchor over a height that was never reached must not verify"
        );
        let th = TreeHead {
            merkle_root: "00".repeat(32),
            tree_size: 9999,
            ts_ms: 1,
            pubkey_hex: hex::encode(key.to_bytes()),
            sig_b64: B64.encode(forgery.to_bytes()),
        };
        assert!(!verify_tree_head_sig(&th, &key));
    }

    #[test]
    fn a_forged_anchor_from_an_untrusted_key_is_refused() {
        // An attacker who truncates the log and drops a self-signed anchor at the
        // lower height must not be able to mask the truncation — the anchor's own
        // signature must come from a trusted ledger key.
        let path = tmp("anchor-forged.ledger");
        let anchor = tmp("anchor-forged.anchor");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&anchor).ok();
        let key = decern_crypto::generate().unwrap();
        let attacker = decern_crypto::generate().unwrap();

        let mut l = Ledger::open(&path, key.clone()).unwrap();
        l.append(entry("Read", true)).unwrap();
        l.append(entry("Write", true)).unwrap();
        let honest = l.checkpoint(9); // correct (root, count) for the current head
        drop(l);

        // The attacker fabricates an anchor over the SAME (root, count) — so it still
        // "extends" the log — but signs it with their OWN key (the honest ledger's
        // records are kid-bound to `key`, so the attacker can't even open it).
        let sig = attacker.sign(&checkpoint_bytes(&honest.root, honest.count, honest.ts_ms));
        let forged = Checkpoint {
            root: honest.root,
            count: honest.count,
            ts_ms: honest.ts_ms,
            pubkey_hex: hex::encode(attacker.verifying_key().to_bytes()),
            sig_b64: B64.encode(sig.to_bytes()),
        };
        save_anchor(&anchor, &forged).unwrap();

        // the honest ledger refuses the anchor: its signer is not in the keyring
        let l = Ledger::open(&path, key).unwrap();
        let err = l.verify_against_anchor(&anchor).unwrap_err();
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "a forged anchor must be refused: {err}"
        );
    }

    #[test]
    fn legacy_kidless_records_verify_against_the_ring() {
        // A record written before rotation support has no `kid`. It must still verify
        // against the trusted key (the try-each-key fallback), so upgrading the code
        // does not brick pre-existing logs.
        let path = tmp("legacy-kidless.ledger");
        std::fs::remove_file(&path).ok();
        let key = decern_crypto::generate().unwrap();

        // Append normally, then strip the `kid` field to simulate a legacy line.
        // Do it by byte surgery on the trailing `,"kid":"<hex>"` — parsing to Value
        // and re-serializing would reorder the `entry` bytes and break the hash
        // (which is exactly why the stored bytes, not a reparse, are the proof).
        let mut l = Ledger::open(&path, key.clone()).unwrap();
        l.append(entry("Read", true)).unwrap();
        drop(l);
        let kid = key_fingerprint(&key.verifying_key());
        let text = std::fs::read_to_string(&path).unwrap();
        let stripped = text.trim_end().replace(&format!(",\"kid\":\"{kid}\""), "");
        assert!(!stripped.contains("kid"), "kid removed: {stripped}");
        std::fs::write(&path, stripped + "\n").unwrap();

        // No kid on the record → verified against any trusted key in the ring.
        assert!(verify(&path, Some(&key.verifying_key())).is_ok());
        assert!(verify_with_keys(&path, &[key.verifying_key()]).is_ok());
    }

    // ===================== per-epoch/size segmentation =====================

    fn tmp_dir(name: &str) -> PathBuf {
        let d = tmp(name);
        std::fs::remove_dir_all(&d).ok();
        d
    }

    #[test]
    fn open_segmented_creates_a_directory_with_one_active_segment_and_a_manifest() {
        let dir = tmp_dir("seg-init");
        let key = decern_crypto::generate().unwrap();
        let _l = Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()).unwrap();
        assert!(dir.join("manifest.json").exists());
        assert!(dir.join("00000001.jsonl").exists());
    }

    #[test]
    fn segmented_append_and_reopen_preserves_root_and_count() {
        let dir = tmp_dir("seg-reopen");
        let key = decern_crypto::generate().unwrap();
        {
            let mut l =
                Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::default())
                    .unwrap();
            for i in 0..5 {
                l.append(entry(&format!("act{i}"), true)).unwrap();
            }
        }
        let l2 = Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()).unwrap();
        assert_eq!(l2.count(), 5);
        let recs = l2.read_records(0, 10).unwrap();
        assert_eq!(recs.len(), 5);
    }

    #[test]
    fn segmented_size_rollover_creates_a_second_segment_and_chain_still_verifies() {
        let dir = tmp_dir("seg-size-rollover");
        let key = decern_crypto::generate().unwrap();
        let vk = key.verifying_key();
        let mut l = Ledger::open_segmented(
            &dir,
            key,
            Vec::new(),
            RolloverPolicy::max_bytes(200), // small enough that a few entries force rollover
        )
        .unwrap();
        for i in 0..8 {
            l.append(entry(&format!("action-{i}"), true)).unwrap();
        }
        drop(l);

        let segs: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".jsonl"))
            .collect();
        assert!(
            segs.len() >= 2,
            "expected rollover to produce multiple segments, got {}",
            segs.len()
        );

        // The whole segmented directory verifies end-to-end via the SAME free
        // function a single file would use — auto-detected via is_dir().
        let report = verify_with_keys(&dir, &[vk]).unwrap();
        assert_eq!(report.entries, 8);

        // Every seq is present exactly once, in order, across the boundary.
        let recs = read_verified(&dir, None, 0, 100).unwrap().1;
        let seqs: Vec<u64> = recs
            .iter()
            .map(|r| r["entry"]["seq"].as_u64().unwrap())
            .collect();
        assert_eq!(seqs, (0..8).collect::<Vec<_>>());
    }

    #[test]
    fn segmented_epoch_rollover_triggers_on_a_bucket_change() {
        let dir = tmp_dir("seg-epoch-rollover");
        let key = decern_crypto::generate().unwrap();
        let mut l =
            Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::epoch_ms(1000)).unwrap();
        let mut e0 = entry("a", true);
        e0.ts_ms = 500; // bucket 0
        l.append(e0).unwrap();
        let mut e1 = entry("b", true);
        e1.ts_ms = 1500; // bucket 1 — crosses the boundary, must roll over
        l.append(e1).unwrap();
        drop(l);

        let segs: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".jsonl"))
            .collect();
        assert_eq!(segs.len(), 2, "epoch bucket change must trigger a rollover");
    }

    #[cfg(unix)]
    #[test]
    fn segmented_sealed_segment_is_chmod_read_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("seg-chmod");
        let key = decern_crypto::generate().unwrap();
        let mut l =
            Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::max_bytes(150)).unwrap();
        for i in 0..8 {
            l.append(entry(&format!("action-{i}"), true)).unwrap();
        }
        drop(l);
        let sealed = dir.join("00000001.jsonl");
        let mode = std::fs::metadata(&sealed).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o400,
            "a sealed segment must be read-only AND not readable by group or other"
        );
    }

    #[test]
    fn segmented_read_records_offset_limit_spans_a_segment_boundary_and_matches_single_file() {
        // offset/limit must be a GLOBAL record index across segments, not
        // re-applied per file. Build the SAME 5 entries
        // into a single-file ledger and a 2-segment ledger (rollover forced
        // after the 2nd entry) and assert every windowed read matches exactly.
        let single_path = tmp("seg-cmp-single.log");
        std::fs::remove_file(&single_path).ok();
        let seg_dir = tmp_dir("seg-cmp-segmented");
        let key = decern_crypto::generate().unwrap();

        let mut single = Ledger::open(&single_path, key.clone()).unwrap();
        let mut segmented =
            Ledger::open_segmented(&seg_dir, key, Vec::new(), RolloverPolicy::max_bytes(1))
                .unwrap(); // 1 byte: rolls over before EVERY append after the first

        for i in 0..5 {
            let e = entry(&format!("act{i}"), true);
            single.append(e.clone()).unwrap();
            segmented.append(e).unwrap();
        }

        // Confirm the rollover actually produced multiple segments (else this
        // test would trivially pass without exercising the boundary at all).
        let segs = std::fs::read_dir(&seg_dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".jsonl")
            })
            .count();
        assert!(segs >= 3, "expected several segments, got {segs}");

        for (offset, limit) in [(0usize, 5usize), (1, 3), (2, 2), (3, 100), (4, 1), (0, 1)] {
            let a = single.read_records(offset, limit).unwrap();
            let b = segmented.read_records(offset, limit).unwrap();
            assert_eq!(a, b, "read_records({offset}, {limit}) mismatch");

            let ar = single.read_raw_records(offset, limit).unwrap();
            let br = segmented.read_raw_records(offset, limit).unwrap();
            let a_strs: Vec<&str> = ar.iter().map(|v| v.get()).collect();
            let b_strs: Vec<&str> = br.iter().map(|v| v.get()).collect();
            assert_eq!(
                a_strs, b_strs,
                "read_raw_records({offset}, {limit}) verbatim-byte mismatch"
            );
        }
    }

    #[test]
    fn segmented_verify_fails_closed_when_a_manifest_listed_segment_is_missing() {
        let dir = tmp_dir("seg-missing-segment");
        let key = decern_crypto::generate().unwrap();
        let mut l = Ledger::open_segmented(
            &dir,
            key.clone(),
            Vec::new(),
            RolloverPolicy::max_bytes(150),
        )
        .unwrap();
        for i in 0..8 {
            l.append(entry(&format!("action-{i}"), true)).unwrap();
        }
        drop(l);

        // Delete a SEALED segment's bytes but leave the manifest still naming
        // it — the mid-log analogue of a tail truncation. The manifest is
        // untrusted metadata; only the actual bytes are load-bearing.
        std::fs::remove_file(dir.join("00000001.jsonl")).unwrap();

        let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
            Err(e) => e,
            Ok(_) => panic!("expected open_segmented to fail on a missing segment"),
        };
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "expected Tamper, got {err:?}"
        );
    }

    #[test]
    fn segmented_anchor_catches_a_truncation_that_deletes_a_whole_sealed_segment() {
        // Parity with the single-file case: the chain walk ALONE cannot
        // distinguish "the log always had 3 records" from "the log had 5 and
        // lost the last 2 (plus their segment + manifest entry)" — that is
        // exactly what an externally-persisted anchor exists to catch.
        let dir = tmp_dir("seg-anchor-truncation");
        let anchor_path = tmp("seg-anchor-truncation.anchor");
        std::fs::remove_file(&anchor_path).ok();
        let key = decern_crypto::generate().unwrap();

        let mut l = Ledger::open_segmented(
            &dir,
            key.clone(),
            Vec::new(),
            RolloverPolicy::max_bytes(150),
        )
        .unwrap();
        for i in 0..8 {
            l.append(entry(&format!("action-{i}"), true)).unwrap();
        }
        l.seal_anchor(&anchor_path, 999).unwrap();
        drop(l);

        // Attacker deletes the newest (active) segment's file AND its
        // manifest entry, then re-marks the new tail as active so the
        // manifest stays SHAPE-VALID (exactly one active segment) — the full,
        // sophisticated attacker capability, not just "delete a file and
        // leave a dangling reference" (that simpler case is covered by
        // `segmented_verify_fails_closed_when_a_manifest_listed_segment_is_missing`
        // and is caught earlier, by `segment_paths` itself).
        let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
        let last = manifest.segments.pop().unwrap();
        if let Some(new_last) = manifest.segments.last_mut() {
            new_last.end_seq = None;
        }
        segment::save_manifest(&dir, &manifest).unwrap();
        std::fs::remove_file(dir.join(&last.file)).unwrap();

        let err = match Ledger::open_segmented_anchored(
            &dir,
            key,
            Vec::new(),
            RolloverPolicy::default(),
            &anchor_path,
        ) {
            Err(e) => e,
            Ok(_) => panic!("expected open_segmented_anchored to fail: anchor no longer extended"),
        };
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "expected Tamper (anchor no longer extended), got {err:?}"
        );
    }

    #[test]
    fn open_on_a_segmented_directory_returns_a_clear_error_not_a_raw_os_error() {
        let dir = tmp_dir("seg-vs-open");
        let key = decern_crypto::generate().unwrap();
        let _l = Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::default())
            .unwrap();
        let err = match Ledger::open(&dir, key) {
            Err(e) => e,
            Ok(_) => panic!("expected Ledger::open to refuse a segmented directory"),
        };
        match err {
            LedgerError::Io { err, .. } => assert!(
                err.contains("open_segmented"),
                "expected a clear pointer to open_segmented, got: {err}"
            ),
            other => panic!("expected LedgerError::Io, got {other:?}"),
        }
    }

    #[test]
    fn open_segmented_ignores_an_orphan_segment_left_by_a_crashed_rollover() {
        let dir = tmp_dir("seg-orphan");
        let key = decern_crypto::generate().unwrap();
        {
            let mut l = Ledger::open_segmented(
                &dir,
                key.clone(),
                Vec::new(),
                RolloverPolicy::default(), // never auto-rolls; we simulate the crash by hand
            )
            .unwrap();
            l.append(entry("a", true)).unwrap();
        }
        // Simulate a rollover that created the new segment file but crashed
        // before the manifest commit: an extra, higher-numbered file the
        // manifest does not (yet) know about.
        std::fs::write(dir.join("00000002.jsonl"), b"").unwrap();

        let mut l =
            Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::max_bytes(1)).unwrap();
        assert_eq!(l.count(), 1, "the orphan must not be silently adopted");
        // The very next append forces a rollover (max_bytes=1); it must pick
        // an index that does NOT collide with the orphan.
        l.append(entry("b", true)).unwrap();
        assert!(
            dir.join("00000003.jsonl").exists(),
            "rollover must skip past the orphan's index, not overwrite it"
        );
        let orphan_still_empty = std::fs::metadata(dir.join("00000002.jsonl")).unwrap().len();
        assert_eq!(
            orphan_still_empty, 0,
            "orphan must never be silently reused/overwritten"
        );
    }

    // ===== segmented-ledger hardening: rollover filenames =====

    #[test]
    fn roll_over_ignores_a_planted_out_of_range_filename_instead_of_overflowing() {
        // A file named exactly u32::MAX (10 digits) would overflow the naive
        // `max_index + 1` in roll_over if it were adopted as a real segment
        // index. validate_segment_filename's 8-digit shape requirement makes
        // max_index's directory scan treat it as "not a segment file" at
        // all (the same as it already treats manifest.json itself) — so
        // rollover proceeds completely unaffected by the decoy, rather than
        // erroring OR overflowing.
        let dir = tmp_dir("seg-overflow-guard");
        let key = decern_crypto::generate().unwrap();
        let mut l =
            Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::max_bytes(1)).unwrap();
        l.append(entry("a", true)).unwrap();
        std::fs::write(dir.join("4294967295.jsonl"), b"").unwrap();

        l.append(entry("b", true))
            .expect("the decoy filename must not block a normal rollover");
        assert!(
            dir.join("00000002.jsonl").exists(),
            "rollover must proceed to the next real index, unaffected by the decoy"
        );
        assert!(
            !dir.join("00000000.jsonl").exists(),
            "must never silently wrap to and create index 0"
        );
    }

    #[test]
    fn open_segmented_rejects_a_manifest_that_names_an_out_of_range_segment_filename() {
        // Unlike a decoy file merely sitting in the directory (ignored, see
        // the sibling test above), a MANIFEST entry naming an out-of-range
        // filename must be rejected outright — load_manifest validates every
        // segment's `file` field unconditionally, the moment the manifest is
        // read, before anything downstream (segment_paths, the active-segment
        // pick) can act on it.
        let dir = tmp_dir("seg-overflow-manifest");
        let key = decern_crypto::generate().unwrap();
        {
            let mut l =
                Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::default())
                    .unwrap();
            l.append(entry("a", true)).unwrap();
        }
        let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
        manifest.segments[0].file = "4294967295.jsonl".into();
        // Bypass save_manifest's own (correct) behavior of writing whatever
        // it's given — write the tampered manifest directly so this test
        // exercises `load_manifest`'s READ-time validation, not a write-path
        // check that doesn't exist and shouldn't need to.
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
            Err(e) => e,
            Ok(_) => panic!("expected an out-of-range manifest filename to be rejected"),
        };
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "expected Tamper (invalid segment filename), got {err:?}"
        );
    }

    #[test]
    fn open_segmented_rejects_a_manifest_with_two_active_segments() {
        let dir = tmp_dir("seg-dual-active");
        let key = decern_crypto::generate().unwrap();
        {
            let mut l =
                Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::max_bytes(1))
                    .unwrap();
            for i in 0..3 {
                l.append(entry(&format!("a{i}"), true)).unwrap();
            }
        }
        // Clear end_seq on an already-sealed, non-tail segment — a manifest
        // edit alone, no signing key, no byte-level tamper — producing a
        // shape-invalid "dual active" manifest.
        let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
        manifest.segments[0].end_seq = None;
        segment::save_manifest(&dir, &manifest).unwrap();

        let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
            Err(e) => e,
            Ok(_) => panic!("expected a dual-active manifest to be rejected"),
        };
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "expected Tamper (dual active segment), got {err:?}"
        );
    }

    #[test]
    fn open_segmented_rejects_a_manifest_whose_active_segment_is_not_the_last_entry() {
        let dir = tmp_dir("seg-active-not-tail");
        let key = decern_crypto::generate().unwrap();
        {
            let mut l =
                Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::max_bytes(1))
                    .unwrap();
            for i in 0..3 {
                l.append(entry(&format!("a{i}"), true)).unwrap();
            }
        }
        // Swap which segment is "active" WITHOUT changing which one is last —
        // mark the true tail sealed and an earlier one active, still exactly
        // one active segment overall (so the dual-active check alone would
        // not catch this), but not the last entry.
        let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
        let last_end = manifest.segments.last().unwrap().end_seq;
        manifest.segments[0].end_seq = None;
        manifest.segments.last_mut().unwrap().end_seq = last_end.or(Some(3));
        segment::save_manifest(&dir, &manifest).unwrap();

        let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
            Err(e) => e,
            Ok(_) => panic!("expected a non-tail-active manifest to be rejected"),
        };
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "expected Tamper (active segment not last), got {err:?}"
        );
    }

    #[test]
    fn segment_paths_rejects_a_path_traversal_filename_in_the_manifest() {
        // A manifest entry's `file` field must be validated BEFORE it is ever
        // joined onto the segment directory — otherwise an unverified read
        // (read_records/read_raw_records, which the admin ledger browser and
        // the evidence-bundle endpoint both call) could be redirected to
        // return the content of an arbitrary file outside the ledger dir.
        let dir = tmp_dir("seg-traversal");
        let outside = tmp("seg-traversal-secret.jsonl");
        std::fs::write(&outside, b"{\"leaked\":true}\n").unwrap();
        let key = decern_crypto::generate().unwrap();
        {
            let mut l =
                Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::default())
                    .unwrap();
            l.append(entry("a", true)).unwrap();
        }
        let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
        manifest.segments[0].file = "../seg-traversal-secret.jsonl".into();
        segment::save_manifest(&dir, &manifest).unwrap();

        let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
            Err(e) => e,
            Ok(_) => panic!("expected a path-traversal filename to be rejected"),
        };
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "expected Tamper (invalid segment filename), got {err:?}"
        );
    }

    #[test]
    fn fresh_epoch_only_ledger_does_not_waste_an_empty_first_segment() {
        // segment::initialize hardcodes the first segment's opened_ms to 0;
        // without the "active segment is still empty" guard in
        // should_roll_over, the FIRST real append (a realistic ts_ms, order
        // 10^12) would roll over before writing anything, since its epoch
        // bucket almost never matches bucket 0.
        let dir = tmp_dir("seg-epoch-fresh-no-waste");
        let key = decern_crypto::generate().unwrap();
        let mut l =
            Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::epoch_ms(86_400_000))
                .unwrap();
        let mut e = entry("first", true);
        e.ts_ms = 1_780_000_000_000; // a realistic, far-from-zero epoch ms
        l.append(e).unwrap();
        drop(l);

        assert!(
            dir.join("00000001.jsonl").exists(),
            "the first entry must land in segment 1"
        );
        assert!(
            !dir.join("00000002.jsonl").exists(),
            "a still-empty first segment must never be rolled over"
        );
        let bytes = std::fs::metadata(dir.join("00000001.jsonl")).unwrap().len();
        assert!(bytes > 0, "segment 1 must actually hold the record");
    }

    #[test]
    fn segmented_deleting_a_middle_segment_with_manifest_reconciled_is_still_caught() {
        // Dropping a middle segment (and editing the manifest to skip it) now
        // breaks start/end contiguity between the two neighbors, so
        // validate_manifest_shape's contiguity check rejects it at
        // load_manifest time — before verify_lines' unconditional per-record
        // seq/prev checks would ever get a chance to catch it independently.
        // Locks in defense-in-depth: two layers now catch this, not one.
        let dir = tmp_dir("seg-middle-gap");
        let key = decern_crypto::generate().unwrap();
        {
            let mut l =
                Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::max_bytes(1))
                    .unwrap();
            for i in 0..4 {
                l.append(entry(&format!("a{i}"), true)).unwrap();
            }
        }
        let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
        assert!(manifest.segments.len() >= 3, "need a real middle segment");
        let middle = manifest.segments.remove(1);
        segment::save_manifest(&dir, &manifest).unwrap();
        std::fs::remove_file(dir.join(&middle.file)).unwrap();

        let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
            Err(e) => e,
            Ok(_) => panic!("expected a reconciled middle-segment gap to still be caught"),
        };
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "expected Tamper (sequence break), got {err:?}"
        );
    }

    #[test]
    fn segmented_read_verified_offset_window_matches_read_records_across_a_boundary() {
        // read_verified windows by a per-record `count` incremented inside
        // verify_lines; read_records/read_raw_records window by Iterator::skip
        // over raw lines. These are two independently-implemented mechanisms
        // that only agree because no writer path ever emits a blank line —
        // this pins that agreement down for a segmented ledger with a
        // non-zero offset spanning a boundary, so a future change that
        // decouples the two counting schemes would be caught here.
        let dir = tmp_dir("seg-read-verified-parity");
        let key = decern_crypto::generate().unwrap();
        let vk = key.verifying_key();
        let mut l =
            Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::max_bytes(1)).unwrap();
        for i in 0..6 {
            l.append(entry(&format!("a{i}"), true)).unwrap();
        }

        for (offset, limit) in [(0usize, 100usize), (2, 3), (1, 1), (5, 10)] {
            let direct = l.read_records(offset, limit).unwrap();
            let (_report, verified) = read_verified(&dir, Some(&vk), offset, limit).unwrap();
            assert_eq!(
                direct, verified,
                "read_verified({offset}, {limit}) must match read_records exactly"
            );
        }
    }

    // ===== segmented-ledger hardening: filename ceiling =====

    #[test]
    fn roll_over_refuses_to_create_a_segment_past_the_8_digit_filename_ceiling() {
        // Fabricate a manifest whose sole active segment is already at the
        // maximum representable 8-digit index (99,999,999) — no need to
        // actually perform 100 million real rollovers to reach the
        // boundary. `segment_filename`'s `{:08}` is a MINIMUM width, not a
        // cap, so the next policy-triggered rollover would otherwise
        // silently create a 9-digit filename that `validate_segment_filename`
        // (the very check that closed the original planted-decoy overflow
        // bug) then rejects as Tamper on the NEXT read or reopen. The
        // rollover must instead refuse cleanly, at append() time.
        let dir = tmp_dir("seg-8digit-ceiling");
        std::fs::create_dir_all(&dir).unwrap();
        let seg_file = segment::segment_filename(99_999_999);
        std::fs::write(dir.join(&seg_file), b"").unwrap();
        let manifest = segment::Manifest {
            version: 1,
            segments: vec![segment::SegmentMeta {
                file: seg_file,
                start_seq: 0,
                end_seq: None,
                opened_ms: 0,
            }],
        };
        segment::save_manifest(&dir, &manifest).unwrap();

        let key = decern_crypto::generate().unwrap();
        let mut l =
            Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::max_bytes(1))
                .unwrap();
        l.append(entry("a", true)).unwrap(); // lands in the pre-seeded segment (active_is_empty)
        let err = match l.append(entry("b", true)) {
            Err(e) => e,
            Ok(_) => panic!("expected rollover past the 8-digit ceiling to be refused"),
        };
        assert!(
            matches!(err, LedgerError::Io { .. }),
            "expected a clean Io error at rollover time, got {err:?}"
        );
        drop(l);

        // Crucially: the refused rollover must not have half-committed
        // anything — the ledger must still open and verify cleanly
        // afterward, holding exactly the one entry that succeeded.
        let reopened =
            Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::max_bytes(1)).unwrap();
        assert_eq!(
            reopened.count(),
            1,
            "only the first append should have landed"
        );
    }

    #[test]
    fn segmented_epoch_policy_keeps_two_same_bucket_entries_in_one_segment() {
        // Regression for the opened_ms-never-rebased gap: segment 1's
        // opened_ms is hardcoded to 0 by segment::initialize (no entry
        // exists yet to read a real timestamp from). Without rebasing it to
        // the first real entry's ts_ms once that entry lands, EVERY append
        // after the first would compare a real ts_ms (~10^12) against the
        // stale 0 and roll over one record after the first no matter how
        // close in time the two really are — silently defeating epoch-based
        // grouping for the entirety of a fresh ledger's first bucket.
        let dir = tmp_dir("seg-epoch-rebase");
        let key = decern_crypto::generate().unwrap();
        let mut l =
            Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::epoch_ms(86_400_000))
                .unwrap();
        let mut e0 = entry("a", true);
        e0.ts_ms = 1_780_000_000_000; // some real Unix-ms timestamp
        l.append(e0).unwrap();
        let mut e1 = entry("b", true);
        e1.ts_ms = 1_780_000_000_500; // 500ms later, same epoch bucket
        l.append(e1).unwrap();
        drop(l);

        let segs: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".jsonl"))
            .collect();
        assert_eq!(
            segs.len(),
            1,
            "two entries in the same real epoch bucket must stay in one segment"
        );
    }

    #[test]
    fn open_segmented_rejects_a_manifest_with_reordered_sealed_segments() {
        // Swapping the array order of two already-sealed segments (no
        // deletion, no active-segment tampering — both existing checks stay
        // silent) still breaks start/end contiguity between neighbors and
        // must be rejected, since segment_paths reads files strictly in
        // manifest array order.
        let dir = tmp_dir("seg-reordered");
        let key = decern_crypto::generate().unwrap();
        {
            let mut l =
                Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::max_bytes(1))
                    .unwrap();
            for i in 0..4 {
                l.append(entry(&format!("a{i}"), true)).unwrap();
            }
        }
        let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
        assert!(
            manifest.segments.len() >= 3,
            "need at least two sealed segments to swap"
        );
        manifest.segments.swap(0, 1);
        segment::save_manifest(&dir, &manifest).unwrap();

        let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
            Err(e) => e,
            Ok(_) => panic!("expected a reordered manifest to be rejected"),
        };
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "expected Tamper (non-contiguous segments), got {err:?}"
        );
    }

    #[test]
    fn open_segmented_rejects_a_manifest_with_zero_segments() {
        // segment::initialize never produces an empty segments list, so this
        // is a shape no legitimate code path can reach — rejecting it is
        // zero-false-positive-risk and closes a gap where the free,
        // path-only read functions (verify/read_verified, which never call
        // open_segmented's separate zero-active check) would otherwise
        // silently report a clean, empty ledger while real segment files
        // with real records sit untouched on disk.
        let dir = tmp_dir("seg-zero-segments");
        let key = decern_crypto::generate().unwrap();
        {
            let mut l =
                Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::default())
                    .unwrap();
            l.append(entry("a", true)).unwrap();
        }
        let empty = segment::Manifest {
            version: 1,
            segments: vec![],
        };
        segment::save_manifest(&dir, &empty).unwrap();

        let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
            Err(e) => e,
            Ok(_) => panic!("expected a zero-segment manifest to be rejected"),
        };
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "expected Tamper (zero segments), got {err:?}"
        );
    }

    // ===== segmented-ledger hardening: manifest integrity =====

    #[test]
    fn segmented_manifest_missing_its_head_segment_is_rejected_including_on_an_already_open_handle()
    {
        // The contiguity check alone only verifies ADJACENT pairs — dropping
        // the earliest segment leaves every remaining pair still mutually
        // contiguous, so it needed its own explicit anchor-to-seq-0 check.
        // Exercise BOTH the reopen path AND the path this gap actually
        // mattered for: read_records on an ALREADY-OPEN handle, which
        // re-reads the manifest fresh on every call but never re-runs the
        // chain walk that would otherwise have caught this independently.
        let dir = tmp_dir("seg-head-drop");
        let key = decern_crypto::generate().unwrap();
        let mut l =
            Ledger::open_segmented(&dir, key.clone(), Vec::new(), RolloverPolicy::max_bytes(1))
                .unwrap();
        for i in 0..4 {
            l.append(entry(&format!("a{i}"), true)).unwrap();
        }
        let mut manifest = segment::load_manifest(&dir).unwrap().unwrap();
        assert!(
            manifest.segments.len() >= 3,
            "need a real head segment to drop"
        );
        manifest.segments.remove(0);
        segment::save_manifest(&dir, &manifest).unwrap();

        let err = l
            .read_records(0, 100)
            .expect_err("head-dropped manifest must be rejected, not silently shifted");
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "expected Tamper (missing chain head), got {err:?}"
        );
        drop(l);

        let err = match Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::default()) {
            Err(e) => e,
            Ok(_) => panic!("expected a head-dropped manifest to be rejected on reopen"),
        };
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "expected Tamper (missing chain head), got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn opened_ms_rebase_rolls_back_in_memory_on_a_failed_persist_so_a_retry_still_persists_it() {
        use std::os::unix::fs::PermissionsExt;
        // If the rebase mutated self.rollover.manifest BEFORE the fallible
        // save_manifest call (with no rollback on failure), a retry with the
        // identical timestamp would find opened_ms already "correct" in
        // memory and silently skip persisting it to disk forever. Force the
        // first attempt's persist to fail, then confirm a retry with the
        // SAME entry still lands the correction on disk.
        let dir = tmp_dir("seg-rebase-rollback");
        let key = decern_crypto::generate().unwrap();
        let mut l =
            Ledger::open_segmented(&dir, key, Vec::new(), RolloverPolicy::epoch_ms(86_400_000))
                .unwrap();

        let mut e0 = entry("a", true);
        e0.ts_ms = 1_780_000_000_000;
        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(&dir, perms.clone()).unwrap();
        l.append(e0.clone())
            .expect_err("save_manifest should fail while the dir is read-only");
        perms.set_mode(0o700);
        std::fs::set_permissions(&dir, perms).unwrap();

        l.append(e0).unwrap();

        let manifest = segment::load_manifest(&dir).unwrap().unwrap();
        assert_eq!(
            manifest.segments[0].opened_ms, 1_780_000_000_000,
            "the retry must have persisted the rebased opened_ms to disk"
        );
    }

    // ===================== torn-tail vs tamper (crash recovery) =====================

    /// A ledger written before a field existed must still verify, byte for byte,
    /// after that field is added. Every optional column is `skip_serializing_if`
    /// for exactly this reason, and the chain hashes the bytes on disk — so the
    /// guarantee is only real if a record lacking the newest fields still checks
    /// out. Written as literal on-disk lines rather than by re-serializing, so
    /// this fails if a future field ever starts emitting a default.
    #[test]
    fn a_record_written_before_the_newest_columns_still_verifies() {
        let key = decern_crypto::generate().unwrap();
        let vk = key.verifying_key();
        let path = tmp("pre-columns-compat.ledger");
        std::fs::remove_file(&path).ok();

        // Append through the current code, then confirm the bytes carry none of
        // the default-valued columns: their absence is what an older writer
        // produced, so today's output IS the old shape when nothing set them.
        let mut l = Ledger::open(&path, key.clone()).unwrap();
        l.append(entry("act0", true)).unwrap();
        drop(l);

        let line = std::fs::read_to_string(&path).unwrap();
        assert!(
            !line.contains("decision_subject_source"),
            "a default source must not be written; old records would not have it: {line}"
        );
        assert!(
            !line.contains("sponsor_source"),
            "a default sponsor source must not be written either: {line}"
        );

        // The chain covers the exact bytes above, so this is the real check: an
        // entry with none of the newer columns verifies as authentic.
        let report = verify(&path, Some(&vk)).unwrap();
        assert_eq!(report.entries, 1);
        assert!(report.signatures_checked);

        // And it round-trips: reading it back yields the defaults rather than
        // failing to parse, which is what lets an old ledger be read at all.
        let (_r, records) = read_verified(&path, Some(&vk), 0, 1).unwrap();
        let rec = records.first().expect("one record");
        assert!(rec["entry"].get("decision_subject_source").is_none());
        std::fs::remove_file(&path).ok();
    }

    /// Write `n` valid, chain+signature-valid records, then return the file's
    /// full lines so a test can rebuild a deliberately damaged tail.
    fn seed_lines(path: &Path, key: &SigningKey, n: usize) -> Vec<String> {
        std::fs::remove_file(path).ok();
        let mut l = Ledger::open(path, key.clone()).unwrap();
        for i in 0..n {
            l.append(entry(&format!("act{i}"), true)).unwrap();
        }
        drop(l);
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn crash_torn_tail_heals_as_torn_tail_not_tamper() {
        let key = decern_crypto::generate().unwrap();
        let vk = key.verifying_key();
        let path = tmp("torn-heals.ledger");
        let lines = seed_lines(&path, &key, 3);

        // Simulate a crash mid-append of record 2: the first two records are
        // whole + newline-terminated; the third is a half-written fragment with
        // NO trailing newline.
        let torn = format!(
            "{}\n{}\n{}",
            lines[0],
            lines[1],
            &lines[2][..lines[2].len() / 2]
        );
        std::fs::write(&path, &torn).unwrap();

        // The read-only verifier SURFACES this as TornTail, distinct from Tamper.
        let err = verify(&path, Some(&vk)).unwrap_err();
        match err {
            LedgerError::TornTail { healed_entries, .. } => assert_eq!(healed_entries, 2),
            other => panic!("expected TornTail, got {other:?}"),
        }

        // Opening HEALS: the verified 2-record prefix is intact and appendable.
        let mut l = Ledger::open(&path, key.clone()).unwrap();
        l.append(entry("after-heal", true)).unwrap();
        drop(l);

        // Reopen: clean, three records (2 healed + 1 new), no torn tail remains.
        let report = verify(&path, Some(&vk)).unwrap();
        assert_eq!(report.entries, 3);
    }

    #[test]
    fn unterminated_but_complete_final_record_is_discarded_then_appends_cleanly() {
        // The strongest proof the rule is keyed on NEWLINE-TERMINATION, not on
        // parseability: the final record's bytes are entirely present and parse
        // fine — only its terminating '\n' never reached disk. It must still be
        // discarded, because keeping an unterminated line would fuse the next
        // append onto it as one physical line and corrupt the log.
        let key = decern_crypto::generate().unwrap();
        let vk = key.verifying_key();
        let path = tmp("torn-complete.ledger");
        let lines = seed_lines(&path, &key, 3);

        // All three records complete; drop ONLY the trailing newline.
        std::fs::write(&path, format!("{}\n{}\n{}", lines[0], lines[1], lines[2])).unwrap();

        // Surfaced as TornTail even though the final line parses cleanly.
        match verify(&path, Some(&vk)).unwrap_err() {
            LedgerError::TornTail { healed_entries, .. } => assert_eq!(healed_entries, 2),
            other => panic!("expected TornTail, got {other:?}"),
        }

        let mut l = Ledger::open(&path, key.clone()).unwrap();
        l.append(entry("after-heal", true)).unwrap();
        drop(l);

        // The append landed on its own line — not fused — and verifies.
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text.lines().count(),
            3,
            "records must stay one-per-line: {text}"
        );
        assert!(
            text.ends_with('\n'),
            "healed log is newline-terminated again"
        );
        assert_eq!(verify(&path, Some(&vk)).unwrap().entries, 3);
    }

    #[test]
    fn attacker_ragged_truncation_below_anchor_stays_tamper() {
        // The discriminating case the review demands: an attacker truncates
        // MID-record so the file ends WITHOUT a newline (entering the heal path),
        // but the healed prefix falls BELOW the committed anchor height. This is
        // deletion of acked history, not a crash tail → must stay Tamper, and the
        // file must NOT be mutated before that verdict.
        let key = decern_crypto::generate().unwrap();
        let path = tmp("torn-below-anchor.ledger");
        let anchor = tmp("torn-below-anchor.anchor");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&anchor).ok();

        let mut l = Ledger::open(&path, key.clone()).unwrap();
        for i in 0..3 {
            l.append(entry(&format!("act{i}"), true)).unwrap();
        }
        l.seal_anchor(&anchor, 1_000).unwrap(); // commits to 3 records
        drop(l);

        let lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        // Keep 1 whole record + a ragged (unterminated) fragment of record 1 →
        // healed prefix = 1 < anchored 3.
        let ragged = format!("{}\n{}", lines[0], &lines[1][..lines[1].len() / 2]);
        std::fs::write(&path, &ragged).unwrap();
        let len_before = std::fs::metadata(&path).unwrap().len();

        let err = match Ledger::open_anchored(&path, key.clone(), Vec::new(), &anchor) {
            Ok(_) => panic!("ragged truncation below the anchor must fail to open"),
            Err(e) => e,
        };
        assert!(
            matches!(err, LedgerError::Tamper { .. }),
            "ragged truncation below the anchor must be Tamper, got {err:?}"
        );
        // The verdict was reached WITHOUT healing/truncating the file.
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            len_before,
            "the file must not be mutated when the torn tail is really a truncation attack"
        );
    }

    #[test]
    fn terminated_final_record_with_broken_signature_stays_tamper() {
        // A fully newline-terminated final record that fails signature is NOT a
        // torn tail — a terminated line can't be a partial write. Stays Tamper.
        let key = decern_crypto::generate().unwrap();
        let vk = key.verifying_key();
        let path = tmp("terminated-bad-sig.ledger");
        let lines = seed_lines(&path, &key, 3);

        // Corrupt one base64 char of the last record's signature, keep the '\n'.
        let mut last: serde_json::Value = serde_json::from_str(&lines[2]).unwrap();
        let sig = last["sig_b64"].as_str().unwrap().to_owned();
        let flipped = if sig.starts_with('A') { 'B' } else { 'A' };
        last["sig_b64"] = json!(format!("{flipped}{}", &sig[1..]));
        let corrupt = format!(
            "{}\n{}\n{}\n",
            lines[0],
            lines[1],
            serde_json::to_string(&last).unwrap()
        );
        std::fs::write(&path, &corrupt).unwrap();

        match verify(&path, Some(&vk)).unwrap_err() {
            LedgerError::Tamper { .. } => {}
            other => panic!("terminated bad-signature record must be Tamper, got {other:?}"),
        }
    }

    #[test]
    fn terminated_final_record_with_broken_chain_stays_tamper() {
        // Same guarantee for a broken hash-chain link on a terminated final line.
        let key = decern_crypto::generate().unwrap();
        let vk = key.verifying_key();
        let path = tmp("terminated-bad-chain.ledger");
        let lines = seed_lines(&path, &key, 3);

        // Flip a byte inside the final record's stored entry: breaks its hash
        // (and thus the chain), while the line stays newline-terminated.
        let mut last: serde_json::Value = serde_json::from_str(&lines[2]).unwrap();
        last["hash"] = json!("00".repeat(32));
        let corrupt = format!(
            "{}\n{}\n{}\n",
            lines[0],
            lines[1],
            serde_json::to_string(&last).unwrap()
        );
        std::fs::write(&path, &corrupt).unwrap();

        match verify(&path, Some(&vk)).unwrap_err() {
            LedgerError::Tamper { .. } => {}
            other => panic!("terminated broken-chain record must be Tamper, got {other:?}"),
        }
    }

    #[test]
    fn healthy_log_ends_newline_terminated_and_reopens_clean() {
        // The single-write append terminates every record in the same write, so
        // a clean shutdown always leaves a newline-terminated file with no torn
        // tail — the round-trip the heal path must never disturb.
        let key = decern_crypto::generate().unwrap();
        let vk = key.verifying_key();
        let path = tmp("healthy-roundtrip.ledger");
        seed_lines(&path, &key, 4);

        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(*bytes.last().unwrap(), b'\n', "log is newline-terminated");
        assert_eq!(verify(&path, Some(&vk)).unwrap().entries, 4);
        // Reopen (no heal) and keep appending.
        let mut l = Ledger::open(&path, key.clone()).unwrap();
        l.append(entry("more", true)).unwrap();
        drop(l);
        assert_eq!(verify(&path, Some(&vk)).unwrap().entries, 5);
    }

    #[test]
    fn anchored_crash_tail_above_the_anchor_heals_and_opens() {
        // The POSITIVE control mirroring `attacker_ragged_truncation_below_anchor`:
        // an honest crash left an unterminated tail whose verified prefix STILL
        // covers the committed height. `open_anchored` must walk the anchor
        // check, heal, AND pass the post-heal `verify_against_anchor` — i.e. an
        // anchored deployment recovers from a crash instead of bricking.
        let key = decern_crypto::generate().unwrap();
        let vk = key.verifying_key();
        let path = tmp("anchored-crash-tail.ledger");
        let anchor = tmp("anchored-crash-tail.anchor");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(&anchor).ok();

        let mut l = Ledger::open(&path, key.clone()).unwrap();
        for i in 0..3 {
            l.append(entry(&format!("act{i}"), true)).unwrap();
        }
        l.seal_anchor(&anchor, 1_000).unwrap(); // commits to 3 records
        l.append(entry("act3", true)).unwrap(); // a 4th, un-acked record
        drop(l);

        let lines: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        // Crash mid-append of record 3: records 0..=2 whole + terminated (== the
        // anchored height), record 3 a ragged unterminated fragment.
        let torn = format!(
            "{}\n{}\n{}\n{}",
            lines[0],
            lines[1],
            lines[2],
            &lines[3][..lines[3].len() / 2]
        );
        std::fs::write(&path, &torn).unwrap();

        // Heals to the 3 acked records AND satisfies the anchor.
        let mut l = Ledger::open_anchored(&path, key.clone(), Vec::new(), &anchor).unwrap();
        l.append(entry("act3-again", true)).unwrap();
        drop(l);
        assert_eq!(verify(&path, Some(&vk)).unwrap().entries, 4);
    }

    #[test]
    fn segmented_torn_tail_in_active_segment_heals() {
        // The heal path routes through `open_segmented_inner` too, and
        // `prefix_lines` keys off the LAST (active) segment. A torn tail in the
        // active segment must heal, leaving the earlier segment's records intact
        // and the chain verifying across the boundary.
        let key = decern_crypto::generate().unwrap();
        let vk = key.verifying_key();
        let dir = tmp("segmented-torn");
        std::fs::remove_dir_all(&dir).ok();

        // A tiny size policy forces a rollover, so records land in >1 segment.
        let policy = RolloverPolicy {
            max_bytes: Some(1),
            epoch_ms: None,
        };
        let mut l = Ledger::open_segmented(&dir, key.clone(), Vec::new(), policy).unwrap();
        for i in 0..4 {
            l.append(entry(&format!("s{i}"), true)).unwrap();
        }
        drop(l);

        // Locate the active (last) segment file and ragged-truncate its final line.
        let paths = segment::segment_paths(&dir).unwrap();
        let active = paths.last().unwrap().clone();
        let alines: Vec<String> = std::fs::read_to_string(&active)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert!(!alines.is_empty(), "active segment should hold >=1 record");
        let kept = &alines[..alines.len() - 1];
        let mut body = kept.iter().map(|s| format!("{s}\n")).collect::<String>();
        // Append a ragged (unterminated) fragment of the last record.
        let torn = alines.last().unwrap();
        body.push_str(&torn[..torn.len() / 2]);
        std::fs::write(&active, &body).unwrap();

        // Read-only verify surfaces TornTail; open heals and stays appendable.
        assert!(matches!(
            verify(&dir, Some(&vk)).unwrap_err(),
            LedgerError::TornTail { .. }
        ));
        let healed_before = match verify(&dir, Some(&vk)).unwrap_err() {
            LedgerError::TornTail { healed_entries, .. } => healed_entries,
            _ => unreachable!(),
        };
        let mut l = Ledger::open_segmented(&dir, key.clone(), Vec::new(), policy).unwrap();
        l.append(entry("post-heal", true)).unwrap();
        drop(l);
        assert_eq!(
            verify(&dir, Some(&vk)).unwrap().entries,
            healed_before + 1,
            "chain verifies across the segment boundary after healing the active tail"
        );
    }
    /// The ledger holds decision subjects and the pseudonymous handles the subject-side
    /// audit route is keyed by. It was created at the process umask — commonly 0644 —
    /// while the signing key and the mission registry beside it are 0600, which made the
    /// audit log the readable one of the three.
    #[cfg(unix)]
    #[test]
    fn a_ledger_file_is_not_readable_by_group_or_other() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp("perm-new.ledger");
        std::fs::remove_file(&path).ok();
        let key = decern_crypto::generate().unwrap();
        let mut led = Ledger::open(&path, key).unwrap();
        led.append(entry("Read", true)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "ledger must be 0600, got {mode:o}");
    }

    /// A ledger written before this change is tightened when it is next opened, rather
    /// than left readable forever. `.mode()` alone would not do it: it applies only on
    /// creation.
    #[cfg(unix)]
    #[test]
    fn reopening_an_existing_world_readable_ledger_tightens_it() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp("perm-tighten.ledger");
        std::fs::remove_file(&path).ok();
        let key = decern_crypto::generate().unwrap();
        {
            let mut led = Ledger::open(&path, key.clone()).unwrap();
            led.append(entry("Read", true)).unwrap();
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _led = Ledger::open(&path, key).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "reopen must tighten, got {mode:o}");
    }
}
