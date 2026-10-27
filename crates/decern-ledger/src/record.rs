// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! What a ledger record holds: the entry, the parties and references it names, the chained record
//! around it, and its chain hash.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

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
    /// Present under every credential posture, where it is what that posture verified, on
    /// decision and search records and on mission lifecycle records (`Mission.Approve`,
    /// `Mission.Terminate`).
    /// Absent under a trusted front: an assertion the server did not verify itself does not
    /// belong on a permanent record. Descriptive, never a decision input.
    ///
    /// The verified caller's identifier is written verbatim, permanently, and the
    /// subject-side projection returns whole records — so a caller should be a service
    /// identity, not a person: a person's identifier here becomes visible to anyone holding
    /// a decision-subject handle on the same record, and cannot be redacted after the fact.
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
/// client acting for it, and the issuer that vouched, where the server checked one —
/// enough for a reader to ask the right party why this request was made, and nothing a
/// caller can write for itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertedBy {
    /// The token's `sub` — the party the server authenticated.
    pub sub: String,
    /// The token's `client_id` — the client acting for that party.
    pub client_id: String,
    /// The issuer whose signature the server verified. Absent when no issuer's was: a
    /// signed request's token is covered by the request signature, never verified against
    /// an issuer key, so its `iss` is the caller's own claim and is not recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
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
    /// How the challenge was answered: `affirm_prior_decision`, or `challenge_classified`
    /// when its standing named a party the record is about, the decision subject it keeps or,
    /// when it keeps none, the requester or the resource's owner, and its basis bears on the
    /// facts the decision was made from. Either way the decision stands as recorded.
    /// Records written by earlier releases name the second `reevaluate_with_subject_context`,
    /// for the same answer.
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
pub(crate) struct RecordOut<'a> {
    pub(crate) entry: &'a serde_json::value::RawValue,
    pub(crate) prev: &'a str,
    pub(crate) hash: &'a str,
    pub(crate) sig_b64: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kid: Option<&'a str>,
}

/// Read-side record: `entry` captures the exact byte span from the line, so
/// verification hashes what is actually stored, not a re-serialization.
#[derive(Deserialize)]
pub(crate) struct RecordIn {
    pub(crate) entry: Box<serde_json::value::RawValue>,
    pub(crate) prev: String,
    pub(crate) hash: String,
    pub(crate) sig_b64: String,
    #[serde(default)]
    pub(crate) kid: Option<String>,
}

/// A record's signature is over this 32-byte hash and nothing else. That is what keeps it
/// out of [`commitment_bytes`]'s space without a tag of its own: every commitment is a
/// tagged string far longer than 32 bytes, so no record signature can be replayed as one.
/// Anything else signed by a ledger key must keep that property or take a tag.
pub(crate) fn chain_hash(entry_bytes: &[u8], prev_hex: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(entry_bytes);
    h.update(prev_hex.as_bytes());
    h.finalize().into()
}
