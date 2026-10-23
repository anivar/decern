// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! What every handler shares: the application state, the recording backend, the server's clock, and
//! the caller disclosure.

use crate::caller;
use decern_kernel::{Kernel, Model};
use decern_ledger::{Ledger, ShardedLedger};
use decern_store::FileMissionRegistry;
use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub(crate) model: Arc<Model>,
    pub(crate) backend: Arc<LedgerBackend>,
    /// Request entity type -> model entity type (`--authzen-type-alias`). Empty means
    /// every request type is taken as written.
    pub(crate) type_aliases: Arc<std::collections::BTreeMap<String, String>>,
    /// The base URL `/.well-known/authzen-configuration` advertises (`--public-url`);
    /// `None` and the document is not served.
    pub(crate) public_url: Option<Arc<str>>,
    /// The durable record of approved Missions. Held so a mission's termination
    /// outlives any single in-memory handle and is seen across processes.
    pub(crate) missions: Arc<FileMissionRegistry>,
    pub(crate) pubkey: VerifyingKey,
    /// Ledger keys this deployment rotated away from (`--retired-key`), in the order given.
    pub(crate) retired_keys: Arc<Vec<VerifyingKey>>,
    /// When true, every decide must name a live `context.mission`.
    pub(crate) require_mission: bool,
    /// Issuer keys a standing token may be signed by. Empty means this deployment
    /// accepts no challenges, which is the default and is stated in its disclosure.
    pub(crate) standing_issuers: Arc<Vec<VerifyingKey>>,
    /// The authority every decision this process makes is taken against, digested once.
    /// The kernel is pinned at boot and exposes no way to mutate it, so this is a
    /// constant for the life of the process rather than something to recompute per
    /// request — and recomputing it per request would serialize the whole entity graph
    /// on the decision path.
    pub(crate) authority_digest: Arc<str>,
    /// How this deployment establishes callers, as the disclosure endpoint reports it —
    /// derived from the running configuration at boot, like everything else it says.
    pub(crate) caller_disclosure: Arc<Value>,
}

impl AppState {
    /// The model entity type a request's spelling names: its alias under
    /// `--authzen-type-alias`, or the spelling itself when it has none.
    pub(crate) fn model_type(&self, request_type: &str) -> String {
        self.type_aliases
            .get(request_type)
            .cloned()
            .unwrap_or_else(|| request_type.to_owned())
    }
}

/// The `caller` object the subject-side disclosure reports: which posture, and under
/// `bearer` the audience a token must be bound to — public by construction, it is what
/// every client must already know to mint a usable token.
pub(crate) fn caller_disclosure(caller: &caller::Caller) -> Value {
    match caller {
        caller::Caller::Bearer(c) => {
            json!({ "mode": "bearer", "audience": c.audience, "bind": "any" })
        }
        caller::Caller::Signed(c) => {
            let mut o = json!({
                "mode": "signed",
                "audience": c.audience,
                "bind": "self",
            });
            if !c.pep.is_empty() {
                o["pep"] = json!(c.pep.iter().cloned().collect::<Vec<_>>());
            }
            o
        }
        caller::Caller::Spiffe(c) => {
            let mut o = json!({
                "mode": "spiffe",
                "audience": c.audience,
                "trust_domains": c.trust_domains.keys().collect::<Vec<_>>(),
                "bind": "self",
            });
            if !c.pep.is_empty() {
                o["pep"] = json!(c.pep.iter().cloned().collect::<Vec<_>>());
            }
            o
        }
        caller::Caller::Aauth(c) => {
            let mut o = json!({
                "mode": "aauth",
                "authority": c.authority,
                "providers": c.providers.keys().collect::<Vec<_>>(),
                "bind": "self",
            });
            if !c.pep.is_empty() {
                o["pep"] = json!(c.pep.iter().cloned().collect::<Vec<_>>());
            }
            o
        }
        caller::Caller::TrustedProxy => json!({ "mode": "trusted-proxy", "bind": "any" }),
    }
}

/// The server's own wall clock in epoch seconds — the single time authority for every
/// decision. Never read from a request body (see `decide`).
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bearer;
    use crate::caller;
    use ed25519_dalek::SigningKey;

    #[test]
    fn the_caller_disclosure_under_signed_request_is_self_bound() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let mut agents = std::collections::BTreeMap::new();
        agents.insert("agent-1".into(), vec![key.verifying_key()]);
        let d = caller_disclosure(&caller::Caller::Signed(Box::new(
            crate::sig::SigConfig::new(agents, "https://pdp.example/access/v1/evaluation"),
        )));
        assert_eq!(d["mode"], "signed");
        assert_eq!(d["bind"], "self");
        assert!(d.get("pep").is_none());
    }

    /// The disclosure's caller object under bearer validation names the audience — which is
    /// public by construction: every client must already know it to mint a usable token.
    #[test]
    fn the_caller_disclosure_names_the_bearer_audience() {
        let d = caller_disclosure(&caller::Caller::Bearer(Box::new(bearer::Config {
            issuer: "https://issuer.example/".into(),
            audience: "https://pdp.example/".into(),
            keys: vec![SigningKey::from_bytes(&[6u8; 32]).verifying_key()],
            scopes: vec![],
        })));
        assert_eq!(d["mode"], "bearer");
        assert_eq!(d["audience"], "https://pdp.example/");
        assert_eq!(d["bind"], "any");
    }
}
