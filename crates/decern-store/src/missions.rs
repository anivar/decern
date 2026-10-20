// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Anivar Aravind
//! The Mission registry: the authoritative record of approved and terminated Missions.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::StoreError;
use crate::fsio::{CoherentMap, poisoned};

/// A registered mission's authoritative state. The mission reference is
/// `(approver, s256)`; this is the persisted record the mint path checks so that a
/// mission's TERMINATION is effective beyond a single in-memory `ApprovedMission`
/// handle, and a mission reference that names nothing registered is refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionEntry {
    /// Principal id that approved the mission (must match the reference's approver).
    pub approver: String,
    /// Mission authority expiry (epoch secs) — the record GCs itself past this.
    pub expiry: u64,
    /// Once true, the mission mints no further tokens and can never revert to active.
    #[serde(default)]
    pub terminated: bool,
    /// Agent principal the mission authorizes. Empty on pre-decision-under-mission
    /// registry rows (serde default); a decide-under-mission check requires it set.
    #[serde(default)]
    pub agent: String,
    /// Tools/scopes approved for the agent. Empty on legacy rows.
    #[serde(default)]
    pub approved_tools: Vec<String>,
}

/// The **mission registry** — the authoritative, persistent record of approved
/// Missions, keyed by the mission reference hash `s256`.
///
/// Why it exists: without it, `ApprovedMission::terminate()` is a flip of an
/// in-memory field, so a token minted from a stale/reconstructed handle would not
/// see the termination, and a hand-built mission reference (`s256`) that names no
/// real approval could be stamped into a token. This registry makes the mission
/// reference *checkable at the mint*: mint only when `s256` resolves to a
/// registered, non-terminated, non-expired mission whose approver matches. It is
/// **local** (memory or file) — sovereign, consulted in-perimeter, no phone-home —
/// and GCs expired entries on write so it stays bounded
/// to live missions. Termination is monotone: a terminated mission can never revert
/// to active (a killswitch that can be un-pressed is not a killswitch).
pub trait MissionRegistry: Send + Sync {
    /// Register an approved mission as active. Idempotent for an already-active same
    /// `s256`; refused if that `s256` is already TERMINATED (no revival). Evicts
    /// entries already past `now` so the registry stays bounded.
    fn register(&self, s256: &str, entry: MissionEntry, now: u64) -> Result<(), StoreError>;

    /// The mission's current record, or `None` if `s256` is unknown. Consulted
    /// before minting a mission-bound token; a caller treats `Err` as not-mintable
    /// (fail-closed).
    fn status(&self, s256: &str) -> Result<Option<MissionEntry>, StoreError>;

    /// Terminate the mission named by `s256` (idempotent). A terminated mission
    /// mints no further tokens. Terminating an unknown `s256` is a no-op.
    fn terminate(&self, s256: &str, now: u64) -> Result<(), StoreError>;
}

/// Volatile backend — for tests and ephemeral nodes. Not durable.
#[derive(Default)]
pub struct MemoryMissionRegistry {
    inner: Mutex<BTreeMap<String, MissionEntry>>,
}

impl MemoryMissionRegistry {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Terminated tombstones are retained for this long PAST their own expiry, so a
/// deliberately-ended grant cannot be replayed the moment it lapses. The identity
/// layer's `approve()` expiry guard is the primary defense (a dead mission is never
/// granted); this keeps the store itself refusing re-registration for a bounded
/// window and bounds how long a terminated tombstone lingers. Active entries are
/// still evicted at their expiry.
const TERMINATED_TOMBSTONE_RETENTION_SECS: u64 = 30 * 24 * 60 * 60; // 30 days

/// Whether a registry entry survives GC at `now`: an active entry lives until its
/// expiry; a terminated tombstone lives for a retention horizon past it, so expiry
/// can never launder a termination into an Active re-registration.
fn mission_entry_retained(e: &MissionEntry, now: u64) -> bool {
    if e.terminated {
        e.expiry.saturating_add(TERMINATED_TOMBSTONE_RETENTION_SECS) > now
    } else {
        e.expiry > now
    }
}

/// Shared register logic: GC expired, then insert-if-new / no-op-if-active /
/// refuse-if-terminated. Returns `(result, dirty)` for the durable backend.
fn mission_register(
    map: &mut BTreeMap<String, MissionEntry>,
    s256: &str,
    entry: MissionEntry,
    now: u64,
) -> (Result<(), StoreError>, bool) {
    map.retain(|_, e| mission_entry_retained(e, now));
    match map.get(s256) {
        Some(existing) if existing.terminated => (
            Err(StoreError::Invalid(format!(
                "mission {s256} is terminated and cannot be re-registered"
            ))),
            false,
        ),
        Some(_) => (Ok(()), false), // already active — idempotent no-op
        None if entry.expiry <= now => (
            // Self-monotone: refuse registering an already-expired mission, independent of
            // the identity-layer approve() guard. Combined with retaining terminated
            // tombstones past expiry, this makes "expiry can never launder a termination
            // into an Active re-registration" true for ALL callers of this crate, not only
            // approve(). (An expired ACTIVE entry was already dropped by the retain above,
            // so an expired blob arrives here as None.)
            Err(StoreError::Invalid(format!(
                "mission {s256} expiry {} is not in the future (now {now}); cannot register",
                entry.expiry
            ))),
            false,
        ),
        None => {
            map.insert(s256.to_owned(), entry);
            (Ok(()), true)
        }
    }
}

impl MissionRegistry for MemoryMissionRegistry {
    fn register(&self, s256: &str, entry: MissionEntry, now: u64) -> Result<(), StoreError> {
        let mut g = self.inner.lock().map_err(poisoned)?;
        mission_register(&mut g, s256, entry, now).0
    }

    fn status(&self, s256: &str) -> Result<Option<MissionEntry>, StoreError> {
        let g = self.inner.lock().map_err(poisoned)?;
        Ok(g.get(s256).cloned())
    }

    fn terminate(&self, s256: &str, now: u64) -> Result<(), StoreError> {
        let mut g = self.inner.lock().map_err(poisoned)?;
        g.retain(|_, e| mission_entry_retained(e, now));
        if let Some(e) = g.get_mut(s256) {
            e.terminated = true;
        }
        Ok(())
    }
}

/// The default, database-free backend: mission records persisted with cross-process
/// coherence (see `CoherentMap`) — so a mission approved or TERMINATED by another
/// process (an operator CLI, a second replica) is seen at this node's mint path, and
/// survives a restart.
pub struct FileMissionRegistry {
    inner: CoherentMap<MissionEntry>,
}

impl FileMissionRegistry {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Ok(FileMissionRegistry {
            inner: CoherentMap::open(path.as_ref().to_owned())?,
        })
    }
}

impl MissionRegistry for FileMissionRegistry {
    fn register(&self, s256: &str, entry: MissionEntry, now: u64) -> Result<(), StoreError> {
        self.inner
            .write(|map| mission_register(map, s256, entry, now))?
    }

    fn status(&self, s256: &str) -> Result<Option<MissionEntry>, StoreError> {
        self.inner.read(|map| map.get(s256).cloned())
    }

    fn terminate(&self, s256: &str, now: u64) -> Result<(), StoreError> {
        self.inner.write(|map| {
            map.retain(|_, e| mission_entry_retained(e, now));
            let dirty = match map.get_mut(s256) {
                Some(e) if !e.terminated => {
                    e.terminated = true;
                    true
                }
                _ => false,
            };
            ((), dirty)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::tmp;

    // --------------------------- mission registry ---------------------------

    fn mentry(approver: &str, expiry: u64) -> MissionEntry {
        MissionEntry {
            approver: approver.into(),
            expiry,
            terminated: false,
            agent: String::new(),
            approved_tools: Vec::new(),
        }
    }

    fn mission_lifecycle(r: &dyn MissionRegistry) {
        assert!(r.status("m1").unwrap().is_none(), "unknown mission → None");
        r.register("m1", mentry("corp", 1000), 10).unwrap();
        let got = r.status("m1").unwrap().unwrap();
        assert_eq!(got.approver, "corp");
        assert!(!got.terminated, "freshly registered is active");

        // re-register the same active mission is an idempotent no-op
        r.register("m1", mentry("corp", 1000), 10).unwrap();
        assert!(!r.status("m1").unwrap().unwrap().terminated);

        // terminate is monotone: it sticks and cannot be re-registered back to active
        r.terminate("m1", 10).unwrap();
        assert!(
            r.status("m1").unwrap().unwrap().terminated,
            "termination sticks"
        );
        let err = r.register("m1", mentry("corp", 1000), 10).unwrap_err();
        assert!(
            matches!(err, StoreError::Invalid(_)),
            "a terminated mission cannot be revived: {err}"
        );
        assert!(
            r.status("m1").unwrap().unwrap().terminated,
            "still terminated"
        );

        // terminating an unknown mission is a no-op
        r.terminate("ghost", 10).unwrap();
        assert!(r.status("ghost").unwrap().is_none());
    }

    #[test]
    fn mission_registry_memory_lifecycle() {
        mission_lifecycle(&MemoryMissionRegistry::new());
    }

    #[test]
    fn mission_registry_file_lifecycle() {
        let path = tmp("mission.json");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(path.with_extension("lock")).ok();
        mission_lifecycle(&FileMissionRegistry::open(&path).unwrap());
    }

    #[test]
    fn mission_registry_gc_drops_expired_on_write() {
        let r = MemoryMissionRegistry::new();
        r.register("old", mentry("corp", 100), 10).unwrap();
        assert!(r.status("old").unwrap().is_some());
        // a later register past `old`'s expiry evicts it — bounded to live missions
        r.register("new", mentry("corp", 500), 200).unwrap();
        assert!(
            r.status("old").unwrap().is_none(),
            "expired mission GC'd on write"
        );
        assert!(r.status("new").unwrap().is_some());
    }

    #[test]
    fn terminated_mission_does_not_revive_after_expiry() {
        // A terminated mission must not come back as Active once its own expiry lapses.
        // Before the fix, mission_register's `retain(e.expiry > now)` ran BEFORE the
        // terminated-check, so the terminated tombstone was GC-evicted at expiry and
        // re-registering the identical s256 returned Active — expiry laundered a
        // termination. Terminated tombstones are now retained past expiry, so the store
        // keeps refusing re-registration.
        let r = MemoryMissionRegistry::new();
        r.register("m", mentry("corp", 1_000), 100).unwrap();
        r.terminate("m", 100).unwrap();
        assert!(
            r.status("m").unwrap().unwrap().terminated,
            "terminated tombstone present"
        );
        // advance `now` past the mission's own expiry, then re-register the identical
        // s256: it must STILL be refused, not revived to Active.
        let revived = r.register("m", mentry("corp", 1_000), 5_000);
        assert!(
            revived.is_err(),
            "a terminated grant must not re-register as Active after its expiry"
        );
        if let Some(e) = r.status("m").unwrap() {
            assert!(e.terminated, "must stay terminated, never revive to Active");
        }
    }

    #[test]
    fn register_refuses_an_already_expired_mission() {
        // The store is self-monotone: registering a mission whose expiry has already
        // passed is refused, independent of the identity-layer approve() guard — so a
        // direct decern-store consumer cannot create (or revive) an expired entry as Active.
        let r = MemoryMissionRegistry::new();
        assert!(
            r.register("m", mentry("corp", 1_000), 5_000).is_err(),
            "an already-expired new registration must be refused"
        );
        // The direct-bypass revival: terminate, wait past the tombstone retention horizon
        // (so the tombstone is GC-evicted), then re-register the identical expired grant —
        // still refused, now by the expiry guard rather than the tombstone.
        r.register("m2", mentry("corp", 1_000), 100).unwrap();
        r.terminate("m2", 100).unwrap();
        let past_horizon = 1_000 + 30 * 24 * 60 * 60 + 1;
        assert!(
            r.register("m2", mentry("corp", 1_000), past_horizon)
                .is_err(),
            "an expired terminated grant must not re-register even after the tombstone horizon"
        );
    }

    #[test]
    fn mission_termination_propagates_across_processes() {
        // The core: a mission TERMINATED by one process must stop the mint
        // path in another — a stale in-memory handle is not the authority.
        let path = tmp("mission-xproc.json");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(path.with_extension("lock")).ok();
        let minter = FileMissionRegistry::open(&path).unwrap();
        let operator = FileMissionRegistry::open(&path).unwrap();

        operator
            .register("m", mentry("corp", 1_000_000), 10)
            .unwrap();
        assert!(
            !minter.status("m").unwrap().unwrap().terminated,
            "active to the minter"
        );
        // operator (another process) terminates the mission...
        operator.terminate("m", 10).unwrap();
        // ...the minter must SEE it and refuse to mint under it
        assert!(
            minter.status("m").unwrap().unwrap().terminated,
            "minter sees a termination written by another process"
        );
    }

    #[cfg(unix)]
    #[test]
    fn durable_store_files_are_0600_not_world_or_group_readable() {
        // atomic_write_json_impl is shared by every durable backend (the ledger head
        // store and the mission registry); a store file world-readable at 0644 would
        // let any local user read its contents without ever touching the process.
        // Assert the file this write path actually produces on disk carries 0600, not
        // just that the API compiles.
        use std::os::unix::fs::PermissionsExt;
        let path = tmp("mission-perms.json");
        std::fs::remove_file(&path).ok();
        std::fs::remove_file(path.with_extension("lock")).ok();
        let r = FileMissionRegistry::open(&path).unwrap();
        r.register("m-perm-check", mentry("root", 1000), 10)
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mission store file must be 0600, got {mode:o}");
    }
}
