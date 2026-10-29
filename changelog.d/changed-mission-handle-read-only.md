- **An approved Mission handle is read-only, and a mint is held to the registered approval.**
  `ApprovedMission` is read-only to its holder: `mission`, `state` and `s256` are read through
  accessors of those names, and only `terminate` changes it. A mint under a registry refuses a
  handle whose approved tools or expiry differ from the registered entry, which refuses a Mission
  whose row was written before its tools were recorded, as `decern-serve` already refuses it at the
  decision. The fields were public and `issue_under_mission` took its ceiling from them, so a
  library caller could widen a handle after approval and mint up to the approver's own authority.
  `decern-serve` never exposed that path. Authored by @anivar.
