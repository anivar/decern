- **The Mission read is stated as unbound, and pinned.** `GET /mission/v1/{s256}` answers every
  established caller, a workload bound to itself included, with the Mission's approver, state and
  expiry, so a reference a caller can compute or obtain tells it who approved what and until when.
  It stays unbound because a PEP consults mission state before honoring a grant, and binding it to the
  approver would refuse the agent a Mission authorizes. A test pins the unbound read, so binding it is
  a change of its own. Authored by @anivar.
