- **Signed-request callers may only name themselves.** Under `--signed-agent-key`, the
  authenticated agent must equal the AuthZEN `subject`, the mission `approver`, the
  stored approver on terminate, and the principal id on
  `/directory/v1/principals/{id}/descendants`. A mismatch is 403 `caller_mismatch` —
  the credential was accepted; the name is not theirs. `--pep <ID>` (repeatable) names
  agents that remain PEPs. Bearer validation and `--trust-proxy` are unchanged: those
  postures authenticate a gateway, which legitimately asks about other parties.
  Authored by @anivar.
