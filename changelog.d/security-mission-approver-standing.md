- **A Mission stops backing decisions once its approver is revoked, expired or loses the scope.** A
  Mission was held to its approver only at approval, so an approver revoked afterwards, directly
  or through a delegator, kept setting `human_approved` for `MoveMoney` through every Mission it
  had approved, across restarts, until each was terminated or expired. Each decision under a
  Mission now reads the approver from the model the server runs, and a Mission whose approver is
  revoked, past its expiry or no longer holds the scope the decision needs backs nothing: the
  decision is denied, and its errors say so. `POST /mission/v1/approve` refuses a revoked approver too.
  The model is fixed at boot, so a revocation reaches existing Missions at the next restart, as
  it reaches every other decision.
  Authored by @anivar.
