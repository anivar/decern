- **MoveMoney now requires a Mission unconditionally.** Previously, a request naming
  `context.human_approved: true` directly could move money whenever an operator had not
  turned on `--require-mission` — the flag only made the *server*-derived guarantee apply
  to every action; MoveMoney itself had no floor beneath it. `decern-serve` now denies any
  MoveMoney decision that does not name a live, verified Mission, regardless of
  `--require-mission`. Read and AccessPII keep the existing opt-in behavior.
  **Migration:** a deployment gating money through its own PEP by asserting
  `human_approved` in the request body, without using Missions, must switch to approving a
  Mission (`POST /mission/v1/approve`) and naming it in `context.mission` before this
  upgrade — the old body assertion is now denied rather than honored.
