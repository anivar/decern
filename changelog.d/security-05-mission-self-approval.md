- **A principal can no longer approve a Mission for itself.** `POST /mission/v1/approve`, and
  `decern_identity::mission::approve` under it, refuses an approver that is also the agent, and a
  Mission recorded that way by an earlier release no longer backs a decision. Such a Mission set
  `human_approved` for `MoveMoney` with no second principal involved. A deployment that used one id
  for both gives the approval to another principal in the agent's tenant that the model marks
  `Human` and that holds the scope. The refusal compares ids only. Authored by @anivar.
