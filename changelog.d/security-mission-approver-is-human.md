- **Only a principal the model marks `Human` approves a Mission.** `POST /mission/v1/approve`
  accepted any principal in the tenant that held the scope, an Agent or a Machine included, and
  a Mission so approved set `human_approved` for `MoveMoney`. Approval now refuses an approver
  whose `kind` is not `Human` (422, nothing recorded), and a Mission a registry already holds
  from such an approver backs no decision: a decision under it is denied, and its errors say so.
  The check is the server's, reading `kind` from the model it runs: a model that omits `kind`
  or spells it another way approves nothing, and a workload caller, which may name only itself
  as approver, approves nothing unless its own principal is marked `Human`. The `money-gate`
  proof still covers the flag, not who approved, and whether the caller that names an approver
  speaks for it rests on the caller posture. Authored by @anivar.
