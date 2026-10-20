- **A Mission's approval stays inside one tenant.** `POST /mission/v1/approve` refuses a Mission
  whose agent is not a principal in the approver's tenant (`422`, nothing recorded): an agent
  in another tenant, and an agent the model does not name, are refused in the same words. At
  decision time a Mission backs a decision only about a subject the model names, approved by a
  principal the model names, in the same tenant, so a cross-tenant Mission a registry already
  holds no longer counts. Before this, a principal in one tenant holding `move_money` could
  supply the approval behind a money movement in another (GHSA-rm33-3hf3-g366, affecting 0.2.0
  through 0.4.0). The approver is still not checked to differ from the agent; that is a
  separate decision. Authored by @anivar.
