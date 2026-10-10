- **AuthZEN Search.** `POST /access/v1/search/subject`, `/resource` and `/action` (AuthZEN 1.0
  §8) answer which subjects of a type may perform an action on a resource, which resources of a
  type a subject may act on, and which actions a subject may perform on a resource. Every
  candidate is decided as an evaluation would be, over the same prepared context, so a result is
  one the evaluation endpoint would permit; results come back in the request's type spelling, the
  searched side's id is ignored, and every result comes in one page (pagination is optional in the
  specification and not implemented — a `page.limit` is accepted, a `page.token` is 400). A search
  binds no Mission, is refused under `--require-mission`, and never lists an action a decision
  would refuse for want of one; a caller bound to itself may search
  for what it may do and not for subjects. Each search is recorded once, with the result ids (up
  to 1000) and the count. Discovery advertises the three endpoints. The certification scenario's
  Search Core and Search Properties tests run against `examples/authzen-certification/model`,
  whose resources now carry `status` and whose policies read it, or a PEP's description, so a
  search finds what an evaluation would permit. `decern-kernel`'s `search_subjects` and
  `search_resources` take the entity type to search, and `search_actions` is new. Authored by
  @anivar.
