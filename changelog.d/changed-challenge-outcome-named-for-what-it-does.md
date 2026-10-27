- **A challenge outcome no longer names a re-evaluation that does not happen.** A challenge
  whose standing named the decision subject a record keeps, and whose basis bears on the facts
  a decision was made from, was answered `reevaluate_with_subject_context`, though the kernel
  runs once, without the challenge, and the decision stands as recorded. It is now answered
  `challenge_classified`, in the ledger record and in `outcomes_supported` on the subject-side
  disclosure, which also says what an outcome describes (`outcomes_describe`) and lists those
  bases as `challenge_bases_that_bear_on_the_facts`, renamed from
  `challenge_bases_that_reopen_a_decision`. Records written by earlier releases keep the old
  name for the same answer. A challenge is classified when a basis it gives bears on those
  facts and its standing names a party the decision's record is about: the third party it keeps
  as its decision subject, or, when it keeps none, the requester or the resource's owner. A
  challenge from the requester or the owner was always affirmed. A challenge whose standing
  names no such party is affirmed with the reason "the challenge's standing names no party the
  decision's record is about", in place of a reason about the challenged decision, which the
  server does not read.
  Authored by @anivar.
