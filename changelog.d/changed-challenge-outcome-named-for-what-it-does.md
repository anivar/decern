- **A challenge outcome no longer names a re-evaluation that does not happen.** A challenge
  whose standing named the request's decision subject, and whose basis bears on the facts a
  decision was made from, was answered `reevaluate_with_subject_context`, though the kernel
  runs once, without the challenge, and the decision stands as recorded. It is now answered
  `challenge_classified`, in the ledger record and in `outcomes_supported` on the subject-side
  disclosure, which also says what an outcome describes (`outcomes_describe`) and lists those
  bases as `challenge_bases_that_bear_on_the_facts`, renamed from
  `challenge_bases_that_reopen_a_decision`. Records written by earlier releases keep the old
  name for the same answer. A challenge whose standing names the requester or the resource's
  owner, named as the request's decision subject, is classified like any other; it was
  affirmed, because the record drops that handle as already named. A challenge whose standing
  names another subject is affirmed with the reason "the challenge's standing does not name
  the decision subject this request carries", in place of a reason about the challenged
  decision, which the server does not read.
  Authored by @anivar.
