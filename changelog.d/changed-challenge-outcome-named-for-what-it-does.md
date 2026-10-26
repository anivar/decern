- **A challenge outcome no longer names a re-evaluation that does not happen.** A challenge
  whose basis bears on the facts a decision was made from was answered
  `reevaluate_with_subject_context`, though the kernel runs once, without the challenge, and
  the decision stands as recorded. It is now answered `challenge_classified`, in the ledger
  record and in `outcomes_supported` on the subject-side disclosure, which also says what an
  outcome describes (`outcomes_describe`) and lists those bases as
  `challenge_bases_that_bear_on_the_facts`, renamed from `challenge_bases_that_reopen_a_decision`.
  Records written by earlier releases keep the old name for the same answer.
  Authored by @anivar.
