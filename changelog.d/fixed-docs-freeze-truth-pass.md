- **Help text, doc comments and docs no longer contradict what the code does.** The ledger's
  `asserted_by` field was described as present only under bearer validation; it is present
  under every credential posture. The CLI described proving over "every input" rather than the
  model's symbolic input space, and its crate description left out `explain`. The kernel's
  `reasons` were described as present only on an Allow. The Postgres store named a money budget
  that does not exist and said the binaries never depend on it, which a `--features postgres`
  build does. The signed-request posture said only a POST covers `content-digest`. `--help`
  cited sections of the CLI reference by names that are not headings. The MCP walkthrough
  listed five records where its ledger holds six. The README now says the AAuth posture follows
  an individual, unadopted Internet-Draft; that on Windows `decern-serve` does not protect its
  files by permission, refusing to create a `--key` file and loading one without checking who can
  read it; and that the Mission self-approval refusal compares ids only.
  Authored by @anivar.
