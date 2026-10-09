- **The AAuth posture follows draft `-11`.** A request that presents no agent token is
  answered `401` with `AAuth-Requirement: requirement=agent-token`, the draft's own challenge,
  and never through `WWW-Authenticate`. An `iat` ahead of this server's clock is tolerated up to
  the signature window (five seconds, the same tolerance a signature's `created` gets) and
  refused beyond it with `Signature-Error: error=clock_skew`, where it was refused at zero
  tolerance and without a signal. A token claiming a lifetime above 24 hours is refused — the
  draft says an agent token SHOULD NOT exceed that, and leaves the bound to the verifier.
  Everything the posture already implemented is unchanged in `-11`. Authored by @anivar.
