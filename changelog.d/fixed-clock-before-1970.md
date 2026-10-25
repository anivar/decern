- **A clock set before 1970 is refused rather than read as 1970.** `decern-serve` read such a
  clock as the epoch itself, a time before every expiry, so no principal, Mission or token had
  expired. Every request that needs the time is now answered `503 clock_unavailable` until the
  clock is right; under `--trust-proxy` a batch answers each of its items `decision: false` with
  that code. Under a credential posture the refusal comes before authentication, so an
  unauthenticated caller gets the `503` rather than a `401`. A tree head already computed is still
  served, carrying the time it was signed at.
  Authored by @anivar.
