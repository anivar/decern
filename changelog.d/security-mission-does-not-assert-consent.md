- **A Mission is not a data subject's consent.** `POST /access/v1/evaluation` no longer
  sets `context.consent = true` when a live Mission covers `AccessPII`. The grant is an
  approver's `pii:read`; F-consent is a claim about the resource owner, and the two are
  not the same. Client-supplied `consent` is still stripped under a Mission, so OBO PII
  access requires a consent signal that did not come from the grant. Self-access is
  unchanged: the owner does not need consent. Authored by @anivar.
