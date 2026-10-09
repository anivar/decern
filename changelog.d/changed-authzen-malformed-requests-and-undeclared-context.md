- **Every malformed evaluation request is 400, and undeclared context is ignored.** A missing
  field, a wrong type, a body that is not JSON or a content type that is not `application/json`
  answers 400 with the parser's own detail, where the extractor spread them over 400, 415 and 422
  (AuthZEN 1.0 §10.1.1). Context attributes the model's schema does not declare are dropped before
  evaluation instead of denying the request as malformed: no validated policy can read them, so no
  decision can turn on them. Declared attributes keep their schema validation, and what was dropped
  never reaches the ledger. Authored by @anivar.
