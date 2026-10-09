- **Bounds settled at the edge, from an adversarial read of the AuthZEN work.** An evaluation
  `context` that is not an object is 400, as any wrong type is (AuthZEN 1.0 §10.1.1), where it
  was quietly taken as empty; a context over 64 KiB, properties included, is 413 and is neither
  evaluated nor recorded, and a batch whose default context is that large answers each item so
  without copying it into every item. What the record keeps of a `context.mission` is the
  `{approver, s256}` pair that was looked up, never the object as sent. `--authzen-type-alias`
  refuses to start the server when the model type it names is not one the schema declares, or
  when the request type is one of the model's own; `--public-url` is parsed as a URL and refuses
  a bad port, a bad host or anything beyond an origin, and takes any loopback address for a
  local walkthrough. Authored by @anivar.
