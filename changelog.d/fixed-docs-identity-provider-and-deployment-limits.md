- **The docs say what an identity provider and a deployment have to supply.** `docs/CLI.md`
  gains three sections. *Pairing with an identity provider* says bearer validation verifies
  `EdDSA` tokens only, so a provider that signs `RS256` belongs in front, authenticating the
  enforcement point rather than the end user. *What a record keeps* lists what a decision
  record makes permanent. *What a deployment supplies* states that the server speaks plain
  HTTP, reads every key once at startup, logs nothing after startup, grows one unbounded
  ledger file, keeps a Mission registry per replica, and does not check that the model it
  serves is the one that was proven. The Missions section says a Mission binds only `Read`,
  `MoveMoney` and `AccessPII`, and that the approver is not checked to differ from the agent.
  Authored by @anivar.
