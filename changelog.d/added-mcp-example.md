- **A worked MCP integration** under `examples/mcp/`: an MCP server (spec revision
  2026-07-28, no SDK) that validates its client's access token and consults
  `POST /access/v1/evaluation` before every tool call — subject from the token, the
  exact arguments digest-bound onto the record. A Deny a fresh grant could satisfy is
  `403 insufficient_scope` with a challenge that actually works on retry; a Deny no
  re-authorization can fix is a tool result with `isError`. The walkthrough proves the
  nine invariants over the example's own model and ends by recomputing the argument
  digest from the arguments and finding it on the verified ledger. Authored by @anivar.
