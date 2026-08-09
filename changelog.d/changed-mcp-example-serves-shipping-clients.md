- **The MCP example serves shipping clients.** Real clients still speak the 2025-06-18
  lifecycle; the example now serves them through the transport spec's own
  backward-compatibility clause — a clearly-marked legacy path that adds no
  authorization surface and is deletable when clients carry per-request metadata.
  Verified end to end with Claude Code as the client: allow, tenant-deny as a tool
  error the model reads, approved money movement, and the insufficient-scope 403 —
  all recorded and verified on the ledger. Authored by @anivar.
