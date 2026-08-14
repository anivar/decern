- **The MCP example mints a Mission for MoveMoney instead of asserting approval.**
  `examples/mcp/server.py` used to relay a verified OAuth scope into
  `context.human_approved` directly. Since MoveMoney now requires a Mission
  unconditionally, that assertion is refused — the example instead calls
  `POST /mission/v1/approve` when the scope is present and names the resulting
  Mission in the decision context, demonstrating the pattern a real PEP should use.
