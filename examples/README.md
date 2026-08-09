<!-- SPDX-License-Identifier: Apache-2.0 -->
# Worked examples

Runnable end to end, tested in CI, never published as crates.

- [`quickstart.sh`](quickstart.sh) — prove → serve → decide → verify → tamper-is-rejected,
  in one script.
- [`mcp/`](mcp/) — an MCP server that consults decern before every tool call: the
  in-process integration. Validates its caller, digest-binds the arguments, serves both
  the stateless revision and shipping clients.
- [`ext_authz_adapter/`](ext_authz_adapter/) — a forward-auth shim that puts decern behind
  NGINX `auth_request`, Traefik `forwardAuth`, or Envoy `ext_authz`: the gateway
  integration. Fails closed on deny, incomplete forwards, and an unreachable PDP.

The two integrations are a pair: same decision point, consulted from inside the tool
server or from the gateway in front of it.
