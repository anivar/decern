<!-- SPDX-License-Identifier: Apache-2.0 -->
# An MCP server that consults decern

The MCP specification says, in its own overview, that the protocol cannot enforce its
security principles and implementors SHOULD "implement appropriate access controls and
data protections". MCP's authorization layer establishes *who is calling*, down to the
scope. It says nothing about which tool that caller may run, over which resource, with
which arguments — and nothing that records what was decided. That is the seam this
example fills.

```
MCP client ──bearer token──▶ server.py ──per tool call──▶ decern-serve ──▶ ledger
             (validated here)            (subject, action,   (--model model/
                                          resource, args      --trust-proxy)
                                          digest)
```

Before executing a tool, `server.py` calls `POST /access/v1/evaluation` with the subject
taken from the validated token, the action and resource mapping from its own tool table
(the resource *id* comes from the tool's arguments on purpose — model-authored input
choosing the target is precisely the threat MCP tools carry, and precisely what the
decision point rules on), and the exact arguments bound as a digest the record keeps.
Allow executes. A Deny that a fresh grant could satisfy is `403` with
`WWW-Authenticate: Bearer error="insufficient_scope", scope="…"` — and the challenge is
honest: retry with that scope and the call succeeds. A Deny no re-authorization can fix
(tenancy, revocation, decay) is a tool result with `isError: true`, where the model can
read it and stop retrying. Afterwards `decern verify` and `decern explain` show what was
decided and that the record holds.

## Run it

```sh
examples/mcp/run.sh
```

Needs `cargo`, `cvc5` on `PATH`, `uv`, `jq`. Eleven asserted beats: the model-drift guard,
the nine invariants proved over this example's model, the earlier-revision handshake,
Allow, the satisfiable 403, the step-up, the unfixable Deny, two 401s, and the ledger check ending with the arguments
digest recomputed from the arguments themselves and found on the record.

## What is different from the builtin model, and why

`model/` is the builtin model with two declared divergences, each guarded by a `diff`
in the walkthrough (the policies are the builtin's verbatim — including the `@id`
names the 403-vs-`isError` split keys on, which live in the builtin itself):

- **`args_sha256?: String`** on each action's context. decern's context schema is
  closed — an undeclared attribute is refused — so binding tool arguments into the
  record is a schema decision, which is where it belongs. The added optional attribute
  widens the input space the nine invariants quantify over without changing what any of
  them says; the walkthrough proves them over this model, not the builtin.
- **Two demo entities**: `account9`, so `move_money` denies on the money-gate rather
  than on an unknown entity, and `mcp_agent` — an agent delegated by `corp`, which is
  what an MCP front is. Its records name `corp` as the accountable owner: the server
  derives who answers for a delegate, and no request field can override that.

## Trust boundaries, stated plainly

- **decern runs `--trust-proxy`**: this server is the declared, authenticated front.
  The client's token is never forwarded to decern — MCP itself forbids passing a
  client's token upstream — and decern decides about the subject this server asserts.
  decern deliberately does not take the AuthZEN subject from a token's `sub`; the
  recorded subject is the front's assertion, and this example is that front.
- **Approval is a relayed claim.** A token carrying `decern.move_money.approved` is the
  issuer's statement that money movement was approved for this bearer; the server
  verifies the token and relays the claim as `context.human_approved`. decern's own
  boundary applies verbatim: establishing the caller says who is asserting those flags,
  not that they are true. A deployment that wants approval derived by the decision
  point itself runs `decern-serve --require-mission` and grants Missions.
- **`mint.py` is a stand-in, not an authorization server.** A fixed, public demo key
  signs the tokens; the issuer URL in the Protected Resource Metadata is an identifier,
  and the discovery chain is demonstrated as far as that document and no further. OAuth
  over plain HTTP and an `http://127.0.0.1` resource identifier are demo-only.

## Earlier-revision clients

The server implements revision 2026-07-28, whose transport spec says a server may treat
a request without the protocol-version metadata as an earlier revision. It does: a
client speaking the 2025-06-18 lifecycle — `initialize`, no per-request `_meta` — is
served through a clearly-marked legacy path that adds no authorization surface (the
bearer check runs before dispatch either way). This is what lets a shipping client
connect today; Claude Code has run this example's whole allow/deny/step-up matrix
end-to-end. Delete `legacy_dispatch` when the clients you care about carry `_meta`,
and the example is single-revision again.

## Why decern's `decide` is not an MCP tool

A tool is something the agent may call — and may decline to call — with arguments the
model authors by construction. An authorization check that the checked party can skip,
or whose inputs the checked party writes, is not a check. The decision point sits in
the server's path, before execution, where the caller cannot decline it. Do not build
the tool version.

## What this proves, and what it does not

decern can prove what was decided for every call that reached it, and that no recorded
decision was altered or dropped afterwards. It cannot prove that a call which never
reached it did not happen. That guarantee — that this server is the only path to the
tools — belongs to the deployment around it, and no decision point can supply it.
