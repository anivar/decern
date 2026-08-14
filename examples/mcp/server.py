# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography"]
# ///
# SPDX-License-Identifier: Apache-2.0
#
# An MCP server that consults decern before every tool call.
#
# MCP's specification says, in its own overview, that the protocol cannot enforce its
# security principles and implementors SHOULD "implement appropriate access controls".
# This file is what taking that sentence seriously looks like: the server validates who
# is calling (an RFC 9068 access token), asks a decision point whether THIS caller may
# take THIS action on THIS resource with THESE arguments, and executes only on Allow —
# with the decision, and a digest of the exact arguments, on a tamper-evident record a
# third party can verify afterwards.
#
# Spec revision 2026-07-28 (stateless): no initialize handshake, no sessions, every
# request self-contained. Each conformance-relevant check below names the spec section
# it implements. Deliberately NOT here: SSE streaming (a server may always answer
# application/json — Transports, "Sending Messages"), subscriptions, and any MCP
# surface inside decern itself.
#
#   MCP_ISSUER_PUBKEY=<hex> PDP_URL=http://127.0.0.1:<port> uv run server.py

import base64
import binascii
import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HOST = "127.0.0.1"  # Transports, Security: local servers SHOULD bind localhost only
PORT = int(os.environ.get("MCP_PORT", "8792"))
PDP_URL = os.environ.get("PDP_URL", "http://127.0.0.1:8793")

PROTOCOL_VERSION = "2026-07-28"
SERVER_INFO = {"name": "decern-mcp-example", "version": "0.1.0"}

# This server's canonical resource identifier — what a token's `aud` must contain
# (Authorization, Token Handling: audience validation is a MUST). Plain HTTP and a
# loopback host are demo-only; the authorization spec's own examples are all https.
RESOURCE = f"http://{HOST}:{PORT}/mcp"
ISSUER = "https://issuer.example/"
ISSUER_KEY = Ed25519PublicKey.from_public_bytes(bytes.fromhex(os.environ["MCP_ISSUER_PUBKEY"]))

# The scope this deployment's step-up story is written in. A verified token carrying it
# is the AS's statement that a human approved money movement for this bearer. decern
# requires a Mission for MoveMoney unconditionally — asserting `human_approved` in the
# body is never honored for this action — so the server turns the verified scope into a
# Mission via /mission/v1/approve and names it in the decision context, rather than
# relaying the scope as an approval flag itself.
APPROVAL_SCOPE = "decern.move_money.approved"
# The principal mcp_agent delegates from (see model/entities.json): the human/operator
# whose authority the Mission attenuates. A real deployment would resolve this from the
# verified token or an out-of-band approval flow, not hardcode it.
MISSION_APPROVER = "corp"

PRM = {  # RFC 9728 Protected Resource Metadata (Authorization: a MUST for MCP servers)
    "resource": RESOURCE,
    # A claim that this AS exists. In the walkthrough it deliberately does not: mint.py
    # is a key that signs, the URL is an identifier, and the discovery chain is
    # demonstrated exactly as far as this document and no further.
    "authorization_servers": [ISSUER],
    "scopes_supported": [APPROVAL_SCOPE],
    "bearer_methods_supported": ["header"],
}

# The tool table IS the configuration the issue speaks of: which decern action a tool
# maps to, which argument names the resource, and what may appear in arguments. The
# resource *id* comes from the arguments on purpose — model-authored input choosing the
# target is precisely the threat MCP tools carry, and precisely what the decision point
# gets to rule on, with the full arguments digest-bound to the record.
TOOLS = {
    "read_claim": {
        "action": "Read",
        "resource_arg": "claim_id",
        "schema": {
            "type": "object",
            "properties": {"claim_id": {"type": "string"}},
            "required": ["claim_id"],
            "additionalProperties": False,
        },
        "description": "Read one claim record.",
        "run": lambda a: f"claim {a['claim_id']}: status=open, amount=1200",
    },
    "move_money": {
        "action": "MoveMoney",
        "resource_arg": "account",
        "schema": {
            "type": "object",
            "properties": {"account": {"type": "string"}, "amount": {"type": "integer"}},
            "required": ["account", "amount"],
            "additionalProperties": False,
        },
        "description": "Move money out of an account.",
        "run": lambda a: f"transfer of {a['amount']} from {a['account']} submitted",
    },
}

TOOL_LIST = [
    {"name": name, "description": t["description"], "inputSchema": t["schema"]}
    for name, t in sorted(TOOLS.items())  # Tools: SHOULD return a deterministic order
]


# ---------------------------------------------------------------- token validation
class Unauthorized(Exception):
    """401 — no credentials, or credentials that cannot be trusted."""

    def __init__(self, detail, code=None):
        super().__init__(detail)
        self.code = code  # None = no error attribute (nothing was presented)


def validate_token(auth_header):
    """RFC 9068 §4 order: typ, alg, iss, aud, signature, time, required claims.

    The order mirrors decern's own bearer validation: everything before the signature
    is a claim the token makes about itself, and `alg` is settled before any key is
    consulted so a token cannot nominate how it is checked.
    """
    if not auth_header:
        raise Unauthorized("no credentials presented")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise Unauthorized("not a bearer presentation", "invalid_token")
    token = token.strip()
    if len(token) > 8192:
        raise Unauthorized("token exceeds the accepted size", "invalid_token")

    def part(seg, what):
        try:
            pad = "=" * (-len(seg) % 4)
            return json.loads(base64.urlsafe_b64decode(seg + pad))
        except (binascii.Error, ValueError):
            raise Unauthorized(f"token {what} is not base64url JSON", "invalid_token") from None

    try:
        h64, p64, s64 = token.split(".")
    except ValueError:
        raise Unauthorized("token is not a compact JWS", "invalid_token") from None
    header, claims = part(h64, "header"), part(p64, "claims")

    typ = header.get("typ", "")
    if typ.lower() not in ("at+jwt", "application/at+jwt"):
        raise Unauthorized("token is not an access token", "invalid_token")
    if header.get("alg") != "EdDSA":
        raise Unauthorized("algorithm not accepted here", "invalid_token")
    if claims.get("iss") != ISSUER:
        raise Unauthorized("issuer not accepted here", "invalid_token")
    aud = claims.get("aud")
    if not (aud == RESOURCE or (isinstance(aud, list) and RESOURCE in aud)):
        # Audience validation is a MUST (Authorization, Token Handling) — and so is
        # refusing to pass this token upstream; see decide() below.
        raise Unauthorized("token was not issued for this server", "invalid_token")
    try:
        sig = base64.urlsafe_b64decode(s64 + "=" * (-len(s64) % 4))
        ISSUER_KEY.verify(sig, f"{h64}.{p64}".encode())
    except (binascii.Error, InvalidSignature):
        raise Unauthorized("signature is not from the configured issuer", "invalid_token") from None
    import time

    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or time.time() >= exp:
        raise Unauthorized("token expired or carries no expiry", "invalid_token")
    for claim in ("sub", "client_id", "iat", "jti"):
        if claim not in claims:
            raise Unauthorized(f"token carries no {claim}", "invalid_token")
    return claims


# ---------------------------------------------------------------- JCS + PDP
def jcs_digest(args):
    """RFC 8785 SHA-256 of the arguments — the value decern binds into the record.

    `json.dumps(sort_keys, compact, ensure_ascii=False)` IS the JCS canonical form only
    inside a fence, which the inputSchema check enforces before we get here: keys are
    the schema's ASCII names, values are strings or integers, booleans are excluded
    (bool is an int subtype in Python), integers stay inside ±2^53-1, and every string
    must UTF-8-encode — a model-authored lone surrogate is refused, not crashed on.
    """
    import hashlib

    for v in args.values():
        if isinstance(v, bool) or not isinstance(v, (str, int)):
            raise ValueError("arguments are strings and integers in this example")
        if isinstance(v, int) and abs(v) > 2**53 - 1:
            raise ValueError("integer arguments must stay inside +/-2^53-1")
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def decide(subject_id, action, resource_id, context):
    """Ask decern. The client's token is NOT forwarded — passing it upstream is a MUST
    NOT (Security Best Practices, token passthrough). decern runs behind this server
    with --trust-proxy: this process is the declared, authenticated front.
    """
    body = json.dumps(
        {
            "subject": {"type": "Principal", "id": subject_id},
            "action": {"name": action},
            "resource": {"type": "Resource", "id": resource_id},
            "context": context,
        }
    ).encode()
    req = urllib.request.Request(
        f"{PDP_URL}/access/v1/evaluation",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        d = json.loads(resp.read())
    ctx = d.get("context", {})
    return d.get("decision") is True, ctx.get("reasons", []), ctx.get("errors", [])


def approve_mission(agent, tools, ttl_seconds=3600):
    """Mint a Mission on decern for `agent`, scoped to `tools`, and return its s256
    reference. Raises on transport failure or a refused approval (e.g. the approver
    lacking a requested tool) — the caller decides how to surface that as a Deny.
    """
    import time

    body = json.dumps(
        {
            "approver": MISSION_APPROVER,
            "agent": agent,
            "description": f"step-up: {agent} requested {', '.join(tools)}",
            "approved_tools": tools,
            "capabilities": [],
            "expiry": int(time.time()) + ttl_seconds,
        }
    ).encode()
    req = urllib.request.Request(
        f"{PDP_URL}/mission/v1/approve",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())["s256"]


# ---------------------------------------------------------------- JSON-RPC plumbing
def rpc_error(rid, code, message, data=None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": rid, "error": err}


def rpc_result(rid, result, legacy=False):
    if legacy:
        # Earlier revisions know neither resultType nor result _meta.
        result.pop("resultType", None)
        return {"jsonrpc": "2.0", "id": rid, "result": result}
    result["_meta"] = {"io.modelcontextprotocol/serverInfo": SERVER_INFO}  # a SHOULD
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def decode_sentinel(value):
    """Transports, Value Encoding: an `=?base64?…?=` header value MUST be decoded
    before comparison with its body counterpart."""
    if value and value.startswith("=?base64?") and value.endswith("?="):
        try:
            return base64.b64decode(value[9:-2]).decode()
        except (binascii.Error, ValueError):
            return value
    return value


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "decern-mcp-example"

    def log_message(self, *_):
        pass  # the walkthrough's output is the story; access logs would drown it

    # ------------------------------------------------------------ responses
    def send_json(self, status, obj, headers=()):
        raw = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def send_challenge(self, status, error=None, scope=None, description=None):
        # RFC 6750 §3 challenge; resource_metadata is one of the two discovery routes
        # RFC 9728 gives a client (Authorization, discovery requirements).
        parts = [f'resource_metadata="{RESOURCE.rsplit("/mcp", 1)[0]}/.well-known/oauth-protected-resource"']
        if error:
            parts.insert(0, f'error="{error}"')
        if scope:
            parts.append(f'scope="{scope}"')
        if description:
            parts.append(f'error_description="{description}"')
        body = {"error": error or "unauthorized"}
        if description:
            body["error_description"] = description
        self.send_json(status, body, [("WWW-Authenticate", "Bearer " + ", ".join(parts))])

    # ------------------------------------------------------------ non-POST
    def do_GET(self):
        if self.path == "/.well-known/oauth-protected-resource":
            self.send_json(200, PRM)
        elif self.path == "/mcp":
            # Transports, Backward Compatibility: no server-initiated streams in this
            # revision — GET on the MCP endpoint answers 405.
            self.send_json(405, {"error": "method not allowed"})
        else:
            self.send_json(404, {"error": "not found"})

    def do_DELETE(self):
        self.send_json(405, {"error": "method not allowed"})

    # ------------------------------------------------------------ the MCP endpoint
    def do_POST(self):
        if self.path != "/mcp":
            self.send_json(404, {"error": "not found"})
            return

        # Transports, Security: validate Origin when present; present-and-invalid → 403.
        origin = self.headers.get("Origin")
        if origin and origin not in (f"http://{HOST}:{PORT}", "http://localhost", "null"):
            self.send_json(403, {"error": "origin not allowed"})
            return

        try:
            claims = validate_token(self.headers.get("Authorization"))
        except Unauthorized as e:
            self.send_challenge(401, e.code, description=str(e) if e.code else None)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            msg = json.loads(self.rfile.read(length))
        except ValueError:
            self.send_json(400, rpc_error(None, -32700, "parse error"))
            return
        if isinstance(msg, list):
            # Transports, Sending Messages: the body is a SINGLE request or
            # notification — this revision has no batching.
            self.send_json(400, rpc_error(None, -32600, "batching is not supported"))
            return
        if "id" not in msg:
            # A notification. Header requirements on notifications are undefined in
            # this revision; the defined obligation is 202 with no body.
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        rid, method = msg.get("id"), msg.get("method")
        meta = (msg.get("params") or {}).get("_meta") or {}

        # Basic protocol, per-request fields: protocolVersion and clientCapabilities
        # are REQUIRED; missing → -32602 (a malformed request, not a header mismatch).
        # A request without the protocolVersion _meta key is an earlier-revision
        # client, which the transport spec's backward-compatibility clause lets a
        # server serve. Keyed on that key alone: real clients decorate _meta with
        # their own namespaced entries, so emptiness discriminates nothing.
        version = meta.get("io.modelcontextprotocol/protocolVersion")
        if version is None:
            self.legacy_dispatch(rid, method, msg.get("params") or {}, claims)
            return
        if "io.modelcontextprotocol/clientCapabilities" not in meta:
            self.send_json(400, rpc_error(rid, -32602, "missing required _meta fields"))
            return
        # Transports, Protocol Version Header: header and body MUST match → -32020.
        if decode_sentinel(self.headers.get("MCP-Protocol-Version")) != version or decode_sentinel(
            self.headers.get("Mcp-Method")
        ) != method:
            self.send_json(400, rpc_error(rid, -32020, "header does not match body"))
            return
        if version != PROTOCOL_VERSION:
            self.send_json(
                400,
                rpc_error(
                    rid,
                    -32022,
                    "unsupported protocol version",
                    {"supported": [PROTOCOL_VERSION], "requested": version},
                ),
            )
            return

        if method == "server/discover":
            self.send_json(
                200,
                rpc_result(
                    rid,
                    {
                        "resultType": "complete",
                        "supportedVersions": [PROTOCOL_VERSION],
                        "capabilities": {"tools": {}},  # no listChanged: nothing streams
                        # Reached only with a token, so cached only per caller — and
                        # never relied on for access control (Caching, security).
                        "ttlMs": 300000,
                        "cacheScope": "private",
                    },
                ),
            )
        elif method == "tools/list":
            self.send_json(
                200,
                rpc_result(
                    rid,
                    {"resultType": "complete", "tools": TOOL_LIST, "ttlMs": 300000, "cacheScope": "private"},
                ),
            )
        elif method == "tools/call":
            self.tool_call(rid, msg.get("params") or {}, claims)
        else:
            # Transports: unknown method → HTTP 404 with -32601.
            self.send_json(404, rpc_error(rid, -32601, "method not found"))

    # ------------------------------------------------- earlier-revision clients
    # The 2026-07-28 transport spec's own backward-compatibility clause: a server MAY
    # treat a request without the protocol-version header as revision 2025-03-26. As of
    # this example's writing, shipping clients (Claude Code included) still speak the
    # 2025-06-18 lifecycle — initialize, notifications/initialized, no per-request
    # _meta — so this block is what lets a real client connect today. It adds no
    # authorization surface: the bearer check ran before dispatch, and tools/call joins
    # the same guarded path. Delete this method when the clients you care about carry
    # _meta, and the example becomes single-revision again.
    def legacy_dispatch(self, rid, method, params, claims):
        if method == "initialize":
            requested = params.get("protocolVersion", "2025-03-26")
            supported = ("2025-03-26", "2025-06-18")
            self.send_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "result": {
                        "protocolVersion": requested if requested in supported else "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": SERVER_INFO,
                    },
                },
            )
        elif method == "ping":
            self.send_json(200, {"jsonrpc": "2.0", "id": rid, "result": {}})
        elif method == "tools/list":
            self.send_json(
                200,
                {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOL_LIST}},
            )
        elif method == "tools/call":
            self.tool_call(rid, params, claims, legacy=True)
        else:
            self.send_json(200, rpc_error(rid, -32601, "method not found"))

    # ------------------------------------------------------------ the seam
    def tool_call(self, rid, params, claims, legacy=False):
        name = params.get("name", "")
        # Transports, Standard Request Headers: Mcp-Name is REQUIRED on tools/call
        # (and MUST NOT be expected on discover/list). Earlier revisions had no such
        # header, so the legacy path does not demand one.
        if not legacy and decode_sentinel(self.headers.get("Mcp-Name")) != name:
            self.send_json(400, rpc_error(rid, -32020, "Mcp-Name does not match params.name"))
            return
        tool = TOOLS.get(name)
        if tool is None:
            # Tools, error handling: an unknown tool is a protocol error, not a tool
            # result — the model cannot self-correct a tool that does not exist.
            self.send_json(200, rpc_error(rid, -32602, f"unknown tool: {name}"))
            return

        args = params.get("arguments") or {}
        problem = check_schema(args, tool["schema"])
        if problem is None:
            try:
                digest = jcs_digest(args)
            except (ValueError, UnicodeEncodeError) as e:
                problem = str(e)
        if problem is not None:
            # Tools, error handling: input validation is a tool-execution error —
            # reported in-result so the model sees it and can correct the call.
            self.send_json(
                200,
                rpc_result(
                    rid,
                    {
                        "resultType": "complete",
                        "content": [{"type": "text", "text": f"invalid arguments: {problem}"}],
                        "isError": True,
                    },
                    legacy,
                ),
            )
            return

        # The decision context: the argument digest always; a Mission only as a relay
        # of a scope this server VERIFIED on the token. MoveMoney requires a Mission
        # unconditionally, so a verified scope is turned into one here rather than
        # asserted as an approval flag decern would refuse to honor for this action.
        context = {"args_sha256": digest}
        scopes = (claims.get("scope") or "").split()
        if tool["action"] == "MoveMoney" and APPROVAL_SCOPE in scopes:
            try:
                s256 = approve_mission(claims["sub"], ["move_money"])
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError):
                # Mission minting is unavailable or was refused: fall through with no
                # mission named, so decide() below denies MoveMoney the same way it
                # would deny any other missing-Mission request.
                pass
            else:
                context["mission"] = {"approver": MISSION_APPROVER, "s256": s256}

        try:
            allowed, reasons, errors = decide(
                claims["sub"], tool["action"], args[tool["resource_arg"]], context
            )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            # The decision point is unavailable or refused to record. Fail closed the
            # same way decern itself does: no decision, no execution.
            self.send_json(
                200,
                rpc_result(
                    rid,
                    {
                        "resultType": "complete",
                        "content": [
                            {"type": "text", "text": "authorization decision unavailable; refusing"}
                        ],
                        "isError": True,
                    },
                    legacy,
                ),
            )
            return

        if allowed:
            self.send_json(
                200,
                rpc_result(
                    rid,
                    {
                        "resultType": "complete",
                        "content": [{"type": "text", "text": tool["run"](args)}],
                    },
                    legacy,
                ),
            )
        elif "F-money" in reasons or any("required for MoveMoney" in e for e in errors):
            # An approval-shaped Deny: a grant the caller could obtain. Authorization,
            # error handling: 403 with an insufficient_scope challenge naming every
            # scope that would satisfy the request — and it truly would; see the
            # step-up beat in run.sh. "F-money" is Cedar's own forbid-policy reason
            # (still possible if a Mission was named but denied for another cause);
            # the mission-required message is decern's unconditional MoveMoney gate,
            # which fires before Cedar ever sees the request.
            self.send_challenge(
                403, "insufficient_scope", scope=APPROVAL_SCOPE, description="human approval required"
            )
        else:
            # A policy Deny no re-authorization can fix (tenancy, revocation, decay) —
            # or a default deny, whose reasons are empty. Tools, error handling: a
            # business-logic refusal goes in the result with isError, so the model can
            # see it and self-correct instead of retrying blindly.
            why = ", ".join(reasons) or ", ".join(errors) or "default deny"
            self.send_json(
                200,
                rpc_result(
                    rid,
                    {
                        "resultType": "complete",
                        "content": [
                            {
                                "type": "text",
                                "text": f"denied by policy ({why}); recorded at the decision point",
                            }
                        ],
                        "isError": True,
                    },
                    legacy,
                ),
            )


def check_schema(args, schema):
    """Just enough JSON Schema for this example's own tools: exact keys, two types."""
    if not isinstance(args, dict):
        return "arguments must be an object"
    for key in schema["required"]:
        if key not in args:
            return f"missing argument: {key}"
    for key, value in args.items():
        prop = schema["properties"].get(key)
        if prop is None:
            return f"unexpected argument: {key}"
        if prop["type"] == "string" and not isinstance(value, str):
            return f"{key} must be a string"
        if prop["type"] == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
            return f"{key} must be an integer"
    return None


if __name__ == "__main__":
    print(f"decern-mcp-example on http://{HOST}:{PORT}/mcp -> PDP {PDP_URL}", file=sys.stderr)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
