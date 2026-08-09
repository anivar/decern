#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# End-to-end: prove the example model, serve decisions behind an MCP server, watch a
# tool call Allow, a Deny become a satisfiable 403, step-up succeed, an unfixable Deny
# surface as a tool error, and every decision land on a ledger a third party can check.
# Needs: cargo, cvc5 on PATH, uv, jq, python3, curl.
set -euo pipefail
cd "$(dirname "$0")/../.."

MCP_PORT=8792
PDP_PORT=8793
WORK="$(mktemp -d)"
LEDGER="$WORK/decern-mcp-ledger.jsonl"
MODEL=examples/mcp/model
MCP=http://127.0.0.1:$MCP_PORT/mcp
AUD=$MCP

echo "== 1. The example model diverges from the builtin in exactly two declared ways =="
# The policies are the builtin's, verbatim — the builtin carries the @id names itself.
diff "$MODEL/authority.cedar" crates/decern-kernel/model/authority.cedar
# Remove the args_sha256 attribute -> the schema must be the builtin's, verbatim.
diff <(sed 's/, args_sha256?: String//' "$MODEL/authority.cedarschema") crates/decern-kernel/model/authority.cedarschema
# Remove the two demo entities -> the graph must be the builtin's.
python3 - "$MODEL/entities.json" crates/decern-kernel/model/entities.json <<'EOF'
import json, sys
ours = [e for e in json.load(open(sys.argv[1])) if e["uid"]["id"] not in ("mcp_agent", "account9")]
theirs = json.load(open(sys.argv[2]))
assert ours == theirs, "entities diverge beyond the whitelisted additions"
EOF
echo "   no drift beyond the whitelist."

echo
echo "== 2. Prove all nine invariants over the EXAMPLE model (cvc5) =="
cargo run -q -p decern-cli -- prove --model "$MODEL"

echo
echo "== 3. Start the PDP and the MCP server =="
# --trust-proxy: the MCP server is the declared, authenticated front — and the client's
# token is never forwarded to decern, which is MCP's own token-passthrough MUST NOT.
cargo run -q -p decern-server -- --model "$MODEL" --ledger "$LEDGER" \
  --addr "127.0.0.1:$PDP_PORT" --trust-proxy &
PDP=$!
MINT=$(uv run examples/mcp/mint.py mcp_agent "$AUD")
PUB=$(jq -r .pub_hex <<<"$MINT")
TOKEN=$(jq -r .token <<<"$MINT")
MCP_ISSUER_PUBKEY=$PUB PDP_URL="http://127.0.0.1:$PDP_PORT" MCP_PORT=$MCP_PORT \
  uv run examples/mcp/server.py &
SRV=$!
trap 'kill "$PDP" "$SRV" 2>/dev/null || true; rm -rf "$WORK"' EXIT
until curl -sf "localhost:$PDP_PORT/healthz" >/dev/null 2>&1; do sleep 0.3; done
# The MCP endpoint answers GET with 405 by design; readiness is the PRM document.
until curl -sf "localhost:$MCP_PORT/.well-known/oauth-protected-resource" >/dev/null 2>&1; do sleep 0.3; done
KID=$(curl -s "localhost:$PDP_PORT/pubkey" | jq -r .kid)
echo "   serving; ledger key = $KID"

# A conformant client call: Accept both content types, the three required headers, the
# required _meta fields. $1=method $2=name-or-empty $3=params-json $4=token
call() {
  local name_header=()
  [ -n "$2" ] && name_header=(-H "Mcp-Name: $2")
  curl -s -w '\n%{http_code}' "$MCP" \
    -H 'Accept: application/json, text/event-stream' \
    -H 'Content-Type: application/json' \
    -H "MCP-Protocol-Version: 2026-07-28" \
    -H "Mcp-Method: $1" "${name_header[@]}" \
    -H "Authorization: Bearer $4" \
    -d "$(jq -nc --arg m "$1" --argjson p "$3" \
      '{jsonrpc:"2.0", id:1, method:$m,
        params: ($p + {_meta: {"io.modelcontextprotocol/protocolVersion":"2026-07-28",
                              "io.modelcontextprotocol/clientCapabilities":{}}})}')"
}

echo
echo "== 4. server/discover and tools/list =="
OUT=$(call server/discover "" '{}' "$TOKEN"); BODY=${OUT%$'\n'*}; CODE=${OUT##*$'\n'}
[ "$CODE" = 200 ] && jq -e '.result.supportedVersions == ["2026-07-28"]' <<<"$BODY" >/dev/null
OUT=$(call tools/list "" '{}' "$TOKEN"); BODY=${OUT%$'\n'*}
jq -e '.result.tools | length == 2' <<<"$BODY" >/dev/null
echo "   discover + list conformant."

echo
echo "== 5. read_claim(claim1) — Allow, and the tool runs =="
ARGS='{"claim_id":"claim1"}'
OUT=$(call tools/call read_claim "{\"name\":\"read_claim\",\"arguments\":$ARGS}" "$TOKEN")
BODY=${OUT%$'\n'*}; CODE=${OUT##*$'\n'}
[ "$CODE" = 200 ]
jq -e '.result.isError != true and (.result.content[0].text | contains("claim1"))' <<<"$BODY" >/dev/null
echo "   allowed and executed."

echo
echo "== 6. move_money — Deny becomes a SATISFIABLE 403 insufficient_scope =="
MOVE='{"account":"account9","amount":40}'
OUT=$(curl -s -D- -o /dev/null "$MCP" \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -H "MCP-Protocol-Version: 2026-07-28" -H "Mcp-Method: tools/call" -H "Mcp-Name: move_money" \
  -H "Authorization: Bearer $TOKEN" \
  -d "$(jq -nc --argjson a "$MOVE" '{jsonrpc:"2.0",id:1,method:"tools/call",
    params:{name:"move_money",arguments:$a,
      _meta:{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
             "io.modelcontextprotocol/clientCapabilities":{}}}}')")
grep -q "HTTP/1.1 403" <<<"$OUT"
grep -qi 'error="insufficient_scope"' <<<"$OUT"
grep -q 'scope="decern.move_money.approved"' <<<"$OUT"
echo "   403 challenge names the scope that will actually work."

echo
echo "== 7. Step-up: a token WITH the scope — the challenge kept its promise =="
UP=$(uv run examples/mcp/mint.py mcp_agent "$AUD" decern.move_money.approved | jq -r .token)
OUT=$(call tools/call move_money "{\"name\":\"move_money\",\"arguments\":$MOVE}" "$UP")
BODY=${OUT%$'\n'*}
jq -e '.result.isError != true and (.result.content[0].text | contains("submitted"))' <<<"$BODY" >/dev/null
echo "   allowed after step-up."

echo
echo "== 8. read_claim(claimB) — a Deny no re-authorization can fix -> isError =="
OUT=$(call tools/call read_claim '{"name":"read_claim","arguments":{"claim_id":"claimB"}}' "$TOKEN")
BODY=${OUT%$'\n'*}
jq -e '.result.isError == true and (.result.content[0].text | contains("F-tenant"))' <<<"$BODY" >/dev/null
echo "   tenant isolation surfaced where the model can read it."

echo
echo "== 9. No token, and a token for another audience -> 401 with a challenge =="
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$MCP" -H "Mcp-Method: tools/list" -d '{}')
[ "$CODE" = 401 ]
OTHER=$(uv run examples/mcp/mint.py mcp_agent "https://other.example/" | jq -r .token)
OUT=$(curl -s -D- -o /dev/null "$MCP" -H "Authorization: Bearer $OTHER" -H "Mcp-Method: tools/list" -d '{}')
grep -q "HTTP/1.1 401" <<<"$OUT" && grep -q resource_metadata <<<"$OUT"
echo "   both refused, WWW-Authenticate present."

echo
echo "== 10. The ledger holds all four decisions, arguments digest-bound =="
kill "$PDP" 2>/dev/null || true; wait "$PDP" 2>/dev/null || true
cargo run -q -p decern-cli -- verify --ledger "$LEDGER" --pubkey "$KID"
# seq 0 allow, 1 money deny, 2 step-up allow, 3 tenant deny — denials are records too.
for SEQ in 0 1 2 3; do
  cargo run -q -p decern-cli -- explain --ledger "$LEDGER" --seq "$SEQ" --pubkey "$KID" \
    | grep -E "decision:|bound to:" | head -2
done
# The binding is externally checkable: recompute the digest from the arguments and
# find it in the recorded context.
EXPECT=$(python3 -c "
import hashlib, json
print(hashlib.sha256(json.dumps(json.loads('$MOVE'), sort_keys=True, separators=(',',':'), ensure_ascii=False).encode()).hexdigest())")
GOT=$(cargo run -q -p decern-cli -- explain --ledger "$LEDGER" --seq 1 --json | jq -r .context.args_sha256)
[ "$EXPECT" = "$GOT" ]
echo "   args_sha256 recomputed from the arguments matches the record: $GOT"

echo
echo "All beats held. What this shows: every call that reached decern is recorded and"
echo "verifiable. What it cannot show: a call that never reached it did not happen —"
echo "that guarantee belongs to whoever enforces that this server is the only path."
