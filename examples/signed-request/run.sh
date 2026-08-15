#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# End-to-end: serve decisions to a caller who must PROVE possession of a key on every
# request, watch a correctly signed call Allow, watch the same token refused when the
# signature comes from a different key, and watch every decision land on a ledger a
# third party can check.
#
# The property this demonstrates is the one a bearer token cannot give you: a leaked
# access token is replayable against any request until it expires. A leaked signed
# request cannot be replayed against a different path (@path is covered) or a different
# POST body (content-digest is covered). Verbatim replay of the same captured signature
# — same path, same body — is not separately prevented (no nonce cache); it verifies
# again within the freshness window, just a much shorter one than a token's full lifetime.
#
# Needs: cargo, uv, jq, python3, curl.
set -euo pipefail
cd "$(dirname "$0")/../.."

PORT=8794
WORK="$(mktemp -d)"
LEDGER="$WORK/decern-signed-ledger.jsonl"
AUD="https://pdp.example/access/v1/evaluation"
PDP="http://127.0.0.1:$PORT"
PATH_OK=/access/v1/evaluation
SIGN=examples/signed-request/sign.py
BODY='{"subject":{"type":"Principal","id":"agent-1"},"action":{"name":"Read"},"resource":{"type":"Resource","id":"claim1"}}'

# Stock policies, example graph: agent-1 owns claim1 and is not decayed, so asking about
# itself can Allow. The builtin cannot serve this walkthrough — it has no agent-1 at all,
# and its agent1 carries expiry 200, so it is wall-clock decayed either way.
MODEL="$WORK/model"
mkdir -p "$MODEL"
cp crates/decern-kernel/model/authority.cedar \
   crates/decern-kernel/model/authority.cedarschema \
   "$MODEL/"
cp examples/signed-request/model/entities.json "$MODEL/"

# Every presentation is built by sign.py; extra args are flags (--wrong-key, --stale).
mk() { uv run "$SIGN" agent-1 "$AUD" POST "127.0.0.1:$PORT" "$PATH_OK" --body "$BODY" "$@"; }
g() { jq -r ".$2" <<<"$1"; }

# $1=presentation-json $2=path $3=optional body (defaults to $BODY).
send() {
  local payload="${3:-$BODY}"
  curl -s -o "$WORK/body" -w '%{http_code}' "$PDP$2" \
    -H 'Content-Type: application/json' \
    -H "Signature-Key: $(g "$1" token)" \
    -H "Signature-Input: $(g "$1" signature_input)" \
    -H "Signature: $(g "$1" signature)" \
    -H "Content-Digest: $(g "$1" content_digest)" \
    -d "$payload"
}

echo "== 1. Start the PDP with ONE agent's key pinned =="
GOOD=$(mk)
PUB=$(g "$GOOD" pub_hex)
# --signed-agent-key is the whole trust decision: an identifier with no entry here cannot
# authenticate at all. Keys are configured, never fetched — this binary makes no outbound
# request to establish a caller, so a decision never waits on a third party.
cargo run -q -p decern-server -- --ledger "$LEDGER" --addr "127.0.0.1:$PORT" \
  --model "$MODEL" \
  --signed-agent-key "agent-1=$PUB" --signed-audience "$AUD" &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true; rm -rf "$WORK"' EXIT
until curl -sf "$PDP/healthz" >/dev/null 2>&1; do sleep 0.3; done
KID=$(curl -s "$PDP/pubkey" | jq -r .kid)
echo "   serving; agent-1 pinned to ${PUB:0:16}…; ledger key = $KID"

echo
echo "== 2. A correctly signed request, as itself — Allow, and it is recorded =="
CODE=$(send "$GOOD" "$PATH_OK")
[ "$CODE" = 200 ]
jq -e '.decision == true' "$WORK/body" >/dev/null
echo "   200 $(jq -c . "$WORK/body")"

echo
echo "== 3. The same agent, correctly signing, but asking as corp — refused =="
# Nothing is wrong with this request cryptographically: it is signed by the right key and
# its Content-Digest matches its own body. What is wrong is the name inside it. 403, not
# 401 — the credential was accepted, the principal named is not theirs.
CORP='{"subject":{"type":"Principal","id":"corp"},"action":{"name":"Read"},"resource":{"type":"Resource","id":"claim1"}}'
CORP_SIG=$(uv run "$SIGN" agent-1 "$AUD" POST "127.0.0.1:$PORT" "$PATH_OK" --body "$CORP")
CODE=$(send "$CORP_SIG" "$PATH_OK" "$CORP")
[ "$CODE" = 403 ]
jq -e '.error == "caller_mismatch"' "$WORK/body" >/dev/null
echo "   403 $(jq -r .detail "$WORK/body")"

echo
echo "== 4. The same agent, approving a Mission as corp — refused =="
# The theft this closes: mint a grant under someone else's authority. Attenuation alone
# would have allowed it, because corp really does hold move_money — the agent simply was
# never corp. Signed over its own body and its own path, so only admission can refuse it.
APPROVE='{"approver":"corp","agent":"agent-1","description":"self-grant","approved_tools":["move_money"],"expiry":32503680000}'
APPROVE_SIG=$(uv run "$SIGN" agent-1 "$AUD" POST "127.0.0.1:$PORT" /mission/v1/approve --body "$APPROVE")
CODE=$(send "$APPROVE_SIG" /mission/v1/approve "$APPROVE")
[ "$CODE" = 403 ]
jq -e '.error == "caller_mismatch"' "$WORK/body" >/dev/null
echo "   403 $(jq -r .detail "$WORK/body")"

echo
echo "== 5. The SAME token, signed by a different key — refused =="
# This is the beat that matters. The token is byte-identical to the one that just worked:
# same sub, same aud, same cnf, unexpired. Only the signature differs, because the caller
# holds the token but not the private key it confirms. A bearer token would be accepted
# here; this is exactly the replay a bearer credential cannot refuse.
CODE=$(send "$(mk --wrong-key)" "$PATH_OK")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("does not verify")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 6. A signature older than the acceptance window — refused =="
# A signature proves possession for one request, not for a session. Age alone is fatal,
# even though the token itself is still well within its own expiry.
CODE=$(send "$(mk --stale)" "$PATH_OK")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("freshness")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 7. The path is genuinely covered: replay the same signature at /decide =="
# /decide is a real alias for the same endpoint, so this request would otherwise succeed.
# The signature was computed over @path=$PATH_OK, so moving it refuses — proof the
# covered components are not decoration.
CODE=$(send "$GOOD" /decide)
[ "$CODE" = 401 ]
echo "   401 $(jq -r .error_description "$WORK/body") (signed for $PATH_OK)"

echo
echo "== 8. The body is genuinely covered: replay the same signature with a different JSON =="
# Same path, same headers, different body. Before content-digest was covered this
# authenticated — the signature contributed nothing. MoveMoney is denied later by
# the Mission requirement; /mission/v1/approve has no such backstop. The digest
# check must refuse here, at the signature, not later.
MOVE='{"subject":{"type":"Principal","id":"corp"},"action":{"name":"MoveMoney"},"resource":{"type":"Resource","id":"claim1"}}'
CODE=$(send "$GOOD" "$PATH_OK" "$MOVE")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("does not match the request body")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 9. No credentials at all — refused, with no hint that guessing helps =="
CODE=$(curl -s -o "$WORK/body" -w '%{http_code}' "$PDP$PATH_OK" \
  -H 'Content-Type: application/json' -d "$BODY")
[ "$CODE" = 401 ]
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 10. The deployment discloses its own caller posture =="
# Read from the running configuration, not from a promise in a README.
curl -s "$PDP/.well-known/decern-subject-side-disclosure" | jq -e '.caller.mode == "signed"' >/dev/null
curl -s "$PDP/.well-known/decern-subject-side-disclosure" | jq -e '.caller.bind == "self"' >/dev/null
curl -s "$PDP/.well-known/decern-subject-side-disclosure" | jq -c .caller

echo
echo "== 11. The ledger says WHO asserted the one decision that was allowed =="
kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true
cargo run -q -p decern-cli -- verify --ledger "$LEDGER" --pubkey "$KID"
# Only beat 2 reached the kernel; the refusals never became decisions, because a
# caller that cannot be established never gets one.
cargo run -q -p decern-cli -- explain --ledger "$LEDGER" --seq 0 --pubkey "$KID" \
  | grep -E "decision:|asserted_by:"
cargo run -q -p decern-cli -- explain --ledger "$LEDGER" --seq 0 --json \
  | jq -e '.asserted_by.sub == "agent-1"' >/dev/null
echo "   the record names agent-1 as the caller the server itself verified."

echo
echo "All beats held. What this shows: the caller proved possession of a configured key on"
echo "the one request that was allowed, could not name another principal, and the record"
echo "says so. What it cannot show: that agent-1 is who its operator believes it is — that"
echo "guarantee belongs to whoever decided which key to pin."
