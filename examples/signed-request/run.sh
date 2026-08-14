#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# End-to-end: serve decisions to a caller who must PROVE possession of a key on every
# request, watch a correctly signed call Allow, watch the same token refused when the
# signature comes from a different key, and watch every decision land on a ledger a
# third party can check.
#
# The property this demonstrates is the one a bearer token cannot give you: a leaked
# access token is replayable until it expires, but a leaked signed request is not
# replayable at all — the signature covers this exact request and nothing else.
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
BODY='{"subject":{"type":"Principal","id":"corp"},"action":{"name":"Read"},"resource":{"type":"Resource","id":"claim1"}}'

# Every presentation is built by sign.py; $1 is any extra flag (--wrong-key, --stale).
mk() { uv run "$SIGN" agent-1 "$AUD" POST "127.0.0.1:$PORT" "$PATH_OK" ${1:+"$1"}; }
g() { jq -r ".$2" <<<"$1"; }

# $1=presentation-json $2=path — prints "code body" so a beat can assert on both.
send() {
  curl -s -o "$WORK/body" -w '%{http_code}' "$PDP$2" \
    -H 'Content-Type: application/json' \
    -H "Signature-Key: $(g "$1" token)" \
    -H "Signature-Input: $(g "$1" signature_input)" \
    -H "Signature: $(g "$1" signature)" \
    -d "$BODY"
}

echo "== 1. Start the PDP with ONE agent's key pinned =="
GOOD=$(mk)
PUB=$(g "$GOOD" pub_hex)
# --signed-agent-key is the whole trust decision: an identifier with no entry here cannot
# authenticate at all. Keys are configured, never fetched — this binary makes no outbound
# request to establish a caller, so a decision never waits on a third party.
cargo run -q -p decern-server -- --ledger "$LEDGER" --addr "127.0.0.1:$PORT" \
  --signed-agent-key "agent-1=$PUB" --signed-audience "$AUD" &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true; rm -rf "$WORK"' EXIT
until curl -sf "$PDP/healthz" >/dev/null 2>&1; do sleep 0.3; done
KID=$(curl -s "$PDP/pubkey" | jq -r .kid)
echo "   serving; agent-1 pinned to ${PUB:0:16}…; ledger key = $KID"

echo
echo "== 2. A correctly signed request — Allow, and it is recorded =="
CODE=$(send "$GOOD" "$PATH_OK")
[ "$CODE" = 200 ]
jq -e '.decision == true' "$WORK/body" >/dev/null
echo "   200 $(jq -c . "$WORK/body")"

echo
echo "== 3. The SAME token, signed by a different key — refused =="
# This is the beat that matters. The token is byte-identical to the one that just worked:
# same sub, same aud, same cnf, unexpired. Only the signature differs, because the caller
# holds the token but not the private key it confirms. A bearer token would be accepted
# here; this is exactly the replay a bearer credential cannot refuse.
CODE=$(send "$(mk --wrong-key)" "$PATH_OK")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("does not verify")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 4. A signature older than the acceptance window — refused =="
# A signature proves possession for one request, not for a session. Age alone is fatal,
# even though the token itself is still well within its own expiry.
CODE=$(send "$(mk --stale)" "$PATH_OK")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("freshness")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 5. The path is genuinely covered: replay the same signature at /decide =="
# /decide is a real alias for the same endpoint, so this request would otherwise succeed.
# The signature was computed over @path=$PATH_OK, so moving it refuses — proof the
# covered components are not decoration.
CODE=$(send "$GOOD" /decide)
[ "$CODE" = 401 ]
echo "   401 $(jq -r .error_description "$WORK/body") (signed for $PATH_OK)"

echo
echo "== 6. No credentials at all — refused, with no hint that guessing helps =="
CODE=$(curl -s -o "$WORK/body" -w '%{http_code}' "$PDP$PATH_OK" \
  -H 'Content-Type: application/json' -d "$BODY")
[ "$CODE" = 401 ]
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 7. The deployment discloses its own caller posture =="
# Read from the running configuration, not from a promise in a README.
curl -s "$PDP/.well-known/decern-subject-side-disclosure" | jq -e '.caller.mode == "signed"' >/dev/null
curl -s "$PDP/.well-known/decern-subject-side-disclosure" | jq -c .caller

echo
echo "== 8. The ledger says WHO asserted the one decision that was allowed =="
kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true
cargo run -q -p decern-cli -- verify --ledger "$LEDGER" --pubkey "$KID"
# Only beat 2 reached the kernel; the four refusals never became decisions, because a
# caller that cannot be established never gets one.
cargo run -q -p decern-cli -- explain --ledger "$LEDGER" --seq 0 --pubkey "$KID" \
  | grep -E "decision:|asserted_by:"
cargo run -q -p decern-cli -- explain --ledger "$LEDGER" --seq 0 --json \
  | jq -e '.asserted_by.sub == "agent-1"' >/dev/null
echo "   the record names agent-1 as the caller the server itself verified."

echo
echo "All beats held. What this shows: the caller proved possession of a configured key on"
echo "the one request that was allowed, and the record says so. What it cannot show: that"
echo "agent-1 is who its operator believes it is — that guarantee belongs to whoever"
echo "decided which key to pin."
