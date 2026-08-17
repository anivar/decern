#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# End-to-end: serve decisions to an AAuth agent, verified against provider keys pinned at
# startup. Watch a valid agent token Allow, watch the refusals that keep the posture honest
# — including the two that are decern's own profile rather than the draft's — and watch the
# agent identity land on the ledger.
#
# No agent provider and no network: mint.py writes the key set and signs both the agent
# token and the request, so the walkthrough runs from a fresh checkout.
#
# Needs: cargo, uv, jq, python3, curl.
set -euo pipefail
cd "$(dirname "$0")/../.."

PORT=8799
WORK="$(mktemp -d)"
LEDGER="$WORK/decern-aauth-ledger.jsonl"
JWKS="$WORK/provider-jwks.json"
ISS="https://agent-provider.example"
AGENT="https://agent-provider.example/agents/agent-1"
# The authority is what stands in for the audience an agent token does not carry, so it is
# exactly the Host curl will send. Getting this wrong is a refusal, which beat 9 shows.
AUTHORITY="127.0.0.1:$PORT"
PDP="http://127.0.0.1:$PORT"
MINT=examples/aauth/mint.py
PATH_EVAL=/access/v1/evaluation
BODY="{\"subject\":{\"type\":\"Principal\",\"id\":\"$AGENT\"},\"action\":{\"name\":\"Read\"},\"resource\":{\"type\":\"Resource\",\"id\":\"claim1\"}}"
CORP='{"subject":{"type":"Principal","id":"corp"},"action":{"name":"Read"},"resource":{"type":"Resource","id":"claim1"}}'

# Stock policies, example graph. The agent's identifier is a principal the OPERATOR declared
# here, and owns claim1 — so it can Allow when asking about itself. decern does not mint a
# principal for a verified agent token; what a decision may be ABOUT is unchanged, so
# against the builtin model this posture is fail-closed by construction.
MODEL="$WORK/model"
mkdir -p "$MODEL"
cp crates/decern-kernel/model/authority.cedar \
   crates/decern-kernel/model/authority.cedarschema \
   "$MODEL/"
cp examples/aauth/model/entities.json "$MODEL/"

# $1 = the body the signature must cover, then any mint.py flags.
mint_for() {
  local body="$1"; shift
  uv run "$MINT" "$AGENT" POST "$AUTHORITY" "$PATH_EVAL" --body "$body" "$@"
}

# $1 = mint.py JSON, $2 = body, $3 = optional Host override. Prints status; body in $WORK/body.
send() {
  local json="$1" body="$2" host="${3:-$AUTHORITY}"
  local args=(-s -o "$WORK/body" -w '%{http_code}'
    -H 'Content-Type: application/json'
    -H "Host: $host"
    -H "Signature-Key: $(jq -r .signature_key <<<"$json")"
    -H "Signature-Input: $(jq -r .signature_input <<<"$json")"
    -H "Signature: $(jq -r .signature <<<"$json")")
  local digest
  digest=$(jq -r '.content_digest // empty' <<<"$json")
  [ -n "$digest" ] && args+=(-H "Content-Digest: $digest")
  curl "${args[@]}" "$PDP$PATH_EVAL" -d "$body"
}

echo "== 1. Write the provider key set and start the PDP pinned to it =="
uv run "$MINT" --jwks >"$JWKS"
# The key set is read once, here. decern performs no `dwk` discovery, so a decision never
# waits on an agent provider being reachable — and an agent from a provider that is not in
# this file is refused before any cryptography runs.
cargo run -q -p decern-server -- --ledger "$LEDGER" --addr "127.0.0.1:$PORT" \
  --model "$MODEL" \
  --aauth-provider "$ISS=$JWKS" --aauth-audience "$AUTHORITY" &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true; rm -rf "$WORK"' EXIT
until curl -sf "$PDP/healthz" >/dev/null 2>&1; do sleep 0.3; done
KID=$(curl -s "$PDP/pubkey" | jq -r .kid)
echo "   serving; provider $ISS pinned; ledger key = $KID"

echo
echo "== 2. A valid agent token, asking about itself — Allow, and it is recorded =="
CODE=$(send "$(mint_for "$BODY")" "$BODY")
[ "$CODE" = 200 ]
jq -e '.decision == true' "$WORK/body" >/dev/null
echo "   200 $(jq -c . "$WORK/body")"

echo
echo "== 3. The same agent, asking as corp — refused =="
# The token is valid and both signatures verify. What is wrong is the name in the request.
# An agent speaks for itself, so this is 403, not 401.
CODE=$(send "$(mint_for "$CORP")" "$CORP")
[ "$CODE" = 403 ]
jq -e '.error == "caller_mismatch"' "$WORK/body" >/dev/null
echo "   403 $(jq -r .detail "$WORK/body")"

echo
echo "== 4. A request signed by a key the token does not confirm — refused =="
# Proof of possession. The token is byte-identical to the one that just worked and its
# provider signature still verifies; only the key signing the request differs. A bearer
# credential would accept this.
CODE=$(send "$(mint_for "$BODY" --wrong-key)" "$BODY")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("confirmed key")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 5. A POST signed over the DRAFT'S OWN component list — refused =="
# This is decern's profile, not the draft's: the draft's example covers @method, @authority,
# @path and signature-key, and does not cover the body. Every AuthZEN evaluation is a POST,
# so accepting that would mean one captured signature authorizing any body at this path —
# the defect closed in 0.3.0. RFC 9421 4.1 assigns component requirements to the profile, so
# requiring content-digest is conformant. An AAuth agent must sign it to talk to decern.
CODE=$(send "$(mint_for "$BODY" --no-digest)" "$BODY")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("required components")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 6. A token from a provider this deployment was never told about — refused =="
# The closed-world boundary, stated as a refusal. decern does not fetch the metadata
# document named by dwk, so an unconfigured issuer cannot be resolved into trust.
CODE=$(send "$(mint_for "$BODY" --iss https://other-provider.example)" "$BODY")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("not configured here")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 7. A token signed by a key the pinned provider does not hold — refused =="
# Unlike the signed-request posture, the agent token's OWN signature is verified here: the
# token is the provider's assertion about which key the agent holds, so without this check
# a caller could mint itself any identity and any cnf.
CODE=$(send "$(mint_for "$BODY" --wrong-provider)" "$BODY")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("does not verify against its provider")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 8. A signature refused for age alone =="
CODE=$(send "$(mint_for "$BODY" --stale)" "$BODY")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("freshness")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 9. A request minted for a DIFFERENT deployment — refused =="
# An agent token carries no aud, and @authority is only the Host the caller sent. Without
# --aauth-audience, this request — internally consistent, correctly signed, from a pinned
# provider — would verify at any deployment pinning the same provider.
OTHER=other.example
CODE=$(send "$(uv run "$MINT" "$AGENT" POST "$OTHER" "$PATH_EVAL" --body "$BODY")" "$BODY" "$OTHER")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("not this deployment")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 10. No credentials at all — refused =="
CODE=$(curl -s -o "$WORK/body" -w '%{http_code}' "$PDP$PATH_EVAL" \
  -H 'Content-Type: application/json' -H "Host: $AUTHORITY" -d "$BODY")
[ "$CODE" = 401 ]
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 11. The deployment discloses the posture it is running =="
curl -s "$PDP/.well-known/decern-subject-side-disclosure" -H "Host: $AUTHORITY" >"$WORK/disc"
jq -e '.caller.mode == "aauth" and .caller.bind == "self"' "$WORK/disc" >/dev/null
echo "   $(jq -c .caller "$WORK/disc")"

echo
echo "== 12. The ledger names the agent decern verified, and the chain holds =="
# asserted_by is the identity the server established, not one the request asserted about
# itself, and the issuer is the provider whose key verified the token.
jq -e --arg a "$AGENT" --arg i "$ISS" \
  'select(.entry.seq == 0) | .entry.asserted_by.sub == $a and .entry.asserted_by.iss == $i' \
  "$LEDGER" >/dev/null
echo "   asserted_by = $(jq -c 'select(.entry.seq == 0) | .entry.asserted_by' "$LEDGER")"
cargo run -q -p decern-cli -- verify --ledger "$LEDGER" --pubkey "$KID"

echo
echo "aauth walkthrough: every beat asserted."
