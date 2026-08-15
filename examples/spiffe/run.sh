#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# End-to-end: serve decisions to a caller identified by a SPIFFE JWT-SVID, verified
# against a trust bundle pinned at startup. Watch a valid SVID Allow, watch the refusals
# that keep the posture honest, and watch the workload identity land on the ledger.
#
# No SPIRE daemon and no network: mint.py is a stand-in issuer that writes the bundle and
# signs the SVIDs, so the walkthrough runs from a fresh checkout.
#
# Needs: cargo, uv, jq, python3, curl.
set -euo pipefail
cd "$(dirname "$0")/../.."

PORT=8798
WORK="$(mktemp -d)"
LEDGER="$WORK/decern-spiffe-ledger.jsonl"
BUNDLE="$WORK/bundle.json"
TD=example.org
SVID_ID="spiffe://$TD/ns/api/sa/web"
AUD="https://pdp.example/access/v1/evaluation"
PDP="http://127.0.0.1:$PORT"
MINT=examples/spiffe/mint.py
BODY='{"subject":{"type":"Principal","id":"spiffe://example.org/ns/api/sa/web"},"action":{"name":"Read"},"resource":{"type":"Resource","id":"claim1"}}'
CORP='{"subject":{"type":"Principal","id":"corp"},"action":{"name":"Read"},"resource":{"type":"Resource","id":"claim1"}}'

# Stock policies, example graph. The workload's SPIFFE ID is a principal the OPERATOR
# declared here, and owns claim1 — so it can Allow when asking about itself. That is a
# different thing from decern minting a principal for a verified SVID, which it never
# does: `spiffe://` stays reserved for a verified-provenance mint path that does not
# exist. The builtin model declares no SPIFFE principals, so this posture is fail-closed
# against it by construction.
MODEL="$WORK/model"
mkdir -p "$MODEL"
cp crates/decern-kernel/model/authority.cedar \
   crates/decern-kernel/model/authority.cedarschema \
   "$MODEL/"
cp examples/spiffe/model/entities.json "$MODEL/"

# $1 = token. Prints the status code; body lands in $WORK/body.
# $1=token $2=optional body (defaults to $BODY, which asks about the workload itself).
send() {
  curl -s -o "$WORK/body" -w '%{http_code}' "$PDP/access/v1/evaluation" \
    -H 'Content-Type: application/json' -H "Authorization: Bearer $1" -d "${2:-$BODY}"
}

echo "== 1. Write a trust bundle and start the PDP pinned to it =="
uv run "$MINT" bundle "$BUNDLE" >/dev/null
# The bundle is read once, here. decern makes no outbound request to establish a caller,
# so a decision never waits on a SPIFFE control plane being reachable.
cargo run -q -p decern-server -- --ledger "$LEDGER" --addr "127.0.0.1:$PORT" \
  --model "$MODEL" \
  --spiffe-trust-domain "$TD=$BUNDLE" --spiffe-audience "$AUD" &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true; rm -rf "$WORK"' EXIT
until curl -sf "$PDP/healthz" >/dev/null 2>&1; do sleep 0.3; done
KID=$(curl -s "$PDP/pubkey" | jq -r .kid)
echo "   serving; trust domain $TD pinned; ledger key = $KID"

echo
echo "== 2. A valid JWT-SVID, asking about itself — Allow, and it is recorded =="
CODE=$(send "$(uv run "$MINT" svid "$SVID_ID" "$AUD")")
[ "$CODE" = 200 ]
jq -e '.decision == true' "$WORK/body" >/dev/null
echo "   200 $(jq -c . "$WORK/body")"

echo
echo "== 3. The same SVID, asking as corp — refused =="
# The SVID is valid and its signature verifies. What is wrong is the name inside the
# request. A workload speaks for itself; naming another principal is 403, not 401.
CODE=$(send "$(uv run "$MINT" svid "$SVID_ID" "$AUD")" "$CORP")
[ "$CODE" = 403 ]
jq -e '.error == "caller_mismatch"' "$WORK/body" >/dev/null
echo "   403 $(jq -r .detail "$WORK/body")"

echo
echo "== 4. The same SVID, approving a Mission as corp — refused =="
# Without this bind a valid SVID could mint a grant under corp's authority, which is the
# escalation the signed-request posture already closes. A second posture must not reopen it.
APPROVE='{"approver":"corp","agent":"spiffe://example.org/ns/api/sa/web","description":"self-grant","approved_tools":["move_money"],"expiry":32503680000}'
CODE=$(curl -s -o "$WORK/body" -w '%{http_code}' "$PDP/mission/v1/approve" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $(uv run "$MINT" svid "$SVID_ID" "$AUD")" -d "$APPROVE")
[ "$CODE" = 403 ]
jq -e '.error == "caller_mismatch"' "$WORK/body" >/dev/null
echo "   403 $(jq -r .detail "$WORK/body")"

echo "== 5. An SVID from a trust domain that merely LOOKS like ours — refused =="
# The reason trust domains are matched exactly and never by prefix: whoever controls
# example.org.evil must not be able to present as example.org.
CODE=$(send "$(uv run "$MINT" svid "spiffe://$TD.evil/ns/api/sa/web" "$AUD")")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("not configured here")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 6. An RS256 SVID — refused on the algorithm, before any signature work =="
# JWT-SVID permits nine algorithms; this deployment verifies ES256 only, because RS*/PS*
# would pull in a crate carrying an unpatched key-recovery advisory. A SPIRE deployment
# issuing RSA is genuinely not interoperable here, and says so rather than failing vaguely.
CODE=$(send "$(uv run "$MINT" svid "$SVID_ID" "$AUD" --alg RS256)")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("ES256")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 7. An expired SVID — refused =="
CODE=$(send "$(uv run "$MINT" svid "$SVID_ID" "$AUD" --expired)")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("expired")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 8. An SVID minted for another service — refused =="
CODE=$(send "$(uv run "$MINT" svid "$SVID_ID" "https://billing.example/")")
[ "$CODE" = 401 ]
jq -e '.error_description | contains("audience")' "$WORK/body" >/dev/null
echo "   401 $(jq -r .error_description "$WORK/body")"

echo
echo "== 9. No credential — 401, and the challenge names the scheme to retry with =="
# JWT-SVID §5.2 makes this a Bearer credential, so the refusal owes an RFC 6750 challenge.
# The signed-request posture deliberately sends none, because RFC 9421 has no scheme to
# name. Same reasoning, opposite answer.
OUT=$(curl -s -D- -o /dev/null "$PDP/access/v1/evaluation" \
  -H 'Content-Type: application/json' -d "$BODY")
grep -q "HTTP/1.1 401" <<<"$OUT"
grep -qi '^www-authenticate: Bearer' <<<"$OUT"
echo "   401 with $(grep -i '^www-authenticate:' <<<"$OUT" | tr -d '\r')"

echo
echo "== 10. The deployment discloses its posture and its trust domains =="
# Domain names, never key material: every SVID carries the domain already.
curl -s "$PDP/.well-known/decern-subject-side-disclosure" | jq -e '.caller.mode == "spiffe"' >/dev/null
curl -s "$PDP/.well-known/decern-subject-side-disclosure" | jq -c .caller

echo
echo "== 11. The ledger names the workload decern itself verified =="
kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true
cargo run -q -p decern-cli -- verify --ledger "$LEDGER" --pubkey "$KID"
# Only beat 2 reached the kernel; the five refusals never became decisions.
cargo run -q -p decern-cli -- explain --ledger "$LEDGER" --seq 0 --pubkey "$KID" \
  | grep -E "decision:|asserted_by:"
# No `iss` claim is required by the spec, so the recorded issuer is derived from the trust
# domain in the verified `sub` — never read from the token.
cargo run -q -p decern-cli -- explain --ledger "$LEDGER" --seq 0 --json \
  | jq -e --arg id "$SVID_ID" --arg td "spiffe://$TD" \
      '.asserted_by.sub == $id and .asserted_by.iss == $td' >/dev/null
echo "   the record names the workload, and the trust domain that vouched for it."

echo
echo "All beats held. What this shows: decern verified the SVID itself against a pinned"
echo "bundle, and the record names the workload it verified. What it cannot show: that this"
echo "workload deserves the identity its SPIFFE issuer gave it — that judgement belongs to"
echo "whoever attested it. Note also that the identity is recorded, never admitted: what a"
echo "decision may be ABOUT is unchanged, and stays closed-world."
