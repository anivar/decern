#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# End-to-end: prove every invariant, serve a decision, verify the audit trail, watch tamper fail.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=8791
LEDGER="$(mktemp -u)-decern-ledger.jsonl"

echo "== 1. Prove all invariants over the entire input space (cvc5) =="
cargo run -q -p decern-cli -- prove

echo
echo "== 2. Start the PDP (ephemeral key, temp ledger) =="
cargo run -q -p decern-server -- --ledger "$LEDGER" --addr "127.0.0.1:$PORT" &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true; rm -f "$LEDGER"' EXIT
until curl -sf "localhost:$PORT/healthz" >/dev/null 2>&1; do sleep 0.3; done
KID=$(curl -s "localhost:$PORT/pubkey" | jq -r .kid)
echo "   serving; ledger key = $KID"

echo
echo "== 3. Decide over HTTP (AuthZEN-shaped) — corp reads a claim it owns =="
curl -s "localhost:$PORT/access/v1/evaluation" -H 'content-type: application/json' -d '{
  "subject":  {"type":"Principal","id":"corp"},
  "action":   {"name":"Read"},
  "resource": {"type":"Resource","id":"claim1"},
  "context":  {"now":100}
}'
echo

echo
echo "== 4. Verify the tamper-evident ledger =="
cargo run -q -p decern-cli -- verify --ledger "$LEDGER" --pubkey "$KID"

echo
echo "== 5. Tamper with the ledger, then verify again — it must fail =="
printf '{"forged":true}\n' >> "$LEDGER"
if cargo run -q -p decern-cli -- verify --ledger "$LEDGER" --pubkey "$KID"; then
  echo "   UNEXPECTED: tampered ledger verified" >&2; exit 1
else
  echo "   tampered ledger correctly rejected."
fi
