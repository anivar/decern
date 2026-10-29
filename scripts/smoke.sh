#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Anivar Aravind
#
# Run the built binaries end to end, the way a deployment does: a CLI allow and deny, the
# server answering an allow and a deny, the ledger verified against the key the server
# published, the server started again on the same key, one more decision, the ledger verified
# again. The examples' walkthroughs and the CLI's integration tests run the binaries too; this
# is the one run a release build gets before upload, and the one that restarts on the same key
# and verifies twice.
#
#   scripts/smoke.sh <bin-dir> <scratch-dir> [<exe-suffix>]
set -euo pipefail
bin=$1
scratch=$2
ext=${3:-}
decern="$bin/decern$ext"
serve="$bin/decern-serve$ext"
addr=127.0.0.1:18090
url="http://$addr"
ledger="$scratch/smoke-ledger.jsonl"
missions="$scratch/smoke-missions.json"
key="$scratch/smoke.key"
log="$scratch/smoke-serve.log"
rm -f "$ledger" "$missions" "$key" "$log"
pid=

say() { printf 'smoke: %s\n' "$*"; }
# Whatever ends the run, a server still up is stopped, and a failed run shows its log.
cleanup() {
  status=$?
  if [ -n "$pid" ]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ] && [ -f "$log" ]; then cat "$log"; fi
  exit "$status"
}
trap cleanup EXIT
fail() {
  say "$*"
  exit 1
}

decision=$("$decern" decide --subject Principal:corp --action Read --resource Resource:claim1 | sed -n 1p)
[ "$decision" = ALLOW ] || fail "decern decide Read said $decision, expected ALLOW"
decision=$("$decern" decide --subject Principal:corp --action MoveMoney --resource Resource:claim1 | sed -n 1p)
[ "$decision" = DENY ] || fail "decern decide MoveMoney said $decision, expected DENY"

# A missing key file is created on Unix only; elsewhere the run is one start on an ephemeral key.
key_args=(--key "$key")
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) key_args=() ;; esac

start() {
  "$serve" --trust-proxy --addr "$addr" --ledger "$ledger" --missions "$missions" ${key_args[@]+"${key_args[@]}"} >"$log" 2>&1 &
  pid=$!
  for _ in $(seq 50); do
    curl -sf -o /dev/null "$url/healthz" && return
    sleep 0.2
  done
  fail "decern-serve did not answer /healthz"
}
stop() {
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  pid=
}
evaluate() {
  curl -sf "$url/access/v1/evaluation" -H 'content-type: application/json' \
    -d "{\"subject\":{\"type\":\"Principal\",\"id\":\"corp\"},\"action\":{\"name\":\"$1\"},\"resource\":{\"type\":\"Resource\",\"id\":\"claim1\"}}"
}
expect() {
  local body
  body=$(evaluate "$1") || fail "the evaluation of $1 failed"
  grep -q "\"decision\":$2" <<<"$body" || fail "$1 was not answered decision $2: $body"
}
records() { wc -l <"$ledger" | tr -d ' '; }

start
expect Read true
expect MoveMoney false
kid=$(curl -sf "$url/pubkey" | sed -n 's/.*"kid":"\([0-9a-f]*\)".*/\1/p') || fail "no answer from /pubkey"
[ -n "$kid" ] || fail "no kid in /pubkey"
stop
"$decern" verify --ledger "$ledger" --pubkey "$kid" || fail "verify refused the ledger after the first run"
[ "$(records)" -eq 2 ] || fail "expected 2 records after the first run, found $(records)"
if [ ${#key_args[@]} -eq 0 ]; then
  say "ok: allow, deny, verify; one run on an ephemeral key, no key file on this platform"
  exit 0
fi
start
expect Read true
stop
"$decern" verify --ledger "$ledger" --pubkey "$kid" || fail "verify refused the ledger after the restart"
[ "$(records)" -eq 3 ] || fail "expected 3 records after the restart, found $(records)"
say "ok: allow, deny, verify, restart, allow, verify"
