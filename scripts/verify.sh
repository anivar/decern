#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The canonical decern verify loop — the single source of truth.
# CI, CONTRIBUTING.md, AGENTS.md, and the `verify` skill all invoke this.
# Runs every gate (doesn't stop at the first failure) and exits non-zero if any failed.
# The proof gate needs cvc5 on PATH (or $CVC5).
#
# --skip-proofs runs every gate EXCEPT the cvc5 proofs, for iterating on a change
# that cannot reach authorization semantics (an SDK, a doc, CLI output) without
# first installing a solver. It is a local convenience only: CI runs the full loop,
# the proofs still gate the merge, and a skipped run exits non-zero so nothing can
# mistake it for a pass.
set -uo pipefail
cd "$(dirname "$0")/.."

skip_proofs=0
for arg in "$@"; do
  case "${arg}" in
    --skip-proofs) skip_proofs=1 ;;
    -h|--help)
      echo "usage: scripts/verify.sh [--skip-proofs]"
      echo
      echo "  (no flags)      every gate, including the cvc5 proofs — what CI runs"
      echo "  --skip-proofs   every gate except the proofs; exits non-zero regardless"
      exit 0
      ;;
    *) echo "verify: unknown argument ${arg}" >&2; exit 2 ;;
  esac
done

fail=0
step() {
  local label="$1"; shift
  echo; echo "==> ${label}"
  if "$@"; then :; else echo "FAILED: ${label}"; fail=1; fi
}

no_lineage() {
  # Bracket classes (e.g. w[z]) keep these patterns from matching themselves.
  if grep -rniE '[w]eavez|w[z]-|w[z]_|[p]roprietary|[c]losed.source|[L]icenseRef' . \
       --exclude-dir=target --exclude-dir=.git; then return 1; fi
  if grep -rnE '#[0-9]+|[P][0-9]-[0-9]' . \
       --include='*.rs' --include='*.toml' --exclude-dir=target --exclude-dir=.git; then return 1; fi
  # Comment-standard denylist (.agent/standards/comments.md), same mechanism as the
  # lineage guard above, over shipped Rust: a comment must not name a sibling crate
  # that does not exist in this workspace, carry a debt marker, or use marketing
  # framing. `-w` keeps the debt-marker scan from tripping on tokens like `\uXXXX`
  # inside a doc comment (and matches a real `TODO`/`HACK` as a whole word).
  if grep -rnE 'decern[-_](authn|oauth|payment|import)' . \
       --include='*.rs' --exclude-dir=target --exclude-dir=.git; then return 1; fi
  if grep -rnwE 'TODO|FIXME|HACK|XXX' . \
       --include='*.rs' --exclude-dir=target --exclude-dir=.git; then return 1; fi
  if grep -rniwE 'moat' . \
       --include='*.rs' --exclude-dir=target --exclude-dir=.git; then return 1; fi
  if grep -rniE 'adoption unlock' . \
       --include='*.rs' --exclude-dir=target --exclude-dir=.git; then return 1; fi
  # Public-launch leak guards over shipped Rust: no derivation narrative naming an
  # external protocol, no internal-review process narration, no phantom HTTP-route
  # strings. `--include='*.rs'` excludes this script, so the patterns don't self-match.
  if grep -rniE 'aauth' . \
       --include='*.rs' --exclude-dir=target --exclude-dir=.git; then return 1; fi
  if grep -rniE 'adversarial[ -]review' . \
       --include='*.rs' --exclude-dir=target --exclude-dir=.git; then return 1; fi
  if grep -rnE '/admin/v1/|/observe/v1/' . \
       --include='*.rs' --exclude-dir=target --exclude-dir=.git; then return 1; fi
  echo "clean"
}

step "build"          cargo build --workspace --tests
step "test"           cargo test --workspace
if [ "${skip_proofs}" -eq 1 ]; then
  echo; echo "==> prove (cvc5)"; echo "SKIPPED by --skip-proofs"
else
  step "prove (cvc5)" cargo test --workspace -- --ignored
fi
step "clippy"         cargo clippy --workspace --all-targets -- -D warnings
step "fmt"            cargo fmt --all -- --check
step "supply-chain"   cargo deny check
step "no-lineage"     no_lineage

echo
if [ "${skip_proofs}" -eq 1 ]; then
  # Never report a pass for a run that did not prove anything. The other gates
  # are reported honestly, and the exit code stays non-zero so no script, hook or
  # habit can read a skipped run as a green one.
  if [ "${fail}" -eq 0 ]; then
    echo "verify: every gate passed EXCEPT the proofs, which were skipped"
  else
    echo "verify: FAILED (proofs also skipped)"
  fi
  echo "        run scripts/verify.sh with no flags before opening a pull request."
  exit 1
fi
if [ "${fail}" -eq 0 ]; then echo "verify: all gates passed"; else echo "verify: FAILED"; fi
exit "${fail}"
