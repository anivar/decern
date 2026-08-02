#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The canonical decern verify loop — the single source of truth.
# CI, CONTRIBUTING.md, AGENTS.md, and the `verify` skill all invoke this.
# Runs every gate (doesn't stop at the first failure) and exits non-zero if any failed.
# The proof gate needs cvc5 on PATH (or $CVC5).
set -uo pipefail
cd "$(dirname "$0")/.."

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
step "prove (cvc5)"   cargo test --workspace -- --ignored
step "clippy"         cargo clippy --workspace --all-targets -- -D warnings
step "fmt"            cargo fmt --all -- --check
step "supply-chain"   cargo deny check
step "no-lineage"     no_lineage

echo
if [ "${fail}" -eq 0 ]; then echo "verify: all gates passed"; else echo "verify: FAILED"; fi
exit "${fail}"
