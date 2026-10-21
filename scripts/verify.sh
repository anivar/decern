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

# One denylist scan: `deny SKIP GREP-ARGS...`. A match fails it, and so does a grep that
# could not read the tree or parse its pattern, whose exit 2 would otherwise read as no
# match. SKIP, when not empty, is an extended regex for output lines (`path:line:`) to drop
# before deciding.
deny() {
  local skip="$1"; shift
  local out rc
  out=$(grep "$@"); rc=$?
  if [ "${rc}" -gt 1 ]; then echo "grep exited ${rc}: grep $*"; return 1; fi
  if [ -n "${skip}" ]; then out=$(printf '%s\n' "${out}" | grep -vE "${skip}"); fi
  if [ -n "${out}" ]; then printf '%s\n' "${out}"; return 1; fi
}

no_lineage() {
  # Bracket classes (e.g. w[z]) keep these patterns from matching themselves.
  deny '' -rniE '[w]eavez|w[z]-|w[z]_|[p]roprietary|[c]losed.source|[L]icenseRef' . \
       --exclude-dir=target --exclude-dir=.git || return 1
  deny '' -rnE '#[0-9]+|[P][0-9]-[0-9]' . \
       --include='*.rs' --include='*.toml' --exclude-dir=target --exclude-dir=.git || return 1
  # Comment-standard denylist (.agent/standards/comments.md), same mechanism as the
  # lineage guard above, over shipped Rust: a comment must not name a sibling crate
  # that does not exist in this workspace, carry a debt marker, or use marketing
  # framing. `-w` keeps the debt-marker scan from tripping on tokens like `\uXXXX`
  # inside a doc comment (and matches a real `TODO`/`HACK` as a whole word).
  deny '' -rnE 'decern[-_](authn|oauth|payment|import)' . \
       --include='*.rs' --exclude-dir=target --exclude-dir=.git || return 1
  deny '' -rnwE 'TODO|FIXME|HACK|XXX' . \
       --include='*.rs' --exclude-dir=target --exclude-dir=.git || return 1
  deny '' -rniwE 'moat|wedge|commercial|pitch|headline' . \
       --include='*.rs' --exclude-dir=target --exclude-dir=.git || return 1
  deny '' -rniE 'adoption unlock' . \
       --include='*.rs' --exclude-dir=target --exclude-dir=.git || return 1
  # Contributor-facing hygiene guards over shipped Rust: no internal-review
  # process narration, no phantom HTTP-route strings. `--include='*.rs'`
  # excludes this script, so the patterns don't self-match.
  deny '' -rniE 'adversarial[ -]review' . \
       --include='*.rs' --exclude-dir=target --exclude-dir=.git || return 1
  deny '' -rnE '/admin/v1/|/observe/v1/' . \
       --include='*.rs' --exclude-dir=target --exclude-dir=.git || return 1
  # The comment standard's rule 5, for the words a grep can hold to it: an absolute
  # claim no code and no solver delivers, in the files the includes below name, each
  # phrase within one line, spaced or hyphenated with an ASCII hyphen. `proven`,
  # `guaranteed`, `impossible` and `100%` have truthful uses here and stay on the author.
  # The standard lists these words, so that one file is skipped by path.
  deny '^(\./)?\.agent/standards/comments\.md:' -rniE \
       '[t]amper[- ]?proof|[u]nforgeable|[u]nbreakable|[b]ullet[- ]?proof|[m]ilitary[- ]?grade|[p]rovably[- ]secure|[z]ero[- ]data[- ]loss' . \
       --include='*.rs' --include='*.md' --include='*.html' --include='*.toml' --include='*.py' --include='*.sh' \
       --include='*.ts' --include='*.js' --include='*.go' --include='*.json' --include='*.yml' --include='*.yaml' \
       --include='*.cedar' --include='*.cedarschema' --include='*.cff' --include='*.txt' \
       --include='*.svg' --include='*.xml' --include='*.mod' \
       --include='NOTICE' --include='MAINTAINERS' --include='CODEOWNERS' \
       --exclude-dir=target --exclude-dir=.git --exclude-dir=node_modules || return 1
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
# A broken intra-doc link is a claim about the code that stopped being true.
step "docs"           env RUSTDOCFLAGS=-Dwarnings cargo doc --workspace --no-deps
step "supply-chain"   cargo deny check
step "no-lineage"     no_lineage
# Spec registry integrity: every surface path exists, every watched server module is
# listed or explicitly non_surface, every entry carries a machine-readable verified date.
# This is what turns `.agent/standards/registry.yaml` into something an agent graph can ground on.
step "standards"      python3 scripts/standards.py check
step "standards tests" python3 -I scripts/test_standards.py

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
