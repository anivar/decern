#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Assemble the fragments in changelog.d/ into a CHANGELOG.md section.
#
# A fragment is named <section>-<slug>.md and holds its entry verbatim; the prefix picks the
# section, so there is no frontmatter to parse and a malformed fragment is a visible filename
# rather than a silent mis-parse. See changelog.d/README.md.
set -uo pipefail
cd "$(dirname "$0")/.."

DIR="changelog.d"
FILE="CHANGELOG.md"
# Keep a Changelog's order, which is also roughly the order a reader cares about.
SECTIONS=(added changed deprecated removed fixed security)

usage() {
  echo "usage: scripts/changelog.sh --check"
  echo "       scripts/changelog.sh --preview"
  echo "       scripts/changelog.sh --release <version> [--date YYYY-MM-DD]"
  echo
  echo "  --check     every fragment is named for a real section and is not empty"
  echo "  --preview   print the section that would be written, changing nothing"
  echo "  --release   fold the fragments into ${FILE} and delete them"
}

fragments() {
  # Sorted, README excluded. Nothing else in the directory is a fragment.
  find "${DIR}" -maxdepth 1 -name '*.md' ! -name 'README.md' | LC_ALL=C sort
}

section_of() {
  basename "$1" | sed -n 's/^\([a-z]*\)-.*/\1/p'
}

check() {
  local bad=0 f section
  for f in $(fragments); do
    section="$(section_of "${f}")"
    if [[ ! " ${SECTIONS[*]} " == *" ${section} "* ]]; then
      echo "  ${f}: prefix '${section:-<none>}' is not a section (${SECTIONS[*]})" >&2
      bad=1
      continue
    fi
    if [ ! -s "${f}" ]; then
      echo "  ${f}: empty" >&2
      bad=1
    fi
  done
  return "${bad}"
}

# The assembled section, on stdout. Fragments are copied verbatim.
render() {
  local version="$1" date="$2" section f found
  echo "## [${version}] - ${date}"
  for section in "${SECTIONS[@]}"; do
    found=0
    for f in $(fragments); do
      [ "$(section_of "${f}")" = "${section}" ] || continue
      if [ "${found}" -eq 0 ]; then
        echo
        # Capitalise the section name for the heading.
        echo "### $(echo "${section}" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')"
        echo
        found=1
      fi
      cat "${f}"
      # A fragment need not end in a newline; the next entry still starts on its own line.
      [ -n "$(tail -c 1 "${f}")" ] && echo
    done
  done
}

[ $# -ge 1 ] || { usage; exit 2; }

case "$1" in
  -h|--help) usage; exit 0 ;;

  --check)
    if [ -z "$(fragments)" ]; then echo "changelog: no fragments"; exit 0; fi
    if check; then
      echo "changelog: $(fragments | wc -l | tr -d ' ') fragment(s), all well-formed"
    else
      echo "changelog: FAILED — see above, and changelog.d/README.md" >&2
      exit 1
    fi
    ;;

  --preview)
    [ -n "$(fragments)" ] || { echo "changelog: no fragments"; exit 0; }
    check || exit 1
    render "UNRELEASED" "$(date +%F)"
    ;;

  --release)
    version="${2:-}"
    [ -n "${version}" ] || { echo "changelog: --release needs a version" >&2; usage; exit 2; }
    date="$(date +%F)"
    if [ "${3:-}" = "--date" ]; then
      date="${4:-}"
      [ -n "${date}" ] || { echo "changelog: --date needs a value" >&2; exit 2; }
    fi
    [ -n "$(fragments)" ] || { echo "changelog: no fragments to release" >&2; exit 1; }
    check || exit 1
    if grep -q "^## \[${version}\]" "${FILE}"; then
      echo "changelog: ${FILE} already has a ${version} section" >&2
      exit 1
    fi

    section="$(mktemp)"; assembled="$(mktemp)"
    trap 'rm -f "${section}" "${assembled}"' EXIT
    render "${version}" "${date}" > "${section}"

    # Insert above the newest existing section, so the file stays newest-first. Done with
    # head/tail rather than awk: an assembled section is many lines, and passing it through
    # `awk -v` silently produces nothing on a BSD awk.
    at="$(grep -n '^## \[' "${FILE}" | head -1 | cut -d: -f1)"
    if [ -n "${at}" ]; then
      head -n "$((at - 1))" "${FILE}" > "${assembled}"
      cat "${section}" >> "${assembled}"
      echo >> "${assembled}"
      tail -n "+${at}" "${FILE}" >> "${assembled}"
    else
      cat "${FILE}" > "${assembled}"
      echo >> "${assembled}"
      cat "${section}" >> "${assembled}"
    fi

    # Nothing is destroyed until the new section is known to be in the output. Reporting a
    # release that did not happen, and taking the fragments with it, is the one failure here
    # that cannot be undone from the working tree.
    if ! grep -q "^## \[${version}\]" "${assembled}"; then
      echo "changelog: assembly produced no ${version} section; ${FILE} and the fragments are untouched" >&2
      exit 1
    fi

    mv "${assembled}" "${FILE}"
    fragments | xargs rm --
    echo "changelog: wrote ${version} to ${FILE} and removed the fragments"
    echo "           review the section before committing."
    ;;

  *) echo "changelog: unknown argument $1" >&2; usage; exit 2 ;;
esac
