<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest minor | Yes |

Only the latest minor release receives security fixes — version-free on purpose, so this page cannot go stale when a release ships.

## Reporting a Vulnerability

Report vulnerabilities **privately** using GitHub's private vulnerability
reporting: open the repository's **Security** tab and click **Report a
vulnerability** to open a draft advisory. Please do not open public issues for
security reports.

## What to Expect

- **Acknowledgement** of your report.
- **Coordinated disclosure**: we investigate, prepare a fix, and agree on a
  public disclosure timeline with you before any details are published.

The trust boundary matters for triage: `decern-serve` refuses to start unless its
caller posture is named — RFC 9068 bearer validation, or a declared authenticating
front (`--trust-proxy`) — and a few routes are open by intent (the anchor, the
disclosure, the subject-side audit projection). The full map is in
[docs/CLI.md](docs/CLI.md#the-trust-boundary-stated-plainly); a report that assumes
an endpoint is unauthenticated should say which posture it was tested under.

decern's safety invariants are machine-checked over the entire input space, but
the project is pre-1.0 — reports of gaps in what the proofs actually cover are
especially welcome.
