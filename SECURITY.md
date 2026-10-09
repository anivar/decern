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

The trust boundary matters for triage: `decern-serve` refuses to start unless its caller
posture is named: RFC 9068 bearer validation, RFC 9421 sender-constrained signed requests
(`--signed-agent-key`), SPIFFE JWT-SVIDs (`--spiffe-trust-domain`), AAuth agent tokens
(`--aauth-provider`), or a declared authenticating front (`--trust-proxy`). The workload
postures — the signed-request, SPIFFE and AAuth ones — also bind a caller to the principals
it may name, so a report about one naming another party should say whether `--pep` was set.
A few routes are open by intent (the anchor, the disclosure, the subject-side audit
projection). The full map is in
[docs/CLI.md](docs/CLI.md#the-trust-boundary-stated-plainly); a report that assumes an
endpoint is unauthenticated should say which posture it was tested under.

decern's safety invariants are machine-checked over the entire input space, but
the project is pre-1.0 — reports of gaps in what the proofs actually cover are
especially welcome.

## Verifying a release

Every release asset is signed keyless with [cosign](https://github.com/sigstore/cosign) by
the release workflow, so the signer is this repository's GitHub Actions identity, not a key
anyone holds. From 0.4.0 each file ships with a Sigstore bundle, `<file>.sigstore.json`,
carrying the signature, the signing certificate and the transparency-log entry:

```sh
cosign verify-blob \
  --bundle decern-aarch64-apple-darwin.sigstore.json \
  --certificate-identity-regexp '^https://github.com/anivar/decern/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  decern-aarch64-apple-darwin
```

`SHA256SUMS` is signed the same way and covers every binary, so verifying it and then
`sha256sum -c SHA256SUMS` checks the rest. Releases before 0.4.0 shipped a `<file>.sig` and
`<file>.pem` pair instead; verify those with `--signature` and `--certificate` in place of
`--bundle`, with the same identity and issuer. A CycloneDX SBOM per crate is attached
unsigned. A script that runs all of this from a version number alone is
[#62](https://github.com/anivar/decern/issues/62).
