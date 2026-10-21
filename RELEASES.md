<!-- SPDX-License-Identifier: Apache-2.0 -->
# Releases

One tag releases everything. `git push origin vX.Y.Z` builds the binaries, publishes the SDKs,
archives the source for citation, and writes the release notes from `CHANGELOG.md`.

## Cutting a release

1. **Assemble the changelog.** Entries are written per pull request in
   [`changelog.d/`](changelog.d/README.md); fold them into a dated section and delete them:

   ```sh
   ./scripts/changelog.sh --release X.Y.Z
   ```

   Read the result. Assembly is mechanical, and ordering inside a section is only alphabetical
   by filename.

2. **Set the version** in `Cargo.toml` (workspace and the inter-crate pins),
   `sdks/python/pyproject.toml` and `sdks/python/decern/__init__.py`, `sdks/typescript/package.json`
   and both `version` fields of its `package-lock.json`, `examples/ext_authz_adapter/Cargo.toml`
   (outside the workspace, so the workspace version does not reach it), and the README's "Known
   limits in X" link text. The website carries no version string. `publish-crates.yml`
   stops before crates.io when `Cargo.toml`, an
   inter-crate pin or the `CHANGELOG.md` section disagrees with the tag; `publish-sdks.yml`
   stops before PyPI and npm when `pyproject.toml` or `package.json` does. Neither checks the
   other's files, so one mismatch can still leave the other registries published. Nothing checks
   the lockfile, the example, the Python module's `__version__` or the README link; they are on
   whoever cuts the release.

3. **Verify**, with no flags, so the proofs run:

   ```sh
   ./scripts/verify.sh
   ```

4. **Merge, then tag the merged commit.**

   ```sh
   git tag -a vX.Y.Z -m "decern X.Y.Z" && git push origin vX.Y.Z
   ```

## What the tag sets off

| Workflow | Produces |
|---|---|
| `release.yml` | Binaries for four targets, each with a Sigstore bundle (`<file>.sigstore.json`: signature, certificate and transparency-log entry); a combined `SHA256SUMS`, signed the same way; a CycloneDX SBOM per crate; a GitHub release whose body is the `CHANGELOG.md` section for the tag |
| `publish-sdks.yml` | `decern` on PyPI and on npm |
| `publish-crates.yml` | The nine workspace crates on crates.io, in dependency order |
| Zenodo | An archived copy and a DOI, from the GitHub integration |

A tag whose version has no `CHANGELOG.md` section fails the release build rather than publishing
empty notes.

## Credentials

There are none. PyPI, npm and crates.io all authenticate by OIDC — GitHub proves the identity of
the workflow, and each registry mints a short-lived credential for that run. Nothing is stored, so
nothing can leak or quietly expire.

Every registry pins that trust to **a workflow filename**: `publish-sdks.yml` for PyPI and npm,
`publish-crates.yml` for crates.io. Renaming either file revokes its ability to publish until the
publisher entries are updated to match — nine times over for crates.io, which configures trust per
crate rather than per project.

The workflows run in the `pypi`, `npm` and `crates-io` GitHub environments, so publishing can be
gated on an approval independently of who can merge.

crates.io publishes in dependency order, since each crate must be on the registry before anything
that depends on it:

```
decern-crypto  decern-kernel  decern-store           # no internal dependencies
decern-ledger  decern-proof   decern-store-postgres  decern-identity
decern-cli     decern-server
```

The index is served through a CDN, so a crate published seconds ago may not resolve yet for the
one that depends on it. The workflow waits for each tier to actually appear rather than sleeping a
guessed interval, packages every crate before uploading any of them, and treats "already published
at this version" as success — nine crates cannot be un-published, and a partial failure has to stay
retryable.

`workflow_dispatch` takes a version and an optional `dry_run`, which resolves and packages
everything without publishing. Use it to rehearse.

### Adding a crate

A new crate needs its own trusted-publishing entry before its first release, and crates.io only
lets you add one to a crate that already exists. So a brand-new crate name is published once with
a scoped token, after which the entry replaces it. Existing crates never need a token again.

## Verifying a release

Every binary and `SHA256SUMS` is signed by the release workflow's identity, so checking one
requires no trust in the person who tagged it; the SBOMs are not signed. The command, and the
form for releases before 0.4.0, is in [SECURITY.md](SECURITY.md#verifying-a-release).

**Builds are not byte-reproducible.** A local `cargo build --release` of a tag does not produce the
same hash as the released binary — absolute paths and build metadata differ between machines. The
signature, not a matching checksum, is what ties an artifact to the workflow that built it.

## Citing a release

Each release is archived with a DOI. Cite the concept DOI —
[10.5281/zenodo.21848620](https://doi.org/10.5281/zenodo.21848620) — which resolves to the newest
version; use a version DOI when reproducibility needs the exact release.
[`CITATION.cff`](CITATION.cff) and `.zenodo.json` carry the metadata, and both must be on `main`
*before* the tag, since Zenodo reads them from the archived commit.
