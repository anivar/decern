<!-- SPDX-License-Identifier: Apache-2.0 -->
# Releases

A release is one commit on `main`, tagged twice: a release candidate that rehearses the build, and
the final tag that publishes. A publish to crates.io, PyPI or npm cannot be undone, so every step
before the final tag exists to find a fault while nothing is public.

## What a release is made of

| Artifact | Where | Made by | Signed |
|---|---|---|---|
| `decern-<target>` and `decern-serve-<target>` for four targets (Linux x64 and arm64 musl, macOS arm64, Windows x64) | GitHub release | `release.yml` | each has a Sigstore bundle, `<file>.sigstore.json` |
| `SHA256SUMS` over the eight binaries | GitHub release | `release.yml` | Sigstore bundle |
| One CycloneDX SBOM per crate, `<crate>.cdx.json` | GitHub release | `release.yml` | no, and not in `SHA256SUMS` |
| Release notes | GitHub release body | `release.yml`, from `CHANGELOG.md` | no |
| The nine workspace crates | crates.io | `publish-crates.yml` | no; published by OIDC |
| `decern` sdist and wheel | PyPI | `publish-sdks.yml` | published by OIDC |
| `decern` package | npm | `publish-sdks.yml` | provenance attested by npm on a trusted-publishing run |
| The Go client | the tag `sdks/go/vX.Y.Z` | by hand, after the release | no |
| An archived copy and a DOI | Zenodo | its GitHub integration, on a published release | no |

The binaries are bare files, not archives. Builds are not byte-reproducible: absolute paths and
build metadata differ between machines, so the signature, not a matching checksum, is what ties a
binary to the workflow that built it.

## The release notes

The notes are the `## [X.Y.Z]` section of `CHANGELOG.md`, copied whole into the GitHub release.
A section has, in this order:

1. **An opening**, two to four plain sentences: what the release is.
2. **Upgrading from the previous release**: each change that can stop an existing deployment or
   script, most disruptive first, with what the reader sees and what to do. One-way steps, a
   store an older binary can no longer open for one, come first and say so.
3. **Added, Changed, Deprecated, Removed, Fixed, Security**: the entries from
   [`changelog.d/`](changelog.d/README.md), assembled by the script.
4. **`### Known limits in this release`**: what the release does not claim, carried forward from
   the previous release with what was closed since. The README links to this heading.

The script writes the heading and part 3. Parts 1, 2 and 4 are written by hand after the fold.
Everything between the section's heading and the next `## [` heading becomes the release body.

## Cutting a release

1. **Order the entries.** Read `./scripts/changelog.sh --preview`. Entries in a section come in
   file-name order; rank the ones a reader must act on first, as
   [`changelog.d/README.md`](changelog.d/README.md) describes. Check every entry against the code
   as it is now: a later change can make an earlier entry false.

2. **Fold.**

   ```sh
   ./scripts/changelog.sh --release X.Y.Z --date YYYY-MM-DD
   ```

   Give the date the final tag will carry. Then write the opening, the upgrade section and the
   known limits by hand.

3. **Set the version** in:
   - `Cargo.toml`: the workspace version and the seven inter-crate pins;
   - `Cargo.lock`: let `cargo metadata` rewrite the nine workspace entries, and check nothing
     else moved;
   - `examples/ext_authz_adapter/Cargo.toml` and its `Cargo.lock`, which are outside the workspace;
   - `sdks/python/pyproject.toml` and `sdks/python/decern/__init__.py`;
   - `sdks/typescript/package.json` and both `version` fields of its `package-lock.json`;
   - the README's "Known limits in X" link text.

   The website, `CITATION.cff`, `.zenodo.json` and `SECURITY.md` carry no version. The citation
   files must be on `main` before the tag, since the archive reads them from the tagged commit.

4. **Verify**, with no flags, so the proofs run:

   ```sh
   ./scripts/verify.sh
   cargo package --workspace --locked
   ```

   The gate fails on a lock file that does not match the manifests. `cargo package --workspace`
   verifies each crate against its siblings' packaged sources, which no workflow can do before
   the first crate is on the index.

5. **Merge**, and take the merge commit: `SHA=$(git rev-parse origin/main)`.

6. **Tag a release candidate on that commit and push that one tag.**

   ```sh
   git tag -s vX.Y.Z-rc.1 -m "decern X.Y.Z release candidate 1" "$SHA"
   git push origin vX.Y.Z-rc.1
   ```

   The name must contain `-rc.`: that is what the publish workflows skip on.

7. **Check the candidate.** `release.yml` must pass on all four targets. Download the draft
   release's files, then:

   ```sh
   cosign verify-blob --bundle SHA256SUMS.sigstore.json \
     --certificate-identity "https://github.com/anivar/decern/.github/workflows/release.yml@refs/tags/vX.Y.Z-rc.1" \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
   sha256sum -c SHA256SUMS
   ```

   Run the candidate binaries on a clean machine: the quickstart, the walkthroughs, and an
   upgrade from the previous release's ledger and stores. Then delete the draft release and the
   candidate tag.

8. **Tag the final release on the same commit.** If `main` has moved, the candidate is void: cut
   a new one on the new commit.

   ```sh
   git tag -s vX.Y.Z -m "decern X.Y.Z" "$SHA"
   git push origin vX.Y.Z
   ```

9. **Approve the publish jobs after the release job has passed.** The `pypi`, `npm` and
   `crates-io` environments each wait for a reviewer. Approve them once `release.yml` shows the
   GitHub release was made, so a failed build leaves no registry ahead of the binaries.

10. **Tag the Go client**, which a `v*` tag does not version:

    ```sh
    git tag -s sdks/go/vX.Y.Z -m "decern Go client X.Y.Z" "$SHA"
    git push origin sdks/go/vX.Y.Z
    ```

11. **Verify from a clean machine**: the signatures with the final tag's identity, each crate at
    the new version on crates.io, the PyPI and npm packages, the quickstart from the registries.

## What a tag sets off

Three workflows start on any `v*` tag. They do not wait for one another.

| Workflow | On a candidate tag (`-rc.`) | On the final tag |
|---|---|---|
| `release.yml` | checks the tag against `Cargo.toml` and the CHANGELOG section, builds four targets with the lock file, runs `scripts/smoke.sh` on each natively, checks each binary reports the version, signs, and makes a **draft** pre-release | the same, and publishes the release |
| `publish-crates.yml` | skipped | checks the manifests and the CHANGELOG section against the tag, then publishes nine crates in dependency order, once its environment is approved |
| `publish-sdks.yml` | skipped | checks `pyproject.toml` and `package.json` against the tag, then publishes to PyPI and npm, once each environment is approved |

A draft release is not public and is not archived. A published candidate once left a permanent
archive record behind, which is why a candidate is a draft.

Nothing checks the example's manifest and lock, the Python module's `__version__`, the
TypeScript lock file, the README link text, the presence of the known-limits heading, the
CHANGELOG date, or that the tagged commit is on `main`. They are on whoever cuts the release.

## Credentials

There are none. PyPI, npm and crates.io all authenticate by OIDC: GitHub proves the identity of
the workflow, and each registry mints a short-lived credential for that run. Nothing is stored, so
nothing can leak or quietly expire.

Every registry pins that trust to a workflow filename: `publish-sdks.yml` for PyPI and npm,
`publish-crates.yml` for crates.io. Renaming either file revokes its ability to publish until the
publisher entries are updated to match, nine times over for crates.io, which configures trust per
crate.

crates.io publishes in dependency order, since each crate must be on the registry before anything
that depends on it:

```
decern-crypto  decern-kernel  decern-store           # no internal dependencies
decern-ledger  decern-proof   decern-store-postgres  decern-identity
decern-cli     decern-server
```

The index is served through a CDN, so a crate published seconds ago may not resolve yet for the
one that depends on it. The workflow waits for each tier to appear rather than sleeping a guessed
interval, and treats "already published at this version" as success, so a run that stopped
partway can be run again. Before the first upload it packages the crates that resolve against
the index, which are the three with no internal dependency; the other six are packaged when
their turn comes. Step 4's local `cargo package --workspace` is the check of all nine.

`publish-crates.yml` can also be started by hand with a version. It is a dry run unless
`dry_run` is unticked, and a dry run packages those same three crates. `publish-sdks.yml` has no
dry run: started by hand it publishes.

### Adding a crate

A new crate needs its own trusted-publishing entry before its first release, and crates.io only
lets you add one to a crate that already exists. So a brand-new crate name is published once with
a scoped token, after which the entry replaces it. Existing crates never need a token again.

## When a step fails

| What failed | State | What to do |
|---|---|---|
| The candidate, in build, smoke or signing | nothing public | fix on `main`, cut the next candidate on the new commit |
| `release.yml` on the final tag | nothing published, if the publish jobs were not yet approved | do not approve them; fix, and release the next patch version |
| crates.io stopped partway | some crates at the new version | run the failed job again: published crates are skipped. A crate that cannot be published as tagged needs a new patch version for all nine, and a yank |
| PyPI passed, npm failed | PyPI at the new version | check `npm view decern@X.Y.Z version` first; if absent, run the failed job again |

A tag is never moved. A version that reached a registry is never reused.

## Verifying a release

Every binary and `SHA256SUMS` is signed by the release workflow's identity, so checking one
requires no trust in the person who tagged it. The command, and the form for releases before
0.4.0, is in [SECURITY.md](SECURITY.md#verifying-a-release).

## Citing a release

Each published release is archived with a DOI. Cite the concept DOI —
[10.5281/zenodo.21848620](https://doi.org/10.5281/zenodo.21848620) — which resolves to the newest
version; use a version DOI when reproducibility needs the exact release.
[`CITATION.cff`](CITATION.cff) and `.zenodo.json` carry the metadata.
