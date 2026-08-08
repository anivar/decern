<!-- SPDX-License-Identifier: Apache-2.0 -->
# Releases

One tag releases everything. `git push origin vX.Y.Z` builds the binaries, publishes the SDKs,
archives the source for citation, and writes the release notes from `CHANGELOG.md`.

## Cutting a release

1. **Assemble the changelog.** Entries are written per pull request in
   [`changelog.d/`](changelog.d/README.md); fold them into a dated section and delete them:

   ```sh
   ./scripts/changelog.sh --release 0.3.0
   ```

   Read the result. Assembly is mechanical, and ordering inside a section is only alphabetical
   by filename.

2. **Set the version** in `Cargo.toml` (workspace and the inter-crate pins),
   `sdks/python/pyproject.toml` and `sdks/typescript/package.json`. All three must equal the tag,
   or the publish workflow stops before touching a registry.

3. **Verify**, with no flags, so the proofs run:

   ```sh
   ./scripts/verify.sh
   ```

4. **Merge, then tag the merged commit.**

   ```sh
   git tag -a v0.3.0 -m "decern 0.3.0" && git push origin v0.3.0
   ```

## What the tag sets off

| Workflow | Produces |
|---|---|
| `release.yml` | Binaries for four targets, each with a cosign signature and certificate; a combined `SHA256SUMS`; a CycloneDX SBOM per crate; a GitHub release whose body is the `CHANGELOG.md` section for the tag |
| `publish-sdks.yml` | `decern` on PyPI and on npm |
| Zenodo | An archived copy and a DOI, from the GitHub integration |

A tag whose version has no `CHANGELOG.md` section fails the release build rather than publishing
empty notes.

## Credentials

There are none for the SDKs. PyPI and npm authenticate by OIDC — GitHub proves the identity of the
workflow, and each registry mints a short-lived credential for that run. Nothing is stored, so
nothing can leak or quietly expire.

Both registries pin that trust to **`publish-sdks.yml` by filename**. Renaming the file revokes
its ability to publish until the publisher entries are updated to match.

The workflow runs in the `pypi` and `npm` GitHub environments, so publishing can be gated on an
approval independently of who can merge.

**crates.io is still manual.** Publish in dependency order, since each crate must be on the
registry before anything that depends on it:

```
decern-crypto  decern-kernel  decern-store          # no internal dependencies
decern-ledger  decern-proof   decern-store-postgres  decern-identity
decern-cli     decern-server
```

A token for this needs the `publish-update` scope. `publish-new` covers only a crate's first ever
version, which is a common way to be surprised by a `403` mid-release. crates.io supports trusted
publishing too, and moving to it is tracked separately — it needs a configuration entry per crate.

## Verifying a release

Every artifact is signed. Nothing here requires trusting the person who tagged it:

```sh
cosign verify-blob \
  --certificate decern-aarch64-apple-darwin.pem \
  --signature   decern-aarch64-apple-darwin.sig \
  --certificate-identity-regexp 'https://github.com/anivar/decern/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  decern-aarch64-apple-darwin
```

**Builds are not byte-reproducible.** A local `cargo build --release` of a tag does not produce the
same hash as the released binary — absolute paths and build metadata differ between machines. The
signature, not a matching checksum, is what ties an artifact to the workflow that built it.

## Citing a release

Each release is archived with a DOI. Cite the concept DOI —
[10.5281/zenodo.21848620](https://doi.org/10.5281/zenodo.21848620) — which resolves to the newest
version; use a version DOI when reproducibility needs the exact release.
[`CITATION.cff`](CITATION.cff) and `.zenodo.json` carry the metadata, and both must be on `main`
*before* the tag, since Zenodo reads them from the archived commit.
