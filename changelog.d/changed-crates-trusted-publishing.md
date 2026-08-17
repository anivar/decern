- **crates.io publishes with no stored token.** The nine crates authenticate by OIDC, the same
  way the PyPI and npm packages already did: crates.io mints a credential for the run and the
  job revokes it at the end, so there is no long-lived secret to leak or to quietly fall out of
  scope. That last part is not hypothetical — the 0.2.0 release stopped mid-publish on a token
  scoped `publish-new`, which does not cover new versions of crates that already exist. Trust is
  pinned per crate to this repository, the workflow filename and the `crates-io` environment.
  Authored by @anivar.
