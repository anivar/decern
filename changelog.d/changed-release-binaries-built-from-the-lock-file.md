- **Release binaries are built from the committed `Cargo.lock`.** The release workflow now passes
  `--locked`, so a release build fails when the lock file does not match the manifests, where it
  used to re-resolve the dependencies without saying so. A build from source is unchanged. Authored
  by @anivar.
