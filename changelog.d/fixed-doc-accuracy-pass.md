- **The compiled-native-code claim reads the same everywhere.** `AGENTS.md` and
  `decern-store-postgres` said the default binaries carry zero compiled-C-FFI dependencies.
  The claim that holds — and that `README.md` and `DEPENDENCIES.md` already state — is no
  TLS, OpenSSL or cmake in the default build: `cedar-policy` → `stacker` → `psm` compiles an
  assembly routine in every one, the default included. Authored by @anivar.
