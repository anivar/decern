<!-- SPDX-License-Identifier: Apache-2.0 -->
# Dependencies

decern is meant to be cheap for a third party to audit. That is the reason behind every choice
here, and the reason the list is short.

`cargo deny check` runs in [`scripts/verify.sh`](scripts/verify.sh), so a dependency that breaks
one of these rules fails the build rather than being noticed later.

## What is allowed

**Licences.** Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0,
Unicode-DFS-2016, CC0-1.0, and MPL-2.0. MPL is file-level copyleft and acceptable while the
MPL-licensed files are used unmodified; modifying one obliges publishing that file. Anything else
fails [`deny.toml`](deny.toml).

**Sources.** crates.io only. No git dependencies, no alternative registries.

**Advisories.** A crate with a security advisory fails the build.

## What is pinned exactly

Two dependencies carry the guarantee, so neither may move without a deliberate change:

```toml
cedar-policy      = "=4.11.2"   # the evaluator the kernel decides with
cedar-policy-symcc = "=0.5.3"   # the symbolic compiler the proofs are discharged through
```

`cedar-policy-symcc` is the more load-bearing of the two: it turns the model into the obligations
cvc5 discharges. A patch release of it could change what gets proved, so it is pinned as tightly
as the evaluator.

**cvc5** is not a Cargo dependency. It is an external solver invoked by `decern prove`, developed
against 1.3.1, and `decern prove` fails closed when it is absent rather than reporting a success
it did not establish.

The Rust toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml).

## Compiled native code

The default build is Rust, with one exception that is worth naming rather than glossing:

- **`psm`**, reached through `cedar-policy` → `stacker`, compiles a small assembly routine for
  stack growth via the `cc` crate. It is present in **every** build, including the default one.

Building with `--features postgres` adds a second:

- **`ring`**, reached through the `rustls` TLS stack that `decern-store-postgres` needs.

So a default `decern`/`decern-serve` build carries no TLS stack, and the postgres feature is the
choice that adds one. Neither claim is "zero compiled C" — that would be false, and an audit that
found `psm` after being told otherwise would be right to distrust everything else.

## Adding one

Ask whether the work it does is worth the reading it costs someone auditing this. A dependency
that saves fifty lines and adds a tree is usually not. Where a crate is added, say in the pull
request why the alternative of writing it was rejected — a changelog entry is not the place for
that reasoning, but a reviewer needs it.

An SBOM in CycloneDX format is published per crate with every release.
