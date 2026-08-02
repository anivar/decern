<!-- SPDX-License-Identifier: Apache-2.0 -->
# Governance

decern is maintained by the people in [MAINTAINERS](MAINTAINERS). Today that is a single maintainer;
the project is young.

## How decisions are made
- Changes land as pull requests that pass CI (`./scripts/verify.sh`) and are signed off (DCO).
- A maintainer reviews and merges. Anything touching authorization semantics must keep the proofs
  green and must never claim more than the solver checks — that principle is not up for a vote.
- Larger or design-changing work starts as an issue for discussion first.

## Becoming a maintainer
Sustained, high-quality contributions and review earn a maintainer invitation from an existing
maintainer.

## Future
decern is intended for eventual donation to a neutral open-source foundation; governance will adopt
that foundation's model then. Until that happens, this document is the whole of it.
