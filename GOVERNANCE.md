<!-- SPDX-License-Identifier: Apache-2.0 -->
# Governance

decern is maintained by the people in [MAINTAINERS](MAINTAINERS). The project is young and currently
has one maintainer. This document describes the governance that exists today; it does not present
contributors or advisers as maintainers.

## Roles

- **Contributors** submit issues, pull requests, reviews, documentation, or other project work.
- **Maintainers** review and merge changes, cut releases, handle security reports, and steward the
  project's technical direction and community.

Affiliation does not determine eligibility for either role.

## How decisions are made

- Changes land as pull requests that pass CI (`./scripts/verify.sh`) and are signed off (DCO).
- Small, reversible changes use maintainer review. Larger or design-changing work starts as an issue
  or draft pull request and remains open for comment for at least 72 hours unless it fixes an
  actively exploited vulnerability.
- Maintainers seek lazy consensus: a proposal proceeds when there is no unresolved, technically
  substantiated objection. When consensus cannot be reached, maintainers record the competing views
  and decision in the issue or pull request.
- Anything touching authorization semantics must keep the proofs green and must never claim more
  than the solver checks. A proposed governance decision cannot waive this technical acceptance
  criterion.
- A maintainer must not approve their own substantive pull request when another active maintainer is
  available. While the project has only one maintainer, CI plus public review is the compensating
  control and that limitation remains explicit.

## Becoming a maintainer

A contributor may be nominated after a sustained record of technically sound contributions, review,
responsiveness, and conduct consistent with the [Code of Conduct](CODE_OF_CONDUCT.md). A nomination
is discussed publicly for at least seven days. Existing maintainers decide by lazy consensus and
record the outcome. There is no minimum contribution count and no requirement to work for a
particular organization.

Maintainers who are inactive for six months may move to emeritus status after public notice and a
14-day comment period. Emeritus maintainers retain attribution but not merge or release authority.

## Conflicts of interest

Maintainers disclose material employer, customer, or financial interests relevant to a decision and
recuse when that interest could reasonably compromise independent judgment. A recusal is recorded
with the decision.

## Amendments

Governance changes use the same public design-change process, with at least 14 days for comment.

## Neutral stewardship

decern is intended for eventual donation to a neutral open-source foundation. Any transfer of the
project name, repositories, domains, or other assets requires a public proposal, completion of the
recipient foundation's process, and an update to this document. Until that happens, this document is
the whole of the project's governance.
