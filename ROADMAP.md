<!-- SPDX-License-Identifier: Apache-2.0 -->
# Roadmap

The public direction, in order. Aspirations, not commitments: priorities move as the work and
its readers teach us more. What a release does lives in the [README](README.md) and the
[CHANGELOG](CHANGELOG.md); what is planned lives in the
[milestones](https://github.com/anivar/decern/milestones), one issue per step.

## Where the project is

0.7.0 is the last feature release of the current design: an AuthZEN decision point over a Cedar
kernel with an SMT-checked forbid envelope, Missions, and a fail-closed ledger. After it the 0.x
line takes security fixes only.

The next line is built in this repository beside it, as new crates that start at 0.1.0. The
0.x crates stay published, and the 0.7 binaries stay the reader for ledgers the 0.x line wrote.

## Direction

decern turns an authorization decision into a receipt. The decision is recorded before it is
answered, the receipt comes back with the answer, and anyone who holds it can check it offline
against the log's public key. A resource can refuse to act without one.

- **A recorder for any AuthZEN decision point.** A small proxy sits between an enforcement
  point and the decision point it already uses. It speaks AuthZEN on both sides, records each
  decision and returns it with the receipt. It enforces nothing.
- **Cedar stays built in**, as the engine whose decisions can be replayed against the policy
  they name and whose invariants a solver can prove.
- **Standard evidence.** The log is an RFC 9162 Merkle tree with signed checkpoints, stored so
  that a proof reads a few small files. The tree commits to a salted digest of each record, so
  a record can be erased, by an entry that says so, without breaking the log.
- **The log is the only state.** A grant, a revocation and a key change are entries.
- **Facts that change a decision are signed.** An approval or a consent enters as a claim
  signed by an issuer the operator configured, and the policy itself says who may approve.

## Milestones

In order, with no dates. Each phase has a gate, and the steps of a later phase can change when
an earlier gate teaches something.

| Phase | Gate | Issues |
|---|---|---|
| 0. Spikes | each risky assumption is proven or broken before the format is written | [milestone 1](https://github.com/anivar/decern/milestone/1) |
| 1. 0.7.0 | released from a tag whose release-candidate run passed | [milestone 2](https://github.com/anivar/decern/milestone/2) |
| 2. First slice | on a clean machine, the proxy in front of an AuthZEN decision point returns a receipt that verifies offline, in under five minutes | [milestone 3](https://github.com/anivar/decern/milestone/3) |
| 3. Cedar on the new log | the built-in model decides through the new crates and a receipt verifies in a browser | [milestone 4](https://github.com/anivar/decern/milestone/4) |
| 4. Facts and grants | the new line holds no state outside the log, and the approval rule is proven | [milestone 5](https://github.com/anivar/decern/milestone/5) |
| 5. Proofs, replay, first use | a recorded decision replays against its policy, and one outside party has run the quickstart | [milestone 6](https://github.com/anivar/decern/milestone/6) |
| 6. Remove the old line | main holds the new crates only | [milestone 7](https://github.com/anivar/decern/milestone/7) |

If no outside issue, pull request or adopter has appeared by the gate of phase 5, the work stops
at the format, its test vectors and the drafts, and phase 6 does not run.

## What moved

The earlier roadmap dated its milestones from October 2026 to April 2027. They are withdrawn:

- **Dropped under the current design:** the MCP binding for `examples/mcp`, the agentgateway
  documentation, the decision about recording a committed effect, a real-time revocation feed,
  `decern anchor`, anchoring for sharded deployments, a release-verification script,
  reproducible builds, Mission APIs in the client SDKs, a worked example per proof, and the
  authority-graph export. Where one had an issue, it is closed as not planned.
- **Moved into the phases above:** the seam for a policy engine other than Cedar (phase 2, the
  engine and the proxy), revocation without a restart (phase 4, revocations as entries), and
  anchoring (phase 3, a held checkpoint and opt-in public anchoring).
- **Done:** crates.io trusted publishing.
- **Not dated any more:** a named adopter, a second maintainer, a neutral project home and a
  foundation proposal. [ADOPTERS.md](ADOPTERS.md) stays the place where adoption is recorded,
  and adoption is evidence, never inferred from stars or integrations.

## Non-goals

- **Enforcement.** decern decides and records. The proxy returns an answer and a receipt to an
  enforcement point; it is not a gateway, a firewall for tool calls or a model gateway.
- **Credentials.** No OAuth server, identity provider or credential vault inside decern, and no
  credential issuance by its binaries. Issuers of approvals and consents are external.
- **Approval UX.** decern verifies an approval it is given; it does not render one.
- **Dropping the proofs.** The SMT proofs and their negative controls stay.
- **A runtime's description of itself.** Claims such as `agent_platform`, `agent_runtime` or
  enclave status are the attester's self-description, not verified facts about a runtime, and
  do not enter the decision context
  ([the reasoning](https://github.com/anivar/decern/issues/140)). A claim signed by an issuer
  the operator configured is a different thing and is what phase 4 admits.
- **More than one writer per log.** The new line has one writer per log and no multi-host
  mode. The 0.x line keeps its multi-host store.

Want to pick something up? See [ARCHITECTURE.md](ARCHITECTURE.md#where-to-start-contributing)
and the [open issues](https://github.com/anivar/decern/issues).
