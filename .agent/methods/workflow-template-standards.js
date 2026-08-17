// SPDX-License-Identifier: Apache-2.0
//
// Graph-shaped review grounded on `.agent/standards/registry.yaml`.
//
// Before running: produce the shared brief once —
//
//   python3 scripts/standards.py for <path>…  > /tmp/standards-for.json
//
// Then pass into the orchestrator:
//
//   args.target      = paths under review (string)
//   args.grounding   = JSON.grounding   (or leave unset to re-derive in Ground)
//   args.dimensions  = JSON.dimensions  (optional; defaults from the script)
//
// The shape matches graph-orchestration.md: ground once, fan out independent
// dimensions, refute before belief, ask what the graph could not see.
// Copy of workflow-template.js with standards-aware Ground.

export const meta = {
  name: 'standards-review',
  description:
    'Ground from the standards registry, fan out across independent dimensions, verify adversarially, synthesize',
  phases: [
    { title: 'Ground' },
    { title: 'Find' },
    { title: 'Verify' },
    { title: 'Synthesize' },
  ],
}

const TARGET = (args && args.target) || 'REPLACE: paths under review'
const PREBUILT_GROUNDING = args && args.grounding
const DIMENSIONS =
  (args && args.dimensions) ||
  [
    'correctness: inputs or orderings that produce a wrong result',
    'fail-open: unknown or unmapped cases that pass instead of refusing',
    'tests: assertions that cannot fail, or paths nothing asserts on',
  ]

const FINDINGS = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          claim: { type: 'string' },
          file_line: { type: 'string' },
          failure: {
            type: 'string',
            description: 'concrete input or state -> wrong outcome',
          },
        },
        required: ['claim', 'file_line', 'failure'],
      },
    },
  },
  required: ['findings'],
}

const VERDICT = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['CONFIRMED', 'REFUTED'] },
    reason: { type: 'string' },
  },
  required: ['verdict', 'reason'],
}

phase('Ground')
const brief = PREBUILT_GROUNDING
  ? PREBUILT_GROUNDING
  : await agent(
      `Run and use the output of: python3 scripts/standards.py brief ${TARGET}\n` +
        `Then read ${TARGET} and append entry points with file:line and what it guarantees. ` +
        `Facts only — no assessment. This brief is handed unchanged to every reviewer.`,
      { label: 'brief', phase: 'Ground' },
    )

const verified = await pipeline(
  DIMENSIONS,
  (dimension) =>
    agent(
      `${brief}\n\nReview ${TARGET} along one dimension only: ${dimension}.\n` +
        `Where a standard's conformance note states a limit (replay window, alg set, ` +
        `no fetch, profile choice), check the code matches that limit. ` +
        `Report only what you can evidence at file:line, with a concrete failure. ` +
        `Say so plainly if the dimension is clean — an empty result is a result.`,
      { label: `find:${dimension.split(':')[0]}`, phase: 'Find', schema: FINDINGS },
    ),

  (found) =>
    parallel(
      (found?.findings || []).map(
        (f) => () =>
          agent(
            `Refute this claim about ${TARGET}, by reading the code:\n\n` +
              `${f.claim}\nat ${f.file_line}\nfailing when: ${f.failure}\n\n` +
              `Default to REFUTED unless you can construct the failure yourself. ` +
              `Re-run the relevant check rather than reasoning about what it would say.`,
            { label: `verify:${f.file_line}`, phase: 'Verify', schema: VERDICT },
          ).then((v) => ({ ...f, ...v })),
      ),
    ),
)

const survived = verified.flat().filter(Boolean).filter((f) => f.verdict === 'CONFIRMED')

phase('Synthesize')
const [summary, missed] = await parallel([
  () =>
    agent(
      `These findings about ${TARGET} survived refutation:\n${JSON.stringify(survived, null, 2)}\n\n` +
        `Order them by what breaks worst, and state what to do about each. No padding.`,
      { label: 'synthesis', phase: 'Synthesize' },
    ),
  () =>
    agent(
      `${brief}\n\nReviewers covered exactly these dimensions of ${TARGET}:\n` +
        `${DIMENSIONS.join('\n')}\n\nName what none of them could have found: a dimension not run, ` +
        `a path not read, a claim asserted but never checked, or a registry conformance ` +
        `limit the code no longer matches. Go look, and cite file:line.`,
      { label: 'completeness', phase: 'Synthesize' },
    ),
])

return { confirmed: survived, summary, missed }
