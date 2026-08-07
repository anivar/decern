// SPDX-License-Identifier: Apache-2.0
//
// A runnable shape for the method in ./graph-orchestration.md: ground once, fan
// out over independent dimensions, verify each finding adversarially, then ask
// what was missed.
//
// It is deliberately small. The orchestration engine is whatever runs this file;
// what is worth keeping is the shape — a shared brief, branches that never read
// each other, refutation before belief, and a bound on the run.
//
// Copy it, delete the stages the job does not need, and repoint the prompts.

export const meta = {
  name: 'review-dimensions',
  description: 'Ground, fan out across independent dimensions, verify adversarially, synthesize',
  phases: [
    { title: 'Ground' },
    { title: 'Find' },
    { title: 'Verify' },
    { title: 'Synthesize' },
  ],
}

// Parameterised, so the graph is reusable rather than a one-off.
const TARGET = (args && args.target) || 'REPLACE: what is under review'

// Each dimension becomes one independent branch. Apply the fake-edge test before
// adding one: if it needs another branch's output, it is not a dimension, it is a
// later stage. Width under three means this should have been a loop.
const DIMENSIONS = (args && args.dimensions) || [
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
          failure: { type: 'string', description: 'concrete input or state -> wrong outcome' },
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

// ---- Ground: one brief, built once, shared verbatim by every branch. ----
// Branches that each re-derive context drift apart, and reconciling that costs
// more than the parallelism won.
phase('Ground')
const brief = await agent(
  `Read ${TARGET} and produce a dense factual brief: what it does, its entry points with file:line,
   what it depends on, and what it guarantees. Facts only — no assessment, no recommendations.
   This brief is handed unchanged to several reviewers, so anything wrong in it is wrong everywhere.`,
  { label: 'brief', phase: 'Ground' },
)

// ---- Find -> Verify, pipelined: a finding is verified as soon as it exists. ----
// A barrier here would make every dimension wait for the slowest one before any
// verification started, for no gain — the verifiers do not read each other.
const verified = await pipeline(
  DIMENSIONS,
  (dimension) =>
    agent(
      `${brief}\n\nReview ${TARGET} along one dimension only: ${dimension}.\n` +
        `Report only what you can evidence at file:line, with a concrete failure. ` +
        `Say so plainly if the dimension is clean — an empty result is a result.`,
      { label: `find:${dimension.split(':')[0]}`, phase: 'Find', schema: FINDINGS },
    ),

  // Every finding is challenged before it is believed. Ask for refutation, not
  // review: a reader told to find the flaw reads differently from one told to check.
  (found) =>
    parallel(
      (found?.findings || []).map((f) => () =>
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

// ---- Synthesize, and then ask what the graph could not see. ----
// The completeness pass is the one that catches a dimension nobody thought to run.
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
        `a path not read, a claim asserted but never checked. Go look, and cite file:line.`,
      { label: 'completeness', phase: 'Synthesize' },
    ),
])

return { confirmed: survived, summary, missed }
