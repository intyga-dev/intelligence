import assert from "node:assert/strict"
import test from "node:test"
import {
  type AssessmentEvidence,
  compareSeverity,
  createFinding,
  type DeterministicEvidence,
  type Evidence,
  type EvidenceList,
  FindingRuleError,
  fromStoredEvidence,
  isDeterministic,
  observeAgain,
  prioritise,
} from "./finding.ts"

const WINDOW = { from: new Date("2026-09-21T08:00:00Z"), to: new Date("2026-09-21T08:08:00Z") }
const AT = new Date("2026-09-21T08:08:00Z")

const metric: DeterministicEvidence = {
  kind: "metric",
  label: "challenge.denied",
  value: 17,
  baseline: 1,
  window: WINDOW,
}

const assessment: AssessmentEvidence = {
  kind: "assessment",
  provider: "typesafe",
  model: "jev-latest",
  question: "anomalous",
  answer: 0.91,
  probability: 0.91,
  confidence: 0.84,
  stateDigest: "sha256:abc",
}

const base = {
  id: "f1",
  tenantId: "t1",
  category: "security",
  severity: "high",
  title: "17 denied operations from one integration",
  detectedAt: AT,
  dedupeKey: "burst:c1:did:intyga:agent-001:challenge.denied",
} as const

test("a finding backed only by model output is a COMPILE error", () => {
  // The whole point of EvidenceList: the first element cannot be an assessment. If this line ever
  // stops erroring, the rule has been weakened and this test fails loudly at typecheck time.
  // @ts-expect-error assessment-only evidence must not satisfy EvidenceList
  const bad: EvidenceList = [assessment]
  assert.ok(bad)

  // An assessment AFTER deterministic evidence is fine — that is annotation, not substitution.
  const good: EvidenceList = [metric, assessment]
  assert.equal(good.length, 2)
})

test("createFinding starts at count 1 / status new and mirrors detectedAt into lastSeenAt", () => {
  const f = createFinding({ ...base, evidence: [metric, assessment] })
  assert.equal(f.count, 1)
  assert.equal(f.status, "new")
  assert.deepEqual(f.lastSeenAt, AT)
})

test("createFinding rejects an empty title, an empty dedupeKey and out-of-range confidence", () => {
  assert.throws(() => createFinding({ ...base, title: "  ", evidence: [metric] }), FindingRuleError)
  assert.throws(() => createFinding({ ...base, dedupeKey: "", evidence: [metric] }), FindingRuleError)
  assert.throws(() => createFinding({ ...base, confidence: 1.5, evidence: [metric] }), FindingRuleError)
})

test("fromStoredEvidence refuses assessment-only evidence read back from the database", () => {
  // The tuple type is erased by a round-trip through storage, so the rule needs a runtime half.
  assert.throws(() => fromStoredEvidence([assessment]), FindingRuleError)
  assert.throws(() => fromStoredEvidence([]), FindingRuleError)
})

test("fromStoredEvidence reorders so a deterministic item leads, without dropping the assessment", () => {
  const rows: Evidence[] = [assessment, metric]
  const list = fromStoredEvidence(rows)
  assert.equal(list[0].kind, "metric")
  assert.equal(list.length, 2, "the assessment must be kept, not filtered away")
})

test("isDeterministic separates facts from opinions", () => {
  assert.equal(isDeterministic(metric), true)
  assert.equal(isDeterministic(assessment), false)
})

test("observeAgain folds a repeat into one row and never lowers severity", () => {
  const f = createFinding({ ...base, evidence: [metric] })
  const later = new Date("2026-09-21T09:00:00Z")

  const escalated = observeAgain(f, later, "critical")
  assert.equal(escalated.count, 2)
  assert.deepEqual(escalated.lastSeenAt, later)
  assert.equal(escalated.severity, "critical")

  // A quieter recurrence must not downgrade an already-critical finding.
  assert.equal(observeAgain(escalated, later, "low").severity, "critical")
})

test("observeAgain does not move lastSeenAt backwards on an out-of-order observation", () => {
  const f = observeAgain(createFinding({ ...base, evidence: [metric] }), AT)
  const earlier = new Date("2026-09-21T07:00:00Z")
  assert.deepEqual(observeAgain(f, earlier).lastSeenAt, AT)
})

test("prioritise sorts most severe first, then most recent", () => {
  const mk = (id: string, severity: "low" | "critical" | "high", seen: string) => ({
    ...createFinding({ ...base, id, severity, evidence: [metric] }),
    lastSeenAt: new Date(seen),
  })
  const order = prioritise([
    mk("a", "low", "2026-09-21T10:00:00Z"),
    mk("b", "critical", "2026-09-21T08:00:00Z"),
    mk("c", "high", "2026-09-21T09:00:00Z"),
    mk("d", "critical", "2026-09-21T09:30:00Z"),
  ]).map((f) => f.id)
  assert.deepEqual(order, ["d", "b", "c", "a"])
})

test("compareSeverity orders the full ladder", () => {
  assert.ok(compareSeverity("critical", "high") > 0)
  assert.ok(compareSeverity("info", "low") < 0)
  assert.equal(compareSeverity("medium", "medium"), 0)
})
