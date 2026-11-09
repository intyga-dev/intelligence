import assert from "node:assert/strict"
import test from "node:test"
import { FINDING_QUERY } from "../domain/findingQuery.ts"
import type { FindingListItem } from "../store/repo.ts"
import { projectForJudgment } from "../redaction/project.ts"
import { renderFindingsPage } from "./findings.ts"
import { findingsPage } from "./findingsPage.ts"

const finding: FindingListItem = {
  kind: "finding",
  id: "f",
  serviceId: null,
  category: "security",
  severity: "high",
  title: "Denial burst",
  summary: null,
  detectedAt: new Date(),
  lastSeenAt: new Date(),
  count: 1,
  status: "new",
  feedback: [],
  evidence: [
    {
      kind: "assessment",
      provider: "typesafe",
      model: "jev",
      question: "anomalous",
      answer: 0.6,
      probability: 0.6,
      confidence: 0.98,
      stateDigest: "fixture",
    },
  ],
}

test("old TypeSafe records label severity confidence independently of the anomaly score", () => {
  for (const html of [
    renderFindingsPage([finding]),
    findingsPage({
      findings: [finding],
      counts: { findings: 1, alerts: 0, connectors: 1 },
      query: FINDING_QUERY.parse({}),
      total: 1,
    }),
  ]) {
    assert.match(html, /60%/)
    assert.match(html, /severity confidence 98%/)
    assert.doesNotMatch(html, /anomalous confidence 98%/)
  }
})

test("review observations cannot be projected into model anomaly requests", () => {
  assert.throws(() => projectForJudgment({ ...finding, kind: "observation" }, "salt"), /not anomaly evidence/)
  assert.doesNotThrow(() => projectForJudgment(finding, "salt"))
})
