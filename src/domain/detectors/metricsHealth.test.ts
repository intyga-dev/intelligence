import assert from "node:assert/strict"
import { test } from "node:test"
import type { NormalizedEvent } from "../../connectors/types.ts"
import { detectMetricsHealth, HEALTH_COUNTERS, HEALTH_GAUGES } from "./metricsHealth.ts"

const now = new Date("2026-11-06T12:00:00Z")
function sample(value: number, minutesAgo = 0, overrides: Partial<NormalizedEvent> = {}): NormalizedEvent {
  const metric = HEALTH_COUNTERS[0]
  return {
    connectionId: "metrics-a",
    source: "metrics",
    sourceId: `sample-${minutesAgo}`,
    kind: "metrics.sample",
    at: new Date(now.getTime() - minutesAgo * 60_000),
    subjectRef: `${metric}{instance=a}`,
    correlationRef: metric,
    attrs: { metric, value, query: metric },
    ...overrides,
  }
}
function detect(events: NormalizedEvent[], history: NormalizedEvent[] = []) {
  return detectMetricsHealth({ tenantId: "tenant", events, history, now })
}

test("health counters need an observed increase, not an initial lifetime value", () => {
  assert.equal(detect([sample(100)]).length, 0)
  assert.equal(detect([sample(100)], [sample(100, 1)]).length, 0)
  const [f] = detect([sample(104)], [sample(100, 1)])
  assert.equal(f?.severity, "high")
  assert.equal(f?.evidence[0].kind, "metric")
  assert.equal(f?.evidence[0].kind === "metric" && f.evidence[0].value, 4)
  assert.equal(f?.evidence.filter((e) => e.kind === "eventRef").length, 2)
})

test("counter resets, collection gaps, stale samples and future samples do not alarm", () => {
  assert.equal(detect([sample(3)], [sample(100, 1)]).length, 0)
  assert.equal(detect([sample(104)], [sample(100, 16)]).length, 0)
  assert.equal(detect([sample(104, 16)], [sample(100, 17)]).length, 0)
  assert.equal(detect([sample(104, -1)], [sample(100)]).length, 0)
  assert.equal(detect([sample(104)], [sample(100, 0, { sourceId: "same-time" })]).length, 0)
})

test("series and connectors keep independent baselines and stable finding identities", () => {
  const before = sample(100, 1)
  assert.equal(detect([sample(104, 0, { connectionId: "metrics-b" })], [before]).length, 0)
  assert.equal(detect([sample(104, 0, { subjectRef: "different-labels" })], [before]).length, 0)
  const [a] = detect([sample(104)], [before])
  const [b] = detect([sample(108)], [before])
  assert.equal(a?.dedupeKey, b?.dedupeKey)
})

test("known integrity gauges report broken objects without requiring a baseline", () => {
  for (const metric of HEALTH_GAUGES) {
    const gauge = sample(2, 0, { attrs: { metric, query: metric, value: 2 } })
    assert.equal(detect([gauge])[0]?.severity, "critical")
    assert.equal(detect([{ ...gauge, attrs: { ...gauge.attrs, value: 0 } }]).length, 0)
  }
})

test("unknown metrics, transformed queries and non-finite values are ignored", () => {
  const before = sample(0, 1)
  for (const value of [Number.NaN, Number.POSITIVE_INFINITY, -1]) {
    assert.equal(detect([sample(value)], [before]).length, 0)
  }
  assert.equal(
    detect([sample(5, 0, { attrs: { metric: "cpu_usage", query: "cpu_usage", value: 5 } })], [before]).length,
    0,
  )
  assert.equal(
    detect(
      [
        sample(5, 0, {
          attrs: { metric: HEALTH_COUNTERS[0], query: `rate(${HEALTH_COUNTERS[0]}[5m])`, value: 5 },
        }),
      ],
      [before],
    ).length,
    0,
  )
})

test("a batch folds increases once per series and history alone never re-fires", () => {
  const first = sample(10, 2)
  const second = sample(12, 1)
  const third = sample(15)
  const findings = detect([second, third], [first, second, third])
  assert.equal(findings.length, 1)
  const evidence = findings[0]?.evidence[0]
  assert.equal(evidence?.kind === "metric" && evidence.value, 5)
  assert.equal(detect([], [first, second, third]).length, 0)
})
