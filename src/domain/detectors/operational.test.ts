import assert from "node:assert/strict"
import test from "node:test"
import type { NormalizedEvent } from "../../connectors/types.ts"
import {
  detectCiHealth,
  detectCollectionHealth,
  detectMergePolicy,
  detectOverdueJobs,
  detectServiceDegradation,
  type OperationalInput,
} from "./operational.ts"
import { CONFIGURE_DETECTOR, operationalSettings } from "./operationalSettings.ts"

const id = "00000000-0000-4000-8000-000000000001"
const now = new Date("2026-11-07T12:00:00Z")
const at = (minutes: number) => new Date(now.getTime() - minutes * 60000)
const source = { id, label: "Production", active: true, serviceId: "service-a", activatedAt: at(2000) }
function event(
  kind: string,
  minutes: number,
  attrs: NormalizedEvent["attrs"],
  sourceId = `${kind}:${minutes}`,
): NormalizedEvent {
  return {
    connectionId: id,
    source: "test",
    sourceId,
    kind,
    at: at(minutes),
    subjectRef: null,
    correlationRef: null,
    attrs,
    serviceId: source.serviceId,
  }
}
const input = (events: NormalizedEvent[]): OperationalInput => ({
  tenantId: "tenant",
  now,
  sources: [source],
  events,
})
const ci = operationalSettings("ci-health", {
  targets: [{ connectionId: id, repo: "acme/app", branch: "main", workflow: "CI" }],
})
const run = (minutes: number, conclusion = "failure", runId = String(minutes)) =>
  event("github.workflow_run", minutes, {
    repo: "acme/app",
    branch: "main",
    workflow: "CI",
    event: "push",
    runId,
    conclusion,
  })
const jobs = operationalSettings("job-overdue", {
  targets: [
    {
      connectionId: id,
      job: "backup",
      startsAt: at(120).toISOString(),
      intervalMinutes: 60,
      graceMinutes: 10,
    },
  ],
})
const slo = operationalSettings("service-degradation", {
  targets: [
    { connectionId: id, objective: "api", shortMinutes: 2, longMinutes: 10, burnRate: 10, minRequests: 100 },
  ],
})
const samples = () =>
  Array.from({ length: 10 }, (_, i) =>
    event("custom.slo.sample", i + 1, { objective: "api", windowSeconds: 60, total: 1000, bad: 20 }),
  )

test("collection requires repeated observed failures; empty successful polls and quiet push sources are healthy", () => {
  const cfg = operationalSettings("collection-health", {})
  assert.equal(detectCollectionHealth(input([]), cfg).length, 0)
  const failed = [3, 2, 1].map((m) => event("intelligence.poll", m, { succeeded: false, gapMinutes: 1 }))
  assert.equal(detectCollectionHealth(input(failed.slice(1)), cfg).length, 0)
  assert.equal(detectCollectionHealth(input(failed), cfg).length, 1)
  assert.equal(
    detectCollectionHealth(
      input([...failed, event("intelligence.poll", 0, { succeeded: true, gapMinutes: 1 })]),
      cfg,
    ).length,
    0,
  )
  const gap = detectCollectionHealth(
    input([event("intelligence.poll", 1, { succeeded: true, gapMinutes: 25 })]),
    cfg,
  )
  assert.equal(gap.length, 1)
  assert.match(gap[0]!.summary ?? "", /historical monitoring gap/)
})

test("CI flags repeated or aged failures, excludes other branches and PR workflows", () => {
  assert.equal(detectCiHealth(input([run(3), run(2), run(1)]), ci).length, 1)
  assert.equal(detectCiHealth(input([run(2), run(1)]), ci).length, 0)
  assert.equal(detectCiHealth(input([run(31)]), ci).length, 1)
  for (const attrs of [
    { branch: "feature" },
    { event: "pull_request" },
    { event: "pull_request_target" },
    { workflow: "Other" },
    { repo: "other/app" },
  ]) {
    const e = run(31)
    Object.assign(e.attrs, attrs)
    assert.equal(detectCiHealth(input([e]), ci).length, 0)
  }
  assert.equal(detectCiHealth(input([run(1500)]), ci).length, 0)
})

test("CI successful retry supersedes failure and duplicates never inflate failed-run counts", () => {
  const fail = run(31, "failure", "same")
  assert.equal(detectCiHealth(input([fail, run(1, "success", "same")]), ci).length, 0)
  const duplicate = run(2, "failure", "same")
  assert.equal(
    detectCiHealth(
      input([duplicate, { ...duplicate, sourceId: "retry-2" }, { ...duplicate, sourceId: "retry-3" }]),
      ci,
    ).length,
    0,
  )
  assert.equal(detectCiHealth(input([run(31), run(1, "cancelled")]), ci).length, 1)
  assert.equal(detectCiHealth(input([run(31), run(1, "unknown")]), ci).length, 0)
})

test("merge controls require affirmative historic evidence of an accepted active-rule bypass", () => {
  const cfg = operationalSettings("merge-policy", {
    targets: [{ connectionId: id, repo: "acme/app", branch: "main" }],
  })
  const e = event("github.rule_suite", 1, {
    repo: "acme/app",
    branch: "main",
    sha: "abc",
    result: "bypass",
    activeMergeRuleFailed: true,
  })
  assert.equal(detectMergePolicy(input([e]), cfg).length, 1)
  for (const attrs of [
    { result: "fail" },
    { result: "pass" },
    { activeMergeRuleFailed: false },
    { activeMergeRuleFailed: null },
    { branch: "feature" },
  ]) {
    assert.equal(detectMergePolicy(input([{ ...e, attrs: { ...e.attrs, ...attrs } }]), cfg).length, 0)
  }
})

test("scheduled jobs allow grace, use successful completions only and retain a stable overdue incident", () => {
  const completion = event("custom.job.completed", 69, { job: "backup", succeeded: true })
  assert.equal(detectOverdueJobs(input([completion]), jobs).length, 0)
  const overdue = event("custom.job.completed", 71, { job: "backup", succeeded: true })
  const f = detectOverdueJobs(
    input([overdue, event("custom.job.completed", 1, { job: "backup", succeeded: false })]),
    jobs,
  )
  assert.equal(f.length, 1)
  assert.equal(detectOverdueJobs({ ...input([overdue]), now: at(-10) }, jobs)[0]!.dedupeKey, f[0]!.dedupeKey)
  assert.equal(
    detectOverdueJobs(input([event("custom.job.completed", 1, { job: "backup", succeeded: true })]), jobs)
      .length,
    0,
  )
  assert.equal(detectOverdueJobs({ ...input([]), now: at(51) }, jobs).length, 0)
  assert.equal(detectOverdueJobs(input([]), jobs).length, 1)
})

test("maintenance and reactivation restart the job expectation", () => {
  for (const maintenanceUntil of [at(-60).toISOString(), at(10).toISOString()]) {
    const cfg = { targets: jobs.targets.map((t) => ({ ...t, maintenanceUntil })) }
    assert.equal(detectOverdueJobs(input([]), cfg).length, 0)
  }
  assert.equal(
    detectOverdueJobs({ ...input([]), sources: [{ ...source, activatedAt: at(10) }] }, jobs).length,
    0,
  )
})

test("service burn requires both windows, full samples, traffic, and unambiguous aggregates", () => {
  const xs = samples()
  assert.equal(detectServiceDegradation(input(xs), slo).length, 1)
  assert.equal(detectServiceDegradation(input(xs.slice(1)), slo).length, 0)
  assert.equal(
    detectServiceDegradation(input(xs.map((e) => ({ ...e, attrs: { ...e.attrs, total: 1, bad: 1 } }))), slo)
      .length,
    0,
  )
  assert.equal(
    detectServiceDegradation(
      input(xs.map((e) => ({ ...e, attrs: { ...e.attrs, bad: e.at >= at(2) ? 0 : 20 } }))),
      slo,
    ).length,
    0,
  )
  assert.equal(
    detectServiceDegradation(
      input(xs.map((e) => ({ ...e, attrs: { ...e.attrs, bad: e.at >= at(2) ? 20 : 0 } }))),
      slo,
    ).length,
    0,
  )
  assert.equal(detectServiceDegradation(input([...xs, { ...xs[0]!, sourceId: "duplicate" }]), slo).length, 1)
  assert.equal(
    detectServiceDegradation(
      input([...xs, { ...xs[0]!, sourceId: "conflict", attrs: { ...xs[0]!.attrs, bad: 100 } }]),
      slo,
    ).length,
    0,
  )
  assert.equal(
    detectServiceDegradation(input(xs.map((e) => ({ ...e, at: new Date(e.at.getTime() + 1) }))), slo).length,
    0,
  )
  assert.equal(
    detectServiceDegradation(input(xs), {
      targets: slo.targets.map((t) => ({ ...t, maintenanceUntil: at(5).toISOString() })),
    }).length,
    0,
  )
})

test("all detectors isolate connector/service scope and ignore inactive sources and future events", () => {
  const checks: [NormalizedEvent[], (i: OperationalInput) => unknown[]][] = [
    [
      [event("intelligence.poll", 1, { succeeded: true, gapMinutes: 30 })],
      (i) => detectCollectionHealth(i, operationalSettings("collection-health", {})),
    ],
    [[run(31)], (i) => detectCiHealth(i, ci)],
    [samples(), (i) => detectServiceDegradation(i, slo)],
  ]
  for (const [events, detect] of checks) {
    assert.equal(detect({ ...input(events), sources: [{ ...source, active: false }] }).length, 0)
    assert.equal(detect(input(events.map((e) => ({ ...e, connectionId: "other" })))).length, 0)
    assert.equal(detect(input(events.map((e) => ({ ...e, serviceId: "other" })))).length, 0)
    assert.equal(detect(input(events.map((e) => ({ ...e, at: at(-1) })))).length, 0)
  }
  assert.equal(detectOverdueJobs({ ...input([]), sources: [{ ...source, active: false }] }, jobs).length, 0)
})

test("settings reject invalid windows, unknown fields and unrealistic thresholds", () => {
  assert.equal(
    CONFIGURE_DETECTOR.safeParse({ detector: "collection-health", settings: { failures: 1 } }).success,
    false,
  )
  assert.equal(
    CONFIGURE_DETECTOR.safeParse({ detector: "collection-health", settings: { unexpected: true } }).success,
    false,
  )
  assert.equal(
    CONFIGURE_DETECTOR.safeParse({
      detector: "service-degradation",
      settings: { targets: [{ ...slo.targets[0], shortMinutes: 10, longMinutes: 5 }] },
    }).success,
    false,
  )
  assert.equal(
    CONFIGURE_DETECTOR.safeParse({
      detector: "service-degradation",
      settings: { targets: [{ ...slo.targets[0], successPercent: 100 }] },
    }).success,
    false,
  )
})

test("delivery lag allows a complete recent SLO window but stale samples never imply current failure", () => {
  const late = samples().map((e) => ({ ...e, at: new Date(e.at.getTime() - 60000) }))
  assert.equal(detectServiceDegradation(input(late), slo).length, 1)
  assert.equal(detectServiceDegradation({ ...input(late), now: at(-3) }, slo).length, 0)
})

test("a polling gap from before activation does not create a new monitoring incident", () => {
  const data = {
    ...input([event("intelligence.poll", 0, { succeeded: true, gapMinutes: 60 })]),
    sources: [{ ...source, activatedAt: at(5) }],
  }
  assert.equal(detectCollectionHealth(data, operationalSettings("collection-health", {})).length, 0)
})
