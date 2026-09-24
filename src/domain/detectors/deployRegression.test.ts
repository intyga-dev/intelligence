import assert from "node:assert/strict"
import test from "node:test"
import type { NormalizedEvent } from "../../connectors/types.ts"
import { PATH_MAPS } from "../sensitivity.ts"
import { asDeploy, type Deploy, detectDeployRegressions } from "./deployRegression.ts"

const D = new Date("2026-09-23T12:00:00Z").getTime()
const min = (m: number) => new Date(D + m * 60_000)
const generic = () => PATH_MAPS.generic

let seq = 0
function ev(source: string, kind: string, at: Date, attrs: NormalizedEvent["attrs"] = {}): NormalizedEvent {
  seq++
  return {
    connectionId: source,
    source,
    sourceId: `${kind}:${seq}`,
    kind,
    at,
    subjectRef: null,
    correlationRef: null,
    attrs,
  }
}

function deploy(sha = "abc1234"): Deploy {
  const d = asDeploy(
    ev("github", "github.deployment", min(0), { workflow: "Deploy API", sha, conclusion: "success" }),
  )
  assert.ok(d)
  return d
}

/** A steady trickle over the baseline, so the history guard is satisfied. */
function baseline(
  source: string,
  kind: string,
  everyMinutes: number,
  fromMinutes = -24 * 60,
): NormalizedEvent[] {
  const out: NormalizedEvent[] = []
  for (let m = fromMinutes; m < 0; m += everyMinutes) out.push(ev(source, kind, min(m)))
  return out
}

test("only successful production deploys anchor anything", () => {
  assert.equal(asDeploy(ev("github", "github.deployment", min(0), { conclusion: "failure" })), null)
  assert.equal(
    asDeploy(ev("vercel", "vercel.deployment", min(0), { isProduction: false, succeeded: true })),
    null,
  )
  assert.ok(asDeploy(ev("vercel", "vercel.deployment", min(0), { isProduction: true, succeeded: true })))
})

test("an error spike after a deploy fires, against a normalised baseline", () => {
  const signals = [
    ...baseline("sentry", "sentry.error", 60), // ~24/day ⇒ ~0.5 per 30m
    ...Array.from({ length: 8 }, (_, i) => ev("sentry", "sentry.error", min(i + 1))),
  ]
  const found = detectDeployRegressions({
    tenantId: "t",
    deploys: [deploy()],
    signals,
    changes: [],
    mapFor: generic,
    now: min(40),
  })
  assert.equal(found.length, 1)
  assert.equal(found[0]?.severity, "medium")
  assert.match(found[0]?.title ?? "", /8 errors in 30m after deploying Deploy API/)
  assert.match(found[0]?.summary ?? "", /Timing only/, "never claims causation")
})

test("the same count is not a regression when it is normal for this service", () => {
  const signals = [
    ...baseline("sentry", "sentry.error", 3), // ~10 per 30m is normal here
    ...Array.from({ length: 8 }, (_, i) => ev("sentry", "sentry.error", min(i + 1))),
  ]
  const found = detectDeployRegressions({
    tenantId: "t",
    deploys: [deploy()],
    signals,
    changes: [],
    mapFor: generic,
    now: min(40),
  })
  assert.equal(found.length, 0)
})

test("a newly connected source does not make the first deploy look like a regression", () => {
  // Errors, but Sentry was first seen only an hour ago: no history, no judgement.
  const signals = [
    ev("sentry", "sentry.error", min(-60)),
    ...Array.from({ length: 20 }, (_, i) => ev("sentry", "sentry.error", min(i + 1))),
  ]
  const found = detectDeployRegressions({
    tenantId: "t",
    deploys: [deploy()],
    signals,
    changes: [],
    mapFor: generic,
    now: min(40),
  })
  assert.equal(found.length, 0)
})

test("a refusal-rate rise needs volume, and a deploy of sensitive code raises severity", () => {
  const approvals = (from: number, to: number, every: number) => {
    const out: NormalizedEvent[] = []
    for (let m = from; m < to; m += every) out.push(ev("intyga", "challenge.approved", min(m)))
    return out
  }
  const signals = [
    ...approvals(-24 * 60, 0, 5), // baseline: all approved
    ...approvals(0, 30, 1), // 30 approvals after the deploy
    ...Array.from({ length: 10 }, (_, i) => ev("intyga", "challenge.denied", min(i + 1))),
  ]
  const change = ev("github", "github.pull_request.merged", min(-30), {
    repo: "acme/api",
    number: 42,
    title: "Rework permission checks",
    sha: "head0000",
    mergeSha: "abc1234",
    merged: true,
    paths: JSON.stringify(["src/permissions/check.ts"]),
    pathsTruncated: false,
  })
  const found = detectDeployRegressions({
    tenantId: "t",
    deploys: [deploy("abc1234")],
    signals,
    changes: [change],
    mapFor: generic,
    now: min(40),
  })
  assert.equal(found.length, 1)
  const f = found[0]
  assert.ok(f)
  assert.equal(f.category, "security")
  assert.equal(f.severity, "critical", "high, raised one step: the shipped diff changed authorization")
  assert.match(f.summary ?? "", /PR acme\/api#42, which changed authorization/)
  assert.ok(
    f.evidence.some((e) => e.kind === "codeChange"),
    "matched on the MERGE commit, not the PR head",
  )
})

test("a quiet hour is not a refusal-rate incident", () => {
  const signals = [
    ...baseline("intyga", "challenge.approved", 30),
    ev("intyga", "challenge.approved", min(5)),
    ev("intyga", "challenge.denied", min(6)),
  ]
  const found = detectDeployRegressions({
    tenantId: "t",
    deploys: [deploy()],
    signals,
    changes: [],
    mapFor: generic,
    now: min(40),
  })
  assert.equal(found.length, 0)
})

test("a single paging incident right after a deploy is enough, once the source has history", () => {
  const history = [ev("pagerduty", "pagerduty.incident.resolved", min(-20 * 60))]
  const incident = ev("pagerduty", "pagerduty.incident.triggered", min(12))
  const found = detectDeployRegressions({
    tenantId: "t",
    deploys: [deploy()],
    signals: [...history, incident],
    changes: [],
    mapFor: generic,
    now: min(40),
  })
  assert.equal(found.length, 1)
  assert.equal(found[0]?.severity, "high")
  assert.match(found[0]?.title ?? "", /1 incident in 30m after deploying/)

  // The same incident with no prior PagerDuty history: a fresh connection, not a regression.
  const fresh = detectDeployRegressions({
    tenantId: "t",
    deploys: [deploy()],
    signals: [incident],
    changes: [],
    mapFor: generic,
    now: min(40),
  })
  assert.equal(fresh.length, 0)
})

test("generic deploy sources anchor only when they say production and did not fail", () => {
  const mk = (attrs: NormalizedEvent["attrs"]) => ev("netlify", "netlify.deployment", min(0), attrs)
  assert.ok(asDeploy(mk({ production: true, succeeded: true, sha: "s", name: "site" })))
  assert.equal(asDeploy(mk({ production: false, succeeded: true })), null)
  assert.equal(asDeploy(mk({ production: true, succeeded: false })), null)
  assert.equal(asDeploy(mk({ succeeded: true })), null)
})
