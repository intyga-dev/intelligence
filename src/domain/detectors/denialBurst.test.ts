import assert from "node:assert/strict"
import test from "node:test"
import type { NormalizedEvent } from "../../connectors/types.ts"
import { isDeterministic } from "../finding.ts"
import { detectDenialBursts, median } from "./denialBurst.ts"

const NOW = new Date("2026-09-21T08:08:00Z")
const CONN = "conn-1"
const AGENT = "did:intyga:agent-001"

let seq = 0
function ev(o: {
  minutesAgo: number
  kind?: string
  subject?: string | null
  actionType?: string | null
}): NormalizedEvent {
  seq += 1
  return {
    connectionId: CONN,
    source: "intyga",
    sourceId: `e${seq}`,
    kind: o.kind ?? "challenge.denied",
    at: new Date(NOW.getTime() - o.minutesAgo * 60_000),
    subjectRef: o.subject === undefined ? AGENT : o.subject,
    correlationRef: `n${seq}`,
    attrs: {
      actionType: o.actionType ?? "read_record",
      requiredApprovals: 1,
      approvalsCount: 0,
      challengeCreatedAt: null,
      latencyMs: null,
    },
  }
}

/** Steady prior activity so the baseline is non-zero where a test needs one. */
function history(perBucket: number, buckets: number, actionType = "read_record"): NormalizedEvent[] {
  const out: NormalizedEvent[] = []
  for (let b = 1; b <= buckets; b++) {
    for (let i = 0; i < perBucket; i++) {
      out.push(ev({ minutesAgo: 8 * b + i * 0.1 + 0.5, actionType }))
    }
  }
  return out
}

test("median handles empty, odd and even inputs", () => {
  assert.equal(median([]), 0)
  assert.equal(median([5]), 5)
  assert.equal(median([1, 9, 2]), 2)
  assert.equal(median([1, 2, 3, 4]), 2.5)
})

test("the brief's worked example fires, at the severity deterministic evidence can justify", () => {
  // 17 refusals in 8 minutes; 12 of them a permission-modifying action never seen before.
  const events = [
    ...history(1, 40), // an ordinary ~1-per-8-minutes subject
    ...Array.from({ length: 12 }, (_, i) => ev({ minutesAgo: i * 0.5, actionType: "grant_permission" })),
    ...Array.from({ length: 5 }, (_, i) => ev({ minutesAgo: i * 0.5 + 1, actionType: "read_record" })),
  ]

  const [f, ...others] = detectDenialBursts({ tenantId: "t1", events, now: NOW })
  assert.equal(others.length, 0, "one subject, one finding")
  assert.ok(f)
  // "high", deliberately not "critical". This detector knows the action type is NOVEL; it has no
  // idea that `grant_permission` is permission-modifying — that is semantic, and inferring it from
  // a string would be the detector guessing. Escalation to critical is the judgment provider's job
  // (`requires_human_attention` / `severity`), applied on top of this evidence. Volume alone can
  // still reach critical: see the floor*2 case below.
  assert.equal(f.severity, "high")
  assert.equal(f.category, "security")
  assert.match(f.title, /17 refused operations/)
  assert.match(f.summary ?? "", /grant_permission/)

  // The count and the novelty must both be present as evidence a human can check.
  const counts = f.evidence.filter((e) => e.kind === "metric")
  assert.equal(counts[0]?.value, 17)
  assert.equal(counts[0]?.baseline, 1)
  assert.ok(
    f.evidence.some(
      (e) => e.kind === "metric" && e.label.includes("action: grant_permission") && e.value === 12,
    ),
    "the 12 permission-modifying attempts must be itemised",
  )
  assert.ok(f.evidence.some((e) => e.kind === "metric" && e.label.includes("never seen")))
})

test("every finding leads with deterministic evidence and cites specific events", () => {
  const events = [
    ...history(1, 40),
    ...Array.from({ length: 17 }, (_, i) => ev({ minutesAgo: i * 0.4, actionType: "grant_permission" })),
  ]
  const [f] = detectDenialBursts({ tenantId: "t1", events, now: NOW })
  assert.ok(f)
  assert.ok(isDeterministic(f.evidence[0]))
  const refs = f.evidence.filter((e) => e.kind === "eventRef")
  assert.ok(refs.length > 0, "a reader must be able to go and look at the actual events")
  assert.ok(refs.length <= 10, "evidence is a pointer, not a mirror of the feed")
})

test("the absolute floor stops a quiet subject going 0 -> 3 from reading as a spike", () => {
  // Ratio-wise this is infinite; in reality it is three refusals.
  const events = Array.from({ length: 3 }, (_, i) => ev({ minutesAgo: i }))
  assert.deepEqual(detectDenialBursts({ tenantId: "t1", events, now: NOW }), [])
})

test("a busy subject running at its own normal rate does not fire", () => {
  // ~20 refusals per 8-minute window, sustained. Well over the floor, but entirely typical for it.
  const events = [...history(20, 40), ...Array.from({ length: 20 }, (_, i) => ev({ minutesAgo: i * 0.3 }))]
  assert.deepEqual(
    detectDenialBursts({ tenantId: "t1", events, now: NOW }),
    [],
    "the baseline is per-subject, so its ordinary volume must not be an incident",
  )
})

test("subjects are judged independently, not pooled", () => {
  const other = "did:intyga:agent-002"
  const events = [
    ...history(1, 40),
    ...Array.from({ length: 17 }, (_, i) => ev({ minutesAgo: i * 0.4, actionType: "grant_permission" })),
    // A second agent with a handful of refusals — below the floor on its own.
    ...Array.from({ length: 4 }, (_, i) => ev({ minutesAgo: i, subject: other })),
  ]
  const found = detectDenialBursts({ tenantId: "t1", events, now: NOW })
  assert.equal(found.length, 1)
  assert.match(found[0]?.title ?? "", /agent-001/)
})

test("non-refusal lifecycle events are ignored", () => {
  const events = [
    ...history(1, 40),
    ...Array.from({ length: 30 }, (_, i) =>
      ev({ minutesAgo: i * 0.2, kind: "challenge.approved", actionType: "grant_permission" }),
    ),
  ]
  assert.deepEqual(
    detectDenialBursts({ tenantId: "t1", events, now: NOW }),
    [],
    "approvals are not refusals — a busy successful agent is not an incident",
  )
})

test("challenge.expired counts as a refusal alongside challenge.denied", () => {
  const events = [
    ...history(1, 40),
    ...Array.from({ length: 17 }, (_, i) => ev({ minutesAgo: i * 0.4, kind: "challenge.expired" })),
  ]
  assert.equal(detectDenialBursts({ tenantId: "t1", events, now: NOW }).length, 1)
})

test("events with no requester DID are skipped rather than pooled into an unattributable finding", () => {
  const events = Array.from({ length: 40 }, (_, i) => ev({ minutesAgo: i * 0.1, subject: null }))
  assert.deepEqual(detectDenialBursts({ tenantId: "t1", events, now: NOW }), [])
})

test("dedupeKey is stable across runs so a continuing burst updates one finding", () => {
  const events = [
    ...history(1, 40),
    ...Array.from({ length: 17 }, (_, i) => ev({ minutesAgo: i * 0.4, actionType: "grant_permission" })),
  ]
  const a = detectDenialBursts({ tenantId: "t1", events, now: NOW })[0]
  const b = detectDenialBursts({ tenantId: "t1", events, now: new Date(NOW.getTime() + 60_000) })[0]
  assert.equal(a?.dedupeKey, b?.dedupeKey)
  assert.equal(a?.dedupeKey, `burst:${CONN}:${AGENT}`)
})

test("more of the same familiar action is high, not critical", () => {
  // Same volume as the worked example, but nothing novel — weaker evidence, lower severity.
  const events = [
    ...history(1, 40),
    ...Array.from({ length: 17 }, (_, i) => ev({ minutesAgo: i * 0.4, actionType: "read_record" })),
  ]
  const [f] = detectDenialBursts({ tenantId: "t1", events, now: NOW })
  assert.equal(f?.severity, "high")
})

test("config is overridable and the floor is respected", () => {
  const events = Array.from({ length: 5 }, (_, i) => ev({ minutesAgo: i * 0.5 }))
  assert.deepEqual(detectDenialBursts({ tenantId: "t1", events, now: NOW }), [])
  const found = detectDenialBursts({ tenantId: "t1", events, now: NOW, config: { floor: 4, ratio: 1 } })
  assert.equal(found.length, 1)
})

test("volume alone can reach critical without any semantic input", () => {
  // 24 refusals with novel action types. No interpretation needed — that much, that new, that fast
  // is worth waking someone for on the numbers.
  const events = [
    ...history(1, 40),
    ...Array.from({ length: 24 }, (_, i) => ev({ minutesAgo: i * 0.3, actionType: "grant_permission" })),
  ]
  const [f] = detectDenialBursts({ tenantId: "t1", events, now: NOW })
  assert.equal(f?.severity, "critical")
})
