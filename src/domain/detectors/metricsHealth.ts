import type { NormalizedEvent } from "../../connectors/types.ts"
import { createFinding, type DeterministicEvidence, type Finding } from "../finding.ts"

// Only metrics whose meaning is known. A generic gauge spike is not necessarily a problem;
// these signals explicitly count failures or broken integrity checks. Age/backlog gauges need
// deployment-specific thresholds and are deliberately left out.
export const HEALTH_COUNTERS = [
  "intyga_audit_write_failures_total",
  "intyga_challenge_replay_guard_degraded_total",
  "intyga_approval_requirement_unavailable_total",
  "intyga_notification_failures_total",
  "intyga_billing_refusals_total",
] as const
export const HEALTH_GAUGES = ["intyga_ledger_broken_blocks", "intyga_ledger_broken_checkpoints"] as const
export const METRICS_MAX_GAP_MS = 15 * 60_000

/** New arrivals are evaluated once; history supplies the previous sample of each exact series. */
export function detectMetricsHealth(input: {
  tenantId: string
  events: readonly NormalizedEvent[]
  history: readonly NormalizedEvent[]
  now: Date
}): Finding[] {
  const fresh = new Set(input.events.map((e) => JSON.stringify([e.connectionId, e.sourceId])))
  const unique = new Map<string, NormalizedEvent>()
  for (const e of [...input.history, ...input.events]) {
    if (e.kind !== "metrics.sample" || e.source !== "metrics" || !e.subjectRef) continue
    if (!Number.isFinite(e.at.getTime()) || e.at > input.now) continue
    if (typeof e.attrs.value !== "number" || !Number.isFinite(e.attrs.value) || e.attrs.value < 0) continue
    if (![...HEALTH_COUNTERS, ...HEALTH_GAUGES].some((m) => m === e.attrs.metric)) continue
    // A PromQL transform can retain __name__ while changing the semantics (e.g. rate(counter)).
    // Counter deltas and positive broken-object counts apply only to the bare metric query.
    if (e.attrs.query !== e.attrs.metric) continue
    unique.set(JSON.stringify([e.connectionId, e.sourceId]), e)
  }
  const groups = new Map<string, NormalizedEvent[]>()
  for (const e of unique.values()) {
    const key = JSON.stringify([e.connectionId, e.subjectRef, e.attrs.metric, e.serviceId ?? null])
    const group = groups.get(key) ?? []
    group.push(e)
    groups.set(key, group)
  }

  const findings: Finding[] = []
  for (const [key, samples] of groups) {
    samples.sort((a, b) => a.at.getTime() - b.at.getTime() || a.sourceId.localeCompare(b.sourceId))
    const metric = String(samples[0]?.attrs.metric)
    const counter = HEALTH_COUNTERS.some((m) => m === metric)
    let previous: NormalizedEvent | undefined
    let value = 0
    const evidenceSamples: NormalizedEvent[] = []
    for (const e of samples) {
      const age = input.now.getTime() - e.at.getTime()
      if (fresh.has(JSON.stringify([e.connectionId, e.sourceId])) && age <= METRICS_MAX_GAP_MS) {
        const gap = previous ? e.at.getTime() - previous.at.getTime() : 0
        // No first-sample alarm from a lifetime counter; no invented increase across a reset or
        // long collection gap. A positive integrity gauge, however, needs no learned baseline.
        const change = counter
          ? previous && gap > 0 && gap <= METRICS_MAX_GAP_MS
            ? Number(e.attrs.value) - Number(previous.attrs.value)
            : 0
          : Number(e.attrs.value)
        if (change >= 1) {
          value = counter ? value + change : Math.max(value, change)
          if (counter && previous) evidenceSamples.push(previous)
          evidenceSamples.push(e)
        }
      }
      previous = e
    }
    const first = evidenceSamples[0]
    const last = evidenceSamples.at(-1)
    if (!first || !last) continue
    const dedupeKey = `metrics-health:${key}`
    const evidence: [DeterministicEvidence, ...DeterministicEvidence[]] = [
      {
        kind: "metric",
        label: `${metric}: ${counter ? "new failures between samples" : "broken objects observed"}`,
        value,
        window: { from: first.at, to: new Date(last.at.getTime() + 1) },
      },
    ]
    for (const e of [...new Map(evidenceSamples.map((e) => [e.sourceId, e])).values()].slice(-10)) {
      evidence.push({
        kind: "eventRef",
        connectionId: e.connectionId,
        sourceId: e.sourceId,
        at: e.at,
        eventKind: e.kind,
      })
    }
    findings.push(
      createFinding({
        id: dedupeKey,
        tenantId: input.tenantId,
        serviceId: last.serviceId ?? null,
        category: "engineering",
        severity: counter ? "high" : "critical",
        title: `${metric}: ${value} ${counter ? "new failure(s)" : "broken object(s)"}`,
        summary: `${last.subjectRef}. ${
          counter
            ? "The counter increased between observed samples no more than 15 minutes apart. Initial values, resets and collection gaps are not counted."
            : "The integrity gauge reports broken objects. Inspect the ledger and its integrity checks."
        }`,
        evidence,
        detectedAt: last.at,
        dedupeKey,
      }),
    )
  }
  return findings
}
