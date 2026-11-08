import type { NormalizedEvent } from "../../connectors/types.ts"
import { createFinding, type EvidenceList, type EventRefEvidence, type Finding } from "../finding.ts"
import type { OperationalSettings } from "./operationalSettings.ts"

const MINUTE = 60_000
export interface OperationalSource {
  id: string
  label: string
  active: boolean
  serviceId: string | null
  activatedAt: Date | null
}
export interface OperationalInput {
  tenantId: string
  events: readonly NormalizedEvent[]
  sources: readonly OperationalSource[]
  now: Date
}
const ref = (e: NormalizedEvent): EventRefEvidence => ({
  kind: "eventRef",
  connectionId: e.connectionId,
  sourceId: e.sourceId,
  at: e.at,
  eventKind: e.kind,
})
function eventsFor(input: OperationalInput, id: string, kinds: string[]): NormalizedEvent[] {
  const source = input.sources.find((s) => s.id === id && s.active)
  if (!source) return []
  return [
    ...new Map(
      input.events
        .filter(
          (e) =>
            e.connectionId === id &&
            kinds.includes(e.kind) &&
            Number.isFinite(e.at.getTime()) &&
            e.at <= input.now &&
            (!source.activatedAt || e.at >= source.activatedAt) &&
            (e.serviceId ?? null) === source.serviceId,
        )
        .map((e) => [e.sourceId, e]),
    ).values(),
  ].sort((a, b) => a.at.getTime() - b.at.getTime() || a.sourceId.localeCompare(b.sourceId))
}
function finding(
  input: OperationalInput,
  source: OperationalSource,
  key: string,
  at: Date,
  title: string,
  summary: string,
  evidence: EvidenceList,
): Finding {
  return createFinding({
    id: key,
    dedupeKey: key,
    tenantId: input.tenantId,
    serviceId: source.serviceId,
    category: "engineering",
    severity: "high",
    detectedAt: at,
    title,
    summary,
    evidence,
  })
}
const identity = (...parts: unknown[]) => JSON.stringify(parts)

export function detectCollectionHealth(
  input: OperationalInput,
  config: OperationalSettings<"collection-health">,
): Finding[] {
  const out: Finding[] = []
  for (const s of input.sources.filter((s) => s.active)) {
    const polls = eventsFor(input, s.id, ["intelligence.poll"])
    const last = polls.at(-1)
    if (!last) continue // Push silence has no polling contract.
    const failed: NormalizedEvent[] = []
    for (const e of [...polls].reverse()) {
      if (e.attrs.succeeded !== false) break
      failed.push(e)
    }
    if (
      failed.length >= config.failures &&
      input.now.getTime() - last.at.getTime() <= config.overdueMinutes * MINUTE
    ) {
      const first = failed.at(-1)
      if (!first) continue
      const key = `collection-health:${identity(s.id, s.serviceId, first.sourceId)}`
      out.push(
        finding(
          input,
          s,
          key,
          last.at,
          `${s.label}: repeated collection failures`,
          `${failed.length} consecutive polls failed. Check connector credentials, provider availability and rate limits. An empty successful poll is healthy.`,
          [
            {
              kind: "metric",
              label: "consecutive failed polls",
              value: failed.length,
              baseline: config.failures,
              window: { from: first.at, to: input.now },
            },
            ...failed.slice(0, 5).map(ref),
          ],
        ),
      )
    }
    // The collector records the gap BEFORE refreshing lastPolledAt, so a resumed scheduler cannot hide it.
    const gapStart =
      typeof last.attrs.gapMinutes === "number"
        ? Math.max(last.at.getTime() - last.attrs.gapMinutes * MINUTE, s.activatedAt?.getTime() ?? 0)
        : last.at.getTime()
    const gapMinutes = (last.at.getTime() - gapStart) / MINUTE
    if (gapMinutes > config.overdueMinutes) {
      const key = `collection-gap:${identity(s.id, s.serviceId, last.sourceId)}`
      out.push(
        finding(
          input,
          s,
          key,
          last.at,
          `${s.label}: collection resumed after a gap`,
          `No poll was recorded for ${Math.round(gapMinutes)} minutes. This is a historical monitoring gap; the latest poll ${last.attrs.succeeded ? "succeeded" : "failed"}. Check the scheduler and service availability.`,
          [
            {
              kind: "metric",
              label: "minutes without a poll",
              value: gapMinutes,
              baseline: config.overdueMinutes,
              window: { from: new Date(gapStart), to: last.at },
            },
            ref(last),
          ],
        ),
      )
    }
  }
  return out
}

export function detectCiHealth(input: OperationalInput, config: OperationalSettings<"ci-health">): Finding[] {
  const out: Finding[] = []
  for (const t of config.targets) {
    const source = input.sources.find((s) => s.id === t.connectionId && s.active)
    if (!source) continue
    const events = eventsFor(input, t.connectionId, [
      "github.workflow_run",
      "github.deployment",
      "custom.ci_run",
    ]).filter(
      (e) =>
        e.attrs.repo === t.repo &&
        e.attrs.branch === t.branch &&
        e.attrs.workflow === t.workflow &&
        e.attrs.event !== "pull_request" &&
        e.attrs.event !== "pull_request_target",
    )
    // A later successful retry of a run supersedes that run's earlier failed attempt.
    const runs = [...new Map(events.map((e) => [String(e.attrs.runId ?? e.sourceId), e])).values()].sort(
      (a, b) => a.at.getTime() - b.at.getTime(),
    )
    const failed: NormalizedEvent[] = []
    for (const e of [...runs].reverse()) {
      if (
        e.attrs.conclusion === "cancelled" ||
        e.attrs.conclusion === "skipped" ||
        e.attrs.conclusion === "neutral"
      )
        continue
      if (!["failure", "timed_out", "action_required"].includes(String(e.attrs.conclusion))) break
      failed.push(e)
    }
    const last = failed[0],
      first = failed.at(-1)
    if (!first || !last) continue
    // Stale CI data is unknown, never a claim that the branch remains broken.
    if (input.now.getTime() - last.at.getTime() > 24 * 60 * MINUTE) continue
    const duration = (input.now.getTime() - first.at.getTime()) / MINUTE
    if (failed.length < config.failures && duration < config.brokenMinutes) continue
    const key = `ci-health:${identity(t.connectionId, source.serviceId, t.repo, t.branch, t.workflow, first.sourceId)}`
    out.push(
      finding(
        input,
        source,
        key,
        last.at,
        `${t.repo}: ${t.workflow} failing on ${t.branch}`,
        `${failed.length} failed run(s); first observed ${Math.floor(duration)} minutes ago, with no later successful run in the collected history. Inspect the workflow before the next release.`,
        [
          {
            kind: "metric",
            label: "failed runs without a later success",
            value: failed.length,
            baseline: config.failures,
            window: { from: first.at, to: input.now },
          },
          ...failed.slice(0, 5).map(ref),
        ],
      ),
    )
  }
  return out
}

export function detectMergePolicy(
  input: OperationalInput,
  config: OperationalSettings<"merge-policy">,
): Finding[] {
  const out: Finding[] = []
  for (const t of config.targets) {
    const source = input.sources.find((s) => s.id === t.connectionId && s.active)
    if (!source) continue
    for (const e of eventsFor(input, t.connectionId, ["github.rule_suite"]).filter(
      (e) => e.attrs.repo === t.repo && e.attrs.branch === t.branch,
    )) {
      if (e.attrs.result !== "bypass" || e.attrs.activeMergeRuleFailed !== true) continue
      const key = `merge-policy:${identity(t.connectionId, source.serviceId, e.sourceId)}`
      out.push({
        ...finding(
          input,
          source,
          key,
          e.at,
          `${t.repo}: required merge controls bypassed on ${t.branch}`,
          `GitHub recorded an accepted bypass with a failed active review or required-check rule for commit ${String(e.attrs.sha)}. Confirm that the exception was authorized. Evaluate-only rules and rejected pushes are excluded.`,
          [ref(e)],
        ),
        category: "security",
      })
    }
  }
  return out
}

export function detectOverdueJobs(
  input: OperationalInput,
  config: OperationalSettings<"job-overdue">,
): Finding[] {
  const out: Finding[] = []
  for (const t of config.targets) {
    const s = input.sources.find((s) => s.id === t.connectionId && s.active)
    if (!s) continue
    const maintenance = t.maintenanceUntil ? new Date(t.maintenanceUntil).getTime() : 0
    if (maintenance > input.now.getTime()) continue
    const start = Math.max(new Date(t.startsAt).getTime(), s.activatedAt?.getTime() ?? 0, maintenance)
    const successes = eventsFor(input, s.id, ["custom.job.completed"]).filter(
      (e) => e.attrs.job === t.job && e.attrs.succeeded === true && e.at.getTime() >= start,
    )
    const last = successes.at(-1)
    const expectedBy = new Date(Math.max(start, last?.at.getTime() ?? 0) + t.intervalMinutes * MINUTE)
    const deadline = new Date(expectedBy.getTime() + t.graceMinutes * MINUTE)
    if (input.now <= deadline) continue
    const key = `job-overdue:${identity(s.id, s.serviceId, t.job, deadline.toISOString())}`
    out.push(
      finding(
        input,
        s,
        key,
        deadline,
        `${t.job}: scheduled completion overdue`,
        `Expected a successful completion every ${t.intervalMinutes} minutes, plus ${t.graceMinutes} minutes grace. Deadline: ${deadline.toISOString()}. ${last ? "The last successful completion is linked below." : "No successful completion has been observed since monitoring began."} Check the job and its event delivery.`,
        [
          {
            kind: "metric",
            label: "configured completion interval including grace (minutes)",
            value: t.intervalMinutes + t.graceMinutes,
            window: { from: new Date(Math.max(start, last?.at.getTime() ?? 0)), to: deadline },
          },
          ...(last ? [ref(last)] : []),
        ],
      ),
    )
  }
  return out
}

export function detectServiceDegradation(
  input: OperationalInput,
  config: OperationalSettings<"service-degradation">,
): Finding[] {
  const out: Finding[] = []
  for (const t of config.targets) {
    const s = input.sources.find((s) => s.id === t.connectionId && s.active)
    if (!s) continue
    const maintenance = t.maintenanceUntil ? new Date(t.maintenanceUntil).getTime() : 0
    if (maintenance > input.now.getTime()) continue
    const closedMinute = Math.floor(input.now.getTime() / MINUTE) * MINUTE
    const available = eventsFor(input, s.id, ["custom.slo.sample"]).filter(
      (e) =>
        e.attrs.objective === t.objective && e.at.getTime() < closedMinute && e.at.getTime() % MINUTE === 0,
    )
    // Allow ordinary delivery lag without silently extending the freshness window indefinitely.
    const latest = available.at(-1)
    if (!latest) continue
    const end = latest.at.getTime() + MINUTE
    if (closedMinute - end > 2 * MINUTE) continue
    const start = end - t.longMinutes * MINUTE
    if (start < maintenance) continue
    const byBucket = new Map<number, NormalizedEvent>()
    const conflicting = new Set<number>()
    for (const e of available) {
      if (e.attrs.objective !== t.objective || e.at.getTime() < start || e.at.getTime() >= end) continue
      if (
        e.at.getTime() % MINUTE !== 0 ||
        e.attrs.windowSeconds !== 60 ||
        !Number.isSafeInteger(e.attrs.total) ||
        !Number.isSafeInteger(e.attrs.bad)
      )
        continue
      const total = Number(e.attrs.total),
        bad = Number(e.attrs.bad)
      if (total < 0 || bad < 0 || bad > total) continue
      const bucket = e.at.getTime(),
        prev = byBucket.get(bucket)
      if (prev && (prev.attrs.total !== total || prev.attrs.bad !== bad)) conflicting.add(bucket)
      byBucket.set(bucket, e)
    }
    // A complete series matters: missing minutes and contradictory aggregates mean unknown.
    if (byBucket.size !== t.longMinutes || conflicting.size) continue
    const samples = [...byBucket.values()].sort((a, b) => a.at.getTime() - b.at.getTime())
    const burn = (xs: NormalizedEvent[]) => {
      const total = xs.reduce((v, e) => v + Number(e.attrs.total), 0),
        bad = xs.reduce((v, e) => v + Number(e.attrs.bad), 0)
      return { total, bad, rate: total > 0 ? bad / total / (1 - t.successPercent / 100) : 0 }
    }
    const short = burn(samples.slice(-t.shortMinutes)),
      long = burn(samples)
    if (
      short.total < t.minRequests ||
      long.total < t.minRequests ||
      short.rate < t.burnRate ||
      long.rate < t.burnRate
    )
      continue
    const first = samples[0],
      last = samples.at(-1)
    if (!first || !last) continue
    const key = `service-degradation:${identity(s.id, s.serviceId, t.objective)}`
    out.push(
      finding(
        input,
        s,
        key,
        new Date(end),
        `${t.objective}: sustained service degradation`,
        `The ${t.successPercent}% success objective is burning its error budget ${short.rate.toFixed(1)}× over ${t.shortMinutes} minutes and ${long.rate.toFixed(1)}× over ${t.longMinutes} minutes. Both exceed ${t.burnRate}× with sufficient traffic. Check errors or slow requests reported for this objective.`,
        [
          {
            kind: "metric",
            label: `${t.shortMinutes}m error-budget burn rate`,
            value: short.rate,
            baseline: t.burnRate,
            window: { from: new Date(end - t.shortMinutes * MINUTE), to: new Date(end) },
          },
          {
            kind: "metric",
            label: `${t.longMinutes}m error-budget burn rate`,
            value: long.rate,
            baseline: t.burnRate,
            window: { from: first.at, to: new Date(end) },
          },
          ref(first),
          ref(last),
        ],
      ),
    )
  }
  return out
}
