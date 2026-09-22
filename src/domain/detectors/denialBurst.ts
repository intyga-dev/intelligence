import type { NormalizedEvent } from "../../connectors/types.ts"
import {
  createFinding,
  type DeterministicEvidence,
  type EvidenceList,
  type Finding,
  type Severity,
} from "../finding.ts"

// Detector 1 — a subject being refused far more than it usually is.
//
// This answers the brief's own worked example directly:
//
//   "17 rejected operations from the same integration occurred within 8 minutes. 12 attempted
//    permission-modifying operations and differ from the integration's previous observed behavior."
//
// Both halves are arithmetic over a grouped event list: the count against the subject's OWN
// trailing baseline, and the set difference between action types seen now and action types ever
// seen before. No model is involved in deciding that this fired — a model is only asked, later and
// optionally, whether the behaviour is expected.
//
// The two guards that keep this from being noise:
//   · an absolute FLOOR, so a subject that normally does nothing going 0 → 3 is not a "300% spike";
//   · a per-subject baseline, so a busy integration is judged against itself rather than against a
//     platform average it would always exceed.

export interface BurstConfig {
  /** Length of the observation window. */
  windowMs: number
  /** How far back to derive the subject's own baseline. */
  baselineMs: number
  /** Minimum absolute count before anything can fire. The main noise guard. */
  floor: number
  /** Window count must exceed this multiple of the baseline. */
  ratio: number
}

export const DEFAULT_BURST_CONFIG: BurstConfig = {
  windowMs: 8 * 60_000,
  baselineMs: 7 * 24 * 60 * 60_000,
  floor: 10,
  ratio: 5,
}

/** Event kinds that mean "this attempt did not result in an approval". */
const REFUSAL_KINDS = new Set(["challenge.denied", "challenge.expired"])

export interface BurstInput {
  tenantId: string
  events: readonly NormalizedEvent[]
  now: Date
  config?: Partial<BurstConfig>
  /** Injected so findings are deterministic in tests; defaults to the dedupe key. */
  idFor?: (dedupeKey: string) => string
}

/** Nearest-rank median. Empty input is 0 — "no prior activity", which the floor then guards. */
export function median(values: readonly number[]): number {
  if (values.length === 0) return 0
  const xs = [...values].sort((a, b) => a - b)
  const mid = Math.floor(xs.length / 2)
  if (xs.length % 2 === 1) return xs[mid] ?? 0
  return ((xs[mid - 1] ?? 0) + (xs[mid] ?? 0)) / 2
}

/**
 * Count a subject's refusals in each complete window-sized bucket across its OBSERVED history.
 *
 * Bucketed rather than averaged so the baseline reflects what a NORMAL eight minutes looks like for
 * this subject. A flat rate-per-hour would smear a spiky-but-normal integration into a low number
 * and make every one of its ordinary spikes look like an incident.
 *
 * The subtlety is where the baseline STARTS. Tiling the full baseline period would, for a subject
 * first seen five hours ago, produce ~1200 empty buckets and a median of zero — so its perfectly
 * ordinary rate would divide against 1 and read as a spike. Every newly-connected integration would
 * fire on its first busy minute, which is exactly the false positive that makes people stop reading
 * the list. So the window is clamped to the subject's first observation: we judge it against as
 * much of its own history as we actually have, and no more.
 */
function baselineBuckets(
  times: readonly number[],
  windowStart: number,
  baselineStart: number,
  windowMs: number,
): number[] {
  const prior = times.filter((t) => t < windowStart)
  if (prior.length === 0) return []
  const effectiveStart = Math.max(baselineStart, Math.min(...prior))
  const buckets: number[] = []
  for (let end = windowStart; end - windowMs >= effectiveStart; end -= windowMs) {
    const start = end - windowMs
    buckets.push(prior.filter((t) => t >= start && t < end).length)
  }
  return buckets
}

function severityFor(count: number, baseline: number, novelCount: number, floor: number): Severity {
  // Novel action types are the qualitative signal — a subject doing MORE of what it always does is
  // weaker evidence than a subject doing something it has never done.
  if (novelCount > 0 && count >= floor * 2) return "critical"
  if (novelCount > 0) return "high"
  if (count >= floor * 3 || (baseline > 0 && count >= baseline * 10)) return "high"
  return "medium"
}

export function detectDenialBursts(input: BurstInput): Finding[] {
  const cfg = { ...DEFAULT_BURST_CONFIG, ...input.config }
  const now = input.now.getTime()
  const windowStart = now - cfg.windowMs
  const baselineStart = windowStart - cfg.baselineMs

  // Group by the subject a finding would be attributed to. Events with no requester DID are
  // deliberately skipped: a finding nobody can act on is worse than no finding.
  const bySubject = new Map<string, NormalizedEvent[]>()
  for (const e of input.events) {
    if (!REFUSAL_KINDS.has(e.kind) || !e.subjectRef) continue
    const key = `${e.connectionId}\u0000${e.subjectRef}`
    const list = bySubject.get(key)
    if (list) list.push(e)
    else bySubject.set(key, [e])
  }

  const findings: Finding[] = []

  for (const [key, events] of bySubject) {
    const [connectionId = "", subjectRef = ""] = key.split("\u0000")
    const times = events.map((e) => e.at.getTime())

    const inWindow = events.filter((e) => {
      const t = e.at.getTime()
      return t >= windowStart && t <= now
    })
    if (inWindow.length < cfg.floor) continue

    const baseline = median(baselineBuckets(times, windowStart, baselineStart, cfg.windowMs))
    // max(baseline, 1) both avoids a divide-by-zero and means a first-ever burst is judged on the
    // floor alone rather than on an undefined ratio.
    if (inWindow.length < cfg.ratio * Math.max(baseline, 1)) continue

    // What was attempted now, versus everything this subject has ever been seen attempting.
    const actionsNow = new Set(
      inWindow.map((e) => e.attrs.actionType).filter((a): a is string => typeof a === "string"),
    )
    const actionsBefore = new Set(
      events
        .filter((e) => e.at.getTime() < windowStart)
        .map((e) => e.attrs.actionType)
        .filter((a): a is string => typeof a === "string"),
    )
    const novel = [...actionsNow].filter((a) => !actionsBefore.has(a)).sort()

    const window = { from: new Date(windowStart), to: new Date(now) }
    const severity = severityFor(inWindow.length, baseline, novel.length, cfg.floor)

    const evidence: DeterministicEvidence[] = [
      {
        kind: "metric",
        label: "refusals in window",
        value: inWindow.length,
        baseline,
        window,
      },
    ]

    // Per-action breakdown — the "12 attempted permission-modifying operations" half of the
    // example. Sorted by count so the biggest contributor reads first.
    const perAction = [...actionsNow]
      .map((a) => ({ a, n: inWindow.filter((e) => e.attrs.actionType === a).length }))
      .sort((x, y) => y.n - x.n)
    for (const { a, n } of perAction) {
      evidence.push({ kind: "metric", label: `action: ${a}`, value: n, window })
    }

    if (novel.length > 0) {
      evidence.push({
        kind: "metric",
        label: `action types never seen from this subject before: ${novel.join(", ")}`,
        value: novel.length,
        window,
      })
    }

    // Cap the event references: they exist so a human can go and look, not to mirror the feed.
    for (const e of inWindow.slice(0, 10)) {
      evidence.push({
        kind: "eventRef",
        connectionId: e.connectionId,
        sourceId: e.sourceId,
        at: e.at,
        eventKind: e.kind,
      })
    }

    const dedupeKey = `burst:${connectionId}:${subjectRef}`
    const [first, ...rest] = evidence as [DeterministicEvidence, ...DeterministicEvidence[]]

    findings.push(
      createFinding({
        id: input.idFor?.(dedupeKey) ?? dedupeKey,
        tenantId: input.tenantId,
        category: "security",
        severity,
        title: `${inWindow.length} refused operations from ${subjectRef}`,
        summary:
          `${inWindow.length} operations from this subject were denied or expired within ` +
          `${Math.round(cfg.windowMs / 60_000)} minutes, against a typical ${baseline} for the same ` +
          `window length.` +
          (novel.length > 0
            ? ` ${novel.length} action type(s) had never been seen from it before: ${novel.join(", ")}.`
            : ""),
        evidence: [first, ...rest] as unknown as EvidenceList,
        detectedAt: new Date(now),
        dedupeKey,
      }),
    )
  }

  return findings
}
