import type { NormalizedEvent } from "../../connectors/types.ts"
import {
  createFinding,
  type DeterministicEvidence,
  type Evidence,
  type EvidenceList,
  type Finding,
  SEVERITY_RANK,
  type Severity,
} from "../finding.ts"
import { classifyChangedPaths, type PathMap } from "../sensitivity.ts"
import { changeRef, prAttrs } from "./sensitiveChange.ts"

// Detector 3 — something got worse right after a deployment.
//
// For each successful production deployment, once its post-deploy window has fully elapsed, compare
// four signals in that window against the same signal over the preceding baseline:
//
//   · errors    — Sentry issues created and error events, custom `error` events
//   · crashes   — Fly machine exits and OOM kills, custom `crash` events
//   · incidents — PagerDuty incidents triggered, Opsgenie alerts created, Datadog monitors triggered
//   · refusals  — the SHARE of INTYGA approvals that ended denied or expired
//
// Incidents have a floor of ONE. The others count noise-prone events; an incident is already a
// human-grade signal that someone's monitoring decided to page on, so one landing in the half hour
// after a deploy is worth a look on its own.
//
// This is TEMPORAL correlation and the finding says so. It is not proof the deploy caused the
// change — a traffic spike or an upstream outage in the same half hour looks identical — so the
// wording is "rose after", never "caused by". What it adds over three separate dashboards is the
// join: the deploy, the change, and, when the deployed commit is a pull request we have seen, which
// sensitive components that diff touched. A regression right after a change to authorization is a
// different conversation from one after a copy edit, and that is the one fact that raises severity.
//
// Guards against noise, each of which exists because the naive version fires constantly:
//   · a FLOOR on the post-window count, so 0 → 2 errors is not an incident
//   · a RATIO against a baseline normalised to the same window length
//   · HISTORY: a signal source must have been observed well before the deploy, or a newly connected
//     Sentry would make the first deploy after connecting it look like a regression
//   · refusals are a RATE with a minimum volume, so a quiet hour with 1 of 2 denied is not 50%

export interface RegressionConfig {
  /** How long after a deploy to watch. */
  postMs: number
  /** How far before it to take the baseline from. */
  baselineMs: number
  /** Post-window rate must be at least this multiple of the baseline rate. */
  ratio: number
  /** Minimum post-window count for the error and crash signals. */
  floor: number
  /** Minimum post-window count for incidents. One page is already a human-grade signal. */
  incidentFloor: number
  /** Minimum terminal approvals in the post window before a refusal RATE means anything. */
  minRefusalVolume: number
  /** Refusal rate must also rise by at least this much, absolute (0.05 = five points). */
  minRefusalRise: number
  /** A signal's source must have an event at least this long before the deploy. */
  minHistoryMs: number
}

export const DEFAULT_REGRESSION_CONFIG: RegressionConfig = {
  postMs: 30 * 60_000,
  baselineMs: 24 * 60 * 60_000,
  ratio: 3,
  floor: 5,
  incidentFloor: 1,
  minRefusalVolume: 20,
  minRefusalRise: 0.05,
  minHistoryMs: 6 * 60 * 60_000,
}

// `custom.*` are the custom webhook's documented kinds (docs/CONNECTORS.md), so any error tracker or
// runtime can feed this detector without a connector of its own.
const ERROR_KINDS = new Set(["sentry.issue.created", "sentry.error", "custom.error"])
const CRASH_KINDS = new Set(["fly.machine.oom", "fly.machine.exit", "custom.crash"])
const INCIDENT_KINDS = new Set([
  "pagerduty.incident.triggered",
  "opsgenie.alert.create",
  "datadog.alert.triggered",
])
const INCIDENT_SOURCES = new Set(["pagerduty", "opsgenie", "datadog"])
const REFUSED_KINDS = new Set(["challenge.denied", "challenge.expired"])
const TERMINAL_KINDS = new Set(["challenge.approved", "challenge.denied", "challenge.expired"])

/** Which signal family an event feeds, for the history guard. */
function family(e: NormalizedEvent): "errors" | "crashes" | "incidents" | "refusals" | null {
  if (INCIDENT_SOURCES.has(e.source)) return "incidents"
  if (e.source === "sentry" || e.kind === "custom.error") return "errors"
  if (e.source === "fly" || e.kind === "custom.crash") return "crashes"
  if (e.source === "intyga" && e.kind.startsWith("challenge.")) return "refusals"
  return null
}

export interface Deploy {
  event: NormalizedEvent
  name: string
  sha: string
}

/** Deploy kinds that follow the shared attrs convention (see `asDeploy`). */
const GENERIC_DEPLOY_KINDS = new Set([
  "custom.deployment",
  "gitlab.deployment",
  "cloudflare.deployment",
  "netlify.deployment",
])

/** Every kind `asDeploy` can accept — what the tick loads as deployment anchors. */
export const DEPLOY_KINDS = ["github.deployment", "vercel.deployment", ...GENERIC_DEPLOY_KINDS]

/** A successful PRODUCTION deployment, or null. Previews and failed deploys anchor nothing. */
export function asDeploy(e: NormalizedEvent): Deploy | null {
  const a = e.attrs as Record<string, unknown>
  if (e.kind === "github.deployment" && a.conclusion === "success") {
    return { event: e, name: String(a.workflow ?? "deploy"), sha: String(a.sha ?? "") }
  }
  if (e.kind === "vercel.deployment" && a.isProduction === true && a.succeeded === true) {
    return { event: e, name: String(a.project ?? "deploy"), sha: String(a.sha ?? "") }
  }
  // Every other deploy source emits one convention: `production` and `succeeded` booleans, a `name`
  // and a `sha`. Production must be SAID; absence is never assumed to mean yes.
  if (GENERIC_DEPLOY_KINDS.has(e.kind) && a.production === true && a.succeeded !== false) {
    return {
      event: e,
      name: String(a.name ?? e.subjectRef ?? "deploy"),
      sha: String(a.sha ?? e.correlationRef ?? ""),
    }
  }
  return null
}

export interface RegressionInput {
  tenantId: string
  /** Deployments whose post window has closed and that have not been evaluated before. */
  deploys: readonly Deploy[]
  /** Every signal event from (earliest deploy − baseline) to (latest deploy + post window). */
  signals: readonly NormalizedEvent[]
  /** Pull-request events, to identify the change a deploy shipped. */
  changes: readonly NormalizedEvent[]
  mapFor: (connectionId: string) => PathMap
  now: Date
  config?: Partial<RegressionConfig>
  idFor?: (dedupeKey: string) => string
}

const SINGULAR: Readonly<Record<string, string>> = {
  errors: "error",
  "machine crashes": "machine crash",
  incidents: "incident",
}

function bump(s: Severity): Severity {
  const order: Severity[] = ["info", "low", "medium", "high", "critical"]
  return order[Math.min(order.length - 1, SEVERITY_RANK[s] + 1)] as Severity
}

export function detectDeployRegressions(input: RegressionInput): Finding[] {
  const cfg = { ...DEFAULT_REGRESSION_CONFIG, ...input.config }
  const findings: Finding[] = []

  // First observation of each signal family, for the history guard.
  const firstSeen = new Map<string, number>()
  for (const e of input.signals) {
    const f = family(e)
    if (!f) continue
    const t = e.at.getTime()
    if (!firstSeen.has(f) || t < (firstSeen.get(f) as number)) firstSeen.set(f, t)
  }

  for (const d of input.deploys) {
    const D = d.event.at.getTime()
    const postEnd = D + cfg.postMs
    const baseStart = D - cfg.baselineMs
    const inPost = (e: NormalizedEvent) => e.at.getTime() >= D && e.at.getTime() < postEnd
    const inBase = (e: NormalizedEvent) => e.at.getTime() >= baseStart && e.at.getTime() < D
    const hasHistory = (f: string) => (firstSeen.get(f) ?? Number.POSITIVE_INFINITY) <= D - cfg.minHistoryMs

    const post = input.signals.filter(inPost)
    const base = input.signals.filter(inBase)
    const scale = cfg.postMs / cfg.baselineMs

    const shipped = changeFor(d.sha, input.changes)
    const sensitive = shipped
      ? classifyChangedPaths(shipped.attrs.paths, {
          truncated: shipped.attrs.truncated,
          map: input.mapFor(shipped.event.connectionId),
        })
      : null
    const touched = sensitive?.hits.map((h) => h.component.id) ?? []

    const signals: {
      key: "errors" | "crashes" | "incidents" | "refusals"
      fired: boolean
      severity: Severity
      category: "engineering" | "security"
      label: string
      value: number
      baseline: number
      headline: string
    }[] = []

    for (const [key, kinds, severity, noun, floor] of [
      ["errors", ERROR_KINDS, "medium", "errors", cfg.floor],
      ["crashes", CRASH_KINDS, "high", "machine crashes", cfg.floor],
      ["incidents", INCIDENT_KINDS, "high", "incidents", cfg.incidentFloor],
    ] as const) {
      if (!hasHistory(key)) continue
      const p = post.filter((e) => kinds.has(e.kind)).length
      const b = base.filter((e) => kinds.has(e.kind)).length * scale
      const fired = p >= floor && (b === 0 || p >= b * cfg.ratio)
      signals.push({
        key,
        fired,
        severity,
        category: "engineering",
        label: `${noun} in the ${cfg.postMs / 60_000}m after deploy`,
        value: p,
        baseline: Math.round(b * 10) / 10,
        headline: `${p} ${p === 1 ? SINGULAR[noun] : noun} in ${cfg.postMs / 60_000}m after deploying ${d.name}`,
      })
    }

    if (hasHistory("refusals")) {
      const rate = (xs: NormalizedEvent[]) => {
        const terminal = xs.filter((e) => TERMINAL_KINDS.has(e.kind))
        const refused = terminal.filter((e) => REFUSED_KINDS.has(e.kind)).length
        return {
          terminal: terminal.length,
          refused,
          rate: terminal.length === 0 ? 0 : refused / terminal.length,
        }
      }
      const p = rate(post)
      const b = rate(base)
      const fired =
        p.terminal >= cfg.minRefusalVolume &&
        p.refused >= cfg.floor &&
        p.rate - b.rate >= cfg.minRefusalRise &&
        (b.rate === 0 || p.rate >= b.rate * cfg.ratio)
      signals.push({
        key: "refusals",
        fired,
        severity: "high",
        category: "security",
        label: `refusal rate in the ${cfg.postMs / 60_000}m after deploy`,
        value: Math.round(p.rate * 1000) / 1000,
        baseline: Math.round(b.rate * 1000) / 1000,
        headline: `Refusal rate rose to ${Math.round(p.rate * 100)}% (from ${Math.round(b.rate * 100)}%) after deploying ${d.name}`,
      })
    }

    for (const s of signals.filter((x) => x.fired)) {
      const dedupeKey = `regression:${d.event.connectionId}:${d.event.sourceId}:${s.key}`
      const depEvidence: DeterministicEvidence = {
        kind: "deployment",
        sha: d.sha,
        workflow: d.name,
        at: d.event.at,
        conclusion: "success",
      }
      const rest: Evidence[] = [
        {
          kind: "metric",
          label: s.label,
          value: s.value,
          baseline: s.baseline,
          window: { from: d.event.at, to: new Date(postEnd) },
        },
      ]
      if (shipped) {
        rest.push({
          kind: "codeChange",
          repo: shipped.attrs.repo,
          pr: shipped.attrs.number,
          sha: shipped.attrs.sha,
          paths: (sensitive?.hits.flatMap((h) => h.paths) ?? []).slice(0, 50),
        })
      }
      const evidence: EvidenceList = [depEvidence, ...rest]

      findings.push(
        createFinding({
          id: input.idFor?.(dedupeKey) ?? dedupeKey,
          tenantId: input.tenantId,
          category: s.category,
          // The one qualitative signal: the shipped diff touched a sensitive component.
          severity: touched.length > 0 ? bump(s.severity) : s.severity,
          title: `${s.headline} (${d.sha.slice(0, 7) || "no commit"})`,
          summary:
            `Compared with the ${cfg.baselineMs / 3_600_000}h before the deploy (${s.baseline}). ` +
            "Timing only — something else in the same window would look the same." +
            (shipped
              ? ` The deploy shipped ${changeRef(shipped.event, shipped.attrs.repo, shipped.attrs.number).noun} ` +
                changeRef(shipped.event, shipped.attrs.repo, shipped.attrs.number).ref +
                (touched.length > 0
                  ? `, which changed ${touched.join(", ")}.`
                  : ", which touched no sensitive component.")
              : ""),
          evidence,
          detectedAt: input.now,
          dedupeKey,
        }),
      )
    }
  }
  return findings
}

/** The pull request a deployed commit came from: its head SHA or, once merged, its merge commit. */
function changeFor(
  sha: string,
  changes: readonly NormalizedEvent[],
): { event: NormalizedEvent; attrs: NonNullable<ReturnType<typeof prAttrs>> } | null {
  if (!sha) return null
  let best: { event: NormalizedEvent; attrs: NonNullable<ReturnType<typeof prAttrs>> } | null = null
  for (const e of changes) {
    const a = prAttrs(e)
    if (!a) continue
    const mergeSha = String((e.attrs as Record<string, unknown>).mergeSha ?? "")
    if (a.sha !== sha && mergeSha !== sha) continue
    if (!best || e.at > best.event.at) best = { event: e, attrs: a }
  }
  return best
}
