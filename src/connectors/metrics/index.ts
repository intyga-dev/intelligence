import type { ConnectorContext, PollConnector } from "../registry.ts"
import type { NormalizedEvent } from "../types.ts"

// Prometheus-compatible metrics.
//
// This is the connector that closes the biggest structural gap. Intyga's webhook feed carries six
// challenge-lifecycle events and nothing else — AUTH_FAILED, RATE_LIMITED, SIGNATURE_REJECTED and
// AGENT_AUTHORITY_VIOLATION never appear there. But every one of them is an `intyga_*` counter on
// the gateway's /internal/metrics, which is already scraped with a read-only token. So the signals
// the push feed cannot carry are recoverable here, with no change to Intyga at all.
//
// Works against anything speaking the Prometheus HTTP API: Prometheus itself, Grafana Mimir,
// Better Stack, VictoriaMetrics. Deliberately not tied to one vendor.
//
// Samples are stored as-is and detectors diff them. A connector that decided what counts as a
// "spike" would be a detector wearing a connector's clothes, and would need redeploying to retune.

const MAX_QUERIES = 25
const TIMEOUT_MS = 15_000

/** The signals worth watching by default — every one of them a gap in the webhook feed. */
const DEFAULT_QUERIES = [
  "intyga_audit_write_failures_total",
  "intyga_challenge_replay_guard_degraded_total",
  "intyga_approval_requirement_unavailable_total",
  "intyga_notification_failures_total",
  "intyga_billing_refusals_total",
  "intyga_watermark_age_seconds",
  "intyga_ledger_broken_blocks",
  "intyga_ledger_broken_checkpoints",
  "intyga_checkpoints_unanchored",
  "intyga_audit_oldest_unsealed_age_seconds",
].join(", ")

interface PromResult {
  status: string
  data?: {
    resultType: string
    result: { metric: Record<string, string>; value: [number, string] }[]
  }
}

function queries(ctx: ConnectorContext): string[] {
  return String(ctx.config.queries || DEFAULT_QUERIES)
    .split(/[\n,]+/)
    .map((q) => q.trim())
    .filter(Boolean)
    .slice(0, MAX_QUERIES)
}

export const metricsConnector: PollConnector = {
  kind: "metrics",
  mode: "poll",
  label: "Metrics (Prometheus)",
  blurb:
    "Counters and gauges the webhook feed cannot carry — auth failures, rate limiting, rejected signatures, ledger health.",

  fields: [
    {
      name: "baseUrl",
      label: "Query API base URL",
      placeholder: "https://prometheus.example.com",
      help: "Anything speaking the Prometheus HTTP API. /api/v1/query is appended.",
      required: true,
    },
    {
      name: "queries",
      label: "Queries",
      placeholder: DEFAULT_QUERIES,
      help: "PromQL expressions or bare metric names, comma separated. Leave blank for the Intyga defaults.",
    },
    {
      name: "token",
      label: "Bearer token",
      help: "A READ-ONLY scrape token. The gateway's METRICS_SCRAPE_TOKEN is exactly this — never METRICS_TOKEN, which opens 33 routes.",
      secret: true,
    },
  ],

  setup: [
    "Point this at whatever already scrapes your gateway — Prometheus, Better Stack or Mimir.",
    "Use the read-only scrape token, not the metrics superset token.",
    "Leave the queries blank to watch the default Intyga security and ledger signals.",
    "Samples arrive each tick; detectors compare them against previous samples.",
  ],

  async poll(ctx: ConnectorContext): Promise<NormalizedEvent[]> {
    const base = String(ctx.config.baseUrl ?? "").replace(/\/+$/, "")
    if (!base) return []
    const out: NormalizedEvent[] = []
    // One bucket per tick: sampling the same series twice within a bucket would make a counter look
    // like it moved when only the clock did.
    const bucket = new Date(Math.floor(Date.now() / 60_000) * 60_000)

    for (const q of queries(ctx)) {
      const ac = new AbortController()
      const timer = setTimeout(() => ac.abort(), TIMEOUT_MS)
      try {
        const res = await fetch(`${base}/api/v1/query?query=${encodeURIComponent(q)}`, {
          headers: ctx.secret ? { authorization: `Bearer ${ctx.secret}` } : {},
          signal: ac.signal,
        })
        if (!res.ok) {
          ctx.log("metrics query failed", { query: q, status: res.status })
          continue
        }
        const body = (await res.json()) as PromResult
        if (body.status !== "success" || !body.data) continue

        for (const series of body.data.result) {
          const value = Number(series.value[1])
          if (!Number.isFinite(value)) continue
          const name = series.metric.__name__ ?? q
          // Labels minus __name__, joined stably, so one series is one subject across ticks.
          const labels = Object.entries(series.metric)
            .filter(([k]) => k !== "__name__")
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([k, v]) => `${k}=${v}`)
            .join(",")
          const seriesKey = labels ? `${name}{${labels}}` : name

          out.push({
            connectionId: ctx.connectionId,
            source: "metrics",
            // Bucketed, so a tick that runs twice in one minute is idempotent rather than a
            // duplicate sample that would read as a flat delta.
            sourceId: `sample:${seriesKey}@${bucket.toISOString()}`,
            kind: "metrics.sample",
            at: bucket,
            subjectRef: seriesKey,
            correlationRef: name,
            attrs: { metric: name, labels, value, query: q },
          })
        }
      } catch (err) {
        ctx.log("metrics query errored", { query: q, err: (err as Error).message })
      } finally {
        clearTimeout(timer)
      }
    }
    return out
  },
}
