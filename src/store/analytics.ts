import type { Point } from "../ui/charts.ts"
import { prisma } from "./client.ts"

// Aggregates for the dashboard.
//
// Bucketed in SQL with date_trunc rather than by streaming rows into JS: these queries are on the
// page someone opens during an incident, and "fine until the table grew" is not a property worth
// shipping. Every query is tenant-scoped in its WHERE clause, and the interval is a validated
// literal rather than interpolated user input.

const REFUSAL_KINDS = ["challenge.denied", "challenge.expired"]

export type Grain = "hour" | "day"

/** Fill gaps so a quiet period reads as zero rather than as a missing bucket. */
function densify(
  rows: { bucket: Date; n: bigint | number }[],
  since: Date,
  until: Date,
  grain: Grain,
): Point[] {
  const step = grain === "hour" ? 3_600_000 : 86_400_000
  const byTime = new Map(rows.map((r) => [new Date(r.bucket).getTime(), Number(r.n)]))
  const out: Point[] = []
  const start = Math.floor(since.getTime() / step) * step
  for (let t = start; t <= until.getTime(); t += step) {
    out.push({ at: new Date(t), value: byTime.get(t) ?? 0 })
  }
  return out
}

async function bucketed(
  tenantId: string,
  since: Date,
  grain: Grain,
  kinds?: string[],
): Promise<{ bucket: Date; n: bigint }[]> {
  // `grain` is a checked union, never interpolated user text — Prisma.sql cannot parameterise an
  // interval unit, so the safety has to come from the type.
  if (kinds?.length) {
    return grain === "hour"
      ? prisma.$queryRaw`SELECT date_trunc('hour', "at") AS bucket, count(*)::bigint AS n FROM "Event"
           WHERE "tenantId"=${tenantId}::uuid AND "at">=${since} AND "kind"=ANY(${kinds}) GROUP BY 1 ORDER BY 1`
      : prisma.$queryRaw`SELECT date_trunc('day', "at") AS bucket, count(*)::bigint AS n FROM "Event"
           WHERE "tenantId"=${tenantId}::uuid AND "at">=${since} AND "kind"=ANY(${kinds}) GROUP BY 1 ORDER BY 1`
  }
  return grain === "hour"
    ? prisma.$queryRaw`SELECT date_trunc('hour', "at") AS bucket, count(*)::bigint AS n FROM "Event"
         WHERE "tenantId"=${tenantId}::uuid AND "at">=${since} GROUP BY 1 ORDER BY 1`
    : prisma.$queryRaw`SELECT date_trunc('day', "at") AS bucket, count(*)::bigint AS n FROM "Event"
         WHERE "tenantId"=${tenantId}::uuid AND "at">=${since} GROUP BY 1 ORDER BY 1`
}

export async function eventSeries(tenantId: string, since: Date, grain: Grain): Promise<Point[]> {
  return densify(await bucketed(tenantId, since, grain), since, new Date(), grain)
}

export async function refusalSeries(tenantId: string, since: Date, grain: Grain): Promise<Point[]> {
  return densify(await bucketed(tenantId, since, grain, REFUSAL_KINDS), since, new Date(), grain)
}

export async function topSubjects(
  tenantId: string,
  since: Date,
  limit = 8,
): Promise<{ label: string; value: number }[]> {
  const rows = await prisma.event.groupBy({
    by: ["subjectRef"],
    where: { tenantId, at: { gte: since }, kind: { in: REFUSAL_KINDS }, subjectRef: { not: null } },
    _count: { _all: true },
    orderBy: { _count: { subjectRef: "desc" } },
    take: limit,
  })
  return rows.map((r) => ({ label: r.subjectRef ?? "unknown", value: r._count._all }))
}

export async function topActionTypes(
  tenantId: string,
  since: Date,
  limit = 8,
): Promise<{ label: string; value: number }[]> {
  const rows = await prisma.$queryRaw<{ action: string | null; n: bigint }[]>`
    SELECT "attrs"->>'actionType' AS action, count(*)::bigint AS n FROM "Event"
    WHERE "tenantId"=${tenantId}::uuid AND "at">=${since} AND "attrs"->>'actionType' IS NOT NULL
    GROUP BY 1 ORDER BY n DESC LIMIT ${limit}`
  return rows.map((r) => ({ label: r.action ?? "unknown", value: Number(r.n) }))
}

const LATENCY_BUCKETS: { label: string; maxMs: number }[] = [
  { label: "<30s", maxMs: 30_000 },
  { label: "<2m", maxMs: 120_000 },
  { label: "<5m", maxMs: 300_000 },
  { label: "<15m", maxMs: 900_000 },
  { label: "<1h", maxMs: 3_600_000 },
  { label: "1h+", maxMs: Number.POSITIVE_INFINITY },
]

/** Approval latency — the one derived measure this feed gives us for free. */
export async function latencyHistogram(
  tenantId: string,
  since: Date,
): Promise<{ label: string; count: number }[]> {
  const rows = await prisma.$queryRaw<{ ms: number }[]>`
    SELECT ("attrs"->>'latencyMs')::float AS ms FROM "Event"
    WHERE "tenantId"=${tenantId}::uuid AND "at">=${since}
      AND "kind"='challenge.approved' AND "attrs"->>'latencyMs' IS NOT NULL
    LIMIT 20000`
  const out = LATENCY_BUCKETS.map((b) => ({ label: b.label, count: 0 }))
  for (const r of rows) {
    const i = LATENCY_BUCKETS.findIndex((b) => r.ms < b.maxMs)
    const slot = out[i === -1 ? out.length - 1 : i]
    if (slot) slot.count++
  }
  return out
}

export interface Overview {
  eventsWindow: number
  refusalsWindow: number
  refusalRatePct: number | null
  openFindings: number
  criticalFindings: number
  activeConnectors: number
  totalConnectors: number
  lastEventAt: Date | null
}

export async function overview(tenantId: string, since: Date): Promise<Overview> {
  const [events, refusals, open, critical, connectors, active, last] = await Promise.all([
    prisma.event.count({ where: { tenantId, at: { gte: since } } }),
    prisma.event.count({ where: { tenantId, at: { gte: since }, kind: { in: REFUSAL_KINDS } } }),
    prisma.finding.count({ where: { tenantId, status: { in: ["new", "investigating"] } } }),
    prisma.finding.count({
      where: { tenantId, status: { in: ["new", "investigating"] }, severity: "critical" },
    }),
    prisma.connection.count({ where: { tenantId } }),
    prisma.connection.count({ where: { tenantId, active: true } }),
    prisma.event.findFirst({ where: { tenantId }, orderBy: { at: "desc" }, select: { at: true } }),
  ])
  return {
    eventsWindow: events,
    refusalsWindow: refusals,
    // Null rather than 0 when nothing happened: "0% refused" and "nothing observed" are different
    // facts and a dashboard that conflates them is lying quietly.
    refusalRatePct: events > 0 ? Math.round((refusals / events) * 1000) / 10 : null,
    openFindings: open,
    criticalFindings: critical,
    activeConnectors: active,
    totalConnectors: connectors,
    lastEventAt: last?.at ?? null,
  }
}
