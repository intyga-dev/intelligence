import type { NormalizedEvent } from "../connectors/types.ts"
import type { Evidence, Finding, Severity } from "../domain/finding.ts"
import { prisma } from "./client.ts"

// The query layer. This database has one trusted writer and no row-level security, so tenant
// isolation lives HERE and nowhere else — which means it has to be unmissable rather than
// conventional. Every exported function that reads or writes tenant data takes `tenantId` as its
// first argument and puts it in the `where`. A function that does not is a bug, and the test suite
// checks the ones that matter.

/** Postgres unique-violation, however Prisma happens to surface it. */
function isUniqueViolation(err: unknown): boolean {
  const code = (err as { code?: string })?.code
  return code === "P2002" || code === "23505"
}

/** Idempotent raw capture. Returns false when this delivery has already been seen. */
export async function recordRawEvent(input: {
  connectionId: string
  sourceId: string
  body: unknown
}): Promise<{ created: boolean; id: string }> {
  // Delivery is at-least-once, so a duplicate is the NORMAL case, not an error.
  //
  // Insert-and-catch rather than upsert: the unique violation is the only unambiguous "this is a
  // redelivery" signal. Inspecting a column instead cannot distinguish a row created microseconds
  // ago from a redelivery whose first normalization failed — both look identical.
  try {
    const row = await prisma.rawEvent.create({
      data: {
        connectionId: input.connectionId,
        sourceId: input.sourceId,
        body: input.body as object,
      },
      select: { id: true },
    })
    return { created: true, id: row.id }
  } catch (err) {
    if (!isUniqueViolation(err)) throw err
    const existing = await prisma.rawEvent.findUniqueOrThrow({
      where: {
        connectionId_sourceId: { connectionId: input.connectionId, sourceId: input.sourceId },
      },
      select: { id: true },
    })
    return { created: false, id: existing.id }
  }
}

export async function markRawNormalized(id: string, error?: string): Promise<void> {
  await prisma.rawEvent.update({
    where: { id },
    data: { normalizedAt: new Date(), normalizeError: error ?? null },
  })
}

/** Idempotent normalized insert, keyed on the source's own event id. */
export async function saveEvent(tenantId: string, e: NormalizedEvent): Promise<void> {
  await prisma.event.upsert({
    where: { connectionId_sourceId: { connectionId: e.connectionId, sourceId: e.sourceId } },
    create: {
      tenantId,
      connectionId: e.connectionId,
      source: e.source,
      sourceId: e.sourceId,
      kind: e.kind,
      at: e.at,
      subjectRef: e.subjectRef,
      correlationRef: e.correlationRef,
      attrs: e.attrs as object,
    },
    update: {},
  })
}

/**
 * Events a detector needs: one tenant, one kind-set, one time range.
 *
 * Capped. A detector is a periodic job over a rolling window, and an uncapped read is how a query
 * that is fine for months becomes an outage the week traffic grows.
 */
export async function loadEvents(
  tenantId: string,
  opts: { kinds?: string[]; since: Date; until?: Date; limit?: number },
): Promise<NormalizedEvent[]> {
  const rows = await prisma.event.findMany({
    where: {
      tenantId,
      ...(opts.kinds?.length ? { kind: { in: opts.kinds } } : {}),
      at: { gte: opts.since, ...(opts.until ? { lte: opts.until } : {}) },
    },
    orderBy: { at: "desc" },
    take: opts.limit ?? 50_000,
  })
  return rows.map((r) => ({
    connectionId: r.connectionId,
    source: r.source,
    sourceId: r.sourceId,
    kind: r.kind,
    at: r.at,
    subjectRef: r.subjectRef,
    correlationRef: r.correlationRef,
    attrs: r.attrs as NormalizedEvent["attrs"],
  }))
}

/**
 * Write a finding, folding a repeat into the existing row.
 *
 * The unique key is (tenantId, dedupeKey) and that is what keeps the list short: an ongoing
 * condition updates count/lastSeenAt instead of adding a row every tick. Evidence is replaced
 * wholesale rather than appended — the newest observation's evidence is the accurate one, and
 * accumulating every tick's copy would bury the reader.
 */
export async function upsertFinding(f: Finding): Promise<{ id: string; isNew: boolean }> {
  return prisma.$transaction(async (tx) => {
    const existing = await tx.finding.findUnique({
      where: { tenantId_dedupeKey: { tenantId: f.tenantId, dedupeKey: f.dedupeKey } },
      select: { id: true, count: true, severity: true, status: true },
    })

    const writeEvidence = async (findingId: string) => {
      await tx.evidence.deleteMany({ where: { findingId } })
      await tx.evidence.createMany({
        data: f.evidence.map((e, i) => ({
          findingId,
          kind: e.kind,
          ordinal: i,
          data: e as object,
        })),
      })
    }

    if (!existing) {
      const created = await tx.finding.create({
        data: {
          tenantId: f.tenantId,
          category: f.category,
          severity: f.severity,
          title: f.title,
          summary: f.summary ?? null,
          confidence: f.confidence ?? null,
          detectedAt: f.detectedAt,
          lastSeenAt: f.lastSeenAt,
          count: f.count,
          dedupeKey: f.dedupeKey,
        },
        select: { id: true },
      })
      await writeEvidence(created.id)
      return { id: created.id, isNew: true }
    }

    // Severity ratchets up but never down: a condition that was once critical does not become
    // medium because the most recent window was quieter. A human closes it, not a quiet tick.
    const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }
    const severity = rank[f.severity] > rank[existing.severity] ? f.severity : existing.severity

    await tx.finding.update({
      where: { id: existing.id },
      data: {
        severity,
        title: f.title,
        summary: f.summary ?? null,
        lastSeenAt: f.lastSeenAt,
        count: existing.count + 1,
        // A resolved or dismissed finding that recurs is genuinely new information, so it reopens.
        status: existing.status === "resolved" || existing.status === "dismissed" ? "new" : existing.status,
      },
    })
    await writeEvidence(existing.id)
    return { id: existing.id, isNew: false }
  })
}

export interface FindingListItem {
  id: string
  category: string
  severity: Severity
  title: string
  summary: string | null
  detectedAt: Date
  lastSeenAt: Date
  count: number
  status: string
  evidence: Evidence[]
  feedback: { verdict: string; actor: string; createdAt: Date }[]
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const

/** The findings list, most severe first. The product surface. */
export async function listFindings(
  tenantId: string,
  opts: { status?: string[]; limit?: number } = {},
): Promise<FindingListItem[]> {
  const rows = await prisma.finding.findMany({
    where: {
      tenantId,
      ...(opts.status?.length ? { status: { in: opts.status as never[] } } : {}),
    },
    include: {
      evidence: { orderBy: { ordinal: "asc" } },
      feedback: { orderBy: { createdAt: "desc" }, take: 5 },
    },
    orderBy: { lastSeenAt: "desc" },
    take: opts.limit ?? 100,
  })

  // Severity is an enum, and Postgres orders enums by declaration order — which here runs
  // info → critical, the opposite of what the page wants. Sorting in JS over a capped list is
  // cheaper to read than a CASE expression and cannot silently invert if the enum is reordered.
  return rows
    .map((r) => ({
      id: r.id,
      category: r.category,
      severity: r.severity as Severity,
      title: r.title,
      summary: r.summary,
      detectedAt: r.detectedAt,
      lastSeenAt: r.lastSeenAt,
      count: r.count,
      status: r.status,
      evidence: r.evidence.map((e) => e.data as unknown as Evidence),
      feedback: r.feedback.map((f) => ({ verdict: f.verdict, actor: f.actor, createdAt: f.createdAt })),
    }))
    .sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
        b.lastSeenAt.getTime() - a.lastSeenAt.getTime(),
    )
}

export type FeedbackVerdict =
  | "useful"
  | "not_useful"
  | "investigating"
  | "expected"
  | "false_positive"
  | "fixed"

/** Which verdicts imply a status change. Feedback is append-only; status is derived from it. */
const STATUS_FOR: Partial<Record<FeedbackVerdict, "investigating" | "resolved" | "dismissed">> = {
  investigating: "investigating",
  fixed: "resolved",
  expected: "dismissed",
  false_positive: "dismissed",
  not_useful: "dismissed",
}

export async function recordFeedback(
  tenantId: string,
  findingId: string,
  input: { actor: string; verdict: FeedbackVerdict; note?: string },
): Promise<boolean> {
  // Scoped by tenant so a findingId from another tenant cannot be written through.
  const finding = await prisma.finding.findFirst({
    where: { id: findingId, tenantId },
    select: { id: true },
  })
  if (!finding) return false

  await prisma.$transaction(async (tx) => {
    await tx.findingFeedback.create({
      data: { findingId, actor: input.actor, verdict: input.verdict, note: input.note ?? null },
    })
    const next = STATUS_FOR[input.verdict]
    if (next) await tx.finding.update({ where: { id: findingId }, data: { status: next } })
  })
  return true
}

export async function getCursor(connectionId: string, name: string): Promise<string | null> {
  const row = await prisma.sourceCursor.findUnique({
    where: { connectionId_name: { connectionId, name } },
    select: { value: true },
  })
  return row?.value ?? null
}

export async function setCursor(connectionId: string, name: string, value: string): Promise<void> {
  await prisma.sourceCursor.upsert({
    where: { connectionId_name: { connectionId, name } },
    create: { connectionId, name, value },
    update: { value },
  })
}

export async function activeConnections(kind?: "intyga" | "github") {
  return prisma.connection.findMany({
    where: { active: true, ...(kind ? { kind } : {}) },
    select: { id: true, tenantId: true, kind: true, label: true, config: true },
  })
}

/**
 * Resolve an ingest target.
 *
 * Deliberately NOT filtered on `active`: an inactive connector must still verify its signature and
 * answer 200, or the producer retries, backs off and eventually disables the endpoint — so turning
 * the connector off for an afternoon would quietly cost you the webhook registration. The caller
 * accepts and discards instead.
 */
export async function connectionForIngest(id: string, kind: string) {
  return prisma.connection.findFirst({
    where: { id, kind },
    select: { id: true, tenantId: true, secretCiphertext: true, active: true },
  })
}
