import type { NormalizedEvent } from "../connectors/types.ts"
import { detectSensitiveChanges } from "../domain/detectors/sensitiveChange.ts"
import type { CodeChangeEvidence, EventRefEvidence } from "../domain/finding.ts"
import { pathMapFor } from "../domain/sensitivity.ts"
import { prisma } from "./client.ts"

/** Reclassify historical path-only signals without replaying detections, alerts, or model requests. */
export async function reclassifyObservations(tenantId: string, apply = false) {
  const rows = await prisma.finding.findMany({
    where: { tenantId, dedupeKey: { startsWith: "sensitive:" } },
    include: { evidence: true },
  })
  let missingSource = 0
  for (const row of rows) {
    const ref = row.evidence.find((e) => e.kind === "eventRef")?.data as unknown as
      | EventRefEvidence
      | undefined
    const codeRow = row.evidence.find((e) => e.kind === "codeChange")
    const code = codeRow?.data as unknown as CodeChangeEvidence | undefined
    const event = ref
      ? await prisma.event.findFirst({
          where: { tenantId, connectionId: ref.connectionId, sourceId: ref.sourceId },
          include: { connection: { select: { config: true } } },
        })
      : null
    const map = pathMapFor((event?.connection.config as Record<string, unknown> | undefined)?.pathMap)
    const updated = event
      ? detectSensitiveChanges({
          tenantId,
          events: [{ ...event, serviceId: row.serviceId, attrs: event.attrs as NormalizedEvent["attrs"] }],
          now: row.detectedAt,
          mapFor: () => map,
        }).find((f) => f.dedupeKey.startsWith("sensitive:"))
      : undefined
    if (!event) missingSource++
    if (!apply) continue

    await prisma.$transaction(async (tx) => {
      await tx.finding.update({
        where: { id: row.id, tenantId },
        data: {
          category: "engineering",
          severity: "info",
          confidence: null,
          title:
            updated?.title ??
            `Review observation: ${code ? `${code.repo}#${code.pr}` : "historical code change"}`,
          summary:
            updated?.summary ??
            (event
              ? "The current path map finds no reviewable sensitive change in this observation. The original event remains available for context."
              : "Historical path-only observation. The source event is unavailable for reclassification; no anomaly is established."),
        },
      })
      if (codeRow && code && event) {
        const updatedCode = updated?.evidence.find((e) => e.kind === "codeChange")
        await tx.evidence.update({
          where: { id: codeRow.id },
          data: { data: { ...(updatedCode ?? code), paths: updatedCode?.paths ?? [] } },
        })
      }
      // Keep JudgmentRequest as the historical audit record, but retire unsupported card scores.
      await tx.evidence.deleteMany({ where: { findingId: row.id, kind: "assessment" } })
    })
  }
  return { observations: rows.length, missingSource, applied: apply }
}
