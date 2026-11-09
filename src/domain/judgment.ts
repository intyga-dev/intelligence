import type { FindingStatus } from "./finding.ts"
import crypto from "node:crypto"
import { config } from "../config.ts"
import { projectForJudgment } from "../redaction/project.ts"
import { QUESTION_SET } from "../redaction/guidance.ts"
import { prisma } from "../store/client.ts"
import { listFindings } from "../store/repo.ts"
import { providerCredential, providerEndpoint, reviewConfiguration } from "../judgment/configuration.ts"
import { callReviewProvider, reviewPayload, ReviewError } from "../judgment/providers.ts"
import type { ReviewProvider } from "../judgment/settings.ts"
import type { AssessmentEvidence } from "./finding.ts"

export interface JudgmentEvaluationResult {
  ok: boolean
  model?: string
  anomalous?: number | undefined
  confidence?: number | undefined
  error?: string
}

const hash = (value: unknown) => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex")

export async function prepareFindingReview(tenantId: string, findingId: string, requested?: ReviewProvider) {
  const settings = await reviewConfiguration(tenantId)
  if (!settings.enabled) throw new ReviewError("AI reviews are disabled for this workspace")
  const provider = settings.providers.find((p) => p.provider === (requested ?? settings.primaryProvider))
  if (!provider?.configured) throw new ReviewError("Review provider is not configured")
  const finding = (await listFindings(tenantId, { query: findingId, limit: 1 })).find(
    (f) => f.id === findingId,
  )
  if (!finding) throw new ReviewError("Finding not found")
  if (finding.kind === "observation") throw new ReviewError("Review observations are not anomaly evidence")
  const state = projectForJudgment(finding, config.secretsEncKey)
  const payload = reviewPayload(provider, state)
  const endpoint = providerEndpoint(provider.provider)
  // Provider, destination, model and prompt version are part of the identity, not just finding ID.
  const stateDigest = hash({ provider: provider.provider, endpoint, questionSet: QUESTION_SET, payload })
  return { provider, finding, payload, endpoint, stateDigest }
}

/** Advisory only: failures never change finding severity, status, alerting or approval decisions. */
export async function evaluateFindingWithJudgment(
  tenantId: string,
  findingId: string,
  requested?: { provider: ReviewProvider; model: string; stateDigest: string },
): Promise<JudgmentEvaluationResult> {
  let prepared: Awaited<ReturnType<typeof prepareFindingReview>>
  try {
    prepared = await prepareFindingReview(tenantId, findingId, requested?.provider)
    if (
      requested &&
      (prepared.stateDigest !== requested.stateDigest || prepared.provider.model !== requested.model)
    )
      throw new ReviewError("The finding or provider settings changed; open a new review approval")
  } catch (error) {
    return { ok: false, error: error instanceof ReviewError ? error.message : "Could not prepare review" }
  }
  const { provider, finding, payload, endpoint, stateDigest } = prepared
  const credential = await providerCredential(tenantId, provider.provider)
  if (!credential) return { ok: false, error: "Review credential is unavailable" }
  const now = new Date()
  const day = new Date(now)
  day.setUTCHours(0, 0, 0, 0)
  const reservation = await prisma.$transaction(async (tx) => {
    // Serialize reservations across processes. Failed and timed-out requests also consume budget.
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${tenantId}), hashtext('judgment'))`
    const existing = await tx.judgmentRequest.findFirst({
      where: {
        tenantId,
        findingId,
        provider: provider.provider,
        stateDigest,
        OR: [{ status: "DONE" }, { createdAt: { gte: new Date(now.getTime() - 300000) } }],
      },
      orderBy: { createdAt: "desc" },
    })
    if (existing)
      return {
        error:
          existing.status === "DONE" ? "cached" : "This review was recently requested; wait before retrying",
      }
    const active = await tx.judgmentRequest.count({
      where: { tenantId, status: "SENDING", createdAt: { gte: new Date(now.getTime() - 120000) } },
    })
    if (active) return { error: "A review is already running; try again shortly" }
    const used = await tx.judgmentRequest.count({
      where: { tenantId, provider: provider.provider, createdAt: { gte: day } },
    })
    if (used >= provider.dailyRequestLimit)
      return { error: "Provider daily request limit reached (resets at midnight UTC)" }
    const row = await tx.judgmentRequest.create({
      data: {
        tenantId,
        findingId,
        provider: provider.provider,
        model: provider.model,
        questionSet: QUESTION_SET,
        status: "SENDING",
        attempts: 1,
        sentState: payload,
        stateDigest,
      },
    })
    return { id: row.id }
  })
  if (!reservation.id)
    return reservation.error === "cached"
      ? { ok: true, model: provider.model }
      : { ok: false, error: reservation.error ?? "Could not reserve review" }
  try {
    // Recheck the approved configuration just before dispatch; never silently switch providers.
    const current = await prepareFindingReview(tenantId, findingId, provider.provider)
    if (current.stateDigest !== stateDigest) throw new ReviewError("Review context changed before dispatch")
    const data = await callReviewProvider({ provider, endpoint, credential, payload })
    await prisma.$transaction(async (tx) => {
      // Keep the audit even if the finding changed while the network request was in flight.
      await tx.judgmentRequest.update({
        where: { id: reservation.id, tenantId },
        data: { status: "DONE", response: data as object, completedAt: new Date() },
      })
      await tx.$queryRaw`SELECT id FROM "Finding" WHERE id = ${findingId}::uuid AND "tenantId" = ${tenantId}::uuid FOR UPDATE`
      const unchanged = await tx.finding.findFirst({
        where: {
          id: findingId,
          tenantId,
          count: finding.count,
          status: finding.status as FindingStatus,
          severity: finding.severity,
          lastSeenAt: finding.lastSeenAt,
        },
      })
      if (!unchanged) return
      // Replace only this provider's current opinion; other providers stay independent.
      await tx.evidence.deleteMany({
        where: { findingId, kind: "assessment", data: { path: ["provider"], equals: provider.provider } },
      })
      const last = await tx.evidence.aggregate({ where: { findingId }, _max: { ordinal: true } })
      const evidence: AssessmentEvidence = {
        kind: "assessment",
        provider: provider.provider,
        model: data.model,
        question: "anomalous",
        answer: data.review.anomalous ?? "insufficient evidence",
        ...(data.review.anomalous !== null ? { probability: data.review.anomalous } : {}),
        ...(data.severityConfidence !== undefined
          ? { confidence: data.severityConfidence, confidenceFor: "severity" }
          : {}),
        stateDigest,
        reviewedAt: new Date().toISOString(),
        review: data.review,
      }
      await tx.evidence.create({
        data: {
          findingId,
          kind: "assessment",
          ordinal: (last._max.ordinal ?? -1) + 1,
          data: evidence as object,
        },
      })
    })
    return {
      ok: true,
      model: data.model,
      anomalous: data.review.anomalous ?? undefined,
      confidence: data.severityConfidence,
    }
  } catch (error) {
    const message = error instanceof ReviewError ? error.message : "Could not complete or save the review"
    await prisma.judgmentRequest.updateMany({
      where: { id: reservation.id, tenantId, status: "SENDING" },
      data: { status: "FAILED", lastError: message, completedAt: new Date() },
    })
    return { ok: false, error: message }
  }
}
