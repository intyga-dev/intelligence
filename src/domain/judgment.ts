import crypto from "node:crypto"
import { config } from "../config.ts"
import { previewRequest, projectForJudgment } from "../redaction/project.ts"
import { prisma } from "../store/client.ts"
import { listFindings } from "../store/repo.ts"

export interface JudgmentEvaluationResult {
  ok: boolean
  model?: string
  /**
   * Explicitly `| undefined`, not merely optional.
   *
   * Under `exactOptionalPropertyTypes` an absent property and a present `undefined` one are
   * different types, and the provider genuinely answers only part of the question set for some
   * findings. Widening here says that out loud; the alternative is a conditional spread at every
   * call site to express the same fact.
   */
  anomalous?: number | undefined
  confidence?: number | undefined
  error?: string
}

/**
 * Evaluates a Finding against the TypeSafe AI / JEV systemone endpoint,
 * attaching the probabilistic assessment evidence and writing the JudgmentRequest record.
 */
export async function evaluateFindingWithJudgment(
  tenantId: string,
  findingId: string,
): Promise<JudgmentEvaluationResult> {
  if (!config.judgment.apiKey) return { ok: false, error: "no API key configured" }

  const detectorCfg = await prisma.detectorConfig.findUnique({
    where: { tenantId_detector: { tenantId, detector: "judgment" } },
  })
  if (!detectorCfg?.enabled) return { ok: false, error: "judgment disabled for tenant" }

  const findings = await listFindings(tenantId, { limit: 100 })
  const finding = findings.find((f) => f.id === findingId)
  if (!finding) return { ok: false, error: "finding not found" }

  const state = projectForJudgment(finding, config.secretsEncKey)
  const payload = JSON.parse(previewRequest(state, config.judgment.model))
  const stateDigest = crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex")

  // Check if this exact finding state was already evaluated with an assessment
  const existingAssessment = await prisma.evidence.findFirst({
    where: {
      findingId,
      kind: "assessment",
      data: { path: ["stateDigest"], equals: stateDigest },
    },
  })
  if (existingAssessment) {
    return { ok: true, model: config.judgment.model }
  }

  const ac = new AbortController()
  const timeout = setTimeout(() => ac.abort(), config.judgment.timeoutMs)

  try {
    const res = await fetch(config.judgment.endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${config.judgment.apiKey}`,
      },
      body: JSON.stringify(payload),
      signal: ac.signal,
    })

    if (!res.ok) {
      const errText = await res.text()
      return { ok: false, error: `HTTP ${res.status}: ${errText}` }
    }

    const data = (await res.json()) as {
      model: string
      answers: {
        anomalous?: { noul: number }
        likely_expected_behavior?: { noul: number }
        requires_human_attention?: { noul: number }
        severity?: { score: number; confidence: number }
      }
      usage?: { input_tokens: number; output_tokens: number }
    }

    await prisma.evidence.deleteMany({ where: { findingId, kind: "assessment" } })
    const count = await prisma.evidence.count({ where: { findingId } })

    const assessmentEv = {
      kind: "assessment",
      provider: "typesafe",
      model: data.model,
      question: "anomalous",
      answer: data.answers.anomalous?.noul ?? 0,
      probability: data.answers.anomalous?.noul,
      confidence: data.answers.severity?.confidence,
      stateDigest,
    }

    await prisma.evidence.create({
      data: {
        findingId,
        kind: "assessment",
        ordinal: count,
        data: assessmentEv,
      },
    })

    await prisma.judgmentRequest.create({
      data: {
        tenantId,
        findingId,
        questionSet: "systemone-v0",
        status: "DONE",
        attempts: 1,
        sentState: payload as object,
        stateDigest,
        response: data as object,
        completedAt: new Date(),
      },
    })

    return {
      ok: true,
      model: data.model,
      anomalous: data.answers.anomalous?.noul,
      confidence: data.answers.severity?.confidence,
    }
  } catch (err) {
    return { ok: false, error: (err as Error).message }
  } finally {
    clearTimeout(timeout)
  }
}
