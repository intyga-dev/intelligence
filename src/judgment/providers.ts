import { z } from "zod"
import { previewRequest, type JudgmentState } from "../redaction/project.ts"
import { judgmentGuidance } from "../redaction/guidance.ts"
import type { ReviewProvider, ReviewProviderView } from "./settings.ts"

const probability = z
  .number()
  .min(0)
  .max(1)
  .nullable()
  .describe("Estimate between 0 and 1, or null when evidence is insufficient; not a calibrated probability.")
export const REVIEW = z
  .object({
    anomalous: probability,
    requiresHumanAttention: probability,
    severity: z.enum(["info", "low", "medium", "high", "critical"]).nullable(),
    explanation: z.string().min(1).max(1600),
    supportedEvidence: z.array(z.string().min(1).max(300)).max(6),
    missingEvidence: z.array(z.string().min(1).max(300)).max(6),
    nextSteps: z.array(z.string().min(1).max(300)).max(6),
  })
  .strict()
export type Review = z.infer<typeof REVIEW>
export interface ProviderReview {
  model: string
  review: Review
  usage?: { input_tokens: number; output_tokens: number }
  severityConfidence?: number
}

// Keep the wire schema in the subset shared by both APIs; enforce every bound locally as well.
function wireSchema(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(wireSchema)
  if (!value || typeof value !== "object") return value
  return Object.fromEntries(
    Object.entries(value)
      .filter(
        ([key]) =>
          !["$schema", "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems"].includes(key),
      )
      .map(([key, item]) => [key, wireSchema(item)]),
  )
}
const schema = wireSchema(z.toJSONSchema(REVIEW))

export function reviewPayload(provider: ReviewProviderView, state: JudgmentState): object {
  if (provider.provider === "typesafe") return JSON.parse(previewRequest(state, provider.model)) as object
  const instructions =
    judgmentGuidance(state.events.map((e) => e.kind)) +
    "\nReturn an advisory review of this finding. List only supplied supporting evidence; distinguish missing context. Suggest human investigation steps, never executable commands or approval decisions. Use null for unknown estimates or impact. Explain briefly (at most 1600 characters); use at most six short items (300 characters each) in each list. No tools or external lookup are available."
  if (provider.provider === "openai")
    return {
      model: provider.model,
      store: false,
      max_output_tokens: provider.maxOutputTokens,
      instructions,
      input: [{ role: "user", content: JSON.stringify(state) }],
      text: { format: { type: "json_schema", name: "finding_review", strict: true, schema } },
    }
  return {
    model: provider.model,
    max_tokens: provider.maxOutputTokens,
    system: instructions,
    messages: [{ role: "user", content: JSON.stringify(state) }],
    output_config: { format: { type: "json_schema", schema } },
  }
}

const usageSchema = z.object({
  input_tokens: z.number().int().nonnegative(),
  output_tokens: z.number().int().nonnegative(),
})
const modelSchema = z.string().min(1).max(160)
const jevProbability = z.object({ noul: z.number().min(0).max(1) })
export function parseReview(provider: ReviewProvider, value: unknown): ProviderReview {
  if (provider === "typesafe") {
    const data = z
      .object({
        model: modelSchema,
        answers: z.object({
          anomalous: jevProbability.optional(),
          requires_human_attention: jevProbability.optional(),
          severity: z
            .object({ score: z.number().min(0).max(4), confidence: z.number().min(0).max(1) })
            .optional(),
        }),
        usage: usageSchema.optional(),
      })
      .parse(value)
    if (Object.keys(data.answers).length === 0) throw new Error("No assessment returned")
    const levels = ["info", "low", "medium", "high", "critical"] as const
    return {
      model: data.model,
      review: {
        anomalous: data.answers.anomalous?.noul ?? null,
        requiresHumanAttention: data.answers.requires_human_attention?.noul ?? null,
        severity: data.answers.severity ? (levels[Math.round(data.answers.severity.score)] ?? null) : null,
        explanation: "This provider returned scores without an explanation.",
        supportedEvidence: [],
        missingEvidence: [],
        nextSteps: [],
      },
      ...(data.usage ? { usage: data.usage } : {}),
      ...(data.answers.severity ? { severityConfidence: data.answers.severity.confidence } : {}),
    }
  }
  const data = z
    .object({
      model: modelSchema,
      status: z.string().optional(),
      stop_reason: z.string().optional(),
      output: z
        .array(
          z.object({
            type: z.string(),
            content: z.array(z.object({ type: z.string(), text: z.string().optional() })).optional(),
          }),
        )
        .optional(),
      content: z.array(z.object({ type: z.string(), text: z.string().optional() })).optional(),
      usage: usageSchema.optional(),
    })
    .parse(value)
  if (provider === "openai" && data.status !== "completed") throw new Error("Incomplete response")
  if (provider === "anthropic" && data.stop_reason !== "end_turn") throw new Error("Incomplete response")
  const blocks =
    provider === "openai"
      ? (data.output ?? []).filter((o) => o.type === "message").flatMap((o) => o.content ?? [])
      : (data.content ?? [])
  if (blocks.some((b) => b.type === "refusal")) throw new Error("Provider refused review")
  const texts = blocks.filter((b) => b.type === (provider === "openai" ? "output_text" : "text"))
  if (texts.length !== 1 || !texts[0]?.text) throw new Error("No structured review returned")
  return {
    model: data.model,
    review: REVIEW.parse(JSON.parse(texts[0].text)),
    ...(data.usage ? { usage: data.usage } : {}),
  }
}

export class ReviewError extends Error {}
export async function callReviewProvider(
  input: {
    provider: ReviewProviderView
    endpoint: string
    credential: string
    payload: object
  },
  fetcher: typeof fetch = fetch,
): Promise<ProviderReview> {
  const body = JSON.stringify(input.payload)
  if (Buffer.byteLength(body) > 32768) throw new ReviewError("Review input exceeds the size limit")
  const headers: Record<string, string> = { "content-type": "application/json" }
  if (input.provider.provider === "anthropic") {
    headers["x-api-key"] = input.credential
    headers["anthropic-version"] = "2026-10-21"
  } else headers.authorization = `Bearer ${input.credential}`
  const abort = new AbortController()
  const timer = setTimeout(() => abort.abort(), input.provider.timeoutMs)
  try {
    const response = await fetcher(input.endpoint, {
      method: "POST",
      headers,
      body,
      redirect: "error",
      signal: abort.signal,
    })
    if (!response.ok) {
      await response.body?.cancel()
      throw new ReviewError(
        `Provider returned HTTP ${response.status}; check credentials, model access and quota`,
      )
    }
    if (!response.body) throw new ReviewError("Provider returned an empty response")
    const reader = response.body.getReader()
    let size = 0
    const chunks: Uint8Array[] = []
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.length
      if (size > 131072) {
        await reader.cancel()
        throw new ReviewError("Provider response exceeds the size limit")
      }
      chunks.push(value)
    }
    try {
      return parseReview(input.provider.provider, JSON.parse(Buffer.concat(chunks).toString("utf8")))
    } catch {
      throw new ReviewError("Provider returned an invalid, incomplete or refused review")
    }
  } catch (error) {
    if (error instanceof ReviewError) throw error
    throw new ReviewError(
      abort.signal.aborted ? "Provider review timed out" : "Could not reach the review provider",
    )
  } finally {
    clearTimeout(timer)
  }
}
