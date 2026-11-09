import { z } from "zod"

export const PROVIDERS = ["typesafe", "openai", "anthropic"] as const
export const PROVIDER = z.enum(PROVIDERS)
export type ReviewProvider = z.infer<typeof PROVIDER>
export const PROVIDER_LABELS: Record<ReviewProvider, string> = {
  typesafe: "TypeSafe AI · JEV",
  openai: "OpenAI",
  anthropic: "Anthropic",
}
export const PROVIDER_ENDPOINTS: Record<ReviewProvider, string> = {
  typesafe: "https://api.typesafe.ai/v1/systemone",
  openai: "https://api.openai.com/v1/responses",
  anthropic: "https://api.anthropic.com/v1/messages",
}
export const CONFIGURE_REVIEW_PROVIDER = z
  .object({
    provider: PROVIDER,
    model: z
      .string()
      .trim()
      .regex(/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,119}$/),
    dailyRequestLimit: z.number().int().min(1).max(1000),
    maxOutputTokens: z.number().int().min(512).max(8192),
    timeoutMs: z.number().int().min(1000).max(30000),
    primary: z.boolean(),
    secretDigest: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .optional(),
  })
  .strict()
export const REQUEST_REVIEW = z
  .object({
    findingId: z.uuid(),
    provider: PROVIDER,
    model: z.string().min(1).max(120),
    stateDigest: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict()

export interface ReviewProviderView {
  provider: ReviewProvider
  model: string
  configured: boolean
  primary: boolean
  dailyRequestLimit: number
  maxOutputTokens: number
  timeoutMs: number
}
