import { config } from "../config.ts"
import { prisma } from "../store/client.ts"
import { decryptSecret } from "../store/crypto.ts"
import {
  PROVIDER,
  PROVIDERS,
  PROVIDER_ENDPOINTS,
  type ReviewProvider,
  type ReviewProviderView,
} from "./settings.ts"

export async function reviewConfiguration(tenantId: string) {
  const [gate, rows] = await Promise.all([
    prisma.detectorConfig.findUnique({ where: { tenantId_detector: { tenantId, detector: "judgment" } } }),
    prisma.reviewProvider.findMany({ where: { tenantId } }),
  ])
  const settings = (gate?.settings ?? {}) as Record<string, unknown>
  const primary = PROVIDER.safeParse(settings.primaryProvider)
  const primaryProvider = primary.success ? primary.data : "typesafe"
  const providers: ReviewProviderView[] = PROVIDERS.map((provider) => {
    const row = rows.find((r) => r.provider === provider)
    const legacy = !row && provider === "typesafe"
    return {
      provider,
      model: row?.model ?? (legacy ? config.judgment.model : ""),
      configured: row
        ? row.enabled && Boolean(row.secretCiphertext)
        : legacy && Boolean(config.judgment.apiKey),
      primary: provider === primaryProvider,
      dailyRequestLimit: row?.dailyRequestLimit ?? 20,
      maxOutputTokens: row?.maxOutputTokens ?? 2048,
      timeoutMs: row?.timeoutMs ?? Math.min(30000, Math.max(1000, config.judgment.timeoutMs)),
    }
  })
  return {
    enabled: (gate?.enabled ?? false) && (settings.primaryProvider === undefined || primary.success),
    primaryProvider,
    providers,
  }
}

export async function providerCredential(tenantId: string, provider: ReviewProvider) {
  const row = await prisma.reviewProvider.findUnique({ where: { tenantId_provider: { tenantId, provider } } })
  if (row) return row.enabled && row.secretCiphertext ? decryptSecret(row.secretCiphertext) : null
  return provider === "typesafe" ? config.judgment.apiKey : null
}

export function providerEndpoint(provider: ReviewProvider): string {
  // Only the pre-existing operator-owned JEV deployment setting can override a destination.
  return provider === "typesafe" ? config.judgment.endpoint : PROVIDER_ENDPOINTS[provider]
}
