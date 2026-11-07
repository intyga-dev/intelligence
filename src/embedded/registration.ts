import { readFileSync, statSync } from "node:fs"
import { z } from "zod"

const originProof = z
  .object({
    type: z.literal("intyga-embedded-origin-proof"),
    v: z.literal(1),
    applicationId: z.uuid(),
    tenantId: z.uuid(),
    origin: z.url(),
    challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    expiresAt: z.iso.datetime(),
  })
  .strict()

/** Only the deployment operator can install the public, short-lived registration challenge. */
export function registrationProof(env: NodeJS.ProcessEnv = process.env, now = new Date()) {
  const file = env.INTYGA_EMBEDDED_REGISTRATION_FILE
  if (!file || !env.PUBLIC_URL || !env.INTYGA_WORKSPACE_ID) return null
  try {
    if (statSync(file).size > 8192) return null
    const parsed = originProof.safeParse(JSON.parse(readFileSync(file, "utf8")))
    if (!parsed.success) return null
    const value = parsed.data
    if (
      value.origin !== env.PUBLIC_URL ||
      value.tenantId !== env.INTYGA_WORKSPACE_ID ||
      new Date(value.expiresAt) <= now ||
      new Date(value.expiresAt).getTime() > now.getTime() + 15 * 60_000
    )
      return null
    return value
  } catch {
    return null
  }
}

// Public advisory marker, not a credential or an admission control.
export const intelligenceMarker = {
  product: "intyga-intelligence",
  markerVersion: 1,
  version: "0.1.0",
} as const
