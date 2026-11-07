import { createHash, randomBytes, timingSafeEqual } from "node:crypto"
import { z } from "zod"
import type { DeploymentConnection } from "../gate/deployment.ts"
import { AuthError } from "../auth/oidc.ts"
import { decryptSecret, encryptSecret } from "../store/crypto.ts"
export const LINK_COOKIE = "intelligence_embedded_link"
const schema = z
  .object({
    state: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    verifier: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    bindingId: z.string(),
    expiresAt: z.number(),
  })
  .strict()
export function beginEmbeddedLink(cfg: DeploymentConnection) {
  if (!cfg.embeddedApplicationId) throw new AuthError("Embedded approvals are not configured.")
  const state = randomBytes(32).toString("base64url")
  const verifier = randomBytes(32).toString("base64url")
  const url = new URL("/embedded/link", cfg.consoleUrl)
  url.search = new URLSearchParams({
    applicationId: cfg.embeddedApplicationId,
    pkceChallenge: createHash("sha256").update(verifier).digest("base64url"),
    state,
  }).toString()
  return {
    url: url.toString(),
    cookie: encryptSecret(
      JSON.stringify({ state, verifier, bindingId: cfg.bindingId, expiresAt: Date.now() + 10 * 60_000 }),
    ),
  }
}
export function readEmbeddedLink(cfg: DeploymentConnection, cookie: string | undefined, state: string) {
  try {
    const parsed = schema.parse(JSON.parse(cookie ? (decryptSecret(cookie) ?? "null") : "null"))
    if (
      parsed.bindingId !== cfg.bindingId ||
      parsed.expiresAt <= Date.now() ||
      parsed.expiresAt > Date.now() + 10 * 60_000 ||
      !/^[A-Za-z0-9_-]{43}$/.test(state) ||
      !timingSafeEqual(Buffer.from(state), Buffer.from(parsed.state))
    )
      throw new Error("invalid state")
    return parsed
  } catch {
    throw new AuthError("Linking expired or belongs to another browser. Start again.")
  }
}
