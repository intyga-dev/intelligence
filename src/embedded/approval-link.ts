import { z } from "zod"
import type { DeploymentConnection } from "../gate/deployment.ts"
import { encryptSecret, decryptSecret } from "../store/crypto.ts"
import { AuthError } from "../auth/oidc.ts"
const ticketSchema = z
  .object({ nonce: z.string().min(8).max(200), bindingId: z.string(), expiresAt: z.number() })
  .strict()
export function embeddedApprovalLink(cfg: DeploymentConnection, nonce: string, expiresAt: number): string {
  const url = new URL("/embedded/approve", cfg.origin)
  url.hash = new URLSearchParams({
    ticket: encryptSecret(JSON.stringify({ nonce, bindingId: cfg.bindingId, expiresAt })),
  }).toString()
  return url.toString()
}
/** A bounded view capability, never authority to sign or execute. */
export function readApprovalTicket(cfg: DeploymentConnection, ticket: string) {
  try {
    const value = ticketSchema.parse(JSON.parse(decryptSecret(ticket) ?? "null"))
    if (
      value.bindingId !== cfg.bindingId ||
      value.expiresAt <= Date.now() ||
      value.expiresAt > Date.now() + 3_600_000
    )
      throw new Error("invalid ticket")
    return value
  } catch {
    throw new AuthError("This approval link is invalid or expired.")
  }
}
