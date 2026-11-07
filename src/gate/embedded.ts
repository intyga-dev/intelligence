import { z } from "zod"
import { GateNotConfigured, GateRefused, GateUnavailable } from "./client.ts"
import type { DeploymentConnection } from "./deployment.ts"
import { gatewayTransportUrl } from "./transport.ts"

/** Application backend relay. Service credentials and access tokens never reach the browser. */
export async function embeddedRequest(
  cfg: DeploymentConnection,
  path: string,
  body: unknown,
): Promise<unknown> {
  if (!cfg.embeddedApplicationId) throw new GateNotConfigured("Embedded approvals are not configured.")
  const base = gatewayTransportUrl(cfg.baseUrl)
  try {
    const tokenRes = await fetch(`${base}/oauth/token`, {
      method: "POST",
      headers: {
        authorization: `Basic ${Buffer.from(`${cfg.serviceClientId}:${cfg.serviceSecret}`).toString("base64")}`,
      },
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    })
    if (!tokenRes.ok) throw new GateRefused("INTYGA refused the service key.")
    const token = z.object({ access_token: z.string().min(1) }).parse(await tokenRes.json())
    const res = await fetch(
      `${base}/embedded/applications/${encodeURIComponent(cfg.embeddedApplicationId)}/${path}`,
      {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token.access_token}` },
        body: JSON.stringify(body),
        redirect: "manual",
        signal: AbortSignal.timeout(15_000),
      },
    )
    if (!res.ok)
      throw new GateRefused(
        "INTYGA refused the embedded ceremony. Check the application registration, membership and passkey.",
      )
    return await res.json()
  } catch (err) {
    if (err instanceof GateRefused) throw err
    throw new GateUnavailable("INTYGA could not complete the embedded ceremony.", { cause: err })
  }
}

export const embeddedMember = z.object({
  sub: z.string().uuid(),
  membershipId: z.string().uuid(),
  role: z.enum(["ADMIN", "MEMBER"]),
  email: z.string().email(),
  name: z.string(),
  did: z.string(),
  credentialId: z.string(),
})
export async function approvalMember(cfg: DeploymentConnection, nonce: string, credentialId: string) {
  const data = z
    .object({ members: z.array(embeddedMember) })
    .parse(await embeddedRequest(cfg, "approval-member", { nonce }))
  const member = data.members.find((m) => m.credentialId === credentialId)
  if (!member) throw new GateRefused("The signing passkey no longer belongs to an active workspace member.")
  return member
}
