import { z } from "zod"
import type { GateConfig } from "./client.ts"
import { GateNotConfigured, GateRefused, GateUnavailable } from "./errors.ts"
import type { DeploymentConnection } from "./deployment.ts"
import { gatewayTransportUrl } from "./transport.ts"

// Only recognized protocol reasons become user-facing text. Never relay an arbitrary gateway
// response: proxy errors and upstream exception messages may contain request data or credentials.
const approvalRefusals = new Map([
  [
    "unknown embedded credential",
    "This passkey is not active for Intelligence. Choose the application passkey you created here, or link your INTYGA membership again from the sign-in page.",
  ],
  ["embedded passkey required", "Choose your Intelligence application passkey to approve this action."],
  [
    "invalid webauthn assertion",
    "INTYGA could not verify this passkey response. Retry from Intelligence's registered address with your application passkey.",
  ],
  [
    "signer is not an eligible approver",
    "Your membership is not eligible to approve this action under the workspace approval rules.",
  ],
  [
    "four-eyes: a different approver is required",
    "The workspace approval rules require a different person to approve this action. Share the approval link with another eligible approver.",
  ],
  [
    "requester controller cannot approve",
    "The workspace approval rules require another eligible approver. Share the approval link with them.",
  ],
  [
    "authenticator does not meet the hardware policy for this action",
    "This passkey does not meet the workspace's hardware requirements for this action.",
  ],
  ["credential revoked", "This passkey has been revoked. Use an active Intelligence application passkey."],
  [
    "embedded credential is no longer eligible",
    "This application passkey is no longer eligible. Check your workspace membership and application registration.",
  ],
  [
    "credential changed during verification; sign again",
    "The passkey changed during verification. Try approving again.",
  ],
  ["expired", "This approval has expired. Close this dialog and request the action again."],
  [
    "approval belongs to another application",
    "This approval belongs to another application. Check Intelligence's application registration.",
  ],
])

async function embeddedRefusal(res: Response): Promise<GateRefused> {
  if (res.status === 403) {
    const body = await res.json().catch(() => null)
    const parsed = z.object({ error: z.string() }).safeParse(body)
    const message = parsed.success ? approvalRefusals.get(parsed.data.error) : undefined
    if (message) return new GateRefused(message)
  }
  return new GateRefused(
    `INTYGA refused the embedded ceremony (HTTP ${res.status}). Check the application registration, membership and passkey.`,
  )
}

/** Application backend relay. Service credentials and access tokens never reach the browser. */
export async function embeddedRequest(
  cfg: Pick<GateConfig, "baseUrl" | "serviceClientId" | "serviceSecret" | "embeddedApplicationId">,
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
    if (path === "authorize" && res.status === 404)
      throw new GateRefused(
        "INTYGA needs the application-approval routing update. Update the gateway and retry.",
      )
    if (!res.ok) throw await embeddedRefusal(res)
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
