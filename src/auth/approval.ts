import { embeddedApprovalLink } from "../embedded/approval-link.ts"
import { approvalMember, type embeddedMember } from "../gate/embedded.ts"
import type { z } from "zod"
import { randomBytes } from "node:crypto"
import { approvalState, openApproval, verifyAndConsume } from "../gate/client.ts"
import type { DeploymentConfig } from "../gate/deployment.ts"
import { decryptSecret, encryptSecret } from "../store/crypto.ts"
import { AuthError } from "./oidc.ts"

export const APPROVAL_LOGIN_COOKIE = "intelligence_approval_login"
const TTL_MS = 10 * 60_000
const ACTION = "intelligence.session.create"

interface ApprovalLogin {
  nonce: string
  browserId: string
  bindingId: string
  credentialId?: string
  expiresAt: number
}

function action(cfg: DeploymentConfig, browserId: string) {
  return {
    target: `intelligence:${new URL(cfg.origin).host}`,
    actionType: ACTION,
    params: {
      browserId,
      origin: cfg.origin,
      role: cfg.embeddedApplicationId ? "workspace-membership" : "ADMIN",
      sessionHours: 12,
    },
  }
}

/** The approval grants a browser access; it makes no claim about an email or workspace role. */
export async function beginApprovalLogin(cfg: DeploymentConfig) {
  const browserId = randomBytes(32).toString("base64url")
  const opened = await openApproval(cfg, {
    ...action(cfg, browserId),
    description: `Sign this browser in to Intelligence at ${cfg.origin} for 12 hours ${cfg.embeddedApplicationId ? "with the signing member’s workspace role" : "with administrator access"}. Browser code: ${browserId.slice(0, 8)}. Only approve if you started this sign-in.`,
    timeoutSeconds: TTL_MS / 1000,
  })
  const state: ApprovalLogin = {
    nonce: opened.nonce,
    browserId,
    bindingId: cfg.bindingId,
    expiresAt: Date.now() + TTL_MS,
  }
  return {
    ...opened,
    ...(cfg.embeddedApplicationId
      ? { embeddedApprovalUrl: embeddedApprovalLink(cfg, opened.nonce, state.expiresAt) }
      : {}),
    browserCode: browserId.slice(0, 8),
    cookie: encryptSecret(JSON.stringify(state)),
  }
}

/** Only the initiating browser's encrypted cookie can select or redeem this sign-in approval. */
export async function completeApprovalLogin(
  cfg: DeploymentConfig,
  cookie: string | undefined,
): Promise<
  { status: "pending" } | { status: "approved"; nonce: string; member?: z.infer<typeof embeddedMember> }
> {
  const state = readApprovalLogin(cfg, cookie)
  const status = await approvalState(cfg, state.nonce)
  if (status.status === "PENDING") return { status: "pending" }
  if (status.status !== "APPROVED")
    throw new AuthError("The sign-in was refused, expired or already used. Start again.")
  const member = cfg.embeddedApplicationId
    ? await approvalMember(cfg, state.nonce, state.credentialId ?? "")
    : undefined
  await verifyAndConsume(cfg, state.nonce, action(cfg, state.browserId), status.receipt)
  return { status: "approved", nonce: state.nonce, ...(member ? { member } : {}) }
}

export function readApprovalLogin(cfg: DeploymentConfig, cookie: string | undefined): ApprovalLogin {
  let state: ApprovalLogin
  try {
    const value = JSON.parse(
      cookie ? (decryptSecret(cookie) ?? "null") : "null",
    ) as Partial<ApprovalLogin> | null
    if (
      !value ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      typeof value.nonce !== "string" ||
      !/^[A-Za-z0-9_-]{8,200}$/.test(value.nonce) ||
      typeof value.browserId !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(value.browserId) ||
      value.bindingId !== cfg.bindingId ||
      typeof value.expiresAt !== "number" ||
      !Number.isFinite(value.expiresAt) ||
      value.expiresAt <= Date.now() ||
      value.expiresAt > Date.now() + TTL_MS
    ) {
      throw new Error("invalid state")
    }
    state = value as ApprovalLogin
  } catch {
    throw new AuthError("This sign-in is expired or does not belong to this browser. Start again.")
  }
  return state
}

export function stampApprovalCredential(
  cfg: DeploymentConfig,
  cookie: string | undefined,
  credentialId: string,
): string {
  const state = readApprovalLogin(cfg, cookie)
  return encryptSecret(JSON.stringify({ ...state, credentialId }))
}
