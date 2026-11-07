import crypto from "node:crypto"
import {
  GatewayRefused,
  GatewayUnreachable,
  IntygaClient,
  parseTrustAnchorFile,
  type TrustAnchorFile,
  trustAnchorApprovers,
  verifyApprovalReceipt,
} from "@intyga/sdk"
import { gatewayTransportUrl } from "./transport.ts"

// Intelligence uses ordinary INTYGA approvals (ADRs 030–031). A SERVICE key asks; an eligible
// member signs with an application passkey (embedded), or at the console in non-embedded mode.
// This gate verifies against frozen parameters and the deployment's pinned keys and origin,
// then requires one-use redemption. A bad anchor can refuse legitimate actions, but cannot
// bypass the gateway's policy and membership checks. No approval authority is held here.

export class GateError extends Error {}
export class GateRefused extends GateError {}
export class GateUnavailable extends GateError {}
export class GateNotConfigured extends GateError {}

export interface GateConfig {
  /** The gateway, e.g. https://api.intyga.com. */
  baseUrl: string
  /** The console people approve at, e.g. https://app.intyga.com. */
  consoleUrl: string
  /** The bound workspace's id — the tenant every receipt must name (DIV v2 tenant binding). */
  workspaceId: string
  /** The SERVICE identity's API key (client credentials). Asks for approvals; grants nothing. */
  serviceClientId: string
  serviceSecret: string
  /** The approvers this instance trusts, as exported from the console (Approval Rules → Export). */
  trustAnchor: TrustAnchorFile
}

/** Parse an exported trust anchor, or say what is wrong with it in words a person can act on. */
export function parseTrustAnchor(
  raw: unknown,
): { ok: true; anchor: TrustAnchorFile } | { ok: false; error: string } {
  const text = typeof raw === "string" ? raw : JSON.stringify(raw ?? null)
  try {
    const anchor = parseTrustAnchorFile(text)
    if (!anchor.webauthn) {
      return {
        ok: false,
        error:
          "the trust anchor carries no WebAuthn origin — export it again from the console's Approval Rules page",
      }
    }
    return { ok: true, anchor }
  } catch (err) {
    return { ok: false, error: `the trust anchor is not usable: ${(err as Error).message}` }
  }
}

function client(cfg: GateConfig): IntygaClient {
  return new IntygaClient({
    gatewayUrl: gatewayTransportUrl(cfg.baseUrl),
    clientId: cfg.serviceClientId,
    clientSecret: cfg.serviceSecret,
  })
}

/**
 * Translate an SDK failure into an authored message. GatewayRefused carries the gateway's status;
 * its body text is not forwarded (it can embed what the gateway was asked). GatewayUnreachable
 * keeps the transport error on `cause` only — undici's text embeds the URL it was handed.
 */
function translate(err: unknown, what: string): GateError {
  if (err instanceof GatewayRefused) {
    if (err.status === 401 || err.status === 403)
      return new GateRefused(
        `INTYGA refused the service key while ${what} — check the client id and secret`,
        {
          cause: err,
        },
      )
    if (err.status === 404)
      return new GateRefused(`INTYGA does not know this approval (${what})`, { cause: err })
    return new GateRefused(`INTYGA refused ${what} (HTTP ${err.status})`, { cause: err })
  }
  if (err instanceof GatewayUnreachable) return new GateUnavailable("INTYGA unreachable", { cause: err })
  if (err instanceof GateError) return err
  return new GateUnavailable(`INTYGA could not be reached while ${what}`, { cause: err })
}

export interface ApprovalRequest {
  /** What the approver reads. Imperative, plain words. */
  description: string
  /** The execution target bound into the signed payload — this instance. */
  target: string
  actionType: string
  params: Record<string, unknown>
  /** How long the approval may stay open, in seconds. */
  timeoutSeconds: number
}

/** Step one: open an approval. Returns the nonce and the console link the approver signs at. */
export async function openApproval(
  cfg: GateConfig,
  req: ApprovalRequest,
): Promise<{ nonce: string; approveUrl: string }> {
  try {
    const res = await client(cfg).authorize(req.description, {
      target: req.target,
      actionType: req.actionType,
      params: req.params,
      timeout: req.timeoutSeconds,
    })
    const approveUrl = new URL("/approve", cfg.consoleUrl)
    approveUrl.searchParams.set("nonce", res.nonce)
    return { nonce: res.nonce, approveUrl: approveUrl.toString() }
  } catch (err) {
    throw translate(err, "opening the approval")
  }
}

export type ApprovalState =
  | { status: "PENDING" }
  | { status: "DENIED" }
  | { status: "EXPIRED" }
  | { status: "CONSUMED" }
  | { status: "APPROVED"; receipt: unknown }

/** Poll the approval. */
export async function approvalState(cfg: GateConfig, nonce: string): Promise<ApprovalState> {
  let result: Awaited<ReturnType<IntygaClient["status"]>>
  try {
    result = await client(cfg).status(nonce)
  } catch (err) {
    throw translate(err, "reading the approval")
  }
  switch (result.status) {
    case "APPROVED":
      if (!result.receipt) throw new GateRefused("INTYGA reported an approval without a receipt")
      return { status: "APPROVED", receipt: result.receipt }
    case "DENIED":
    case "EXPIRED":
    case "CONSUMED":
      return { status: result.status }
    default:
      return { status: "PENDING" }
  }
}

/**
 * Step two: verify the receipt against the parameters THIS instance froze and the approvers it
 * trusts — never against anything the receipt says about itself — then consume the approval.
 * Only after both may the action run.
 */
export async function verifyAndConsume(
  cfg: GateConfig,
  nonce: string,
  action: { target: string; actionType: string; params: Record<string, unknown> },
  receipt: unknown,
): Promise<void> {
  const anchor = cfg.trustAnchor
  let check: ReturnType<typeof verifyApprovalReceipt>
  try {
    check = verifyApprovalReceipt(
      receipt as Parameters<typeof verifyApprovalReceipt>[0],
      {
        target: action.target,
        actionType: action.actionType,
        params: action.params,
        nonce,
        tenantId: cfg.workspaceId,
        approvers: trustAnchorApprovers(anchor),
      },
      {
        expectedOrigin: anchor.webauthn?.origin ?? "",
        expectedRpId: anchor.webauthn?.rpId ?? "",
      },
    )
  } catch (err) {
    throw new GateRefused("the receipt does not verify: malformed receipt", { cause: err })
  }
  if (!check.ok) throw new GateRefused(`the receipt does not verify: ${check.reason}`)
  let used: { ok: boolean; reason?: string }
  try {
    used = await client(cfg).consume(nonce, action)
  } catch (err) {
    throw translate(err, "consuming the approval")
  }
  if (!used.ok)
    throw new GateRefused(`INTYGA refused to consume the approval: ${used.reason ?? "no reason given"}`)
}

/**
 * Prove the binding works without changing anything: exchange the service key for a token by
 * asking about an approval that cannot exist. "Not found" means the key is good; 401/403 means it
 * is not; anything else is reported as what it is.
 */
export async function testConnection(cfg: GateConfig): Promise<{ ok: boolean; error?: string }> {
  try {
    await client(cfg).status(crypto.randomUUID())
    return { ok: true }
  } catch (err) {
    if (err instanceof GatewayRefused && err.status === 404) return { ok: true }
    return { ok: false, error: translate(err, "testing the connection").message }
  }
}
