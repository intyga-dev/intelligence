import { embeddedApprovalLink } from "../embedded/approval-link.ts"
import { approvalState, type GateConfig, GateError, openApproval, verifyAndConsume } from "../gate/client.ts"
import { prisma } from "../store/client.ts"
import { resolveGateConfig } from "../gate/deployment.ts"
import { type ActionOutcome, actionDef } from "./registry.ts"

// The two halves of a privileged action, and the state that survives between them.
//
// Split because an INTYGA approval spans time: we open it, a member of the workspace signs it at
// the console or on their phone, and only then may the action run. What must NOT span that gap is
// trust in the client — the parameters are frozen in the database at step one and read back from
// there at step two. If they came from a later request instead, an approver could be shown one
// action and a different one executed, which is the whole class of attack the signature closes.

/** How long an approval stays open. Mirrors the gateway's `timeout` on the challenge. */
const APPROVAL_TTL_SECONDS = 15 * 60
export class ActionError extends Error {}

/** The deployment origin is part of the receipt's signed execution target. */
export function executionTarget(): string {
  return `intelligence:${new URL(resolveGateConfig().origin).host}`
}

export interface OpenedAction {
  nonce: string
  summary: string
  impact: "low" | "medium" | "high"
  /** Where the approver signs: the application share link or hosted console ceremony. */
  approveUrl: string
  embeddedApprovalUrl?: string
  embedded?: boolean
  expiresAt: string
}

/** Step one: validate, freeze, and open an approval bound to the frozen parameters. */
export async function openAction(input: {
  tenantId: string
  actor: { externalId: string; role: "ADMIN" | "MEMBER" }
  action: string
  params: unknown
}): Promise<OpenedAction> {
  const def = actionDef(input.action)
  if (!def) throw new ActionError(`unknown action: ${input.action}`)
  const parsed = def.schema.safeParse(input.params)
  if (!parsed.success) {
    throw new ActionError(`invalid parameters: ${parsed.error.issues[0]?.message ?? "rejected"}`)
  }
  // Workspace ADMINs administer Intelligence. The role comes from the id_token at sign-in, never
  // from anything the request says.
  if (input.actor.role !== "ADMIN")
    throw new ActionError("only a workspace administrator can open a privileged action")
  const member = await prisma.member.findFirst({
    where: { tenantId: input.tenantId, externalId: input.actor.externalId, active: true },
    select: { id: true },
  })
  if (!member) throw new ActionError("not an active member of this tenant")
  const cfg = resolveGateConfig()
  // `parsed.data` is unknown to the compiler because the registry lookup erases the generic; the
  // schema has just validated it is an object, so the assertion is narrow and load-bearing.
  const params = parsed.data as Record<string, unknown>
  const target = executionTarget()
  const summary = def.summary(parsed.data)
  const opened = await openApproval(cfg, {
    description: summary,
    target,
    actionType: input.action,
    params,
    timeoutSeconds: APPROVAL_TTL_SECONDS,
  })
  const expiresAt = new Date(Date.now() + APPROVAL_TTL_SECONDS * 1000)
  const approveUrl = cfg.embeddedApplicationId
    ? embeddedApprovalLink(cfg, opened.nonce, expiresAt.getTime())
    : opened.approveUrl
  if (!approveUrl) throw new ActionError("INTYGA did not provide an approval ceremony.")
  await prisma.pendingAction.create({
    data: {
      tenantId: input.tenantId,
      bindingId: cfg.bindingId,
      nonce: opened.nonce,
      action: input.action,
      // Frozen. Step two reads these, never a later request.
      params: params as object,
      target,
      approveUrl,
      actorExternalId: input.actor.externalId,
      expiresAt,
    },
  })
  return {
    nonce: opened.nonce,
    summary,
    impact: def.impact,
    approveUrl,
    expiresAt: expiresAt.toISOString(),
    embedded: Boolean(cfg.embeddedApplicationId),
    ...(cfg.embeddedApplicationId ? { embeddedApprovalUrl: approveUrl } : {}),
  }
}

export type ActionProgress =
  | { status: "pending"; approveUrl: string; expiresAt: string }
  | { status: "refused"; reason: string }
  | ({ status: "applied" } & ActionOutcome)

/**
 * Step two, polled: when INTYGA reports the approval, verify the receipt against the FROZEN
 * parameters and the approvers this instance trusts, consume it, then execute. Exactly once.
 */
export async function pollAction(input: { tenantId: string; nonce: string }): Promise<ActionProgress> {
  const pending = await prisma.pendingAction.findFirst({
    where: { nonce: input.nonce, tenantId: input.tenantId },
  })
  if (!pending) throw new ActionError("no such approval")
  if (pending.bindingId !== resolveGateConfig().bindingId)
    throw new ActionError("the deployment configuration changed; open a new approval")
  if (pending.status === "APPLIED") return { status: "applied" }
  if (pending.status === "REFUSED" || pending.status === "EXPIRED")
    return { status: "refused", reason: pending.error ?? "the approval was not granted" }
  if (pending.expiresAt < new Date()) {
    await prisma.pendingAction.updateMany({
      where: { nonce: pending.nonce, status: "AWAITING_SIGNATURE" },
      data: { status: "EXPIRED", error: "the approval expired before anyone signed it" },
    })
    return { status: "refused", reason: "the approval expired before anyone signed it" }
  }

  let cfg: GateConfig
  try {
    cfg = resolveGateConfig()
  } catch (err) {
    throw err instanceof GateError ? new ActionError(err.message) : err
  }
  const state = await approvalState(cfg, pending.nonce)
  if (state.status === "PENDING") {
    return { status: "pending", approveUrl: pending.approveUrl, expiresAt: pending.expiresAt.toISOString() }
  }
  // `reason` is authored and goes back to the browser. `detail` may be raw exception text — an
  // upstream URL, a column name — so it is recorded on the row for the operator and never returned.
  const fail = async (reason: string, detail?: string): Promise<ActionProgress> => {
    const error = detail ? `${reason}: ${detail}` : reason
    await prisma.pendingAction.updateMany({
      where: { nonce: pending.nonce, status: "AWAITING_SIGNATURE" },
      data: { status: "REFUSED", error: error.slice(0, 500) },
    })
    return { status: "refused", reason }
  }
  if (state.status === "DENIED") return fail("the approver denied it")
  if (state.status === "EXPIRED") return fail("the approval expired before anyone signed it")
  if (state.status === "CONSUMED") return fail("this approval was already redeemed")

  // Claimed atomically: the row leaves AWAITING_SIGNATURE in the same statement that selects it, so
  // two concurrent polls cannot both execute one approval.
  const claimed = await prisma.pendingAction.updateMany({
    where: { nonce: pending.nonce, tenantId: input.tenantId, status: "AWAITING_SIGNATURE" },
    data: { status: "APPLIED", appliedAt: new Date() },
  })
  if (claimed.count !== 1) return { status: "applied" }
  const def = actionDef(pending.action)
  if (!def) return fail(`unknown action: ${pending.action}`)
  // Undo the claim on refusal, so the row records what happened rather than a false "applied".
  const refuse = async (reason: string, detail?: string): Promise<ActionProgress> => {
    const error = detail ? `${reason}: ${detail}` : reason
    await prisma.pendingAction.update({
      where: { nonce: pending.nonce },
      data: { status: "REFUSED", error: error.slice(0, 500), appliedAt: null },
    })
    return { status: "refused", reason }
  }
  const frozen = {
    target: pending.target,
    actionType: pending.action,
    params: pending.params as Record<string, unknown>,
  }
  try {
    await verifyAndConsume(cfg, pending.nonce, frozen, state.receipt)
  } catch (err) {
    return refuse(
      err instanceof GateError ? err.message : "the receipt could not be verified",
      (err as Error).message,
    )
  }
  let outcome: ActionOutcome | undefined
  try {
    outcome = (await def.run(input.tenantId, pending.params, { nonce: pending.nonce })) ?? undefined
  } catch (err) {
    // The approval was valid; the action itself failed. Recorded distinctly, because "refused" and
    // "approved but broke" are different incidents.
    return refuse("the action failed after approval", (err as Error).message)
  }
  return { status: "applied", ...(outcome ?? {}) }
}
