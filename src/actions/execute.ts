import { type GateIntent, intentDigest } from "../gate/intent.ts"
import {
  completeChallenge,
  type GateConfig,
  GateError,
  openChallenge,
  resolveGateConfig,
  type TenantRpBinding,
} from "../gate/rp.ts"
import { prisma } from "../store/client.ts"
import { decryptSecret } from "../store/crypto.ts"
import { type ActionOutcome, actionDef } from "./registry.ts"

// The two halves of a privileged action, and the state that survives between them.
//
// Split because a WebAuthn ceremony spans two round trips: we open a challenge, the browser gets an
// assertion from the admin's passkey, and only then may the action run. What must NOT span those
// trips is trust in the client — the parameters are frozen in the database at step one and read
// back from there at step two. If they came from the second request instead, an approver could be
// shown one action and a different one executed, which is the whole class of attack the signature
// exists to close.

const CHALLENGE_TTL_MS = 180_000

export class ActionError extends Error {}

/** Load a tenant's RP binding, decrypting the private key for use. */
export async function tenantBinding(tenantId: string): Promise<TenantRpBinding | null> {
  const t = await prisma.tenant.findUnique({
    where: { id: tenantId },
    select: {
      intygaBaseUrl: true,
      intygaClientId: true,
      intygaKeyCipher: true,
      intygaRpId: true,
      intygaOrigin: true,
    },
  })
  if (!t) return null
  return {
    intygaBaseUrl: t.intygaBaseUrl,
    intygaClientId: t.intygaClientId,
    intygaPrivateKeyPem: t.intygaKeyCipher ? decryptSecret(t.intygaKeyCipher) : null,
    intygaRpId: t.intygaRpId,
    intygaOrigin: t.intygaOrigin,
  }
}

export interface OpenedAction {
  nonce: string
  summary: string
  impact: "low" | "medium" | "high"
  /** WebAuthn assertion options for the browser, on Intelligence's own origin. */
  options: unknown
  expiresAt: string
}

/** Step one: validate, freeze, and open a signing ceremony bound to the frozen parameters. */
export async function openAction(input: {
  tenantId: string
  actorExternalId: string
  action: string
  params: unknown
}): Promise<OpenedAction> {
  const def = actionDef(input.action)
  if (!def) throw new ActionError(`unknown action: ${input.action}`)

  const parsed = def.schema.safeParse(input.params)
  if (!parsed.success) {
    throw new ActionError(`invalid parameters: ${parsed.error.issues[0]?.message ?? "rejected"}`)
  }

  const member = await prisma.member.findFirst({
    where: { tenantId: input.tenantId, externalId: input.actorExternalId, active: true },
    select: { enrolledAt: true },
  })
  if (!member) throw new ActionError("not an active administrator of this tenant")
  if (!member.enrolledAt) throw new ActionError("enrol a passkey before approving actions")

  const cfg = resolveGateConfig(await tenantBinding(input.tenantId))
  // `parsed.data` is unknown to the compiler because the registry lookup erases the generic; the
  // schema has just validated it is an object, so the assertion is narrow and load-bearing rather
  // than a shrug.
  const intent: GateIntent = {
    action: input.action as GateIntent["action"],
    params: parsed.data as Record<string, unknown>,
  }
  const challenge = await openChallenge(cfg, input.actorExternalId, intent)

  await prisma.pendingAction.create({
    data: {
      tenantId: input.tenantId,
      nonce: challenge.nonce,
      action: input.action,
      // Frozen. Step two reads these, never the incoming request.
      params: parsed.data as object,
      payloadHash: challenge.payloadHash,
      actorExternalId: input.actorExternalId,
      expiresAt: new Date(Date.now() + CHALLENGE_TTL_MS),
    },
  })

  return {
    nonce: challenge.nonce,
    summary: def.summary(parsed.data),
    impact: def.impact,
    options: challenge.options,
    expiresAt: challenge.expiresAt,
  }
}

/** Step two: redeem the signature against the FROZEN parameters, then execute. */
export async function completeAction(input: {
  tenantId: string
  nonce: string
  assertion: unknown
}): Promise<{ applied: true } & ActionOutcome> {
  // Claimed atomically: a pending action moves out of AWAITING_SIGNATURE in the same statement that
  // selects it, so two concurrent completions cannot both execute one approval.
  const claimed = await prisma.pendingAction.updateMany({
    where: {
      nonce: input.nonce,
      tenantId: input.tenantId,
      status: "AWAITING_SIGNATURE",
      expiresAt: { gt: new Date() },
    },
    data: { status: "APPLIED", appliedAt: new Date() },
  })
  if (claimed.count !== 1) throw new ActionError("no live approval for this challenge")

  const pending = await prisma.pendingAction.findUniqueOrThrow({ where: { nonce: input.nonce } })
  const def = actionDef(pending.action)
  if (!def) throw new ActionError(`unknown action: ${pending.action}`)

  // `reason` is authored and goes back to the approver. `detail` may be raw exception text — an
  // upstream URL, a column name — so it is recorded on the row for the operator and never returned.
  const fail = async (reason: string, detail?: string): Promise<never> => {
    const error = detail ? `${reason}: ${detail}` : reason
    await prisma.pendingAction.update({
      where: { nonce: input.nonce },
      data: { status: "REFUSED", error: error.slice(0, 500), appliedAt: null },
    })
    throw new ActionError(reason)
  }

  // Recomputed from the FROZEN params, never taken from the request or the receipt. A mismatch
  // means the stored intent and the signed digest disagree, which must never execute.
  const digest = intentDigest({
    action: pending.action as GateIntent["action"],
    params: pending.params as Record<string, unknown>,
  })
  if (digest !== pending.payloadHash) await fail("stored intent does not match the signed digest")

  let cfg: GateConfig
  try {
    cfg = resolveGateConfig(await tenantBinding(input.tenantId))
  } catch (err) {
    return await fail(
      err instanceof GateError ? err.message : "the Intyga binding is not usable",
      (err as Error).message,
    )
  }

  try {
    await completeChallenge(
      cfg,
      { nonce: pending.nonce, expiresAt: "", options: null, payloadHash: pending.payloadHash },
      input.assertion,
    )
  } catch (err) {
    // GateError messages are authored in rp.ts (status codes, never response bodies).
    return await fail(
      err instanceof GateError ? err.message : "signature could not be verified",
      (err as Error).message,
    )
  }

  let outcome: ActionOutcome | undefined
  try {
    outcome = (await def.run(input.tenantId, pending.params, { nonce: pending.nonce })) ?? undefined
  } catch (err) {
    // The signature was valid; the action itself failed. Recorded distinctly, because "refused" and
    // "approved but broke" are different incidents.
    return await fail("the action failed after approval", (err as Error).message)
  }

  return { applied: true, ...(outcome ?? {}) }
}
