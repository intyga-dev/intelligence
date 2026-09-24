import crypto from "node:crypto"
import { canonicalize } from "../gate/jcs.ts"
import {
  completeChallenge,
  ensureSubject,
  type GateConfig,
  openChallenge,
  registerCredential,
  registrationOptions,
  resolveGateConfig,
} from "../gate/rp.ts"
import { tenantBinding } from "../actions/execute.ts"
import { prisma } from "../store/client.ts"
import { hashInvite, isInviteShaped, resolveInvite } from "./invite.ts"
import { createSession } from "./session.ts"

// Logging in and enrolling, both through Intyga's platform plane.
//
// Intelligence has no password and no identity provider: an administrator IS an Intyga platform
// subject, and signing in is the same passkey ceremony that approves a privileged change. That is
// the whole point of the product model — remove Intyga and there is nobody to authenticate.
//
// SEPARATION THAT MATTERS: a login digest lives in its own namespace and its own table
// (AuthCeremony, not PendingAction). If a login were digested like an action, a captured login
// assertion could be redeemed as an approval for whatever action happened to share its shape.
// Different purpose, different bytes, different storage.

const CEREMONY_TTL_MS = 180_000

export class AuthError extends Error {}

/**
 * What a passkey signs to prove a login.
 *
 * `purpose` is deliberately not a GatedAction value and never will be — the two vocabularies are
 * disjoint so that no login can ever collide with an action's digest.
 */
export function loginDigest(input: { externalId: string; challengeId: string }): string {
  const payload = canonicalize({
    purpose: "intelligence.session.login",
    externalId: input.externalId,
    challengeId: input.challengeId,
  })
  return crypto.createHash("sha256").update(payload, "utf8").digest("hex")
}

async function cfgFor(tenantId: string): Promise<GateConfig> {
  return resolveGateConfig(await tenantBinding(tenantId))
}

async function activeMember(tenantId: string, externalId: string) {
  const m = await prisma.member.findFirst({
    where: { tenantId, externalId, active: true },
    select: { id: true, enrolledAt: true, label: true },
  })
  return m
}

// ─── Enrolment ───────────────────────────────────────────────────────────────────────────────────

//
// WHO is being enrolled comes from the invite, never from the request. See src/auth/invite.ts for
// why an externalId in the body cannot be the check: it is a name, not a secret, and trusting it let
// anyone bind their own passkey to any administrator. Proof of possession of the new key is
// necessary and proves nothing about who is holding it.

/** One message for every way an invite can be unusable, so a prober learns nothing from it. */
const INVITE_UNUSABLE =
  "This enrolment link is invalid, expired or already used. Ask an administrator for a new one."

export async function beginEnrol(
  tenantId: string,
  inviteToken: string,
): Promise<{ options: unknown; externalId: string; label: string }> {
  const invite = await resolveInvite(tenantId, inviteToken)
  if (!invite) throw new AuthError(INVITE_UNUSABLE)

  const cfg = await cfgFor(tenantId)
  await ensureSubject(cfg, invite.externalId, { source: "intyga-intelligence" })

  await prisma.authCeremony.create({
    data: {
      tenantId,
      kind: "enrol",
      externalId: invite.externalId,
      inviteId: invite.id,
      expiresAt: new Date(Date.now() + CEREMONY_TTL_MS),
    },
  })
  return {
    options: await registrationOptions(cfg, invite.externalId),
    externalId: invite.externalId,
    label: invite.label,
  }
}

export async function completeEnrol(tenantId: string, inviteToken: string, response: unknown): Promise<void> {
  if (!isInviteShaped(inviteToken)) throw new AuthError(INVITE_UNUSABLE)
  const now = new Date()

  // The invite and its ceremony are claimed together, atomically: two concurrent completions of one
  // link cannot both bind a credential, and a link with no begun ceremony binds nothing.
  const claimed = await prisma.$transaction(async (tx) => {
    const invite = await tx.memberInvite.findUnique({
      where: { tokenHash: hashInvite(inviteToken) },
      include: { member: { select: { externalId: true, active: true } } },
    })
    if (!invite || invite.tenantId !== tenantId || !invite.member.active) return null

    const inv = await tx.memberInvite.updateMany({
      where: { id: invite.id, consumedAt: null, expiresAt: { gt: now } },
      data: { consumedAt: now },
    })
    if (inv.count !== 1) return null

    const cer = await tx.authCeremony.updateMany({
      where: { tenantId, kind: "enrol", inviteId: invite.id, consumedAt: null, expiresAt: { gt: now } },
      data: { consumedAt: now },
    })
    // Throwing rolls the invite claim back with it, so a link whose ceremony lapsed still works.
    if (cer.count === 0) throw new AuthError("This enrolment timed out. Start again from the same link.")

    return { inviteId: invite.id, memberId: invite.memberId, externalId: invite.member.externalId }
  })
  if (!claimed) throw new AuthError(INVITE_UNUSABLE)

  const cfg = await cfgFor(tenantId)
  try {
    await registerCredential(cfg, claimed.externalId, response)
  } catch (err) {
    // Nothing was bound, so the link is handed back rather than burnt — a refused attestation is
    // usually a wrong-device retry, and making the admin re-issue for it teaches nothing. Only the
    // claim this call made is released (matched on its own timestamp).
    await prisma.memberInvite.updateMany({
      where: { id: claimed.inviteId, consumedAt: now },
      data: { consumedAt: null },
    })
    throw err
  }

  // First enrolment only: a second passkey added later does not rewrite when this member started.
  await prisma.member.updateMany({
    where: { id: claimed.memberId, enrolledAt: null },
    data: { enrolledAt: now },
  })
}

// ─── Login ───────────────────────────────────────────────────────────────────────────────────────

export interface LoginChallenge {
  nonce: string
  options: unknown
}

export async function beginLogin(tenantId: string, externalId: string): Promise<LoginChallenge> {
  const member = await activeMember(tenantId, externalId)
  // Deliberately the same error for "not a member" and "not enrolled": distinguishing them lets an
  // unauthenticated caller enumerate who administers this workspace.
  if (!member?.enrolledAt) throw new AuthError("cannot sign in with those details")

  const cfg = await cfgFor(tenantId)
  const challengeId = crypto.randomUUID()
  const payloadHash = loginDigest({ externalId, challengeId })

  // Reuses the platform signing ceremony, with a login digest rather than an action digest.
  const challenge = await openChallenge(cfg, externalId, {
    action: "intelligence.session.login" as never,
    params: { challengeId },
  })

  await prisma.authCeremony.create({
    data: {
      tenantId,
      kind: "login",
      externalId,
      nonce: challenge.nonce,
      payloadHash: challenge.payloadHash,
      expiresAt: new Date(Date.now() + CEREMONY_TTL_MS),
    },
  })
  // payloadHash is computed but intentionally unused here: the gate derives its own from the intent,
  // and trusting ours would let the two disagree silently.
  void payloadHash

  return { nonce: challenge.nonce, options: challenge.options }
}

/** Verify the assertion and mint a session. Returns the session token for the cookie. */
export async function completeLogin(
  tenantId: string,
  nonce: string,
  assertion: unknown,
): Promise<{ token: string; label: string }> {
  const claimed = await prisma.authCeremony.updateMany({
    where: { tenantId, kind: "login", nonce, consumedAt: null, expiresAt: { gt: new Date() } },
    data: { consumedAt: new Date() },
  })
  if (claimed.count === 0) throw new AuthError("no live sign-in for this challenge")

  const ceremony = await prisma.authCeremony.findUniqueOrThrow({ where: { nonce } })
  const member = await activeMember(tenantId, ceremony.externalId)
  if (!member?.enrolledAt) throw new AuthError("cannot sign in with those details")

  const cfg = await cfgFor(tenantId)
  await completeChallenge(
    cfg,
    {
      nonce: ceremony.nonce ?? nonce,
      expiresAt: "",
      options: null,
      payloadHash: ceremony.payloadHash ?? "",
    },
    assertion,
  )

  const token = await createSession({
    tenantId,
    memberId: member.id,
    receiptNonce: ceremony.nonce ?? nonce,
  })
  return { token, label: member.label }
}

/** Drop ceremonies that were opened and never finished. */
export async function pruneCeremonies(now = new Date()): Promise<number> {
  const r = await prisma.authCeremony.deleteMany({ where: { expiresAt: { lt: now } } })
  return r.count
}
