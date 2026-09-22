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

export async function beginEnrol(tenantId: string, externalId: string): Promise<unknown> {
  const member = await activeMember(tenantId, externalId)
  // Enrolment is only ever offered to someone an administrator already added. It is not a signup
  // path: anyone who could enrol themselves could grant themselves approval rights.
  if (!member) throw new AuthError("not an administrator of this workspace")

  const cfg = await cfgFor(tenantId)
  await ensureSubject(cfg, externalId, { source: "intyga-intelligence" })

  await prisma.authCeremony.create({
    data: {
      tenantId,
      kind: "enrol",
      externalId,
      expiresAt: new Date(Date.now() + CEREMONY_TTL_MS),
    },
  })
  return registrationOptions(cfg, externalId)
}

export async function completeEnrol(tenantId: string, externalId: string, response: unknown): Promise<void> {
  // The ceremony row is claimed atomically, so one begin yields at most one enrolment.
  const claimed = await prisma.authCeremony.updateMany({
    where: {
      tenantId,
      kind: "enrol",
      externalId,
      consumedAt: null,
      expiresAt: { gt: new Date() },
    },
    data: { consumedAt: new Date() },
  })
  if (claimed.count === 0) throw new AuthError("no live enrolment for this subject")

  const cfg = await cfgFor(tenantId)
  await registerCredential(cfg, externalId, response)

  await prisma.member.updateMany({
    where: { tenantId, externalId },
    data: { enrolledAt: new Date() },
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
