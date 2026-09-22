import crypto from "node:crypto"
import { config } from "../config.ts"
import { prisma } from "../store/client.ts"

// Sessions.
//
// Opaque and server-side. A signed cookie carrying claims would avoid a database read, but it also
// cannot be revoked — and "sign me out everywhere" is the one thing an admin console must be able
// to do after a laptop goes missing. The cost is one indexed lookup per request; the benefit is
// that logout means something.
//
// Only the SHA-256 of the token is stored, for the same reason a password hash is: a read of this
// table, by any route, must not yield usable sessions.

export const COOKIE = "intelligence_session"
const TTL_MS = 12 * 60 * 60_000
/** Re-stamp lastSeenAt at most this often, so an active session is not a write per request. */
const TOUCH_INTERVAL_MS = 5 * 60_000

export interface SessionActor {
  sessionId: string
  tenantId: string
  memberId: string
  externalId: string
  label: string
}

function hash(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex")
}

export async function createSession(input: {
  tenantId: string
  memberId: string
  receiptNonce?: string
}): Promise<string> {
  const token = crypto.randomBytes(32).toString("base64url")
  await prisma.session.create({
    data: {
      tenantId: input.tenantId,
      memberId: input.memberId,
      tokenHash: hash(token),
      expiresAt: new Date(Date.now() + TTL_MS),
      receiptNonce: input.receiptNonce ?? null,
    },
  })
  return token
}

/** Resolve a cookie to an actor, or null. Expired and revoked sessions resolve to null. */
export async function resolveSession(token: string | undefined): Promise<SessionActor | null> {
  if (!token) return null
  const row = await prisma.session.findUnique({
    where: { tokenHash: hash(token) },
    include: { member: { select: { id: true, externalId: true, label: true, active: true } } },
  })
  if (!row || row.revokedAt || row.expiresAt < new Date()) return null
  // A deactivated member's sessions stop working immediately, without needing to find and revoke
  // each one — removing someone must not depend on remembering to sweep their browsers.
  if (!row.member.active) return null

  if (Date.now() - row.lastSeenAt.getTime() > TOUCH_INTERVAL_MS) {
    await prisma.session.update({ where: { id: row.id }, data: { lastSeenAt: new Date() } })
  }

  return {
    sessionId: row.id,
    tenantId: row.tenantId,
    memberId: row.member.id,
    externalId: row.member.externalId,
    label: row.member.label,
  }
}

export async function revokeSession(sessionId: string): Promise<void> {
  await prisma.session.updateMany({
    where: { id: sessionId, revokedAt: null },
    data: { revokedAt: new Date() },
  })
}

/** Sign out every browser for one member. */
export async function revokeAllForMember(memberId: string): Promise<number> {
  const r = await prisma.session.updateMany({
    where: { memberId, revokedAt: null },
    data: { revokedAt: new Date() },
  })
  return r.count
}

export function sessionCookie(token: string): string {
  return [
    `${COOKIE}=${token}`,
    "Path=/",
    "HttpOnly",
    // Lax, not Strict: the passkey ceremony returns via a top-level navigation, and Strict would
    // drop the cookie on that hop. Lax still blocks cross-site POSTs, which is the threat here.
    "SameSite=Lax",
    `Max-Age=${Math.floor(TTL_MS / 1000)}`,
    ...(config.isProdLike ? ["Secure"] : []),
  ].join("; ")
}

export function clearCookie(): string {
  return `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${config.isProdLike ? "; Secure" : ""}`
}

/** Minimal cookie-header parse — one header, no dependency, no options to get wrong. */
export function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined
  for (const part of header.split(";")) {
    const eq = part.indexOf("=")
    if (eq === -1) continue
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim()
  }
  return undefined
}
