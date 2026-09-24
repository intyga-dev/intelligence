import crypto from "node:crypto"
import type { Prisma } from "../generated/prisma/client.ts"
import { prisma } from "../store/client.ts"

// Enrolment invites.
//
// Binding a passkey to an administrator is the most sensitive write this service makes: the passkey
// is what signs in and what approves every privileged change. So the identity being enrolled must
// come from something only an existing administrator or the operator could have created — never
// from the request. The member's externalId does not qualify. It is typed into the login form and
// listed on /members; it is a name, not a secret, and "a member with this id exists" let anyone
// enrol their own key as `admin`.
//
// An invite is that server-side artefact: a 256-bit single-use token, stored only as its SHA-256,
// naming one member, expiring. It is minted by the `intelligence.member.add` / `.member.invite`
// signed actions, by first-time setup, or by `scripts/invite-member.ts` for someone holding the
// database credential.
//
// The link carries the token in the URL FRAGMENT (`/members/enrol#invite=…`). A fragment is never
// sent to the server, so the token does not land in the request log, a proxy's access log or a
// Referer header; the enrol page reads it in the browser and posts it in a request body.

/** Long enough to reach someone across a weekend, short enough that a forgotten link dies. */
export const INVITE_TTL_MS = 72 * 60 * 60_000

const PREFIX = "inv_"
/** 32 random bytes, base64url: 43 characters. */
const SHAPE = /^inv_[A-Za-z0-9_-]{43}$/

export function newInviteToken(): string {
  return PREFIX + crypto.randomBytes(32).toString("base64url")
}

export function hashInvite(token: string): string {
  return crypto.createHash("sha256").update(token, "utf8").digest("hex")
}

/** Cheap rejection before any database work, and a bound on what gets hashed. */
export function isInviteShaped(token: unknown): token is string {
  return typeof token === "string" && SHAPE.test(token)
}

/** The enrolment link for an invite. The token rides in the fragment — see the header. */
export function enrolLink(origin: string, token: string): string {
  return `${origin.replace(/\/+$/, "")}/members/enrol#invite=${token}`
}

type Db = Pick<Prisma.TransactionClient, "memberInvite">

export interface IssuedInvite {
  token: string
  expiresAt: Date
}

/**
 * Mint a fresh invite for one member, superseding any still-open one.
 *
 * Superseding matters: re-issuing is what an administrator does when a link was sent to the wrong
 * place, and the old link must stop working at that moment rather than when it expires.
 */
export async function issueInvite(
  db: Db,
  input: { tenantId: string; memberId: string },
  now: Date = new Date(),
): Promise<IssuedInvite> {
  await db.memberInvite.updateMany({
    where: { tenantId: input.tenantId, memberId: input.memberId, consumedAt: null },
    data: { consumedAt: now },
  })
  const token = newInviteToken()
  const expiresAt = new Date(now.getTime() + INVITE_TTL_MS)
  await db.memberInvite.create({
    data: { tenantId: input.tenantId, memberId: input.memberId, tokenHash: hashInvite(token), expiresAt },
  })
  return { token, expiresAt }
}

export interface LiveInvite {
  id: string
  memberId: string
  externalId: string
  label: string
}

/** Resolve a token to a live invite for an active member of this tenant, or null. */
export async function resolveInvite(
  tenantId: string,
  token: string,
  now: Date = new Date(),
): Promise<LiveInvite | null> {
  if (!isInviteShaped(token)) return null
  const row = await prisma.memberInvite.findUnique({
    where: { tokenHash: hashInvite(token) },
    include: { member: { select: { id: true, externalId: true, label: true, active: true } } },
  })
  if (!row || row.tenantId !== tenantId || row.consumedAt || row.expiresAt <= now) return null
  if (!row.member.active) return null
  return { id: row.id, memberId: row.member.id, externalId: row.member.externalId, label: row.member.label }
}
