#!/usr/bin/env -S pnpm exec tsx
// Issue a one-time passkey enrolment link for an existing administrator.
//
// The console does this as a signed action ("Enrolment link" on /members). This is the operator's
// escape hatch for when nobody CAN sign — the only administrator lost their device, or the link from
// setup expired before anyone used it. It talks to the database directly, the same trust context as
// provision-tenant.ts and bind-workspace.ts: whoever holds the database credential can already do
// anything, and the signature protects the HTTP surface, not the DBA.
//
// Issuing supersedes any link still open for that member.
//
//   pnpm exec tsx scripts/invite-member.ts <member-external-id> [--slug <tenant>]

import "../src/loadenv.ts"
import { enrolLink, INVITE_TTL_MS, issueInvite } from "../src/auth/invite.ts"
import { prisma } from "../src/store/client.ts"

const args = process.argv.slice(2)
const slugAt = args.indexOf("--slug")
const slug = slugAt === -1 ? undefined : args[slugAt + 1]
const externalId = args.find((a, i) => !a.startsWith("--") && i !== slugAt + 1)

if (!externalId) {
  console.error("usage: invite-member.ts <member-external-id> [--slug <tenant>]")
  process.exit(1)
}

const tenant = slug
  ? await prisma.tenant.findUnique({ where: { slug }, select: { id: true, intygaOrigin: true } })
  : await prisma.tenant.findFirst({ orderBy: { createdAt: "asc" }, select: { id: true, intygaOrigin: true } })
if (!tenant) {
  console.error("no tenant — run provision-tenant.ts first")
  process.exit(1)
}

const member = await prisma.member.findFirst({
  where: { tenantId: tenant.id, externalId, active: true },
  select: { id: true, label: true, enrolledAt: true },
})
if (!member) {
  console.error(`no active administrator "${externalId}" — add one with provision-tenant.ts or the console`)
  process.exit(1)
}

const invite = await issueInvite(prisma, { tenantId: tenant.id, memberId: member.id })
const origin = tenant.intygaOrigin ?? process.env.PUBLIC_URL ?? `http://localhost:${process.env.PORT ?? 4100}`

console.log(`
Enrolment link for ${member.label} (${externalId})${member.enrolledAt ? " — adds another passkey" : ""}
Works once, expires in ${INVITE_TTL_MS / 3_600_000} hours:

  ${enrolLink(origin, invite.token)}

Treat it like a password: whoever opens it first can add a passkey to this administrator.
Any earlier link for them no longer works.
`)

await prisma.$disconnect()
