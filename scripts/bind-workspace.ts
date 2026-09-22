#!/usr/bin/env -S pnpm exec tsx
// Bind (or re-bind) this tenant's Intyga workspace from the command line.
//
// The console deliberately makes re-binding a SIGNED action — repointing the workspace is the one
// change that could hand the tenant to someone else. That creates a bootstrap deadlock the first
// time, and after any mistake: you cannot sign the rebind without an enrolled administrator, and
// you cannot enrol one against a binding that does not work yet.
//
// This is the escape hatch, and it is a CLI on purpose. Whoever holds the database credential can
// already do anything; the signature protects the HTTP surface, not the DBA. Making that explicit
// is better than leaving people stuck or, worse, weakening the console path to unstick them.
//
//   pnpm exec tsx scripts/bind-workspace.ts \
//     --base-url https://api.staging.intyga.com \
//     --client-id cid_… \
//     --rp-id localhost \
//     --origin http://localhost:4100 \
//     --key ./rp.pk8
//
// RP ID is a BARE HOST — no scheme, no port, no path. Origin is the full URL, and its host must
// equal the RP ID or be a subdomain of it. That pair is what Intyga's console validates.

import "../src/loadenv.ts"
import { readFileSync } from "node:fs"
import { prisma } from "../src/store/client.ts"
import { encryptSecret } from "../src/store/crypto.ts"

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`)
  return i === -1 ? undefined : process.argv[i + 1]
}

const baseUrl = arg("base-url")
const clientId = arg("client-id")
const rpId = arg("rp-id")
const origin = arg("origin")
const keyPath = arg("key")
const slug = arg("slug")

if (!baseUrl || !clientId || !rpId || !origin || !keyPath) {
  console.error(
    "usage: bind-workspace.ts --base-url <url> --client-id <id> --rp-id <host> --origin <url> --key <pkcs8.pem> [--slug <tenant>]",
  )
  process.exit(1)
}

// Validated here rather than left to fail later inside a WebAuthn ceremony, where the symptom is
// "enrolment silently never verifies" rather than a sentence you can act on.
const problems: string[] = []
if (rpId.includes("://") || rpId.includes("/") || /\s/.test(rpId)) {
  problems.push(`--rp-id must be a bare host, got "${rpId}" (no scheme, no port, no path)`)
}
let originUrl: URL | undefined
try {
  originUrl = new URL(origin)
  if (originUrl.origin !== origin) problems.push(`--origin must be a bare origin, got "${origin}"`)
} catch {
  problems.push(`--origin is not a valid URL: "${origin}"`)
}
if (originUrl && !(originUrl.hostname === rpId || originUrl.hostname.endsWith(`.${rpId}`))) {
  problems.push(`--origin host "${originUrl.hostname}" must equal --rp-id "${rpId}" or be a subdomain of it`)
}
const loopback = originUrl ? ["localhost", "127.0.0.1", "::1"].includes(originUrl.hostname) : false
if (originUrl && originUrl.protocol !== "https:" && !loopback) {
  problems.push(`--origin must be https (http is allowed for loopback only)`)
}
if (problems.length > 0) {
  for (const p of problems) console.error(`  ✗ ${p}`)
  process.exit(1)
}

const privateKey = readFileSync(keyPath, "utf8")
if (!privateKey.includes("BEGIN PRIVATE KEY")) {
  console.error(`  ✗ ${keyPath} is not a PKCS#8 PEM — convert with:`)
  console.error(`      openssl pkcs8 -topk8 -nocrypt -in ec.key -out rp.pk8`)
  process.exit(1)
}

const tenant = slug
  ? await prisma.tenant.findUnique({ where: { slug }, select: { id: true, slug: true } })
  : await prisma.tenant.findFirst({ orderBy: { createdAt: "asc" }, select: { id: true, slug: true } })

if (!tenant) {
  console.error("no tenant — sign up at /, or run provision-tenant.ts first")
  process.exit(1)
}

await prisma.tenant.update({
  where: { id: tenant.id },
  data: {
    intygaBaseUrl: baseUrl,
    intygaClientId: clientId,
    intygaRpId: rpId,
    intygaOrigin: origin,
    intygaKeyCipher: encryptSecret(privateKey),
  },
})

const members = await prisma.member.findMany({
  where: { tenantId: tenant.id, active: true },
  select: { externalId: true, label: true, enrolledAt: true },
  orderBy: { createdAt: "asc" },
})

console.log(`
Bound tenant "${tenant.slug}" to ${baseUrl}
  RP ID   ${rpId}
  Origin  ${origin}

Administrators:`)
for (const m of members) {
  console.log(`  ${m.externalId.padEnd(16)} ${m.enrolledAt ? "enrolled" : "NOT enrolled"}  (${m.label})`)
}
const next = members.find((m) => !m.enrolledAt)
console.log(`
Next:
  1. ${origin}/settings — press "Test connection". It must succeed before anything else will.
  2. ${origin}/members/enrol?id=${next?.externalId ?? "<subject>"} — enrol a passkey.
  3. ${origin}/login — sign in.
`)

await prisma.$disconnect()
