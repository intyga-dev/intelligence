#!/usr/bin/env -S pnpm exec tsx
// Add an additional Intyga webhook connector (e.g. Intyga staging) for a tenant.

import "../src/loadenv.ts"
import crypto from "node:crypto"
import { prisma } from "../src/store/client.ts"
import { encryptSecret } from "../src/store/crypto.ts"

const [label = "INTYGA staging", slug] = process.argv.slice(2).filter((a) => !a.startsWith("--"))

const tenant = slug
  ? await prisma.tenant.findUnique({ where: { slug }, select: { id: true, slug: true, intygaOrigin: true } })
  : await prisma.tenant.findFirst({
      orderBy: { createdAt: "asc" },
      select: { id: true, slug: true, intygaOrigin: true },
    })

if (!tenant) {
  console.error("no tenant found")
  process.exit(1)
}

const secret = `whsec_${crypto.randomBytes(24).toString("base64url")}`
const connection = await prisma.connection.create({
  data: {
    tenantId: tenant.id,
    kind: "intyga",
    label,
    builtIn: false,
    active: true,
    secretCiphertext: encryptSecret(secret),
  },
  select: { id: true, label: true },
})

const origin = tenant.intygaOrigin ?? "http://localhost:4101"

console.log(`
Added connector "${connection.label}"
  Connection ID : ${connection.id}
  Webhook URL   : ${origin}/ingest/intyga/${connection.id}
  Signing Secret: ${secret}

Next:
  1. Open https://app.staging.intyga.com -> Webhooks -> Add Endpoint
  2. Paste the Webhook URL: ${origin}/ingest/intyga/${connection.id}
  3. Paste the Signing Secret: ${secret}
  4. Subscribe to: challenge.created, challenge.approved, challenge.denied, challenge.expired, challenge.consumed, challenge.escalated
`)

await prisma.$disconnect()
