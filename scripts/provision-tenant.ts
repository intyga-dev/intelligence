#!/usr/bin/env -S pnpm exec tsx
// Provision an Intelligence tenant.
//
// Creates the tenant and the BUILT-IN INTYGA connector — inactive. INTYGA is a hard dependency of
// Intelligence (it signs members in and approves privileged actions), so every tenant has an INTYGA
// relationship by definition; the connector just decides whether we also *observe* it. Activation
// is an approved action through the HTTP API. Members are not created here: whoever signs in with
// INTYGA after the workspace is bound (bind-workspace.ts) appears with their workspace role.
//
// This script talks to the database directly, which is deliberately a different trust context from
// the HTTP surface: whoever holds the database credential can already do anything. The gate exists
// to constrain the API, not to pretend the DBA is not the DBA. `--activate` is offered for local
// development and says so.
//
//   pnpm exec tsx scripts/provision-tenant.ts <slug> [--activate]
import "../src/loadenv.ts"
import crypto from "node:crypto"
import { prisma } from "../src/store/client.ts"
import { encryptSecret } from "../src/store/crypto.ts"

const args = process.argv.slice(2)
const flags = new Set(args.filter((a) => a.startsWith("--")))
const [slug] = args.filter((a) => !a.startsWith("--"))
if (!slug) {
  console.error("usage: provision-tenant.ts <slug> [--activate]")
  process.exit(1)
}

const tenant = await prisma.tenant.upsert({
  where: { slug },
  create: { slug, name: slug },
  update: {},
  select: { id: true },
})
let connection = await prisma.connection.findFirst({
  where: { tenantId: tenant.id, kind: "intyga", builtIn: true },
  select: { id: true, active: true },
})
let secret: string | null = null
if (!connection) {
  // The consumer mints the webhook secret and tells the producer. Nothing travels back.
  secret = `whsec_${crypto.randomBytes(24).toString("base64url")}`
  connection = await prisma.connection.create({
    data: {
      tenantId: tenant.id,
      kind: "intyga",
      label: "INTYGA",
      builtIn: true,
      active: false,
      secretCiphertext: encryptSecret(secret),
    },
    select: { id: true, active: true },
  })
}
if (flags.has("--activate") && !connection.active) {
  await prisma.connection.update({
    where: { id: connection.id },
    data: { active: true, activatedAt: new Date(), activationReceipt: "local-dev-no-receipt" },
  })
  connection.active = true
}
const base = process.env.PUBLIC_URL ?? `http://localhost:${process.env.PORT ?? 4100}`
console.log(`
Tenant      ${tenant.id}  (${slug})
Sign-in     bind the workspace (scripts/bind-workspace.ts or Settings), then members sign in at
            ${base}/login with their INTYGA passkey. Workspace ADMINs administer Intelligence.
Connector   INTYGA (built in) — ${connection.active ? "ACTIVE" : "INACTIVE"}
To observe your INTYGA, register this webhook endpoint in the INTYGA console:
  URL     ${base}/ingest/intyga/${connection.id}
  Secret  ${secret ?? "(unchanged — the connector already existed)"}
`)
await prisma.$disconnect()
