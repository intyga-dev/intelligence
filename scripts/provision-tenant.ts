#!/usr/bin/env -S pnpm exec tsx
// Provision an Intelligence tenant.
//
// Creates the tenant, its first member, and the BUILT-IN Intyga connector — inactive. Intyga is a
// hard dependency of Intelligence (it is what authenticates members and signs privileged actions),
// so every tenant has an Intyga relationship by definition; the connector just decides whether we
// also *observe* it. Activation is a signed action through the HTTP API.
//
// This script talks to the database directly, which is deliberately a different trust context from
// the HTTP surface: whoever holds the database credential can already do anything. The gate exists
// to constrain the API, not to pretend the DBA is not the DBA. `--activate` is offered for local
// development and says so.
//
//   pnpm exec tsx scripts/provision-tenant.ts <slug> <member-external-id> [--activate]

import "../src/loadenv.ts"
import crypto from "node:crypto"
import { prisma } from "../src/store/client.ts"
import { encryptSecret } from "../src/store/crypto.ts"

const args = process.argv.slice(2)
const flags = new Set(args.filter((a) => a.startsWith("--")))
const [slug = "default", memberExternalId = "admin"] = args.filter((a) => !a.startsWith("--"))

const tenant = await prisma.tenant.upsert({
  where: { slug },
  create: { slug, name: slug },
  update: {},
  select: { id: true },
})

await prisma.member.upsert({
  where: { tenantId_externalId: { tenantId: tenant.id, externalId: memberExternalId } },
  create: { tenantId: tenant.id, externalId: memberExternalId, label: memberExternalId },
  update: {},
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
      label: "Intyga",
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
Member      ${memberExternalId}  — enrols a passkey via Intyga before they can approve anything
Connector   Intyga (built in) — ${connection.active ? "ACTIVE" : "INACTIVE"}

To observe your Intyga, register this webhook endpoint in the Intyga console:

  URL     ${base}/ingest/intyga/${connection.id}
  Secret  ${secret ?? "(unchanged — the connector already existed)"}
  Events  challenge.created, challenge.approved, challenge.denied,
          challenge.expired, challenge.consumed, challenge.escalated

  Leave "include params" OFF. Action descriptions and parameters are not needed
  here and should not leave Intyga.
${secret ? "\nThe secret is shown once. Store it now." : ""}${
  connection.active
    ? ""
    : "\nThe connector is INACTIVE. Activate it with a signed action, or pass --activate for local development."
}`)

await prisma.$disconnect()
