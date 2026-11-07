#!/usr/bin/env -S pnpm exec tsx
// Bind (or re-bind) this tenant's INTYGA workspace from the command line.
//
// The console deliberately makes re-binding an APPROVED action — repointing the workspace is the
// one change that could hand the tenant to someone else. That creates a bootstrap deadlock the
// first time, and after any mistake: you cannot get the rebind approved without a working binding.
//
// This is the escape hatch, and it is a CLI on purpose. Whoever holds the database credential can
// already do anything; the approval protects the HTTP surface, not the DBA. Making that explicit
// is better than leaving people stuck or, worse, weakening the console path to unstick them.
//
//   pnpm exec tsx scripts/bind-workspace.ts \
//     --base-url https://api.intyga.com \
//     --console-url https://app.intyga.com \
//     --workspace-id <workspace id> \
//     --oidc-client-id oidc_… \
//     --service-client-id cid_… \
//     --service-secret-file ./service.secret \
//     --trust-anchor ./trust-anchor.json \
//     [--origin https://intelligence.example.com] [--slug <tenant>]
//
// The OIDC client comes from the console's Integrations → App sign-in page (its redirect URI is
// <origin>/auth/callback); the service key from API Keys (a SERVICE identity); the trust anchor from
// Approval Rules → Export. Nothing here can approve anything: the key asks, members sign.
import "../src/loadenv.ts"
import { readFileSync } from "node:fs"
import { parseTrustAnchor } from "../src/gate/client.ts"
import { prisma } from "../src/store/client.ts"
import { encryptSecret } from "../src/store/crypto.ts"

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`)
  return i === -1 ? undefined : process.argv[i + 1]
}

const baseUrl = arg("base-url")
const consoleUrl = arg("console-url")
const workspaceId = arg("workspace-id")
const oidcClientId = arg("oidc-client-id")
const serviceClientId = arg("service-client-id")
const secretPath = arg("service-secret-file")
const anchorPath = arg("trust-anchor")
const origin = arg("origin") ?? process.env.PUBLIC_URL
const slug = arg("slug")

if (
  !baseUrl ||
  !consoleUrl ||
  !workspaceId ||
  !oidcClientId ||
  !serviceClientId ||
  !secretPath ||
  !anchorPath
) {
  console.error(
    "usage: bind-workspace.ts --base-url <url> --console-url <url> --workspace-id <id> --oidc-client-id <id> " +
      "--service-client-id <id> --service-secret-file <path> --trust-anchor <path> [--origin <url>] [--slug <tenant>]",
  )
  process.exit(1)
}

const problems: string[] = []
for (const [name, value] of [
  ["--base-url", baseUrl],
  ["--console-url", consoleUrl],
] as const) {
  try {
    const u = new URL(value)
    if (u.protocol !== "https:" && !["localhost", "127.0.0.1", "::1"].includes(u.hostname))
      problems.push(`${name} must be https (http is allowed for loopback only)`)
  } catch {
    problems.push(`${name} is not a valid URL: "${value}"`)
  }
}
if (origin) {
  try {
    const u = new URL(origin)
    if (u.origin !== origin) problems.push(`--origin must be a bare origin, got "${origin}"`)
  } catch {
    problems.push(`--origin is not a valid URL: "${origin}"`)
  }
}
const serviceSecret = readFileSync(secretPath, "utf8").trim()
if (!serviceSecret) problems.push(`${secretPath} is empty`)
const anchorText = readFileSync(anchorPath, "utf8")
const anchor = parseTrustAnchor(anchorText)
if (!anchor.ok) problems.push(anchor.error)
else if (anchor.anchor.tenantId !== workspaceId)
  problems.push("the trust anchor must name the connected workspace")
if (problems.length > 0) {
  for (const p of problems) console.error(`  ✗ ${p}`)
  process.exit(1)
}

const tenant = slug
  ? await prisma.tenant.findUnique({ where: { slug }, select: { id: true, slug: true } })
  : await prisma.tenant.findFirst({ orderBy: { createdAt: "asc" }, select: { id: true, slug: true } })
if (!tenant) {
  console.error("no tenant — complete setup at /, or run provision-tenant.ts first")
  process.exit(1)
}
await prisma.tenant.update({
  where: { id: tenant.id },
  data: {
    intygaBaseUrl: baseUrl,
    intygaConsoleUrl: consoleUrl,
    intygaWorkspaceId: workspaceId,
    intygaOidcClientId: oidcClientId,
    intygaServiceClientId: serviceClientId,
    intygaServiceSecretCipher: encryptSecret(serviceSecret),
    intygaTrustAnchor: JSON.parse(anchorText),
    intygaTrustAnchorAt: new Date(),
    ...(origin ? { publicOrigin: origin } : {}),
  },
})
// Everyone signed in belonged to whatever was bound before.
await prisma.session.updateMany({
  where: { tenantId: tenant.id, revokedAt: null },
  data: { revokedAt: new Date() },
})
console.log(`
Tenant ${tenant.slug} (${tenant.id}) is bound to ${baseUrl}, workspace ${workspaceId}.
Members sign in at ${origin ?? "this instance"}/login with their INTYGA passkey; workspace ADMINs
administer Intelligence, MEMBERs read it. Re-export the trust anchor whenever the workspace's
approvers change, and re-run this script (or use Settings) to store it.`)
await prisma.$disconnect()
