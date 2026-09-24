import assert from "node:assert/strict"
import { generateKeyPairSync } from "node:crypto"
import { after, before, beforeEach, test } from "node:test"
import type { FastifyInstance } from "fastify"

// The first-time setup and enrolment paths, driven through the real routes against a real database.
//
// These are the two places where nobody can be asked for a passkey yet, so they are where a stranger
// could take an instance over: by binding a freshly deployed one to their own workspace, or by
// enrolling their own passkey as an administrator whose subject id they guessed. Both happened in
// earlier versions; these tests pin the fixes.
//
// DATABASE-BACKED, so opt-in: set TEST_DATABASE_URL to a database whose name contains "test". The
// suite TRUNCATES every table in it. Without the variable it is skipped, so `pnpm test` stays
// database-free; CI sets it. See CONTRIBUTING.md.

const TEST_URL = process.env.TEST_DATABASE_URL
const skip = TEST_URL ? false : "TEST_DATABASE_URL is not set"

if (TEST_URL) {
  // Refuse anything that is not plainly a test database: this suite deletes everything in it.
  if (!/test/i.test(new URL(TEST_URL).pathname)) {
    throw new Error("TEST_DATABASE_URL must name a database containing 'test' — this suite truncates it")
  }
  process.env.DATABASE_URL = TEST_URL
}

const SETUP_TOKEN = "setup-token-for-tests-0123456789"
process.env.SETUP_TOKEN = SETUP_TOKEN

// Port 9 (discard) on loopback: connections are refused at once, so every call to "Intyga" fails
// fast and deterministically. What these tests check is everything decided BEFORE that call.
const UNREACHABLE_GATEWAY = "http://127.0.0.1:9"
const PRIVATE_KEY = generateKeyPairSync("ec", { namedCurve: "P-256" })
  .privateKey.export({ type: "pkcs8", format: "pem" })
  .toString()

type Prisma = typeof import("../store/client.ts")["prisma"]
type InviteModule = typeof import("../auth/invite.ts")
type SessionModule = typeof import("../auth/session.ts")

let app: FastifyInstance
let prisma: Prisma
let invites: InviteModule
let sessions: SessionModule

before(async () => {
  if (skip) return
  // Imported only now: the Prisma client reads DATABASE_URL when its module loads.
  prisma = (await import("../store/client.ts")).prisma
  invites = await import("../auth/invite.ts")
  sessions = await import("../auth/session.ts")
  app = (await import("./app.ts")).buildApp()
  await app.ready()
})

after(async () => {
  if (skip) return
  await app.close()
  await prisma.$disconnect()
})

beforeEach(async () => {
  if (skip) return
  const tables = await prisma.$queryRaw<{ tablename: string }[]>`
    SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> '_prisma_migrations'`
  // Names come from the catalogue, not from input, and are quoted.
  await prisma.$executeRawUnsafe(`TRUNCATE ${tables.map((t) => `"${t.tablename}"`).join(", ")} CASCADE`)
})

function form(fields: Record<string, string>): string {
  return new URLSearchParams(fields).toString()
}

const BIND_FIELDS = {
  baseUrl: UNREACHABLE_GATEWAY,
  clientId: "cid_test",
  rpId: "localhost",
  origin: "http://localhost:4100",
  privateKey: PRIVATE_KEY,
  adminExternalId: "admin",
  adminLabel: "Admin",
}

function bindRequest(fields: Record<string, string>) {
  return app.inject({
    method: "POST",
    url: "/settings/bind",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: form(fields),
  })
}

/** Complete first-time setup and return the first administrator's invite token. */
async function bind(): Promise<string> {
  const res = await bindRequest({ setupToken: SETUP_TOKEN, ...BIND_FIELDS })
  assert.equal(res.statusCode, 303, res.body)
  const m = /^\/members\/enrol#invite=(inv_[A-Za-z0-9_-]{43})$/.exec(String(res.headers.location))
  assert.ok(m, `unexpected redirect: ${res.headers.location}`)
  return m[1] as string
}

function postJson(url: string, body: unknown, cookie?: string) {
  return app.inject({
    method: "POST",
    url,
    headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) },
    payload: JSON.stringify(body),
  })
}

// ─── setup ───────────────────────────────────────────────────────────────────────────────────────

test("an unbound instance serves the setup form and nothing else", { skip }, async () => {
  const home = await app.inject({ method: "GET", url: "/", headers: { accept: "text/html" } })
  assert.equal(home.statusCode, 200)
  assert.match(home.body, /name="setupToken"/)

  const page = await app.inject({ method: "GET", url: "/connectors", headers: { accept: "text/html" } })
  assert.equal(page.statusCode, 303)
  assert.equal(page.headers.location, "/")

  // These were reachable with no authentication at all before a workspace was bound.
  for (const url of ["/connectors/add", "/settings/key", "/alerts/create"]) {
    const res = await app.inject({
      method: "POST",
      url,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: form({ kind: "github", privateKey: "x", label: "x" }),
    })
    assert.equal(res.statusCode, 409, `${url}: ${res.body}`)
  }
  assert.equal(await prisma.connection.count(), 0)
  assert.equal(await prisma.tenant.count(), 0)
})

test("setup refuses a missing or wrong setup token, and creates nothing", { skip }, async () => {
  const missing = await bindRequest(BIND_FIELDS)
  assert.equal(missing.statusCode, 400)
  assert.match(missing.body, /Enter the setup token/)

  const wrong = await bindRequest({ setupToken: "not-the-token", ...BIND_FIELDS })
  assert.equal(wrong.statusCode, 403)
  assert.match(wrong.body, /setup token is not correct/)

  assert.equal(await prisma.tenant.count(), 0)
  assert.equal(await prisma.member.count(), 0)
})

test("setup with the right token binds once and hands the first administrator an invite", {
  skip,
}, async () => {
  const token = await bind()

  const stored = await prisma.memberInvite.findMany()
  assert.equal(stored.length, 1)
  assert.equal(stored[0]?.tokenHash, invites.hashInvite(token), "the invite is stored as its hash only")

  // Once bound, the route is behind sign-in like everything else — even holding the setup token.
  const again = await bindRequest({ setupToken: SETUP_TOKEN, ...BIND_FIELDS, adminExternalId: "mallory" })
  assert.equal(again.statusCode, 401)
  assert.equal(await prisma.member.count({ where: { externalId: "mallory" } }), 0)
})

// ─── enrolment ───────────────────────────────────────────────────────────────────────────────────

test("enrolment cannot be started with a subject id", { skip }, async () => {
  await bind()
  // The original hole: anyone could enrol their own passkey as "admin".
  const res = await postJson("/members/enrol/begin", { externalId: "admin" })
  assert.equal(res.statusCode, 400)
  assert.equal(await prisma.authCeremony.count(), 0)
})

test("an unknown, superseded or foreign invite is refused before Intyga is contacted", { skip }, async () => {
  const first = await bind()
  const member = await prisma.member.findFirstOrThrow({ where: { externalId: "admin" } })
  const tenant = await prisma.tenant.findFirstOrThrow()
  const second = await invites.issueInvite(prisma, { tenantId: tenant.id, memberId: member.id })

  for (const invite of [`inv_${"A".repeat(43)}`, first]) {
    const res = await postJson("/members/enrol/begin", { invite })
    assert.equal(res.statusCode, 400, res.body)
    assert.match(JSON.parse(res.body).error, /invalid, expired or already used/)
  }
  assert.equal(await prisma.authCeremony.count(), 0, "a refused invite opens no ceremony")

  assert.ok(await invites.resolveInvite(tenant.id, second.token), "the newest invite is live")
  assert.equal(await invites.resolveInvite(crypto.randomUUID(), second.token), null, "bound to its tenant")
  const later = new Date(Date.now() + invites.INVITE_TTL_MS + 1000)
  assert.equal(await invites.resolveInvite(tenant.id, second.token, later), null, "expires")

  await prisma.member.update({ where: { id: member.id }, data: { active: false } })
  assert.equal(await invites.resolveInvite(tenant.id, second.token), null, "dies with the member")
})

test("a live invite reaches Intyga, and the failure is reported in authored words", { skip }, async () => {
  const invite = await bind()
  const res = await postJson("/members/enrol/begin", { invite })
  assert.equal(res.statusCode, 502, res.body)
  const { error } = JSON.parse(res.body) as { error: string }
  assert.equal(error, "Intyga unreachable")
  assert.doesNotMatch(res.body, /127\.0\.0\.1|ECONNREFUSED|fetch failed/, "no raw fetch error text")
})

test("completing enrolment claims the invite only when it binds a credential", { skip }, async () => {
  const invite = await bind()
  const tenant = await prisma.tenant.findFirstOrThrow()
  const row = await prisma.memberInvite.findFirstOrThrow()

  // No begun ceremony: refused, and the claim is rolled back so the link still works.
  const early = await postJson("/members/enrol/complete", { invite, response: {} })
  assert.equal(early.statusCode, 400, early.body)
  assert.match(early.body, /timed out/)
  assert.equal((await prisma.memberInvite.findUniqueOrThrow({ where: { id: row.id } })).consumedAt, null)

  // A begun ceremony, but Intyga refuses the credential: the invite is handed back, not burnt.
  await prisma.authCeremony.create({
    data: {
      tenantId: tenant.id,
      kind: "enrol",
      externalId: "admin",
      inviteId: row.id,
      expiresAt: new Date(Date.now() + 60_000),
    },
  })
  const refused = await postJson("/members/enrol/complete", { invite, response: {} })
  assert.equal(refused.statusCode, 502, refused.body)
  assert.equal((await prisma.memberInvite.findUniqueOrThrow({ where: { id: row.id } })).consumedAt, null)
  assert.equal(
    (await prisma.member.findFirstOrThrow({ where: { externalId: "admin" } })).enrolledAt,
    null,
    "nothing was enrolled",
  )
})

test("a consumed invite cannot be used again", { skip }, async () => {
  const invite = await bind()
  await prisma.memberInvite.updateMany({ data: { consumedAt: new Date() } })
  const res = await postJson("/members/enrol/begin", { invite })
  assert.equal(res.statusCode, 400)
  const done = await postJson("/members/enrol/complete", { invite, response: {} })
  assert.equal(done.statusCode, 400)
  assert.match(done.body, /invalid, expired or already used/)
})

// ─── feedback attribution ────────────────────────────────────────────────────────────────────────

test("feedback is attributed to the signed-in member, never to what the body claims", { skip }, async () => {
  await bind()
  const tenant = await prisma.tenant.findFirstOrThrow()
  const member = await prisma.member.findFirstOrThrow({ where: { externalId: "admin" } })
  const finding = await prisma.finding.create({
    data: {
      tenantId: tenant.id,
      category: "security",
      severity: "low",
      title: "t",
      detectedAt: new Date(),
      lastSeenAt: new Date(),
      dedupeKey: "k",
    },
  })
  const url = `/api/findings/${finding.id}/feedback`

  const anonymous = await postJson(url, { verdict: "useful" })
  assert.equal(anonymous.statusCode, 401)

  const token = await sessions.createSession({ tenantId: tenant.id, memberId: member.id })
  const res = await postJson(url, { actor: "someone-else", verdict: "useful" }, `${sessions.COOKIE}=${token}`)
  assert.equal(res.statusCode, 200, res.body)
  const fb = await prisma.findingFeedback.findFirstOrThrow({ where: { findingId: finding.id } })
  assert.equal(fb.actor, "admin")
})
