import assert from "node:assert/strict"
import { after, before, beforeEach, test } from "node:test"
import type { FastifyInstance } from "fastify"

// Same isolated, opt-in database contract as setup-and-enrol.test.ts and CI.
const TEST_URL = process.env.TEST_DATABASE_URL
const skip = TEST_URL ? false : "TEST_DATABASE_URL is not set"
if (TEST_URL) {
  if (!/test/i.test(new URL(TEST_URL).pathname)) throw new Error("Expected a test database")
  process.env.DATABASE_URL = TEST_URL
}
let prisma: typeof import("../store/client.ts")["prisma"]
let app: FastifyInstance
let tenantId: string
let cookie: string

before(async () => {
  if (skip) return
  prisma = (await import("../store/client.ts")).prisma
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
  await prisma.$executeRawUnsafe(`TRUNCATE ${tables.map((t) => `"${t.tablename}"`).join(", ")} CASCADE`)
  const tenant = await prisma.tenant.create({
    data: { slug: "triage", name: "Triage", intygaKeyCipher: "test-binding" },
  })
  tenantId = tenant.id
  const member = await prisma.member.create({
    data: { tenantId, externalId: "investigator", label: "Investigator", enrolledAt: new Date() },
  })
  const sessions = await import("../auth/session.ts")
  cookie = `${sessions.COOKIE}=${await sessions.createSession({ tenantId, memberId: member.id })}`
})

async function finding(overrides: Record<string, unknown> = {}) {
  return prisma.finding.create({
    data: {
      tenantId,
      title: "Authorization failures",
      summary: "gateway regression",
      category: "security",
      severity: "high",
      detectedAt: new Date(),
      lastSeenAt: new Date(),
      dedupeKey: "test",
      ...overrides,
    },
  })
}
function get(url: string) {
  return app.inject({ method: "GET", url, headers: { cookie } })
}

test("service assignment scopes history and subsequent ingestion without moving prior incidents", {
  skip,
}, async () => {
  const { ACTIONS } = await import("../actions/registry.ts")
  const { saveEvent } = await import("../store/repo.ts")
  const { serviceDetail } = await import("../store/services.ts")
  const service = await prisma.service.create({ data: { tenantId, name: "API" } })
  const laterService = await prisma.service.create({ data: { tenantId, name: "Worker" } })
  const connection = await prisma.connection.create({
    data: { tenantId, kind: "custom", label: "Deploys", active: true },
  })
  const event = {
    connectionId: connection.id,
    source: "custom",
    sourceId: "one",
    kind: "custom.error",
    at: new Date(),
    subjectRef: null,
    correlationRef: null,
    attrs: {},
  }
  await saveEvent(tenantId, { ...event, serviceId: laterService.id })
  assert.equal((await prisma.event.findFirstOrThrow()).serviceId, null, "payload cannot choose the service")
  const f = await finding({ dedupeKey: `regression:${connection.id}:deploy:errors` })
  const assign = (serviceId: string | null) =>
    ACTIONS["intelligence.connector.assign-service"].run(
      tenantId,
      { connectionId: connection.id, serviceId },
      { nonce: "fixture-signed" },
    )
  await assign(service.id)
  assert.equal((await prisma.event.findFirstOrThrow()).serviceId, service.id)
  assert.equal((await prisma.finding.findUniqueOrThrow({ where: { id: f.id } })).serviceId, service.id)
  await assign(laterService.id)
  await saveEvent(tenantId, { ...event, sourceId: "two" })
  assert.equal((await serviceDetail(tenantId, service.id))?.events.length, 1)
  assert.equal((await serviceDetail(tenantId, laterService.id))?.events.length, 1)
  assert.equal((await get(`/api/findings?service=${service.id}`)).json().total, 1)
  assert.equal((await get(`/api/findings?service=${laterService.id}`)).json().total, 0)
  assert.equal((await get(`/services/${service.id}`)).statusCode, 200)
  await assign(null)
  assert.equal((await prisma.finding.findUniqueOrThrow({ where: { id: f.id } })).serviceId, service.id)
})

test("services refuse cross-tenant assignment and unsigned creation; demo discloses no live data", {
  skip,
}, async () => {
  const { ACTIONS } = await import("../actions/registry.ts")
  const other = await prisma.tenant.create({ data: { slug: "foreign", name: "Foreign" } })
  const foreign = await prisma.service.create({ data: { tenantId: other.id, name: "Secret tenant service" } })
  const connection = await prisma.connection.create({ data: { tenantId, kind: "custom", label: "Local" } })
  await assert.rejects(
    ACTIONS["intelligence.connector.assign-service"].run(
      tenantId,
      { connectionId: connection.id, serviceId: foreign.id },
      { nonce: "fixture-signed" },
    ),
    /service not found/,
  )
  assert.equal((await get(`/services/${foreign.id}`)).statusCode, 404)
  assert.doesNotMatch((await get("/services")).body, /Secret tenant service/)
  const unauthenticated = await app.inject({
    method: "POST",
    url: "/api/actions/open",
    payload: { action: "intelligence.service.create", params: { name: "Forged" } },
  })
  assert.equal(unauthenticated.statusCode, 401)
  const forged = await app.inject({
    method: "POST",
    url: "/api/actions/complete",
    headers: { cookie },
    payload: { nonce: "invented", assertion: {} },
  })
  assert.equal(forged.statusCode, 400)
  assert.equal(await prisma.service.count({ where: { tenantId } }), 0)
  const demo = await app.inject({ method: "GET", url: "/demo" })
  assert.equal(demo.statusCode, 200)
  assert.match(demo.body, /Example data/)
  assert.doesNotMatch(demo.body, /Secret tenant service/)
  assert.equal(await prisma.event.count(), 0)
})

test("priority is applied before the page limit and pagination reaches older findings", {
  skip,
}, async () => {
  const critical = await finding({ severity: "critical", lastSeenAt: new Date("2026-01-01") })
  await prisma.finding.createMany({
    data: Array.from({ length: 105 }, (_, i) => ({
      tenantId,
      title: `Recent ${i}`,
      category: "engineering",
      severity: "low",
      detectedAt: new Date(),
      lastSeenAt: new Date(),
      dedupeKey: `recent-${i}`,
    })),
  })
  const first = await get("/api/findings?limit=5")
  assert.equal(first.statusCode, 200, first.body)
  assert.equal(first.json().findings[0].id, critical.id)
  assert.equal(first.json().total, 106)
  assert.equal(first.json().hasMore, true)
  const final = await get("/api/findings?limit=5&page=22")
  assert.equal(final.json().findings.length, 1)
  assert.equal(final.json().hasMore, false)
  const recent = await get("/api/findings?limit=1&sort=recent")
  assert.notEqual(recent.json().findings[0].id, critical.id)
})

test("combined filters count all matches and stay scoped to the tenant", { skip }, async () => {
  const f = await finding()
  await finding({ dedupeKey: "other-category", category: "engineering" })
  await finding({ dedupeKey: "resolved", status: "resolved" })
  const other = await prisma.tenant.create({ data: { slug: "other", name: "Other" } })
  await finding({ tenantId: other.id, title: "Private finding" })
  const response = await get("/api/findings?status=open&severity=high&category=security&q=GATEWAY")
  assert.equal(response.json().total, 1)
  assert.equal(response.json().findings[0].id, f.id)
  assert.equal((await get("/api/findings?q=Private")).json().total, 0)
})

test("feedback persists notes, uses the session actor and keeps resolved findings linkable", {
  skip,
}, async () => {
  const f = await finding()
  const note = 'Checked the deployment. <script>alert("x")</script>'
  const response = await app.inject({
    method: "POST",
    url: `/api/findings/${f.id}/feedback`,
    headers: { cookie, "content-type": "application/json" },
    payload: { verdict: "fixed", note, actor: "spoofed" },
  })
  assert.equal(response.statusCode, 200, response.body)
  const record = (await get(`/api/findings?q=${f.id}`)).json().findings[0]
  assert.equal(record.status, "resolved")
  assert.equal(record.feedback[0].note, note)
  assert.equal(record.feedback[0].actor, "investigator")
  const page = await get(`/findings?status=all&q=${f.id}`)
  assert.match(page.body, /Authorization failures/)
  assert.match(page.body, /&lt;script&gt;alert/)
  assert.doesNotMatch(page.body, /<script>alert/)
  assert.equal((await get(`/api/findings?status=open&q=${f.id}`)).json().total, 0)
})

test("invalid filters return a client error and findings still require authentication", {
  skip,
}, async () => {
  for (const query of [
    "status=bogus",
    "limit=-1",
    "limit=2.5",
    "page=NaN",
    "severity=urgent",
    "status=new&status=resolved",
  ]) {
    for (const route of ["/findings", "/api/findings"]) {
      const response = await get(`${route}?${query}`)
      assert.equal(response.statusCode, 400, `${route}?${query}: ${response.body}`)
    }
  }
  assert.equal((await app.inject({ method: "GET", url: "/api/findings" })).statusCode, 401)
})

test("connector page surfaces retained normalization failures without exposing raw errors", {
  skip,
}, async () => {
  const connection = await prisma.connection.create({
    data: { tenantId, kind: "webhook", label: "Custom", active: true },
  })
  await prisma.rawEvent.create({
    data: {
      connectionId: connection.id,
      sourceId: "bad",
      body: {},
      normalizedAt: new Date(),
      normalizeError: "private-payload-detail",
    },
  })
  const response = await get("/connectors")
  assert.equal(response.statusCode, 200, response.body)
  assert.match(response.body, /Delivery errors/)
  assert.doesNotMatch(response.body, /private-payload-detail/)
  assert.match(response.body, /Setup instructions/)
})
