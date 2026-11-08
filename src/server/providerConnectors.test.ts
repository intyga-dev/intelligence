import { STYLESHEETS } from "../ui/styles.ts"
import { testDeployment } from "../test/deployment.ts"
import assert from "node:assert/strict"
import { before, beforeEach, after, test } from "node:test"
import type { FastifyInstance } from "fastify"

const TEST_URL = process.env.TEST_DATABASE_URL,
  skip = TEST_URL ? false : "TEST_DATABASE_URL is not set"
if (TEST_URL) {
  if (!/test/i.test(new URL(TEST_URL).pathname)) throw new Error("Requires test database")
  process.env.DATABASE_URL = TEST_URL
}
const deployment = testDeployment()
let prisma: typeof import("../store/client.ts")["prisma"],
  app: FastifyInstance,
  tenantId: string,
  cookie: string
let encrypt: typeof import("../store/crypto.ts")["encryptSecret"]
before(async () => {
  if (skip) return
  prisma = (await import("../store/client.ts")).prisma
  encrypt = (await import("../store/crypto.ts")).encryptSecret
  app = (await import("./app.ts")).buildApp()
  await app.ready()
})
after(async () => {
  if (!skip) {
    await app.close()
    await prisma.$disconnect()
  }
  deployment.dispose()
})
beforeEach(async () => {
  if (skip) return
  const tables = await prisma.$queryRaw<
    { tablename: string }[]
  >`SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename<>'_prisma_migrations'`
  await prisma.$executeRawUnsafe(`TRUNCATE ${tables.map((t) => `"${t.tablename}"`).join(", ")} CASCADE`)
  const tenant = await prisma.tenant.create({ data: { slug: "connectors", name: "Connectors" } })
  tenantId = tenant.id
  const member = await prisma.member.create({
    data: { tenantId, externalId: "admin@example.com", label: "Admin", role: "ADMIN" },
  })
  const session = await import("../auth/session.ts")
  cookie = `${session.COOKIE}=${await session.createSession({ tenantId, memberId: member.id })}`
})
const secret = "connector-test-secret"
const minute = 60000
test("public UI styles are served as CSS from a fixed allowlist", { skip }, async () => {
  for (const name of STYLESHEETS) {
    const response = await app.inject({ url: `/assets/ui/${name}.module.css` })
    assert.equal(response.statusCode, 200)
    assert.match(response.headers["content-type"] ?? "", /text\/css/)
    assert.ok(response.body.length > 100)
  }
  const missing = await app.inject({ url: "/assets/ui/config.module.css", headers: { cookie } })
  assert.equal(missing.statusCode, 404)
})

async function connection(kind: string, active = true) {
  return prisma.connection.create({
    data: {
      tenantId,
      kind,
      label: kind,
      active,
      activatedAt: new Date(Date.now() - minute),
      secretCiphertext: encrypt(secret),
    },
  })
}
async function detect() {
  const { runOperationalDetectors } = await import("../jobs/operational.ts")
  await runOperationalDetectors(tenantId, new Date(Date.now() + minute), new Set(), async (_id, body) => {
    await body()
  })
}
const awsBody = (id: string, state: string, at: string) => ({
  id,
  account: "123456789012",
  region: "eu-west-1",
  time: at,
  source: "aws.cloudwatch",
  "detail-type": "CloudWatch Alarm State Change",
  resources: ["arn:test:alarm"],
  detail: { alarmName: "Checkout errors", state: { value: state, timestamp: at } },
})

test("catalogue exposes working integrations and creates an encrypted inactive source without skipping approval", {
  skip,
}, async () => {
  const page = await app.inject({ url: "/connectors", headers: { cookie } })
  assert.equal(page.statusCode, 200)
  for (const name of [
    "AWS EventBridge",
    "Google Cloud Monitoring",
    "Google Workspace Alert Center",
    "Azure Monitor",
    "Grafana Alerting",
    "Prometheus Alertmanager",
    "Stripe",
    "Better Stack",
  ])
    assert.ok(page.body.includes(name), name)
  assert.match(page.body, /connector-search/)
  assert.match(page.body, /Coverage:/)
  const create = await app.inject({
    method: "POST",
    url: "/connectors/add",
    headers: {
      cookie,
      origin: deployment.env.PUBLIC_URL,
      "content-type": "application/x-www-form-urlencoded",
    },
    payload: new URLSearchParams({ kind: "aws-eventbridge", label: "AWS production" }).toString(),
  })
  assert.equal(create.statusCode, 200, create.body)
  const row = await prisma.connection.findFirstOrThrow()
  assert.equal(row.active, false)
  assert.ok(row.secretCiphertext?.startsWith("v1."))
  const { decryptSecret } = await import("../store/crypto.ts"),
    value = decryptSecret(row.secretCiphertext!)!
  assert.ok(create.body.includes(value), "one-time reveal")
  const later = await app.inject({ url: "/connectors", headers: { cookie } })
  assert.ok(!later.body.includes(value))
  const ingest = await app.inject({
    method: "POST",
    url: `/ingest/aws-eventbridge/${row.id}`,
    headers: { "x-intelligence-token": value },
    payload: awsBody("1", "ALARM", new Date().toISOString()),
  })
  assert.equal(ingest.json().ignored, "connector inactive")
  assert.equal(await prisma.event.count(), 0)
  const unauthorized = await app.inject({
    method: "POST",
    url: "/api/actions/open",
    payload: { action: "intelligence.connector.activate", params: { connectionId: row.id } },
  })
  assert.equal(unauthorized.statusCode, 401)
})

test("AWS delivery travels through authentication, persistence, detection and the findings API; explicit recovery is replay-safe", {
  skip,
}, async () => {
  const c = await connection("aws-eventbridge"),
    opened = new Date().toISOString(),
    closed = new Date(Date.now() + 1000).toISOString()
  const post = (body: unknown, token = secret) =>
    app.inject({
      method: "POST",
      url: `/ingest/aws-eventbridge/${c.id}`,
      headers: { "x-intelligence-token": token },
      payload: body as object,
    })
  assert.equal((await post(awsBody("open", "ALARM", opened), "wrong")).statusCode, 401)
  assert.equal(await prisma.rawEvent.count(), 0)
  assert.equal((await post(awsBody("open", "ALARM", opened))).json().stored, true)
  assert.equal((await post(awsBody("open", "ALARM", opened))).json().duplicate, true)
  await detect()
  const f = await prisma.finding.findFirstOrThrow()
  assert.match(f.title, /Checkout errors/)
  assert.equal(f.status, "new")
  const result = await app.inject({ url: "/api/findings", headers: { cookie } })
  assert.equal(result.statusCode, 200)
  assert.match(result.body, /Checkout errors/)
  await detect()
  assert.equal((await prisma.finding.findUniqueOrThrow({ where: { id: f.id } })).count, 1)
  await post(awsBody("closed", "OK", closed))
  await detect()
  assert.equal((await prisma.finding.findUniqueOrThrow({ where: { id: f.id } })).status, "resolved")
  await post(awsBody("late-old-open", "ALARM", opened))
  await detect()
  assert.equal((await prisma.finding.findUniqueOrThrow({ where: { id: f.id } })).status, "resolved")
  assert.equal(await prisma.judgmentRequest.count(), 0)
})

test("Basic auth challenges Google and grouped Grafana alerts stay independent", { skip }, async () => {
  const google = await connection("google-monitoring")
  const challenge = await app.inject({
    method: "POST",
    url: `/ingest/google-monitoring/${google.id}`,
    payload: { incident: {} },
  })
  assert.equal(challenge.statusCode, 401)
  assert.match(String(challenge.headers["www-authenticate"]), /Basic/)
  const c = await connection("grafana"),
    startsAt = new Date().toISOString(),
    authorization = `Basic ${Buffer.from(`intelligence:${secret}`).toString("base64")}`
  const alerts = ["CPU", "Queue"].map((name) => ({
    fingerprint: name,
    labels: { alertname: name, severity: "high" },
    status: "firing",
    startsAt,
  }))
  const send = (body: unknown) =>
    app.inject({
      method: "POST",
      url: `/ingest/grafana/${c.id}`,
      headers: { authorization },
      payload: body as object,
    })
  assert.equal((await send({ alerts })).json().stored, true)
  assert.equal(await prisma.event.count(), 2)
  await detect()
  assert.equal(await prisma.finding.count(), 2)
  await send({
    alerts: [
      { ...alerts[0], status: "resolved", endsAt: new Date(Date.now() + 1000).toISOString() },
      alerts[1],
    ],
  })
  await detect()
  assert.equal(await prisma.finding.count({ where: { status: "resolved" } }), 1)
  assert.equal(await prisma.finding.count({ where: { status: "new" } }), 1)
  const truncated = await send({ alerts, truncatedAlerts: 2 })
  assert.equal(truncated.json().deferred, true)
  const page = await app.inject({ url: "/connectors", headers: { cookie } })
  assert.match(page.body, /Delivery errors/)
})

test("Better Stack polling state reaches a finding without importing response content", {
  skip,
}, async (t) => {
  const c = await connection("better-stack")
  t.mock.method(
    globalThis,
    "fetch",
    async () =>
      new Response(
        JSON.stringify({
          data: [
            {
              id: "incident-1",
              attributes: {
                name: "API uptime",
                status: "Started",
                started_at: "2026-01-01T00:00:00Z",
                response_content: "PRIVATE",
              },
            },
          ],
          pagination: { next: null },
        }),
      ),
  )
  const { betterStackConnector } = await import("../connectors/providerAlerts/poll.ts"),
    { saveEvent } = await import("../store/repo.ts")
  const events = await betterStackConnector.poll({
    connectionId: c.id,
    tenantId,
    config: {},
    secret,
    getCursor: async () => null,
    setCursor: async () => {},
    log: () => {
      assert.fail("healthy fixture should not report polling error")
    },
  })
  for (const e of events) await saveEvent(tenantId, e, null)
  await detect()
  assert.equal(await prisma.finding.count(), 1)
  assert.doesNotMatch(JSON.stringify(await prisma.event.findMany()), /PRIVATE/)
})
