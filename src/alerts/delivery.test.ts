import assert from "node:assert/strict"
import http from "node:http"
import type { AddressInfo } from "node:net"
import { after, before, beforeEach, test } from "node:test"

// ─── delivery, against a real database and a real HTTP receiver ─────────────────────────────────
//
// Same opt-in as src/server/setup-and-enrol.test.ts: needs TEST_DATABASE_URL, truncates it. A file of
// its own because every module is imported dynamically, after DATABASE_URL is redirected — a static
// import of deliver.ts would load the Prisma client against the wrong database first.

const TEST_URL = process.env.TEST_DATABASE_URL
const skip = TEST_URL ? false : "TEST_DATABASE_URL is not set"
if (TEST_URL) {
  if (!/test/i.test(new URL(TEST_URL).pathname)) {
    throw new Error("TEST_DATABASE_URL must name a database containing 'test' — this suite truncates it")
  }
  process.env.DATABASE_URL = TEST_URL
}

type Prisma = typeof import("../store/client.ts")["prisma"]
let prisma: Prisma
type Deliver = typeof import("./deliver.ts")
let deliverAlerts: Deliver["deliverAlerts"]
let signBody: Deliver["signBody"]
let SIGNATURE_HEADER: Deliver["SIGNATURE_HEADER"]
let encryptSecret: typeof import("../store/crypto.ts")["encryptSecret"]

interface Received {
  headers: http.IncomingHttpHeaders
  body: string
}
let received: Received[] = []
let respondWith = 200
let server: http.Server
let hookUrl = ""

before(async () => {
  if (skip) return
  prisma = (await import("../store/client.ts")).prisma
  ;({ deliverAlerts, signBody, SIGNATURE_HEADER } = await import("./deliver.ts"))
  encryptSecret = (await import("../store/crypto.ts")).encryptSecret
  server = http.createServer((req, res) => {
    let body = ""
    req.on("data", (c) => {
      body += c
    })
    req.on("end", () => {
      received.push({ headers: req.headers, body })
      res.statusCode = respondWith
      if (respondWith === 302) res.setHeader("location", "https://elsewhere.example/")
      res.end("ok")
    })
  })
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r))
  hookUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/hook`
})

after(async () => {
  if (skip) return
  server.close()
  await prisma.$disconnect()
})

beforeEach(async () => {
  if (skip) return
  received = []
  respondWith = 200
  const tables = await prisma.$queryRaw<{ tablename: string }[]>`
    SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> '_prisma_migrations'`
  await prisma.$executeRawUnsafe(`TRUNCATE ${tables.map((t) => `"${t.tablename}"`).join(", ")} CASCADE`)
})

const T0 = new Date("2026-09-23T10:00:00Z")
const at = (minutes: number) => new Date(T0.getTime() + minutes * 60_000)

async function seed(opts: { active: boolean; minSeverity?: "high" | "low" }) {
  const tenant = await prisma.tenant.create({
    data: { slug: "t", name: "t", intygaOrigin: "https://intel.example" },
  })
  const rule = await prisma.alertRule.create({
    data: {
      tenantId: tenant.id,
      name: "Page on high",
      minSeverity: opts.minSeverity ?? "high",
      channel: "webhook",
      targetCipher: encryptSecret(hookUrl),
      targetHost: new URL(hookUrl).host,
      signingSecretCipher: encryptSecret("whsig_test"),
      active: opts.active,
      activatedAt: T0,
      cooldownMinutes: 60,
    },
  })
  return { tenant, rule }
}

async function finding(tenantId: string, key: string, severity: "low" | "high" | "critical", seenAt: Date) {
  return prisma.finding.create({
    data: {
      tenantId,
      category: "security",
      severity,
      title: `finding ${key}`,
      summary: "SECRET-SUMMARY-MUST-NOT-LEAVE",
      detectedAt: seenAt,
      lastSeenAt: seenAt,
      dedupeKey: key,
    },
  })
}

test("an inactive rule sends nothing", { skip }, async () => {
  const { tenant } = await seed({ active: false })
  await finding(tenant.id, "a", "critical", at(5))
  const r = await deliverAlerts(at(10))
  assert.deepEqual(r, { attempted: 0, delivered: 0, failed: 0 })
  assert.equal(received.length, 0)
})

test("an active rule delivers matching findings once, signed, then respects its cooldown", {
  skip,
}, async () => {
  const { tenant, rule } = await seed({ active: true })
  await finding(tenant.id, "old", "critical", at(-5)) // before activation: not replayed
  await finding(tenant.id, "low", "low", at(5)) // below threshold
  await finding(tenant.id, "hit", "high", at(5))

  assert.deepEqual(await deliverAlerts(at(10)), { attempted: 1, delivered: 1, failed: 0 })
  assert.equal(received.length, 1)
  const [got] = received as [Received]
  const body = JSON.parse(got.body)
  assert.deepEqual(
    body.findings.map((f: { title: string }) => f.title),
    ["finding hit"],
  )
  assert.doesNotMatch(got.body, /SECRET-SUMMARY/, "summaries never leave")

  const sig = String(got.headers[SIGNATURE_HEADER])
  const t = Number(/t=(\d+)/.exec(sig)?.[1])
  assert.equal(sig, signBody("whsig_test", got.body, t), "the receiver can verify the raw body")

  // Within the cooldown: a new finding waits.
  await finding(tenant.id, "next", "critical", at(20))
  assert.equal((await deliverAlerts(at(30))).attempted, 0)
  // After it: only what is new since the last delivery.
  assert.equal((await deliverAlerts(at(71))).delivered, 1)
  assert.deepEqual(
    JSON.parse((received[1] as Received).body).findings.map((f: { title: string }) => f.title),
    ["finding next"],
  )

  const after = await prisma.alertRule.findUniqueOrThrow({ where: { id: rule.id } })
  assert.deepEqual(after.lastFiredAt, at(71))
  assert.equal(after.lastError, null)
})

test("a failed delivery records an authored reason and is retried", { skip }, async () => {
  const { tenant, rule } = await seed({ active: true })
  await finding(tenant.id, "hit", "high", at(5))

  respondWith = 500
  assert.deepEqual(await deliverAlerts(at(10)), { attempted: 1, delivered: 0, failed: 1 })
  let row = await prisma.alertRule.findUniqueOrThrow({ where: { id: rule.id } })
  assert.equal(row.lastError, "HTTP 500")
  assert.equal(row.lastFiredAt, null, "the watermark does not move on failure")

  // A redirect is a failure, not a hop: the findings would go to a host nobody approved.
  respondWith = 302
  await deliverAlerts(at(11))
  row = await prisma.alertRule.findUniqueOrThrow({ where: { id: rule.id } })
  assert.match(String(row.lastError), /redirect/)
  assert.doesNotMatch(String(row.lastError), /127\.0\.0\.1|elsewhere/, "no URL in the recorded error")

  respondWith = 200
  assert.equal((await deliverAlerts(at(12))).delivered, 1, "the same batch is retried")
  row = await prisma.alertRule.findUniqueOrThrow({ where: { id: rule.id } })
  assert.equal(row.lastError, null)
})
