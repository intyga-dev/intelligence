import assert from "node:assert/strict"
import { after, before, beforeEach, test } from "node:test"
const TEST_URL = process.env.TEST_DATABASE_URL
const skip = TEST_URL ? false : "TEST_DATABASE_URL is not set"
if (TEST_URL) {
  if (!/test/i.test(new URL(TEST_URL).pathname)) throw new Error("Requires test database")
  process.env.DATABASE_URL = TEST_URL
}
let prisma: typeof import("../store/client.ts")["prisma"]
let run: typeof import("./operational.ts")["runOperationalDetectors"]
let actions: typeof import("../actions/registry.ts")["ACTIONS"]
before(async () => {
  if (skip) return
  prisma = (await import("../store/client.ts")).prisma
  run = (await import("./operational.ts")).runOperationalDetectors
  actions = (await import("../actions/registry.ts")).ACTIONS
})
after(async () => {
  if (!skip) await prisma.$disconnect()
})
beforeEach(async () => {
  if (skip) return
  const tables = await prisma.$queryRaw<
    { tablename: string }[]
  >`SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> '_prisma_migrations'`
  await prisma.$executeRawUnsafe(`TRUNCATE ${tables.map((t) => `"${t.tablename}"`).join(",")} CASCADE`)
})
async function setup() {
  const tenant = await prisma.tenant.create({ data: { slug: "ops", name: "Operations" } })
  const source = await prisma.connection.create({
    data: {
      tenantId: tenant.id,
      kind: "webhook",
      label: "Jobs",
      active: true,
      activatedAt: new Date("2026-01-01"),
    },
  })
  return { tenant, source }
}
const now = new Date("2026-11-07T12:00:00Z")
async function tick(tenantId: string, off = new Set<string>()) {
  const reports: Record<string, { found: number; created: number }> = {}
  await run(tenantId, now, off, async (id, body) => {
    reports[id] = await body()
  })
  return reports
}
test("configuration validates workspace ownership, connector kind and configured repositories", {
  skip,
}, async () => {
  const { tenant, source } = await setup()
  const other = await prisma.tenant.create({ data: { slug: "other", name: "Other" } })
  const configure = actions["intelligence.detector.configure"]
  const params = configure.schema.parse({
    detector: "job-overdue",
    settings: { targets: [{ connectionId: source.id, job: "backup", startsAt: now.toISOString() }] },
  })
  await assert.rejects(() => configure.run(other.id, params, { nonce: "test" }), /workspace/)
  const merge = configure.schema.parse({
    detector: "merge-policy",
    settings: { targets: [{ connectionId: source.id, repo: "acme/app" }] },
  })
  await assert.rejects(() => configure.run(tenant.id, merge, { nonce: "test" }), /GitHub/)
  await prisma.connection.update({
    where: { id: source.id },
    data: { kind: "github", config: { repos: "acme/core" } },
  })
  await assert.rejects(() => configure.run(tenant.id, merge, { nonce: "test" }), /repository/)
  await prisma.connection.update({ where: { id: source.id }, data: { kind: "webhook" } })
  await prisma.detectorConfig.create({
    data: { tenantId: tenant.id, detector: "job-overdue", enabled: false },
  })
  await configure.run(tenant.id, params, { nonce: "test" })
  assert.equal(
    (await prisma.detectorConfig.findFirstOrThrow()).enabled,
    false,
    "saving preserves disabled state",
  )
})

test("overdue jobs persist once, stay dismissed on replay, recover and create a new missed-deadline incident", {
  skip,
}, async () => {
  const { tenant, source } = await setup()
  await prisma.detectorConfig.create({
    data: {
      tenantId: tenant.id,
      detector: "job-overdue",
      updatedAt: new Date("2026-01-01"),
      settings: {
        targets: [
          {
            connectionId: source.id,
            job: "backup",
            startsAt: "2026-11-07T09:00:00Z",
            intervalMinutes: 60,
            graceMinutes: 5,
          },
        ],
      },
    },
  })
  assert.equal((await tick(tenant.id))["job-overdue"]!.created, 1)
  const f = await prisma.finding.findFirstOrThrow()
  await prisma.finding.update({ where: { id: f.id }, data: { status: "dismissed" } })
  assert.equal((await tick(tenant.id))["job-overdue"]!.found, 0)
  assert.equal((await prisma.finding.findUniqueOrThrow({ where: { id: f.id } })).status, "dismissed")
  await prisma.event.create({
    data: {
      tenantId: tenant.id,
      connectionId: source.id,
      source: "webhook",
      sourceId: "success",
      kind: "custom.job.completed",
      at: new Date("2026-11-07T11:45:00Z"),
      attrs: { job: "backup", succeeded: true },
    },
  })
  assert.equal((await tick(tenant.id))["job-overdue"]!.found, 0)
  await run(tenant.id, new Date("2026-11-07T13:00:00Z"), new Set(), async (_id, body) => {
    await body()
  })
  assert.equal(await prisma.finding.count(), 2)
  assert.equal(await prisma.judgmentRequest.count(), 0)
})

test("disabled detectors and a new activation boundary do not replay old failures", { skip }, async () => {
  const { tenant, source } = await setup()
  const settings = {
    targets: [{ connectionId: source.id, repo: "acme/app", branch: "main", workflow: "CI" }],
  }
  await prisma.detectorConfig.create({
    data: {
      tenantId: tenant.id,
      detector: "ci-health",
      updatedAt: new Date("2026-11-07T11:50:00Z"),
      settings,
    },
  })
  await prisma.event.create({
    data: {
      tenantId: tenant.id,
      connectionId: source.id,
      source: "webhook",
      sourceId: "failed",
      kind: "custom.ci_run",
      at: new Date("2026-11-07T11:00:00Z"),
      attrs: { repo: "acme/app", branch: "main", workflow: "CI", conclusion: "failure", runId: "1" },
    },
  })
  assert.equal((await tick(tenant.id))["ci-health"]!.found, 0)
  assert.equal((await tick(tenant.id, new Set(["ci-health"])))["ci-health"], undefined)
  assert.equal(await prisma.finding.count(), 0)
})

test("complete SLO series reaches persisted findings; missing data and another tenant do not", {
  skip,
}, async () => {
  const { tenant, source } = await setup()
  const other = await prisma.tenant.create({ data: { slug: "other", name: "Other" } })
  await prisma.detectorConfig.create({
    data: {
      tenantId: tenant.id,
      detector: "service-degradation",
      updatedAt: new Date("2026-01-01"),
      settings: {
        targets: [
          { connectionId: source.id, objective: "api", shortMinutes: 2, longMinutes: 5, burnRate: 10 },
        ],
      },
    },
  })
  const rows = Array.from({ length: 5 }, (_, i) => ({
    tenantId: tenant.id,
    connectionId: source.id,
    source: "webhook",
    sourceId: `minute-${i}`,
    kind: "custom.slo.sample",
    at: new Date(now.getTime() - (i + 1) * 60000),
    attrs: { objective: "api", windowSeconds: 60, total: 1000, bad: 20 },
  }))
  await prisma.event.createMany({ data: rows.slice(1) })
  assert.equal((await tick(tenant.id))["service-degradation"]!.found, 0)
  await prisma.event.create({ data: rows[0]! })
  assert.equal((await tick(tenant.id))["service-degradation"]!.created, 1)
  assert.equal((await tick(tenant.id))["service-degradation"]!.found, 0)
  await tick(other.id)
  assert.equal(await prisma.finding.count({ where: { tenantId: other.id } }), 0)
})
