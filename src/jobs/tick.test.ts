import assert from "node:assert/strict"
import { after, before, beforeEach, test } from "node:test"

// The tick, against a real database: each event is folded into a finding exactly once, and a
// switched-off detector neither runs nor replays what it missed when switched back on.
//
// Same opt-in as src/server/setup-and-enrol.test.ts: needs TEST_DATABASE_URL, truncates it, and
// imports everything dynamically after redirecting DATABASE_URL.

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
let runDetectors: typeof import("./tick.ts")["runDetectors"]

before(async () => {
  if (skip) return
  prisma = (await import("../store/client.ts")).prisma
  runDetectors = (await import("./tick.ts")).runDetectors
})

after(async () => {
  if (skip) return
  await prisma.$disconnect()
})

beforeEach(async () => {
  if (skip) return
  const tables = await prisma.$queryRaw<{ tablename: string }[]>`
    SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> '_prisma_migrations'`
  await prisma.$executeRawUnsafe(`TRUNCATE ${tables.map((t) => `"${t.tablename}"`).join(", ")} CASCADE`)
})

async function setup() {
  const tenant = await prisma.tenant.create({ data: { slug: "t", name: "t" } })
  // Inactive, so the tick does not try to poll GitHub; the events are inserted directly.
  const gh = await prisma.connection.create({
    data: {
      tenantId: tenant.id,
      kind: "github",
      label: "GitHub",
      active: false,
      config: { pathMap: "generic" },
    },
  })
  return { tenant, gh }
}

async function pushPr(tenantId: string, connectionId: string, n: number, sha: string, paths: string[]) {
  await prisma.event.create({
    data: {
      tenantId,
      connectionId,
      source: "github",
      sourceId: `pr:acme/app#${n}@${sha}`,
      kind: "github.pull_request.updated",
      at: new Date(),
      attrs: {
        repo: "acme/app",
        number: n,
        title: `PR ${n}`,
        sha,
        draft: false,
        merged: false,
        paths: JSON.stringify(paths),
        pathsTruncated: false,
      },
    },
  })
}

const sensitive = () => prisma.finding.findMany({ where: { dedupeKey: { startsWith: "sensitive:" } } })

test("historical PR alerts are reclassified without losing feedback or changing observation history", {
  skip,
}, async () => {
  const { tenant, gh } = await setup()
  await pushPr(tenant.id, gh.id, 1, "a1", ["src/auth/login.ts", "apps/marketing/app/blog/authors.ts"])
  await runDetectors(new Date())
  const original = (await sensitive())[0]!
  await prisma.finding.update({
    where: { id: original.id },
    data: { severity: "high", category: "security", status: "dismissed", count: 4 },
  })
  await prisma.findingFeedback.create({
    data: { findingId: original.id, verdict: "expected", actor: "reviewer", note: "Already reviewed" },
  })
  await prisma.evidence.create({
    data: {
      findingId: original.id,
      kind: "assessment",
      ordinal: 2,
      data: { kind: "assessment", question: "anomalous", answer: 0.68 },
    },
  })
  const { reclassifyObservations } = await import("../store/reclassifyObservations.ts")
  await reclassifyObservations(tenant.id)
  assert.equal((await sensitive())[0]?.severity, "high", "preview does not mutate")
  await reclassifyObservations(tenant.id, true)
  await reclassifyObservations(tenant.id, true)
  const row = await prisma.finding.findUniqueOrThrow({
    where: { id: original.id },
    include: { evidence: true, feedback: true },
  })
  assert.equal(row.severity, "info")
  assert.equal(row.category, "engineering")
  assert.equal(row.status, "dismissed")
  assert.equal(row.count, 4)
  assert.equal(row.detectedAt.toISOString(), original.detectedAt.toISOString())
  assert.equal(row.lastSeenAt.toISOString(), original.lastSeenAt.toISOString())
  assert.equal(row.feedback[0]?.note, "Already reviewed")
  assert.ok(!row.evidence.some((e) => e.kind === "assessment"))
  const codeEvidence = row.evidence.find((e) => e.kind === "codeChange")
  assert.ok(codeEvidence)
  assert.deepEqual((codeEvidence.data as { paths: string[] }).paths, ["src/auth/login.ts"])
  await pushPr(tenant.id, gh.id, 1, "a2", ["src/auth/login.ts"])
  await runDetectors(new Date())
  assert.equal((await sensitive())[0]?.severity, "info", "future polls keep the observation informational")
})

test("a pull request is folded into its finding once per push, not once per tick", { skip }, async () => {
  const { tenant, gh } = await setup()
  await pushPr(tenant.id, gh.id, 1, "a1", ["src/auth/login.ts"])

  const report = await runDetectors(new Date())
  assert.deepEqual(report.detectors["sensitive-code-change"], { found: 1, created: 1 })
  await runDetectors(new Date())
  await runDetectors(new Date())
  let rows = await sensitive()
  assert.equal(rows.length, 1)
  assert.equal(rows[0]?.count, 1, "re-running the tick must not re-count the same push")

  await pushPr(tenant.id, gh.id, 1, "a2", ["src/auth/login.ts", "src/auth/session.ts"])
  await runDetectors(new Date())
  rows = await sensitive()
  assert.equal(rows.length, 1, "a second push folds into the same finding")
  assert.equal(rows[0]?.count, 2)
})

test("a switched-off detector does not run, and does not replay when switched back on", {
  skip,
}, async () => {
  const { tenant, gh } = await setup()
  await prisma.detectorConfig.create({
    data: { tenantId: tenant.id, detector: "sensitive-code-change", enabled: false },
  })
  await pushPr(tenant.id, gh.id, 2, "b1", ["src/crypto/keys.ts"])

  const off = await runDetectors(new Date())
  assert.equal(off.detectors["sensitive-code-change"], undefined, "not run at all")
  assert.equal((await sensitive()).length, 0)

  await prisma.detectorConfig.update({
    where: { tenantId_detector: { tenantId: tenant.id, detector: "sensitive-code-change" } },
    data: { enabled: true },
  })
  await runDetectors(new Date())
  assert.equal((await sensitive()).length, 0, "what happened while it was off is not replayed")

  await pushPr(tenant.id, gh.id, 3, "c1", ["src/crypto/keys.ts"])
  await runDetectors(new Date())
  assert.equal((await sensitive()).length, 1, "and it watches again from now")
})

test("metrics health runs once per arrival and respects the signed detector switch", { skip }, async () => {
  const { tenant, gh } = await setup()
  const metric = "intyga_audit_write_failures_total"
  const now = new Date()
  const push = (value: number, offset: number) =>
    prisma.event.create({
      data: {
        tenantId: tenant.id,
        connectionId: gh.id,
        source: "metrics",
        sourceId: `metric-${value}`,
        kind: "metrics.sample",
        subjectRef: metric,
        at: new Date(now.getTime() + offset),
        createdAt: new Date(now.getTime() + offset),
        attrs: { metric, query: metric, value },
      },
    })
  await push(100, -120_000)
  await push(105, -60_000)
  const report = await runDetectors(now)
  assert.deepEqual(report.detectors["metrics-health"], { found: 1, created: 1 })
  await runDetectors(new Date(now.getTime() + 1000))
  assert.equal((await prisma.finding.findFirstOrThrow()).count, 1)
  await prisma.detectorConfig.create({
    data: { tenantId: tenant.id, detector: "metrics-health", enabled: false },
  })
  await push(110, 2000)
  await runDetectors(new Date(now.getTime() + 3000))
  await prisma.detectorConfig.update({
    where: { tenantId_detector: { tenantId: tenant.id, detector: "metrics-health" } },
    data: { enabled: true },
  })
  await runDetectors(new Date(now.getTime() + 4000))
  assert.equal((await prisma.finding.findFirstOrThrow()).count, 1)
})

test("poll request failures are visible, safe to display and cleared on recovery", { skip }, async (t) => {
  const { tenant } = await setup()
  const connection = await prisma.connection.create({
    data: {
      tenantId: tenant.id,
      kind: "metrics",
      label: "Metrics",
      active: true,
      config: { baseUrl: "https://metrics.example", queries: "up" },
    },
  })
  const fetch = t.mock.method(
    globalThis,
    "fetch",
    async () => new Response("sensitive-upstream-error", { status: 503 }),
  )
  const failed = await runDetectors()
  assert.deepEqual(failed.polled.Metrics, { error: true })
  let row = await prisma.connection.findUniqueOrThrow({ where: { id: connection.id } })
  assert.ok(row.lastPolledAt)
  assert.ok(row.lastPollError)
  assert.equal(row.lastPollSuccessAt, null)
  assert.doesNotMatch(row.lastPollError, /sensitive-upstream-error/)
  await runDetectors(new Date(Date.now() + 1000))
  const repeated = await runDetectors(new Date(Date.now() + 1000))
  assert.deepEqual(repeated.detectors["collection-health"], { found: 1, created: 1 })
  const polls = await prisma.event.findMany({
    where: { connectionId: connection.id, kind: "intelligence.poll" },
  })
  assert.equal(polls.length, 3)
  assert.ok(polls.every((e) => (e.attrs as { succeeded: boolean }).succeeded === false))
  assert.doesNotMatch(JSON.stringify(polls), /sensitive-upstream-error/)
  fetch.mock.mockImplementation(
    async () =>
      new Response(JSON.stringify({ status: "success", data: { resultType: "vector", result: [] } })),
  )
  await runDetectors()
  row = await prisma.connection.findUniqueOrThrow({ where: { id: connection.id } })
  assert.equal(row.lastPollError, null)
  assert.ok(row.lastPollSuccessAt)
})
