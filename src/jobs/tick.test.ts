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
