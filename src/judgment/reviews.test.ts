import assert from "node:assert/strict"
import { after, before, beforeEach, test } from "node:test"
import { testDeployment } from "../test/deployment.ts"
const url = process.env.TEST_DATABASE_URL
const skip = url ? false : "TEST_DATABASE_URL is not set"
if (url) {
  if (!/test/i.test(new URL(url).pathname)) throw new Error("Expected test database")
  process.env.DATABASE_URL = url
}
const deployment = testDeployment()
let prisma: typeof import("../store/client.ts")["prisma"]
let tenantId: string, findingId: string
let evaluate: typeof import("../domain/judgment.ts")["evaluateFindingWithJudgment"]
let prepare: typeof import("../domain/judgment.ts")["prepareFindingReview"]
const originalFetch = globalThis.fetch
const review = {
  anomalous: 0.2,
  requiresHumanAttention: 0.8,
  severity: "medium",
  explanation: "Investigate collection failures; an outage is not established.",
  supportedEvidence: ["Failed polls"],
  missingEvidence: ["Service health"],
  nextSteps: ["Check credentials"],
}
let calls: { url: string; body: string }[] = []
let reply: () => Promise<Response>
const openaiReply = () =>
  Response.json({
    model: "fixture-openai",
    status: "completed",
    output: [{ type: "message", content: [{ type: "output_text", text: JSON.stringify(review) }] }],
  })
before(async () => {
  if (skip) return
  prisma = (await import("../store/client.ts")).prisma
  const module = await import("../domain/judgment.ts")
  evaluate = module.evaluateFindingWithJudgment
  prepare = module.prepareFindingReview
})
after(async () => {
  globalThis.fetch = originalFetch
  if (!skip) await prisma.$disconnect()
  deployment.dispose()
})
beforeEach(async () => {
  if (skip) return
  const tables = await prisma.$queryRaw<
    { tablename: string }[]
  >`SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> '_prisma_migrations'`
  await prisma.$executeRawUnsafe(`TRUNCATE ${tables.map((t) => `"${t.tablename}"`).join(", ")} CASCADE`)
  const { encryptSecret } = await import("../store/crypto.ts")
  const tenant = await prisma.tenant.create({ data: { name: "Review tests", slug: "review-tests" } })
  tenantId = tenant.id
  await prisma.detectorConfig.create({
    data: { tenantId, detector: "judgment", enabled: true, settings: { primaryProvider: "openai" } },
  })
  for (const provider of ["openai", "anthropic", "typesafe"])
    await prisma.reviewProvider.create({
      data: {
        tenantId,
        provider,
        model: `fixture-${provider}`,
        secretCiphertext: encryptSecret("fixture-secret"),
        dailyRequestLimit: 2,
      },
    })
  const f = await prisma.finding.create({
    data: {
      tenantId,
      title: "CustomerX private-system title",
      category: "engineering",
      severity: "high",
      detectedAt: new Date(),
      lastSeenAt: new Date(),
      dedupeKey: "test-review",
      evidence: {
        create: [
          {
            kind: "metric",
            ordinal: 0,
            data: {
              kind: "metric",
              label: "consecutive failed polls",
              value: 5,
              window: { from: new Date(0), to: new Date(1000) },
            },
          },
        ],
      },
    },
  })
  findingId = f.id
  calls = []
  reply = async () => openaiReply()
  globalThis.fetch = async (input, init) => {
    calls.push({ url: String(input), body: String(init?.body) })
    return reply()
  }
})

test("independent reviews retain both provider identities; primary calls never fan out", {
  skip,
}, async () => {
  assert.equal((await evaluate(tenantId, findingId)).ok, true)
  assert.equal(calls.length, 1)
  assert.equal(calls[0]?.url, "https://api.openai.com/v1/responses")
  assert.doesNotMatch(calls[0]?.body ?? "", /CustomerX|private-system|fixture-secret/)
  assert.equal((await evaluate(tenantId, findingId)).ok, true)
  assert.equal(calls.length, 1)
  reply = async () =>
    Response.json({
      model: "fixture-anthropic",
      stop_reason: "end_turn",
      content: [{ type: "text", text: JSON.stringify({ ...review, anomalous: 0.9 }) }],
    })
  const second = await prepare(tenantId, findingId, "anthropic")
  assert.equal(
    (
      await evaluate(tenantId, findingId, {
        provider: "anthropic",
        model: second.provider.model,
        stateDigest: second.stateDigest,
      })
    ).ok,
    true,
  )
  const assessments = await prisma.evidence.findMany({ where: { findingId, kind: "assessment" } })
  assert.deepEqual(
    new Set(assessments.map((e) => (e.data as { provider: string }).provider)),
    new Set(["openai", "anthropic"]),
  )
  const f = await prisma.finding.findUniqueOrThrow({ where: { id: findingId } })
  assert.equal(f.severity, "high")
  assert.equal(f.status, "new")
  const audit = await prisma.judgmentRequest.findMany({ where: { tenantId } })
  assert.equal(audit.length, 2)
  assert.doesNotMatch(JSON.stringify(audit), /fixture-secret|CustomerX|private-system/)
})

test("disabled, unconfigured, foreign and observation reviews never leave the host", { skip }, async () => {
  const foreign = await prisma.tenant.create({ data: { slug: "other", name: "Other" } })
  assert.equal((await evaluate(foreign.id, findingId)).ok, false)
  await prisma.finding.update({ where: { id: findingId }, data: { dedupeKey: "sensitive:test" } })
  assert.equal((await evaluate(tenantId, findingId)).ok, false)
  await prisma.finding.update({ where: { id: findingId }, data: { dedupeKey: "test-review" } })
  await prisma.detectorConfig.updateMany({ where: { tenantId }, data: { enabled: false } })
  assert.equal((await evaluate(tenantId, findingId)).ok, false)
  await prisma.detectorConfig.updateMany({ where: { tenantId }, data: { enabled: true } })
  await prisma.reviewProvider.updateMany({
    where: { tenantId, provider: "openai" },
    data: { secretCiphertext: null },
  })
  assert.equal((await evaluate(tenantId, findingId)).ok, false)
  assert.equal(calls.length, 0)
})

test("concurrent requests reserve once and failed attempts consume the daily limit", { skip }, async () => {
  const results = await Promise.all([evaluate(tenantId, findingId), evaluate(tenantId, findingId)])
  assert.ok(results.some((r) => r.ok))
  assert.equal(calls.length, 1)
  await prisma.finding.update({ where: { id: findingId }, data: { count: { increment: 1 } } })
  reply = async () => new Response("fixture-secret internal response", { status: 429 })
  assert.equal((await evaluate(tenantId, findingId)).ok, false)
  assert.equal(calls.length, 2)
  await prisma.finding.update({ where: { id: findingId }, data: { count: { increment: 1 } } })
  assert.match((await evaluate(tenantId, findingId)).error ?? "", /daily request limit/)
  assert.equal(calls.length, 2)
  const failed = await prisma.judgmentRequest.findFirstOrThrow({ where: { status: "FAILED" } })
  assert.match(failed.lastError ?? "", /429/)
  assert.doesNotMatch(failed.lastError ?? "", /fixture-secret|internal response/)
})

test("approved previews bind model and finding state; in-flight stale results are audit-only", {
  skip,
}, async () => {
  const preview = await prepare(tenantId, findingId, "openai")
  await prisma.finding.update({ where: { id: findingId }, data: { status: "resolved" } })
  assert.equal(
    (
      await evaluate(tenantId, findingId, {
        provider: "openai",
        model: preview.provider.model,
        stateDigest: preview.stateDigest,
      })
    ).ok,
    false,
  )
  assert.equal(calls.length, 0)
  reply = async () => {
    await prisma.finding.update({ where: { id: findingId }, data: { count: { increment: 1 } } })
    return openaiReply()
  }
  assert.equal((await evaluate(tenantId, findingId)).ok, true)
  assert.equal(await prisma.evidence.count({ where: { findingId, kind: "assessment" } }), 0)
  assert.equal(await prisma.judgmentRequest.count({ where: { findingId, status: "DONE" } }), 1)
})

test("removing a provider clears only its workspace credential and keeps historical reviews", {
  skip,
}, async () => {
  await evaluate(tenantId, findingId)
  const { ACTIONS } = await import("../actions/registry.ts")
  const foreign = await prisma.tenant.create({ data: { name: "Foreign", slug: "foreign" } })
  await prisma.reviewProvider.create({
    data: { tenantId: foreign.id, provider: "openai", model: "other", secretCiphertext: "other-cipher" },
  })
  await ACTIONS["intelligence.judgment.remove"].run(
    tenantId,
    { provider: "openai" },
    { nonce: "test-receipt" },
  )
  assert.equal(
    (
      await prisma.reviewProvider.findUniqueOrThrow({
        where: { tenantId_provider: { tenantId, provider: "openai" } },
      })
    ).secretCiphertext,
    null,
  )
  assert.equal(
    (
      await prisma.reviewProvider.findUniqueOrThrow({
        where: { tenantId_provider: { tenantId: foreign.id, provider: "openai" } },
      })
    ).secretCiphertext,
    "other-cipher",
  )
  assert.equal(await prisma.judgmentRequest.count({ where: { tenantId, status: "DONE" } }), 1)
  assert.equal((await evaluate(tenantId, findingId)).ok, false)
})

test("unknown primary settings fail closed without silently sending to the legacy provider", {
  skip,
}, async () => {
  await prisma.detectorConfig.updateMany({
    where: { tenantId, detector: "judgment" },
    data: { settings: { primaryProvider: "not-installed" } },
  })
  assert.equal((await evaluate(tenantId, findingId)).ok, false)
  assert.equal(calls.length, 0)
})
