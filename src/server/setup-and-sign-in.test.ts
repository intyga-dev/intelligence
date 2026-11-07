import assert from "node:assert/strict"
import { after, before, beforeEach, test } from "node:test"
import type { FastifyInstance } from "fastify"
import { anchor, CLIENT_ID, ORIGIN, signedReceipt, stubGateway, WORKSPACE } from "../test/intyga.ts"

const TEST_URL = process.env.TEST_DATABASE_URL
const skip = TEST_URL ? false : "TEST_DATABASE_URL is not set"
if (TEST_URL) {
  if (!/test/i.test(new URL(TEST_URL).pathname)) throw new Error("Expected a test database")
  process.env.DATABASE_URL = TEST_URL
}
// Exercise the fail-closed production setup rules, including an unset or weak setup token.
process.env.NODE_ENV = "production"
process.env.SECRETS_ENC_KEY = "test-only-encryption-key-with-enough-entropy"
process.env.LOG_LEVEL = "silent"
const SETUP_TOKEN = "test-only-operator-setup-token"
let prisma: typeof import("../store/client.ts")["prisma"]
let app: FastifyInstance
let gateway: Awaited<ReturnType<typeof stubGateway>>
before(async () => {
  if (skip) return
  gateway = await stubGateway()
  prisma = (await import("../store/client.ts")).prisma
  app = (await import("./app.ts")).buildApp()
  await app.ready()
})
after(async () => {
  if (skip) return
  await app.close()
  await gateway.app.close()
  await prisma.$disconnect()
})
beforeEach(async () => {
  if (skip) return
  process.env.SETUP_TOKEN = SETUP_TOKEN
  gateway.reset()
  const tables = await prisma.$queryRaw<
    { tablename: string }[]
  >`SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> '_prisma_migrations'`
  await prisma.$executeRawUnsafe(`TRUNCATE ${tables.map((t) => `"${t.tablename}"`).join(", ")} CASCADE`)
})
function details() {
  return {
    setupToken: SETUP_TOKEN,
    baseUrl: gateway.baseUrl,
    consoleUrl: gateway.config.consoleUrl,
    workspaceId: WORKSPACE,
    oidcClientId: CLIENT_ID,
    serviceClientId: gateway.config.serviceClientId,
    serviceSecret: gateway.config.serviceSecret,
    trustAnchor: JSON.stringify(anchor),
    origin: ORIGIN,
  }
}
function form(url: string, values: Record<string, string>, cookie = "") {
  return app.inject({
    method: "POST",
    url,
    headers: { "content-type": "application/x-www-form-urlencoded", cookie },
    payload: new URLSearchParams(values).toString(),
  })
}
async function connect() {
  const response = await form("/settings/bind", details())
  assert.equal(response.statusCode, 303, response.body)
  assert.equal(response.headers.location, "/login")
  return prisma.tenant.findFirstOrThrow()
}
async function signIn(role: "ADMIN" | "MEMBER" = "ADMIN") {
  gateway.state.claims.role = role
  const started = await form("/login/begin", { email: "hint@example.test" })
  assert.equal(started.statusCode, 303, started.body)
  const location = new URL(String(started.headers.location))
  const loginCookie = started.cookies.find((c) => c.name === "intelligence_login")
  assert.ok(loginCookie)
  assert.equal(loginCookie.httpOnly, true)
  assert.equal(loginCookie.secure, true)
  const callback = await app.inject({
    method: "GET",
    url: `/auth/callback?code=one-time-code&state=${location.searchParams.get("state")}`,
    headers: { cookie: `intelligence_login=${loginCookie.value}` },
  })
  assert.equal(callback.statusCode, 303, callback.body)
  const session = callback.cookies.find((c) => c.name === "intelligence_session")
  assert.ok(session)
  assert.equal(session.httpOnly, true)
  assert.equal(session.secure, true)
  return `intelligence_session=${session.value}`
}
async function open(cookie: string) {
  return app.inject({
    method: "POST",
    url: "/api/actions/open",
    headers: { cookie },
    payload: { action: "intelligence.service.create", params: { name: "Production API" } },
  })
}
function poll(cookie: string) {
  return app.inject({ method: "GET", url: `/api/actions/${gateway.state.nonce}`, headers: { cookie } })
}

test("an unconnected instance exposes setup and public health/demo, but no private pages or writes", {
  skip,
}, async () => {
  const home = await app.inject({ url: "/" })
  assert.equal(home.statusCode, 200)
  assert.match(home.body, /Connect your INTYGA workspace/)
  assert.match(home.body, /name="setupToken"/)
  for (const url of ["/connectors", "/members", "/settings", "/api/findings"]) {
    assert.equal((await app.inject({ url })).statusCode, 409, url)
    const page = await app.inject({ url, headers: { accept: "text/html" } })
    assert.equal(page.statusCode, 303)
    assert.equal(page.headers.location, "/")
  }
  for (const url of ["/api/actions/open", "/settings/credentials", "/connectors"]) {
    assert.equal((await app.inject({ method: "POST", url, payload: {} })).statusCode, 409, url)
  }
  assert.equal((await app.inject({ url: "/health" })).statusCode, 200)
  assert.equal((await app.inject({ url: "/demo" })).statusCode, 200)
  assert.equal(await prisma.member.count(), 0)
  assert.equal(await prisma.connection.count(), 0)
})

test("missing and incorrect setup tokens never connect a workspace", { skip }, async () => {
  const { setupToken: _token, ...without } = details()
  assert.equal((await form("/settings/bind", without)).statusCode, 400)
  assert.equal((await form("/settings/bind", { ...details(), setupToken: "wrong" })).statusCode, 403)
  assert.equal(await prisma.tenant.count(), 0)
})

test("production browser setup is disabled without a token and refuses placeholders", { skip }, async () => {
  delete process.env.SETUP_TOKEN
  const home = await app.inject({ url: "/" })
  assert.match(home.body, /Browser setup is disabled/)
  assert.doesNotMatch(home.body, /name="setupToken"/)
  assert.equal((await form("/settings/bind", details())).statusCode, 403)
  process.env.SETUP_TOKEN = "dev-setup-token-change-me"
  assert.equal((await form("/settings/bind", details())).statusCode, 503)
  assert.equal(await prisma.tenant.count(), 0)
})

test("connecting saves encrypted credentials, creates no local admin and cannot be repeated unsigned", {
  skip,
}, async () => {
  const tenant = await connect()
  const { decryptSecret } = await import("../store/crypto.ts")
  assert.equal(tenant.intygaWorkspaceId, WORKSPACE)
  assert.equal(tenant.intygaOidcClientId, CLIENT_ID)
  assert.notEqual(tenant.intygaServiceSecretCipher, gateway.config.serviceSecret)
  assert.equal(decryptSecret(tenant.intygaServiceSecretCipher ?? ""), gateway.config.serviceSecret)
  assert.deepEqual(tenant.intygaTrustAnchor, anchor)
  assert.equal(await prisma.member.count(), 0)
  assert.equal((await prisma.connection.findFirstOrThrow()).active, false)
  assert.equal((await form("/settings/bind", details())).statusCode, 401)
  assert.equal((await form("/settings/bind", details(), await signIn())).statusCode, 409)
})

test("setup refuses malformed or foreign-workspace anchors", { skip }, async () => {
  for (const trustAnchor of ["garbled", JSON.stringify({ ...anchor, tenantId: "foreign" })]) {
    assert.equal((await form("/settings/bind", { ...details(), trustAnchor })).statusCode, 400)
  }
  assert.equal(await prisma.tenant.count(), 0)
})

test("the OIDC callback creates the verified member and session, and refreshes their role at sign-in", {
  skip,
}, async () => {
  await connect()
  const cookie = await signIn()
  let member = await prisma.member.findFirstOrThrow()
  assert.equal(member.externalId, "admin@example.test")
  assert.equal(member.label, "Test Admin")
  assert.equal(member.role, "ADMIN")
  assert.ok(member.lastLoginAt)
  assert.notEqual((await prisma.session.findFirstOrThrow()).tokenHash, cookie.split("=")[1])
  assert.equal((await app.inject({ url: "/", headers: { cookie } })).statusCode, 200)
  await signIn("MEMBER")
  member = await prisma.member.findFirstOrThrow()
  assert.equal(member.role, "MEMBER")
  assert.equal(await prisma.member.count(), 1)
  assert.equal((await open(cookie)).statusCode, 400, "old session resolves the refreshed member role")
})

test("a refused callback clears login state and creates neither member nor session", { skip }, async () => {
  await connect()
  const response = await app.inject({
    url: "/auth/callback?code=forged&state=forged",
    headers: { cookie: "intelligence_login=garbled" },
  })
  assert.equal(response.statusCode, 401)
  assert.equal(response.cookies[0]?.maxAge, 0)
  assert.equal(await prisma.member.count(), 0)
  assert.equal(await prisma.session.count(), 0)
})

test("MEMBER cannot open actions, replace credentials or test the service key", { skip }, async () => {
  await connect()
  const cookie = await signIn("MEMBER")
  const response = await open(cookie)
  assert.equal(response.statusCode, 400)
  assert.match(response.json().error, /administrator/)
  assert.equal(
    (await form("/settings/credentials", { serviceSecret: "replacement" }, cookie)).statusCode,
    403,
  )
  assert.equal((await form("/settings/test", {}, cookie)).statusCode, 403)
  assert.equal(await prisma.pendingAction.count(), 0)
  assert.equal(gateway.state.authorizeCalls.length, 0)
})

test("credential repair rejects foreign and missing tenant IDs atomically, but accepts same-workspace keys", {
  skip,
}, async () => {
  const tenant = await connect()
  const cookie = await signIn()
  for (const tenantId of ["foreign", undefined]) {
    const response = await form(
      "/settings/credentials",
      { serviceSecret: "must-not-be-written", trustAnchor: JSON.stringify({ ...anchor, tenantId }) },
      cookie,
    )
    assert.equal(response.statusCode, 400)
    const stored = await prisma.tenant.findFirstOrThrow()
    assert.equal(stored.intygaServiceSecretCipher, tenant.intygaServiceSecretCipher)
    assert.deepEqual(stored.intygaTrustAnchor, anchor)
  }
  const refreshed = { ...anchor, epoch: 2 }
  assert.equal(
    (await form("/settings/credentials", { trustAnchor: JSON.stringify(refreshed) }, cookie)).statusCode,
    303,
  )
  assert.deepEqual((await prisma.tenant.findFirstOrThrow()).intygaTrustAnchor, refreshed)
})

test("polling waits for approval, verifies frozen parameters, redeems once and executes once", {
  skip,
}, async () => {
  await connect()
  const cookie = await signIn()
  const opened = await open(cookie)
  assert.equal(opened.statusCode, 200, opened.body)
  assert.equal((await poll(cookie)).json().status, "pending")
  assert.equal(await prisma.service.count(), 0)
  const frozen = gateway.state.authorizeCalls[0]
  assert.ok(frozen)
  gateway.state.receipt = signedReceipt(gateway.state.nonce, frozen)
  gateway.state.status = "APPROVED"
  const response = await poll(cookie)
  assert.equal(response.json().status, "applied", response.body)
  assert.equal((await prisma.service.findFirstOrThrow()).name, "Production API")
  assert.equal(gateway.state.consumeCalls.length, 1)
  assert.equal((await poll(cookie)).json().status, "applied")
  assert.equal(await prisma.service.count(), 1)
  assert.equal(gateway.state.consumeCalls.length, 1)
})

for (const scenario of [
  "DENIED",
  "EXPIRED",
  "CONSUMED",
  "bad receipt",
  "used receipt",
  "rejected key",
] as const) {
  test(`polling cannot execute after ${scenario}`, { skip }, async () => {
    await connect()
    const cookie = await signIn()
    assert.equal((await open(cookie)).statusCode, 200)
    const frozen = gateway.state.authorizeCalls[0]
    assert.ok(frozen)
    gateway.state.status = ["DENIED", "EXPIRED", "CONSUMED"].includes(scenario) ? scenario : "APPROVED"
    gateway.state.receipt = scenario === "bad receipt" ? {} : signedReceipt(gateway.state.nonce, frozen)
    gateway.state.consumeOk = scenario !== "used receipt"
    if (scenario === "rejected key") gateway.state.tokenStatus = 401
    const response = await poll(cookie)
    if (scenario === "rejected key") assert.equal(response.statusCode, 502)
    else assert.equal(response.json().status, "refused", response.body)
    assert.equal(await prisma.service.count(), 0)
    assert.equal(gateway.state.consumeCalls.length, scenario === "used receipt" ? 1 : 0)
  })
}
