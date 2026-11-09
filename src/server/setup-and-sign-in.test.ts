import { writeFileSync } from "node:fs"
import { testDeployment } from "../test/deployment.ts"
import assert from "node:assert/strict"
import { after, before, beforeEach, test } from "node:test"
import type { FastifyInstance } from "fastify"
import { anchor, ORIGIN, signedReceipt, stubGateway } from "../test/intyga.ts"

const TEST_URL = process.env.TEST_DATABASE_URL
const skip = TEST_URL ? false : "TEST_DATABASE_URL is not set"
if (TEST_URL) {
  if (!/test/i.test(new URL(TEST_URL).pathname)) throw new Error("Expected a test database")
  process.env.DATABASE_URL = TEST_URL
}
// Exercise production cookie and authentication behavior.
process.env.NODE_ENV = "production"
process.env.SECRETS_ENC_KEY = "test-only-encryption-key-with-enough-entropy"
process.env.LOG_LEVEL = "silent"
let deployment: ReturnType<typeof testDeployment>
let prisma: typeof import("../store/client.ts")["prisma"]
let app: FastifyInstance
let gateway: Awaited<ReturnType<typeof stubGateway>>
before(async () => {
  if (skip) return
  gateway = await stubGateway()
  deployment = testDeployment(gateway.baseUrl, gateway.config.serviceClientId, gateway.config.serviceSecret)
  prisma = (await import("../store/client.ts")).prisma
  app = (await import("./app.ts")).buildApp()
  await app.ready()
})
after(async () => {
  if (skip) return
  await app.close()
  await gateway.app.close()
  await prisma.$disconnect()
  deployment.dispose()
})
beforeEach(async () => {
  if (skip) return
  deployment.apply()
  gateway.reset()
  const tables = await prisma.$queryRaw<
    { tablename: string }[]
  >`SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> '_prisma_migrations'`
  await prisma.$executeRawUnsafe(`TRUNCATE ${tables.map((t) => `"${t.tablename}"`).join(", ")} CASCADE`)
})
function form(url: string, values: Record<string, string>, cookie = "") {
  return app.inject({
    method: "POST",
    url,
    headers: { "content-type": "application/x-www-form-urlencoded", cookie },
    payload: new URLSearchParams(values).toString(),
  })
}
async function connect() {
  const response = await app.inject({ url: "/" })
  assert.equal(response.statusCode, 401, response.body)
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

test("an unconfigured instance shows status only and cannot be configured through HTTP", {
  skip,
}, async () => {
  delete process.env.INTYGA_SERVICE_CLIENT_SECRET
  const home = await app.inject({ url: "/" })
  assert.equal(home.statusCode, 200)
  assert.match(home.body, /connection is not configured/)
  assert.doesNotMatch(home.body, /<form|type="password"/)
  for (const url of ["/connectors", "/members", "/settings", "/api/findings"]) {
    assert.equal((await app.inject({ url })).statusCode, 409, url)
  }
  for (const url of ["/settings/bind", "/settings/credentials", "/api/actions/open"]) {
    assert.equal((await form(url, { serviceSecret: "cannot-configure-over-http" })).statusCode, 409)
  }
  assert.equal((await app.inject({ url: "/health" })).statusCode, 200)
  assert.equal((await app.inject({ url: "/demo" })).statusCode, 200)
  assert.equal(await prisma.tenant.count(), 0)
})

test("deployment configuration creates local data storage without copying connection settings", {
  skip,
}, async () => {
  const tenant = await connect()
  assert.deepEqual(Object.keys(tenant).sort(), ["createdAt", "id", "name", "slug"])
  assert.equal(await prisma.member.count(), 0)
  assert.equal((await prisma.connection.findFirstOrThrow()).active, false)
  const cookie = await signIn()
  const settings = await app.inject({ url: "/settings", headers: { cookie } })
  assert.match(settings.body, /Managed through deployment environment/)
  assert.doesNotMatch(settings.body, /settings\/credentials|workspace\.rebind/)
  assert.ok(!settings.body.includes(gateway.config.serviceSecret))
  assert.equal((await form("/settings/bind", {}, cookie)).statusCode, 404)
  assert.equal((await form("/settings/credentials", {}, cookie)).statusCode, 404)
})

test("embedded first-time setup is reachable from home before installing an application anchor", {
  skip,
}, async () => {
  process.env.INTYGA_EMBEDDED_APPLICATION_ID = "81627773-ecde-4833-a732-1b0afd0b8f93"
  writeFileSync(deployment.anchorPath, JSON.stringify({ ...anchor, approvers: [] }))
  for (const url of ["/", "/login"]) {
    const response = await app.inject({ url, headers: { accept: "text/html" } })
    assert.equal(response.statusCode, 200)
    assert.match(response.body, /Set up your Intelligence passkey/)
    assert.match(response.body, /id="embedded-link"/)
    assert.match(response.body, /id="embedded-login" disabled/)
  }
  const linked = await app.inject({
    method: "POST",
    url: "/embedded/link/start",
    headers: { origin: ORIGIN, "x-intelligence-login": "1" },
    payload: {},
  })
  assert.equal(linked.statusCode, 200, linked.body)
  assert.equal(
    new URL(linked.json().url).searchParams.get("applicationId"),
    process.env.INTYGA_EMBEDDED_APPLICATION_ID,
  )
  const invalidState = await app.inject({
    method: "POST",
    url: "/embedded/link/options",
    headers: { origin: ORIGIN, "x-intelligence-login": "1" },
    payload: { token: "a".repeat(43), state: "b".repeat(43) },
  })
  assert.equal(invalidState.statusCode, 403, invalidState.body)
  assert.match(invalidState.body, /another browser/)
  const denied = await app.inject({
    method: "POST",
    url: "/api/actions/open",
    payload: { action: "intelligence.service.create", params: { name: "unauthorized" } },
  })
  assert.equal(denied.statusCode, 409)
})

test("a foreign workspace trust anchor locks sign-in and privileged routes", { skip }, async () => {
  await connect()
  const cookie = await signIn()
  writeFileSync(deployment.anchorPath, JSON.stringify({ ...anchor, tenantId: "foreign" }))
  assert.equal((await open(cookie)).statusCode, 409)
  assert.equal((await form("/login/begin", {})).statusCode, 404)
})

test("changing the deployment identity invalidates old sessions and pending actions", { skip }, async () => {
  await connect()
  const cookie = await signIn()
  assert.equal((await open(cookie)).statusCode, 200)
  const tenant = await prisma.tenant.findFirstOrThrow()
  process.env.INTYGA_SERVICE_CLIENT_ID = "replacement-service-key"
  assert.equal((await app.inject({ url: "/settings", headers: { cookie } })).statusCode, 401)
  const { pollAction } = await import("../actions/execute.ts")
  await assert.rejects(
    pollAction({ tenantId: tenant.id, nonce: gateway.state.nonce }),
    /configuration changed/,
  )
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
  assert.equal(
    (
      await app.inject({
        method: "POST",
        url: "/api/profile",
        headers: { cookie, origin: ORIGIN },
        payload: { name: "My chosen name" },
      })
    ).statusCode,
    200,
  )
  await signIn("MEMBER")
  member = await prisma.member.findFirstOrThrow()
  assert.equal(member.role, "MEMBER")
  assert.equal(member.label, "My chosen name", "sign-in preserves the chosen display name")
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

test("MEMBER cannot open actions or test the service key", { skip }, async () => {
  await connect()
  const cookie = await signIn("MEMBER")
  const response = await open(cookie)
  assert.equal(response.statusCode, 400)
  assert.match(response.json().error, /administrator/)
  assert.equal(
    (await form("/settings/credentials", { serviceSecret: "replacement" }, cookie)).statusCode,
    404,
  )
  assert.equal((await form("/settings/test", {}, cookie)).statusCode, 403)
  assert.equal(await prisma.pendingAction.count(), 0)
  assert.equal(gateway.state.authorizeCalls.length, 0)
})

test("GitHub configuration waits for a verified approval and preserves credentials and cursors", {
  skip,
}, async () => {
  const t = await connect()
  const cookie = await signIn()
  const c = await prisma.connection.create({
    data: {
      tenantId: t.id,
      kind: "github",
      label: "GitHub",
      active: true,
      config: { repos: "acme/core, acme/deploy", custom: "preserved" },
      secretCiphertext: "encrypted-test-token",
    },
  })
  await prisma.sourceCursor.create({
    data: { connectionId: c.id, name: "pr:acme/core", value: "2026-11-07T00:00:00Z" },
  })
  const params = {
    connectionId: c.id,
    label: "GitHub core",
    repos: "acme/core",
    deployWorkflows: "Deploy",
    pathMap: "generic",
  }
  const opened = await app.inject({
    method: "POST",
    url: "/api/actions/open",
    headers: { cookie },
    payload: { action: "intelligence.connector.configure-github", params },
  })
  assert.equal(opened.statusCode, 200, opened.body)
  assert.equal((await poll(cookie)).json().status, "pending")
  assert.deepEqual((await prisma.connection.findUniqueOrThrow({ where: { id: c.id } })).config, c.config)
  const frozen = gateway.state.authorizeCalls[0]
  assert.ok(frozen)
  assert.deepEqual(frozen.params, params)
  gateway.state.receipt = signedReceipt(gateway.state.nonce, frozen)
  gateway.state.status = "APPROVED"
  assert.equal((await poll(cookie)).json().status, "applied")
  const updated = await prisma.connection.findUniqueOrThrow({ where: { id: c.id } })
  assert.deepEqual(updated.config, {
    repos: "acme/core",
    deployWorkflows: "Deploy",
    pathMap: "generic",
    custom: "preserved",
  })
  assert.equal(updated.secretCiphertext, c.secretCiphertext)
  assert.equal(updated.active, true)
  assert.equal(await prisma.sourceCursor.count({ where: { connectionId: c.id } }), 1)
  assert.equal(gateway.state.consumeCalls.length, 1)
})

test("GitHub token replacement is encrypted, receipt-bound and applied once without losing history", {
  skip,
}, async () => {
  const t = await connect()
  const cookie = await signIn()
  const { encryptSecret, decryptSecret } = await import("../store/crypto.ts")
  const c = await prisma.connection.create({
    data: {
      tenantId: t.id,
      kind: "github",
      label: "GitHub",
      active: true,
      secretCiphertext: encryptSecret("old-token"),
      config: { repos: "acme/core", custom: "preserved" },
    },
  })
  await prisma.sourceCursor.create({ data: { connectionId: c.id, name: "pr:acme/core", value: "unchanged" } })
  const params = {
    connectionId: c.id,
    label: c.label,
    repos: "acme/core",
    deployWorkflows: "",
    pathMap: "generic",
  }
  const replacementToken = "github_pat_replacement-test-only"
  const opened = await app.inject({
    method: "POST",
    url: "/api/actions/open",
    headers: { cookie },
    payload: { action: "intelligence.connector.configure-github", params, replacementToken },
  })
  assert.equal(opened.statusCode, 200, opened.body)
  assert.match(opened.json().summary, /Replace its GitHub token/)
  const pending = await prisma.pendingAction.findUniqueOrThrow({ where: { nonce: gateway.state.nonce } })
  assert.ok(pending.secretCiphertext)
  assert.equal(decryptSecret(pending.secretCiphertext), replacementToken)
  assert.doesNotMatch(JSON.stringify(pending), new RegExp(replacementToken))
  const frozen = gateway.state.authorizeCalls[0]
  assert.ok(frozen)
  assert.match(String(frozen.params.tokenDigest), /^[a-f0-9]{64}$/)
  assert.equal(JSON.stringify(frozen).includes(pending.secretCiphertext), false)
  assert.equal(JSON.stringify(frozen).includes(replacementToken), false)
  assert.equal(opened.body.includes(replacementToken), false)
  assert.equal((await poll(cookie)).json().status, "pending")
  assert.equal(
    (await prisma.connection.findUniqueOrThrow({ where: { id: c.id } })).secretCiphertext,
    c.secretCiphertext,
  )
  gateway.state.receipt = signedReceipt(gateway.state.nonce, frozen)
  gateway.state.status = "APPROVED"
  assert.equal((await poll(cookie)).json().status, "applied")
  const updated = await prisma.connection.findUniqueOrThrow({ where: { id: c.id } })
  assert.equal(decryptSecret(updated.secretCiphertext!), replacementToken)
  assert.equal(updated.active, true)
  assert.equal((updated.config as Record<string, unknown>).custom, "preserved")
  assert.equal(await prisma.sourceCursor.count({ where: { connectionId: c.id } }), 1)
  assert.equal(
    (await prisma.pendingAction.findUniqueOrThrow({ where: { nonce: pending.nonce } })).secretCiphertext,
    null,
  )
  assert.equal((await poll(cookie)).json().status, "applied")
  assert.equal(gateway.state.consumeCalls.length, 1)
})

for (const outcome of ["denied", "expired", "tampered-secret", "tampered-params", "blank"] as const) {
  test(`GitHub token replacement handles ${outcome} without changing the existing credential`, {
    skip,
  }, async () => {
    const t = await connect()
    const cookie = await signIn()
    const { encryptSecret } = await import("../store/crypto.ts")
    const c = await prisma.connection.create({
      data: {
        tenantId: t.id,
        kind: "github",
        label: "GitHub",
        secretCiphertext: encryptSecret("keep-me"),
      },
    })
    const params = {
      connectionId: c.id,
      label: c.label,
      repos: "acme/core",
      deployWorkflows: "",
      pathMap: "generic",
    }
    const opened = await app.inject({
      method: "POST",
      url: "/api/actions/open",
      headers: { cookie },
      payload: {
        action: "intelligence.connector.configure-github",
        params,
        replacementToken: outcome === "blank" ? "   " : "replacement-token",
      },
    })
    assert.equal(opened.statusCode, 200, opened.body)
    const frozen = gateway.state.authorizeCalls[0]
    assert.ok(frozen)
    gateway.state.receipt = signedReceipt(gateway.state.nonce, frozen)
    gateway.state.status = outcome === "denied" ? "DENIED" : "APPROVED"
    if (outcome === "expired")
      await prisma.pendingAction.update({
        where: { nonce: gateway.state.nonce },
        data: { expiresAt: new Date(0) },
      })
    if (outcome === "tampered-secret")
      await prisma.pendingAction.update({
        where: { nonce: gateway.state.nonce },
        data: { secretCiphertext: encryptSecret("different-token") },
      })
    if (outcome === "tampered-params")
      await prisma.pendingAction.update({
        where: { nonce: gateway.state.nonce },
        data: { params: { ...frozen.params, tokenDigest: "0".repeat(64) } },
      })
    assert.equal((await poll(cookie)).json().status, outcome === "blank" ? "applied" : "refused")
    assert.equal(
      (await prisma.connection.findUniqueOrThrow({ where: { id: c.id } })).secretCiphertext,
      c.secretCiphertext,
    )
    assert.equal(
      (await prisma.pendingAction.findUniqueOrThrow({ where: { nonce: gateway.state.nonce } }))
        .secretCiphertext,
      null,
    )
    if (outcome === "blank") assert.deepEqual(frozen.params, params)
  })
}

test("connector removal waits for approval, clears credentials and keeps evidence", { skip }, async () => {
  const t = await connect()
  const cookie = await signIn()
  const c = await prisma.connection.create({
    data: {
      tenantId: t.id,
      kind: "github",
      label: "Remove this source",
      active: true,
      secretCiphertext: "saved-token",
    },
  })
  const event = await prisma.event.create({
    data: {
      tenantId: t.id,
      connectionId: c.id,
      source: "github",
      sourceId: "historical",
      kind: "ci.run",
      at: new Date(),
    },
  })
  const before = await app.inject({ url: "/connectors", headers: { cookie } })
  assert.match(before.body, /Remove connector/)
  const opened = await app.inject({
    method: "POST",
    url: "/api/actions/open",
    headers: { cookie },
    payload: { action: "intelligence.connector.remove", params: { connectionId: c.id } },
  })
  assert.equal(opened.statusCode, 200, opened.body)
  assert.equal((await poll(cookie)).json().status, "pending")
  assert.equal((await prisma.connection.findUniqueOrThrow({ where: { id: c.id } })).active, true)
  const frozen = gateway.state.authorizeCalls[0]
  assert.ok(frozen)
  gateway.state.receipt = signedReceipt(gateway.state.nonce, frozen)
  gateway.state.status = "APPROVED"
  assert.equal((await poll(cookie)).json().status, "applied")
  const removed = await prisma.connection.findUniqueOrThrow({ where: { id: c.id } })
  assert.ok(removed.removedAt)
  assert.equal(removed.active, false)
  assert.equal(removed.secretCiphertext, null)
  assert.ok(await prisma.event.findUnique({ where: { id: event.id } }))
  assert.doesNotMatch(
    (await app.inject({ url: "/connectors", headers: { cookie } })).body,
    /Remove this source/,
  )
  assert.equal((await app.inject({ url: `/connectors/${c.id}/edit`, headers: { cookie } })).statusCode, 404)
  const { connectionForIngest, activeConnections } = await import("../store/repo.ts")
  assert.equal(await connectionForIngest(c.id, "github"), null)
  assert.equal(
    (await activeConnections()).some((row) => row.id === c.id),
    false,
  )
  const { ACTIONS } = await import("../actions/registry.ts")
  await assert.rejects(
    ACTIONS["intelligence.connector.activate"].run(t.id, { connectionId: c.id }, { nonce: "stale" }),
    /not found/,
  )
  await assert.rejects(
    ACTIONS["intelligence.connector.configure-github"].run(
      t.id,
      {
        connectionId: c.id,
        label: "Restored",
        repos: "acme/core",
        deployWorkflows: "",
        pathMap: "generic",
      },
      { nonce: "stale" },
    ),
    /not found/,
  )
})

test("connector removal cannot reach built-in or foreign sources and members cannot request it", {
  skip,
}, async () => {
  const t = await connect()
  const cookie = await signIn()
  const foreign = await prisma.tenant.create({ data: { slug: "foreign-removal", name: "Foreign" } })
  const ownBuiltin = await prisma.connection.findFirstOrThrow({ where: { tenantId: t.id, builtIn: true } })
  const other = await prisma.connection.create({
    data: { tenantId: foreign.id, kind: "github", label: "Foreign" },
  })
  for (const c of [ownBuiltin, other]) {
    gateway.reset()
    const opened = await app.inject({
      method: "POST",
      url: "/api/actions/open",
      headers: { cookie },
      payload: { action: "intelligence.connector.remove", params: { connectionId: c.id } },
    })
    assert.equal(opened.statusCode, 200, opened.body)
    const frozen = gateway.state.authorizeCalls[0]
    assert.ok(frozen)
    gateway.state.receipt = signedReceipt(gateway.state.nonce, frozen)
    gateway.state.status = "APPROVED"
    assert.equal((await poll(cookie)).json().status, "refused")
    assert.equal((await prisma.connection.findUniqueOrThrow({ where: { id: c.id } })).removedAt, null)
  }
  await prisma.member.updateMany({ where: { tenantId: t.id }, data: { role: "MEMBER" } })
  const denied = await app.inject({
    method: "POST",
    url: "/api/actions/open",
    headers: { cookie },
    payload: { action: "intelligence.connector.remove", params: { connectionId: ownBuiltin.id } },
  })
  assert.equal(denied.statusCode, 400)
  assert.doesNotMatch(
    (await app.inject({ url: "/connectors", headers: { cookie } })).body,
    /Remove connector/,
  )
})

test("every registered connector supports signed edits and encrypted credential replacement", {
  skip,
}, async () => {
  const t = await connect()
  const cookie = await signIn()
  const { allConnectors } = await import("../connectors/index.ts")
  const { encryptSecret, decryptSecret } = await import("../store/crypto.ts")
  for (const def of allConnectors()) {
    gateway.reset()
    const config = Object.fromEntries(
      def.fields
        .filter((f) => !f.secret)
        .map((f) => [
          f.name,
          f.name === "repos" ? "acme/core" : f.name === "pathMap" ? "generic" : "test-value",
        ]),
    )
    const c = await prisma.connection.create({
      data: {
        tenantId: t.id,
        kind: def.kind,
        label: def.label,
        builtIn: Boolean(def.builtIn),
        active: true,
        config: { ...config, preserved: "history-setting" },
        secretCiphertext: encryptSecret("old-credential"),
      },
    })
    await prisma.sourceCursor.create({
      data: { connectionId: c.id, name: "position", value: "keep-this-cursor" },
    })
    const edit = await app.inject({ url: `/connectors/${c.id}/edit`, headers: { cookie } })
    assert.equal(edit.statusCode, 200, def.kind)
    assert.doesNotMatch(edit.body, /old-credential/)
    assert.equal(edit.body.includes(c.secretCiphertext!), false)
    for (const field of def.fields.filter((f) => !f.secret))
      assert.ok(edit.body.includes(`name="${field.name}"`), `${def.kind}: ${field.name}`)
    if (def.kind === "google-workspace") assert.match(edit.body, /<textarea id="connector-secret"/)
    if (def.builtIn)
      assert.match(edit.body, /Sign-in credentials and trust anchors are managed by the deployment operator/)
    const replacementSecret =
      def.kind === "google-workspace"
        ? '{\n  "type": "service_account",\n  "private_key": "test-only-key"\n}'
        : "whsec_replacement-credential-with-32-characters"
    const params = { connectionId: c.id, kind: def.kind, label: `${def.label} updated`, config }
    const opened = await app.inject({
      method: "POST",
      url: "/api/actions/open",
      headers: { cookie },
      payload: { action: "intelligence.connector.configure", params, replacementSecret },
    })
    assert.equal(opened.statusCode, 200, `${def.kind}: ${opened.body}`)
    const pending = await prisma.pendingAction.findUniqueOrThrow({ where: { nonce: gateway.state.nonce } })
    assert.ok(pending.secretCiphertext)
    assert.equal(decryptSecret(pending.secretCiphertext), replacementSecret)
    const frozen = gateway.state.authorizeCalls[0]
    assert.ok(frozen)
    assert.deepEqual(frozen.params.config, config)
    assert.equal(JSON.stringify(frozen).includes(pending.secretCiphertext), false)
    assert.equal(JSON.stringify(frozen).includes(JSON.stringify(replacementSecret).slice(1, -1)), false)
    assert.equal((await poll(cookie)).json().status, "pending")
    assert.equal(
      (await prisma.connection.findUniqueOrThrow({ where: { id: c.id } })).secretCiphertext,
      c.secretCiphertext,
    )
    gateway.state.receipt = signedReceipt(gateway.state.nonce, frozen)
    gateway.state.status = "APPROVED"
    assert.equal((await poll(cookie)).json().status, "applied", def.kind)
    const updated = await prisma.connection.findUniqueOrThrow({ where: { id: c.id } })
    assert.equal(updated.label, params.label)
    assert.equal(decryptSecret(updated.secretCiphertext!), replacementSecret)
    assert.deepEqual(updated.config, { ...config, preserved: "history-setting" })
    assert.equal(updated.active, true)
    assert.equal(updated.builtIn, c.builtIn)
    assert.equal(await prisma.sourceCursor.count({ where: { connectionId: c.id } }), 1)
    assert.equal(
      (await prisma.pendingAction.findUniqueOrThrow({ where: { nonce: pending.nonce } })).secretCiphertext,
      null,
    )
    assert.equal((await poll(cookie)).json().status, "applied")
    assert.equal(gateway.state.consumeCalls.length, 1)
  }
})

for (const outcome of [
  "blank",
  "denied",
  "tampered-secret",
  "tampered-kind",
  "foreign",
  "wrong-kind",
  "removed",
] as const) {
  test(`general connector edits handle ${outcome} without replacing the credential`, { skip }, async () => {
    const t = await connect()
    const cookie = await signIn()
    const { encryptSecret } = await import("../store/crypto.ts")
    const foreign = await prisma.tenant.create({ data: { slug: "foreign-edit", name: "Foreign" } })
    const c = await prisma.connection.create({
      data: {
        tenantId: outcome === "foreign" ? foreign.id : t.id,
        kind: "better-stack",
        label: "Better Stack",
        secretCiphertext: encryptSecret("keep-me"),
        ...(outcome === "removed" ? { removedAt: new Date() } : {}),
      },
    })
    const params = {
      connectionId: c.id,
      kind: outcome === "wrong-kind" ? "stripe" : c.kind,
      label: "Updated",
      config: {},
    }
    const opened = await app.inject({
      method: "POST",
      url: "/api/actions/open",
      headers: { cookie },
      payload: {
        action: "intelligence.connector.configure",
        params,
        replacementSecret: outcome === "blank" ? "   " : "replacement-test-token",
      },
    })
    assert.equal(opened.statusCode, 200, opened.body)
    const frozen = gateway.state.authorizeCalls[0]
    assert.ok(frozen)
    gateway.state.receipt = signedReceipt(gateway.state.nonce, frozen)
    gateway.state.status = outcome === "denied" ? "DENIED" : "APPROVED"
    if (outcome === "tampered-secret")
      await prisma.pendingAction.update({
        where: { nonce: gateway.state.nonce },
        data: { secretCiphertext: encryptSecret("different-token") },
      })
    if (outcome === "tampered-kind")
      await prisma.pendingAction.update({
        where: { nonce: gateway.state.nonce },
        data: { params: { ...frozen.params, kind: "stripe" } },
      })
    assert.equal((await poll(cookie)).json().status, outcome === "blank" ? "applied" : "refused")
    assert.equal(
      (await prisma.connection.findUniqueOrThrow({ where: { id: c.id } })).secretCiphertext,
      c.secretCiphertext,
    )
    assert.equal(
      (await prisma.pendingAction.findUniqueOrThrow({ where: { nonce: gateway.state.nonce } }))
        .secretCiphertext,
      null,
    )
    if (outcome === "blank") assert.deepEqual(frozen.params, params)
  })
}

test("general connector editing rejects credential leaks, weak generated secrets and member requests before approval", {
  skip,
}, async () => {
  const t = await connect()
  const cookie = await signIn()
  const c = await prisma.connection.create({ data: { tenantId: t.id, kind: "webhook", label: "Webhook" } })
  const params = { connectionId: c.id, kind: c.kind, label: c.label, config: {} }
  for (const payload of [
    { action: "intelligence.connector.configure", params, replacementSecret: "too-short" },
    { action: "intelligence.connector.configure", params: { ...params, secretDigest: "0".repeat(64) } },
    {
      action: "intelligence.connector.configure",
      params: { ...params, config: { token: "must-not-leave-host" } },
    },
    { action: "intelligence.connector.configure", params, replacementToken: "wrong-credential-field" },
    { action: "intelligence.service.create", params: { name: "API" }, replacementSecret: "wrong-action" },
  ]) {
    const response = await app.inject({
      method: "POST",
      url: "/api/actions/open",
      headers: { cookie },
      payload,
    })
    assert.equal(response.statusCode, 400, response.body)
  }
  await prisma.member.updateMany({ where: { tenantId: t.id }, data: { role: "MEMBER" } })
  assert.equal((await app.inject({ url: `/connectors/${c.id}/edit`, headers: { cookie } })).statusCode, 403)
  assert.equal(
    (
      await app.inject({
        method: "POST",
        url: "/api/actions/open",
        headers: { cookie },
        payload: {
          action: "intelligence.connector.configure",
          params,
        },
      })
    ).statusCode,
    400,
  )
  assert.equal(gateway.state.authorizeCalls.length, 0)
  assert.equal(await prisma.pendingAction.count(), 0)
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

test("normal approval signs in its browser without an OIDC client and cannot be redeemed twice", {
  skip,
}, async () => {
  delete process.env.INTYGA_OIDC_CLIENT_ID
  await connect()
  const login = await app.inject({ url: "/login" })
  assert.match(login.body, /Request sign-in approval/)
  assert.doesNotMatch(login.body, /name="email"/)
  const started = await app.inject({
    method: "POST",
    url: "/login/approval/begin",
    headers: { origin: ORIGIN, "x-intelligence-login": "1" },
  })
  assert.equal(started.statusCode, 200, started.body)
  const state = started.cookies.find((c) => c.name === "intelligence_approval_login")
  assert.ok(state)
  assert.equal(state.httpOnly, true)
  assert.equal(state.secure, true)
  const cookie = `${state.name}=${state.value}`
  const pollLogin = (value = cookie) =>
    app.inject({ url: "/login/approval/status", headers: { cookie: value } })
  assert.equal((await pollLogin("")).statusCode, 401)
  assert.equal((await pollLogin()).json().status, "pending")
  const frozen = gateway.state.authorizeCalls[0]
  assert.ok(frozen)
  gateway.state.status = "APPROVED"
  gateway.state.receipt = signedReceipt(gateway.state.nonce, frozen)
  const finished = await pollLogin()
  assert.equal(finished.statusCode, 200, finished.body)
  const session = finished.cookies.find((c) => c.name === "intelligence_session")
  assert.ok(session)
  assert.equal(
    (await app.inject({ url: "/settings", headers: { cookie: `${session.name}=${session.value}` } }))
      .statusCode,
    200,
  )
  const member = await prisma.member.findFirstOrThrow()
  assert.equal(member.role, "ADMIN")
  assert.equal(member.externalId, `approved-browser:${gateway.state.nonce}`)
  assert.equal((await prisma.session.findFirstOrThrow()).receiptNonce, gateway.state.nonce)
  gateway.state.consumeOk = false
  assert.equal((await pollLogin()).statusCode, 401)
  assert.equal(await prisma.session.count(), 1)
})

test("cross-origin approval sign-in cannot replace a browser's request", { skip }, async () => {
  await connect()
  for (const headers of [
    {},
    { origin: "https://attacker.example", "x-intelligence-login": "1" },
    { origin: ORIGIN },
  ]) {
    assert.equal(
      (await app.inject({ method: "POST", url: "/login/approval/begin", headers })).statusCode,
      403,
    )
  }
  assert.equal(gateway.state.authorizeCalls.length, 0)
})

test("AI provider configuration freezes encrypted keys and applies only after verified approval", {
  skip,
}, async () => {
  const t = await connect()
  const cookie = await signIn()
  const { decryptSecret } = await import("../store/crypto.ts")
  for (const provider of ["typesafe", "openai", "anthropic"] as const) {
    gateway.reset()
    const replacementSecret = `fixture-secret-${provider}`
    const params = {
      provider,
      model: "fixture-model",
      dailyRequestLimit: 10,
      maxOutputTokens: 2048,
      timeoutMs: 10000,
      primary: provider === "openai",
    }
    const opened = await app.inject({
      method: "POST",
      url: "/api/actions/open",
      headers: { cookie },
      payload: { action: "intelligence.judgment.configure", params, replacementSecret },
    })
    assert.equal(opened.statusCode, 200, opened.body)
    const pending = await prisma.pendingAction.findUniqueOrThrow({ where: { nonce: gateway.state.nonce } })
    assert.ok(pending.secretCiphertext)
    assert.equal(decryptSecret(pending.secretCiphertext), replacementSecret)
    const frozen = gateway.state.authorizeCalls[0]
    assert.ok(frozen)
    assert.doesNotMatch(JSON.stringify(frozen), /fixture-secret-/)
    assert.equal(JSON.stringify(frozen).includes(pending.secretCiphertext), false)
    assert.equal((await poll(cookie)).json().status, "pending")
    assert.equal(await prisma.reviewProvider.count({ where: { tenantId: t.id, provider } }), 0)
    gateway.state.receipt = signedReceipt(gateway.state.nonce, frozen)
    gateway.state.status = "APPROVED"
    assert.equal((await poll(cookie)).json().status, "applied")
    const saved = await prisma.reviewProvider.findUniqueOrThrow({
      where: { tenantId_provider: { tenantId: t.id, provider } },
    })
    assert.equal(decryptSecret(saved.secretCiphertext ?? ""), replacementSecret)
    assert.equal(
      (await prisma.pendingAction.findUniqueOrThrow({ where: { nonce: gateway.state.nonce } }))
        .secretCiphertext,
      null,
    )
  }
  const page = await app.inject({ url: "/judgment", headers: { cookie } })
  assert.equal(page.statusCode, 200, page.body)
  assert.match(page.body, /OpenAI/)
  assert.match(page.body, /Anthropic/)
  assert.doesNotMatch(page.body, /fixture-secret-/)
  assert.equal(
    (await prisma.detectorConfig.findFirstOrThrow({ where: { tenantId: t.id, detector: "judgment" } }))
      .enabled,
    false,
  )
  await prisma.member.updateMany({ where: { tenantId: t.id }, data: { role: "MEMBER" } })
  const denied = await app.inject({
    method: "POST",
    url: "/api/actions/open",
    headers: { cookie },
    payload: { action: "intelligence.judgment.remove", params: { provider: "openai" } },
  })
  assert.equal(denied.statusCode, 400)
})

test("manual second opinion is previewed without sending and dispatched once after receipt redemption", {
  skip,
}, async () => {
  const t = await connect()
  const cookie = await signIn()
  const { encryptSecret } = await import("../store/crypto.ts")
  const { prepareFindingReview } = await import("../domain/judgment.ts")
  await prisma.reviewProvider.create({
    data: {
      tenantId: t.id,
      provider: "openai",
      model: "fixture-model",
      secretCiphertext: encryptSecret("private-review-key"),
    },
  })
  await prisma.detectorConfig.create({ data: { tenantId: t.id, detector: "judgment", enabled: true } })
  const finding = await prisma.finding.create({
    data: {
      tenantId: t.id,
      title: "private-finding-title",
      category: "engineering",
      severity: "medium",
      dedupeKey: "manual-review",
      detectedAt: new Date(),
      lastSeenAt: new Date(),
      evidence: {
        create: {
          kind: "eventRef",
          ordinal: 0,
          data: {
            kind: "eventRef",
            connectionId: "private",
            sourceId: "private",
            eventKind: "intelligence.poll",
            at: new Date(),
          },
        },
      },
    },
  })
  const preview = await app.inject({
    url: `/findings/${finding.id}/review?provider=openai`,
    headers: { cookie },
  })
  assert.equal(preview.statusCode, 200, preview.body)
  assert.match(preview.body, /Review and approve request/)
  assert.doesNotMatch(preview.body, /private-review-key/)
  assert.equal(await prisma.judgmentRequest.count(), 0)
  const prepared = await prepareFindingReview(t.id, finding.id, "openai")
  const opened = await app.inject({
    method: "POST",
    url: "/api/actions/open",
    headers: { cookie },
    payload: {
      action: "intelligence.judgment.review",
      params: {
        findingId: finding.id,
        provider: "openai",
        model: prepared.provider.model,
        stateDigest: prepared.stateDigest,
      },
    },
  })
  assert.equal(opened.statusCode, 200, opened.body)
  const originalFetch = globalThis.fetch
  let providerCalls = 0
  globalThis.fetch = async (input, init) => {
    if (String(input) !== "https://api.openai.com/v1/responses") return originalFetch(input, init)
    providerCalls++
    assert.doesNotMatch(String(init?.body), /private-finding-title|private-review-key/)
    return Response.json({
      model: "fixture-model",
      status: "completed",
      output: [
        {
          type: "message",
          content: [
            {
              type: "output_text",
              text: JSON.stringify({
                anomalous: null,
                requiresHumanAttention: null,
                severity: null,
                explanation: "Insufficient evidence.",
                supportedEvidence: [],
                missingEvidence: ["Measurements"],
                nextSteps: ["Inspect source health"],
              }),
            },
          ],
        },
      ],
    })
  }
  try {
    assert.equal((await poll(cookie)).json().status, "pending")
    assert.equal(providerCalls, 0)
    const frozen = gateway.state.authorizeCalls[0]
    assert.ok(frozen)
    gateway.state.receipt = signedReceipt(gateway.state.nonce, frozen)
    gateway.state.status = "APPROVED"
    assert.equal((await poll(cookie)).json().status, "applied")
    assert.equal((await poll(cookie)).json().status, "applied")
    assert.equal(providerCalls, 1)
    assert.equal(await prisma.judgmentRequest.count({ where: { tenantId: t.id, status: "DONE" } }), 1)
  } finally {
    globalThis.fetch = originalFetch
  }
})
