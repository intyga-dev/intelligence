import assert from "node:assert/strict"
import { test } from "node:test"
import { GateRefused, GateUnavailable } from "./client.ts"
import type { DeploymentConnection } from "./deployment.ts"
import { embeddedRequest } from "./embedded.ts"

const cfg: DeploymentConnection = {
  baseUrl: "https://gateway.example.test",
  consoleUrl: "https://console.example.test",
  workspaceId: "workspace-test",
  serviceClientId: "service-test",
  serviceSecret: "secret-test",
  embeddedApplicationId: "application-test",
  oidcClientId: null,
  origin: "https://intelligence.example.test",
  bindingId: "binding-test",
}

test("embedded approval explains a recognized refusal without exposing the upstream body", async (t) => {
  t.mock.method(globalThis, "fetch", async (url: string) =>
    url.endsWith("/oauth/token")
      ? Response.json({ access_token: "token-test" })
      : Response.json({ error: "unknown embedded credential", secret: "do-not-expose" }, { status: 403 }),
  )
  await assert.rejects(embeddedRequest(cfg, "approve/verify", {}), (err: unknown) => {
    assert.ok(err instanceof GateRefused)
    assert.match(err.message, /Choose the application passkey you created here/)
    assert.doesNotMatch(err.message, /do-not-expose/)
    return true
  })
})

test("unknown, malformed and non-403 refusals keep upstream details private", async (t) => {
  for (const [status, body] of [
    [403, JSON.stringify({ error: "secret-test upstream request details" })],
    [403, "<html>secret-test proxy error</html>"],
    [403, JSON.stringify({ error: { secret: "secret-test" } })],
    [500, JSON.stringify({ error: "unknown embedded credential" })],
  ] as const) {
    const mocked = t.mock.method(globalThis, "fetch", async (url: string) =>
      url.endsWith("/oauth/token")
        ? Response.json({ access_token: "token-test" })
        : new Response(body, { status }),
    )
    try {
      await assert.rejects(embeddedRequest(cfg, "approve/verify", {}), (err: unknown) => {
        assert.ok(err instanceof GateRefused)
        assert.equal(
          err.message,
          `INTYGA refused the embedded ceremony (HTTP ${status}). Check the application registration, membership and passkey.`,
        )
        return true
      })
    } finally {
      mocked.mock.restore()
    }
  }
})

test("embedded transport and service-key failures remain closed", async (t) => {
  const mocked = t.mock.method(globalThis, "fetch", async () => {
    throw new Error("secret-test transport details")
  })
  await assert.rejects(embeddedRequest(cfg, "approve/verify", {}), GateUnavailable)
  mocked.mock.restore()
  const refused = t.mock.method(globalThis, "fetch", async () =>
    Response.json({ error: "secret-test" }, { status: 401 }),
  )
  await assert.rejects(embeddedRequest(cfg, "approve/verify", {}), /INTYGA refused the service key/)
  assert.equal(refused.mock.callCount(), 1)
})

test("successful embedded responses pass through", async (t) => {
  const result = { ok: true, reason: "pending 1/2 approvals" }
  t.mock.method(globalThis, "fetch", async (url: string) =>
    Response.json(url.endsWith("/oauth/token") ? { access_token: "token-test" } : result),
  )
  assert.deepEqual(await embeddedRequest(cfg, "approve/verify", {}), result)
})
