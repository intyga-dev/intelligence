import assert from "node:assert/strict"
import { generateKeyPairSync, randomUUID, verify } from "node:crypto"
import { test } from "node:test"
import type { ConnectorContext } from "../registry.ts"
import {
  azureMonitorConnector as azure,
  googleWorkspaceConnector as workspace,
  betterStackConnector as better,
} from "./poll.ts"

const date = "2026-11-07T11:00:00Z"
const uuid = "00000000-0000-4000-8000-000000000001"
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
function context(config: Record<string, unknown> = {}, secret = "test-secret") {
  const logs: string[] = []
  const ctx: ConnectorContext = {
    connectionId: randomUUID(),
    tenantId: "tenant",
    config,
    secret,
    getCursor: async () => null,
    setCursor: async () => {},
    log: (m) => {
      logs.push(m)
    },
  }
  return { ctx, logs }
}
const azAlert = (state = "Fired") => ({
  id: "/subscriptions/test/providers/Microsoft.AlertsManagement/alerts/id1",
  name: "id1",
  properties: {
    essentials: {
      alertRule: "High errors",
      monitorCondition: state,
      severity: "Sev1",
      lastModifiedDateTime: date,
      targetResource: "resource",
      alertState: "Acknowledged",
    },
  },
})
test("Azure uses client credentials and read-only alert requests, follows same-scope pages, and preserves native state", async (t) => {
  const calls: { url: string; init: RequestInit | undefined }[] = [],
    { ctx } = context({ azureTenantId: uuid, subscriptionId: uuid, clientId: uuid })
  t.mock.method(globalThis, "fetch", async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    if (url.includes("/oauth2/")) return response({ access_token: "access", expires_in: 3600 })
    if (url.includes("page=2")) return response({ value: [{ ...azAlert("Resolved"), id: "closed" }] })
    return response({
      value: [azAlert()],
      nextLink: `https://management.azure.com/subscriptions/${uuid}/providers/Microsoft.AlertsManagement/alerts?page=2`,
    })
  })
  const events = await azure.poll(ctx)
  assert.equal(events.length, 2)
  assert.equal(events[0]!.attrs.status, "firing")
  assert.equal(events[1]!.attrs.status, "resolved")
  assert.equal(events[0]!.attrs.severity, "high")
  assert.match(String(calls[0]!.init?.body), /grant_type=client_credentials/)
  assert.ok(calls.slice(1).every((c) => !c.init?.method && c.init?.redirect === "error"))
  const again = await azure.poll(ctx)
  assert.equal(again[0]!.sourceId, events[0]!.sourceId, "poll snapshots must retain stable identities")
  assert.equal(
    calls.filter((c) => c.url.includes("/oauth2/")).length,
    1,
    "short-lived tokens are reused until near expiry",
  )
})
test("Azure rejects foreign pagination hosts and reports authentication errors without copying provider bodies", async (t) => {
  const { ctx } = context({ azureTenantId: uuid, subscriptionId: uuid, clientId: uuid }),
    calls: string[] = []
  t.mock.method(globalThis, "fetch", async (url: string) => {
    calls.push(url)
    return url.includes("/oauth2/")
      ? response({ access_token: "access", expires_in: 3600 })
      : response({ value: [], nextLink: "https://attacker.example/collect" })
  })
  await assert.rejects(() => azure.poll(ctx), /Unsafe provider pagination/)
  assert.equal(calls.length, 2)
})
test("polling does not mistake a rejected or malformed upstream response for a healthy empty feed", async (t) => {
  const { ctx } = context()
  const fetch = t.mock.method(globalThis, "fetch", async () => response({ secret: "DO-NOT-EXPOSE" }, 403))
  await assert.rejects(
    () => better.poll(ctx),
    (e) => e instanceof Error && e.message === "Provider returned HTTP 403",
  )
  fetch.mock.mockImplementation(async () => response({ unexpected: true }))
  await assert.rejects(() => better.poll(ctx), /Invalid Better Stack/)
})
test("Workspace signs delegated credentials for Google's fixed token endpoint and copies only alert metadata", async (t) => {
  const keys = generateKeyPairSync("rsa", { modulusLength: 2048 })
  const credentials = {
    type: "service_account",
    client_email: "alerts@example.iam.gserviceaccount.com",
    private_key: keys.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
    token_uri: "https://ignored-untrusted.example",
  }
  const { ctx } = context({ adminEmail: "admin@example.com" }, JSON.stringify(credentials)),
    calls: string[] = []
  t.mock.method(globalThis, "fetch", async (url: string, init?: RequestInit) => {
    calls.push(url)
    if (url === "https://oauth2.googleapis.com/token") {
      const assertion = new URLSearchParams(String(init?.body)).get("assertion")!,
        parts = assertion.split(".")
      const claims = JSON.parse(Buffer.from(parts[1]!, "base64url").toString())
      assert.equal(claims.sub, "admin@example.com")
      assert.equal(claims.scope, "https://www.googleapis.com/auth/apps.alerts")
      assert.ok(
        verify(
          "RSA-SHA256",
          Buffer.from(parts.slice(0, 2).join(".")),
          keys.publicKey,
          Buffer.from(parts[2]!, "base64url"),
        ),
      )
      return response({ access_token: "google-token", expires_in: 3600 })
    }
    assert.ok(url.startsWith("https://alertcenter.googleapis.com/v1beta1/alerts?"))
    return response({
      alerts: [
        {
          alertId: "alert1",
          type: "Suspicious login",
          source: "Google",
          updateTime: date,
          metadata: { status: "NOT_STARTED", severity: "HIGH" },
          data: { email: "private-user@example.com", body: "private content" },
        },
        { alertId: "alert2", updateTime: date, metadata: { status: "CLOSED", severity: "MEDIUM" } },
      ],
    })
  })
  const events = await workspace.poll(ctx)
  assert.equal(events.length, 2)
  assert.equal(events[0]!.attrs.category, "security")
  assert.equal(events[1]!.attrs.status, "resolved")
  assert.doesNotMatch(JSON.stringify(events), /private-user|private content|private_key/)
  assert.equal(calls.length, 2)
})
test("Better Stack imports confirmed uptime/heartbeat incidents, ignores unconfirmed and retains recovery", async (t) => {
  const { ctx } = context()
  t.mock.method(globalThis, "fetch", async () =>
    response({
      data: [
        {
          id: "1",
          attributes: { name: "API", status: "Started", started_at: date, response_content: "PRIVATE" },
        },
        {
          id: "2",
          attributes: { name: "Backup heartbeat", status: "Resolved", started_at: date, resolved_at: date },
        },
        { id: "3", attributes: { name: "Checking", status: "Unconfirmed", started_at: null } },
      ],
      pagination: { next: null },
    }),
  )
  const events = await better.poll(ctx)
  assert.equal(events.length, 2)
  assert.equal(events[1]!.attrs.status, "resolved")
  assert.doesNotMatch(JSON.stringify(events), /PRIVATE/)
})
test("bounded polling flags incomplete coverage instead of silently declaring success", async (t) => {
  const { ctx, logs } = context()
  let calls = 0
  t.mock.method(globalThis, "fetch", async () => {
    calls++
    return response({
      data: [],
      pagination: { next: `https://incidents.betterstack.com/api/v3/incidents?page=${calls + 1}` },
    })
  })
  await better.poll(ctx)
  assert.equal(calls, 5)
  assert.deepEqual(logs, ["Better Stack incident coverage truncated"])
})
