import assert from "node:assert/strict"
import { writeFileSync } from "node:fs"
import { test } from "node:test"
import { testDeployment } from "../test/deployment.ts"
import { anchor } from "../test/intyga.ts"
import { resolveGateConfig, resolveConnectionConfig } from "./deployment.ts"

test("connection settings come from the environment and file; OIDC is optional", (t) => {
  const d = testDeployment()
  t.after(() => d.dispose())
  const cfg = resolveGateConfig(d.env)
  assert.equal(cfg.workspaceId, d.env.INTYGA_WORKSPACE_ID)
  assert.equal(cfg.serviceSecret, d.env.INTYGA_SERVICE_CLIENT_SECRET)
  assert.deepEqual(cfg.trustAnchor, anchor)
  assert.equal(resolveGateConfig({ ...d.env, INTYGA_OIDC_CLIENT_ID: "" }).oidcClientId, null)
  for (const key of [
    "INTYGA_URL",
    "INTYGA_CONSOLE_URL",
    "INTYGA_WORKSPACE_ID",
    "INTYGA_SERVICE_CLIENT_ID",
    "INTYGA_SERVICE_CLIENT_SECRET",
    "INTYGA_TRUST_ANCHOR_FILE",
    "PUBLIC_URL",
  ]) {
    assert.throws(() => resolveGateConfig({ ...d.env, [key]: "" }), new RegExp(key))
  }
})

test("missing, malformed, oversized and foreign-workspace trust files fail closed", (t) => {
  const d = testDeployment()
  t.after(() => d.dispose())
  assert.throws(
    () => resolveGateConfig({ ...d.env, INTYGA_TRUST_ANCHOR_FILE: `${d.anchorPath}.missing` }),
    /readable/,
  )
  for (const raw of [
    "garbled",
    "x".repeat(200_001),
    JSON.stringify({ ...anchor, tenantId: "foreign" }),
    JSON.stringify({ ...anchor, tenantId: undefined }),
  ]) {
    writeFileSync(d.anchorPath, raw)
    assert.throws(() => resolveGateConfig(d.env), /trust anchor/)
  }
})

test("public identity changes invalidate sessions while a secret rotation keeps the same identity", (t) => {
  const d = testDeployment()
  t.after(() => d.dispose())
  const original = resolveGateConfig(d.env).bindingId
  for (const [key, value] of Object.entries({
    INTYGA_URL: "https://other.example",
    INTYGA_OIDC_CLIENT_ID: "new-client",
    INTYGA_SERVICE_CLIENT_ID: "new-service",
    PUBLIC_URL: "https://other-intelligence.example",
  })) {
    assert.notEqual(resolveGateConfig({ ...d.env, [key]: value }).bindingId, original)
  }
  assert.equal(resolveGateConfig({ ...d.env, INTYGA_SERVICE_CLIENT_SECRET: "rotated" }).bindingId, original)
})

test("first-time embedded linking does not need an anchor, while sign-in requires the application anchor", (t) => {
  const d = testDeployment()
  t.after(() => d.dispose())
  const env = {
    ...d.env,
    INTYGA_EMBEDDED_APPLICATION_ID: "123e4567-e89b-42d3-a456-426614174000",
    INTYGA_TRUST_ANCHOR_FILE: "missing",
  }
  assert.equal(resolveConnectionConfig(env).embeddedApplicationId, env.INTYGA_EMBEDDED_APPLICATION_ID)
  assert.throws(() => resolveGateConfig(env), /readable/)
  env.INTYGA_TRUST_ANCHOR_FILE = d.anchorPath
  assert.throws(() => resolveGateConfig(env), /application trust anchor/)
  writeFileSync(
    d.anchorPath,
    JSON.stringify({ ...anchor, webauthn: { origin: d.env.PUBLIC_URL, rpId: "localhost" } }),
  )
  assert.ok(resolveGateConfig(env).trustAnchor)
})
