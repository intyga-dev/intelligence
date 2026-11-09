import assert from "node:assert/strict"
import crypto from "node:crypto"
import test from "node:test"
import { asDeploy } from "../../domain/detectors/deployRegression.ts"
import { SIGNATURE_HEADER, verifyCustomSignature, webhookConnector } from "./index.ts"

const SECRET = "whsec_custom"
const NOW = 1_790_000_000
const sign = (body: string, t = NOW, secret = SECRET) =>
  `t=${t},v1=${crypto.createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")}`

const BODY = JSON.stringify({
  id: "deploy-981",
  kind: "deployment",
  at: "2026-09-23T12:00:00Z",
  subject: "billing-api",
  correlation: "abc1234",
  attrs: { production: true, succeeded: true, sha: "abc1234", name: "billing-api" },
})

test("accepts a fresh, correctly signed delivery", () => {
  assert.deepEqual(verifyCustomSignature({ header: sign(BODY), rawBody: BODY, secret: SECRET }, NOW), {
    ok: true,
  })
})

test("rejects a tampered body, a wrong secret, a stale or future timestamp, and a malformed header", () => {
  const cases: [string, string, string, number][] = [
    [sign(BODY), `${BODY} `, SECRET, NOW],
    [sign(BODY, NOW, "other"), BODY, SECRET, NOW],
    [sign(BODY, NOW - 301), BODY, SECRET, NOW],
    [sign(BODY, NOW + 301), BODY, SECRET, NOW],
    ["v1=deadbeef", BODY, SECRET, NOW],
    ["", BODY, SECRET, NOW],
  ]
  for (const [header, rawBody, secret, now] of cases) {
    assert.equal(verifyCustomSignature({ header, rawBody, secret }, now).ok, false, header)
  }
})

test("the connector reads the documented header", () => {
  const r = webhookConnector.verify({
    headers: { [SIGNATURE_HEADER]: sign(BODY, Math.floor(Date.now() / 1000)) },
    rawBody: BODY,
    secret: SECRET,
  })
  assert.equal(r.ok, true)
})

test("every kind is namespaced, so a custom producer cannot impersonate a built-in source", () => {
  const spoof = { id: "x1", kind: "challenge.denied", subject: "did:key:victim" }
  const e = webhookConnector.normalize({ connectionId: "c", body: spoof, receivedAt: new Date() })
  assert.equal(e?.kind, "custom.challenge.denied")
  assert.equal(e?.source, "webhook")
})

test("a custom production deployment anchors deploy-regression", () => {
  const e = webhookConnector.normalize({ connectionId: "c", body: JSON.parse(BODY), receivedAt: new Date() })
  assert.ok(e)
  assert.equal(webhookConnector.eventId({}, JSON.parse(BODY)), "deploy-981")
  const d = asDeploy(e)
  assert.equal(d?.sha, "abc1234")
  assert.equal(d?.name, "billing-api")
  // Not production unless it says so.
  const preview = { ...JSON.parse(BODY), attrs: { succeeded: true } }
  const p = webhookConnector.normalize({ connectionId: "c", body: preview, receivedAt: new Date() })
  assert.ok(p)
  assert.equal(asDeploy(p), null)
})

test("malformed events are dropped, not thrown, and nested attrs are refused", () => {
  for (const body of [
    {},
    { id: "1" },
    { id: "1", kind: "Bad Kind" },
    { id: "1", kind: "x", attrs: { nested: { a: 1 } } },
  ]) {
    assert.equal(
      webhookConnector.normalize({ connectionId: "c", body, receivedAt: new Date() }),
      null,
      JSON.stringify(body),
    )
  }
})
