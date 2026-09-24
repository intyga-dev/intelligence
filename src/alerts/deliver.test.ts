import assert from "node:assert/strict"
import crypto from "node:crypto"
import test from "node:test"
import {
  type AlertFinding,
  buildBody,
  isDue,
  parseTarget,
  severitiesAtLeast,
  signBody,
  UnsafeTargetError,
  watermark,
} from "./deliver.ts"

// ─── pure ────────────────────────────────────────────────────────────────────────────────────────

test("destinations must be https; http only for loopback outside production", () => {
  assert.equal(
    parseTarget("https://hooks.slack.com/services/T/B/x", { allowLoopbackHttp: false }).host,
    "hooks.slack.com",
  )
  assert.equal(parseTarget("http://127.0.0.1:9999/hook", { allowLoopbackHttp: true }).host, "127.0.0.1:9999")
  for (const [raw, allow] of [
    ["http://127.0.0.1:9999/hook", false],
    ["http://example.com/hook", true],
    ["ftp://example.com/", true],
    ["https://user:pass@example.com/", true],
    ["not a url", true],
  ] as const) {
    assert.throws(() => parseTarget(raw, { allowLoopbackHttp: allow }), UnsafeTargetError, raw)
  }
})

test("the signature is an HMAC over timestamp and exact body", () => {
  const sig = signBody("whsig_k", '{"a":1}', 1_700_000_000)
  const expected = crypto.createHmac("sha256", "whsig_k").update('1700000000.{"a":1}').digest("hex")
  assert.equal(sig, `t=1700000000,v1=${expected}`)
  assert.notEqual(sig, signBody("whsig_k", '{"a":2}', 1_700_000_000), "bound to the body")
  assert.notEqual(sig, signBody("whsig_k", '{"a":1}', 1_700_000_001), "bound to the timestamp")
})

test("severity thresholds are inclusive", () => {
  assert.deepEqual(severitiesAtLeast("high"), ["high", "critical"])
  assert.equal(severitiesAtLeast("info").length, 5)
})

test("cooldown and watermark", () => {
  const now = new Date("2026-09-23T12:00:00Z")
  assert.equal(isDue({ lastFiredAt: null, cooldownMinutes: 60 }, now), true)
  assert.equal(isDue({ lastFiredAt: new Date("2026-09-23T11:30:00Z"), cooldownMinutes: 60 }, now), false)
  assert.equal(isDue({ lastFiredAt: new Date("2026-09-23T11:00:00Z"), cooldownMinutes: 60 }, now), true)

  const activated = new Date("2026-09-23T10:00:00Z")
  const fired = new Date("2026-09-23T11:00:00Z")
  assert.deepEqual(watermark({ activatedAt: activated, lastFiredAt: null }), activated, "no history replay")
  assert.deepEqual(watermark({ activatedAt: activated, lastFiredAt: fired }), fired)
  // Re-activated after a long pause: what happened while it was off is not replayed.
  assert.deepEqual(watermark({ activatedAt: now, lastFiredAt: fired }), now)
})

const F: AlertFinding = {
  id: "f1",
  title: "3 refused operations from <@U123> & co",
  severity: "high",
  category: "security",
  status: "new",
  count: 3,
  detectedAt: new Date("2026-09-23T10:00:00Z"),
  lastSeenAt: new Date("2026-09-23T11:00:00Z"),
}

test("the webhook body carries only the listed finding fields", () => {
  const body = JSON.parse(
    buildBody("webhook", {
      ruleName: "r",
      findings: [F],
      more: false,
      consoleOrigin: "https://i.example/",
      now: new Date(0),
    }),
  )
  assert.equal(body.type, "intelligence.alert")
  assert.equal(body.link, "https://i.example/findings")
  assert.deepEqual(Object.keys(body.findings[0]).sort(), [
    "category",
    "count",
    "detectedAt",
    "id",
    "lastSeenAt",
    "severity",
    "status",
    "title",
  ])
})

test("the Slack body escapes markup so a title cannot mention or link", () => {
  const { text } = JSON.parse(
    buildBody("slack", { ruleName: "r", findings: [F], more: true, consoleOrigin: null, now: new Date(0) }),
  ) as { text: string }
  assert.match(text, /&lt;@U123&gt; &amp; co/)
  assert.doesNotMatch(text, /<@U123>/)
  assert.match(text, /and more/)
})
