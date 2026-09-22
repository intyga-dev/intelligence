import assert from "node:assert/strict"
import crypto from "node:crypto"
import test from "node:test"
import { sentryConnector } from "./index.ts"

// Sentry's scheme differs from Intyga's in a way that matters: a bare HMAC-SHA256 hex digest of the
// raw body with NO timestamp. So there is authenticity but no freshness — a captured delivery
// replays forever. These tests pin both the check that exists and the limit that does not.

const SECRET = "sentry_client_secret"
const BODY = JSON.stringify({
  action: "created",
  data: {
    issue: {
      id: "4509",
      shortId: "CORE-7F",
      title: "TypeError: cannot read property of undefined",
      culprit: "gateway/authorization",
      level: "error",
      count: "17",
      project: { slug: "intyga-gateway" },
      lastSeen: "2026-09-21T08:00:00.000Z",
    },
  },
})

const sign = (body: string, secret = SECRET) =>
  crypto.createHmac("sha256", secret).update(body, "utf8").digest("hex")

const headers = (sig: string) => ({ "sentry-hook-signature": sig })

test("accepts a correctly signed delivery", () => {
  assert.deepEqual(sentryConnector.verify({ headers: headers(sign(BODY)), rawBody: BODY, secret: SECRET }), {
    ok: true,
  })
})

test("rejects a tampered body and a wrong secret", () => {
  // Asserted, not assumed: JSON.stringify emits `"count":"17"` with no space, so a replace written
  // against the pretty-printed form is a silent no-op and the test passes for the wrong reason.
  const tampered = BODY.replace('"count":"17"', '"count":"1"')
  assert.notEqual(tampered, BODY, "the body must actually differ for this test to mean anything")
  assert.equal(
    sentryConnector.verify({ headers: headers(sign(BODY)), rawBody: tampered, secret: SECRET }).ok,
    false,
  )
  assert.equal(
    sentryConnector.verify({ headers: headers(sign(BODY, "wrong")), rawBody: BODY, secret: SECRET }).ok,
    false,
  )
})

test("rejects malformed signature headers without throwing", () => {
  for (const sig of ["", "nothex!!", "abc", sign(BODY).slice(0, 10)]) {
    assert.equal(
      sentryConnector.verify({ headers: headers(sig), rawBody: BODY, secret: SECRET }).ok,
      false,
      `signature ${JSON.stringify(sig)} must not verify`,
    )
  }
  assert.equal(sentryConnector.verify({ headers: {}, rawBody: BODY, secret: SECRET }).ok, false)
})

test("a replayed delivery still verifies — the scheme carries no timestamp", () => {
  // Documenting the limit rather than pretending it is closed. Containment is event-id
  // idempotency downstream, which is why eventId() below must be stable.
  const sig = sign(BODY)
  assert.equal(sentryConnector.verify({ headers: headers(sig), rawBody: BODY, secret: SECRET }).ok, true)
  assert.equal(
    sentryConnector.verify({ headers: headers(sig), rawBody: BODY, secret: SECRET }).ok,
    true,
    "unchanged on replay — only idempotency makes this harmless",
  )
})

test("eventId is stable across replays, which is what makes a replay a no-op", () => {
  const body = JSON.parse(BODY)
  assert.equal(sentryConnector.eventId({}, body), sentryConnector.eventId({}, body))
  assert.equal(sentryConnector.eventId({}, body), "created:4509")
})

test("normalizes an issue, attributing it to the project rather than the issue", () => {
  const e = sentryConnector.normalize({
    connectionId: "c1",
    body: JSON.parse(BODY),
    receivedAt: new Date("2026-09-21T09:00:00Z"),
  })
  assert.ok(e)
  assert.equal(e.source, "sentry")
  assert.equal(e.kind, "sentry.issue.created")
  // An error rate is a property of a service; one issue is not a subject worth baselining.
  assert.equal(e.subjectRef, "intyga-gateway")
  assert.equal(e.correlationRef, "CORE-7F")
  assert.equal(e.attrs.count, 17)
  assert.deepEqual(e.at, new Date("2026-09-21T08:00:00.000Z"))
})

test("a payload carrying neither an issue nor an error is ignored, not stored", () => {
  assert.equal(
    sentryConnector.normalize({ connectionId: "c1", body: { action: "ping" }, receivedAt: new Date() }),
    null,
  )
})
