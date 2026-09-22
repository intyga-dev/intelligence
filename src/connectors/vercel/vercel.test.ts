import assert from "node:assert/strict"
import crypto from "node:crypto"
import test from "node:test"
import { vercelConnector } from "./index.ts"

const SECRET = "vercel_webhook_secret"
const BODY = JSON.stringify({
  id: "evt_01HZ",
  type: "deployment.error",
  createdAt: 1758441000000,
  payload: {
    deployment: {
      id: "dpl_abc",
      name: "console",
      url: "console-abc.vercel.app",
      meta: { githubCommitSha: "577e9870fedcba", githubCommitRef: "main", githubCommitAuthorLogin: "ada" },
    },
    project: { id: "prj_1", name: "console" },
    target: "production",
    errorMessage: "Build exceeded memory limit",
  },
})

// HMAC-SHA1, not SHA-256 — Vercel's choice. Pinned so nobody "modernises" it and silently rejects
// every delivery.
const sign = (body: string, secret = SECRET) =>
  crypto.createHmac("sha1", secret).update(body, "utf8").digest("hex")

const headers = (sig: string) => ({ "x-vercel-signature": sig })

test("accepts a correctly signed delivery", () => {
  assert.deepEqual(vercelConnector.verify({ headers: headers(sign(BODY)), rawBody: BODY, secret: SECRET }), {
    ok: true,
  })
})

test("an HMAC-SHA256 signature is rejected — the scheme is SHA1", () => {
  const sha256 = crypto.createHmac("sha256", SECRET).update(BODY, "utf8").digest("hex")
  assert.equal(vercelConnector.verify({ headers: headers(sha256), rawBody: BODY, secret: SECRET }).ok, false)
})

test("rejects a tampered body and a wrong secret", () => {
  const tampered = BODY.replace('"target":"production"', '"target":"preview"')
  assert.notEqual(tampered, BODY, "the body must actually differ for this to mean anything")
  assert.equal(
    vercelConnector.verify({ headers: headers(sign(BODY)), rawBody: tampered, secret: SECRET }).ok,
    false,
  )
  assert.equal(
    vercelConnector.verify({ headers: headers(sign(BODY, "nope")), rawBody: BODY, secret: SECRET }).ok,
    false,
  )
})

test("rejects malformed signatures without throwing", () => {
  for (const sig of ["", "zz", "abc", sign(BODY).slice(0, 8)]) {
    assert.equal(vercelConnector.verify({ headers: headers(sig), rawBody: BODY, secret: SECRET }).ok, false)
  }
  assert.equal(vercelConnector.verify({ headers: {}, rawBody: BODY, secret: SECRET }).ok, false)
})

test("normalizes a failed production deployment, keeping the commit as the join key", () => {
  const e = vercelConnector.normalize({
    connectionId: "c1",
    body: JSON.parse(BODY),
    receivedAt: new Date(),
  })
  assert.ok(e)
  assert.equal(e.kind, "vercel.deployment")
  assert.equal(e.subjectRef, "console")
  // The SHA is what lets a deployment be joined to the pull request that caused it.
  assert.equal(e.correlationRef, "577e9870fedcba")
  assert.equal(e.attrs.isProduction, true)
  assert.equal(e.attrs.succeeded, false)
  assert.equal(e.attrs.state, "ERROR")
  assert.equal(e.attrs.errorMessage, "Build exceeded memory limit")
})

test("a non-terminal event is ignored — an in-flight deploy carries no outcome", () => {
  const body = { ...JSON.parse(BODY), type: "deployment.created" }
  assert.equal(vercelConnector.normalize({ connectionId: "c1", body, receivedAt: new Date() }), null)
})

test("a CLI deploy with no git metadata yields a null join key rather than a guess", () => {
  const body = JSON.parse(BODY)
  body.payload.deployment.meta = {}
  const e = vercelConnector.normalize({ connectionId: "c1", body, receivedAt: new Date() })
  assert.equal(e?.correlationRef, null, "correlation must decline to attribute rather than invent")
})

test("eventId is stable, which is what makes a redelivery a no-op", () => {
  const body = JSON.parse(BODY)
  assert.equal(vercelConnector.eventId({}, body), "evt_01HZ")
  assert.equal(vercelConnector.eventId({}, body), vercelConnector.eventId({}, body))
})

test("the connector asks for no API token at all", () => {
  // The point of moving this to a webhook: the only credential is a verification secret.
  assert.deepEqual(
    vercelConnector.fields.map((f) => f.name),
    ["secret"],
  )
  assert.ok(vercelConnector.setup.some((s) => /no API token is needed/i.test(s)))
})
