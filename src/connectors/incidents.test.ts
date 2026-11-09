import assert from "node:assert/strict"
import crypto from "node:crypto"
import test from "node:test"
import { DATADOG_PAYLOAD_TEMPLATE, datadogConnector } from "./datadog/index.ts"
import { opsgenieConnector } from "./opsgenie/index.ts"
import { pagerdutyConnector, verifyPagerDutySignature } from "./pagerduty/index.ts"
import { TOKEN_HEADER } from "./shared.ts"

// PagerDuty, Opsgenie and Datadog: the incident sources that feed deploy-regression.

const now = new Date("2026-09-23T12:00:00Z")

// ─── PagerDuty ───────────────────────────────────────────────────────────────────────────────────

const PD_SECRET = "pd_secret"
const PD_BODY = JSON.stringify({
  event: {
    id: "01DEN4NQ6N1Z2R6X8K0Q5P8V9M",
    event_type: "incident.triggered",
    resource_type: "incident",
    occurred_at: "2026-09-23T11:58:00Z",
    data: {
      id: "PGR0VU2",
      title: "API 5xx rate",
      urgency: "high",
      service: { id: "P1", summary: "billing-api" },
    },
  },
})
const pdSig = (body: string, secret = PD_SECRET) =>
  `v1=${crypto.createHmac("sha256", secret).update(body).digest("hex")}`

test("PagerDuty: accepts a match anywhere in a rotating signature list, ignores unknown schemes", () => {
  assert.equal(verifyPagerDutySignature(pdSig(PD_BODY), PD_BODY, PD_SECRET).ok, true)
  const rotating = `v1=${"0".repeat(64)}, v2=abc, ${pdSig(PD_BODY)}`
  assert.equal(verifyPagerDutySignature(rotating, PD_BODY, PD_SECRET).ok, true)
})

test("PagerDuty: rejects tampering, a wrong secret, and headers with no v1 entry", () => {
  assert.equal(verifyPagerDutySignature(pdSig(PD_BODY), `${PD_BODY} `, PD_SECRET).ok, false)
  assert.equal(verifyPagerDutySignature(pdSig(PD_BODY, "other"), PD_BODY, PD_SECRET).ok, false)
  assert.equal(verifyPagerDutySignature("v2=abc", PD_BODY, PD_SECRET).ok, false)
  assert.equal(verifyPagerDutySignature(undefined, PD_BODY, PD_SECRET).ok, false)
})

test("PagerDuty: an incident becomes a service-attributed event; other resources are not modelled", () => {
  const e = pagerdutyConnector.normalize({ connectionId: "c", body: JSON.parse(PD_BODY), receivedAt: now })
  assert.equal(e?.kind, "pagerduty.incident.triggered")
  assert.equal(e?.subjectRef, "billing-api")
  assert.equal(e?.at.toISOString(), "2026-09-23T11:58:00.000Z")
  assert.equal(pagerdutyConnector.eventId({}, JSON.parse(PD_BODY)), "01DEN4NQ6N1Z2R6X8K0Q5P8V9M")
  const service = { event: { id: "x", event_type: "service.updated", data: {} } }
  assert.equal(pagerdutyConnector.normalize({ connectionId: "c", body: service, receivedAt: now }), null)
})

// ─── Opsgenie & Datadog (shared-secret header) ───────────────────────────────────────────────────

test("the token header is required and compared exactly", () => {
  for (const c of [opsgenieConnector, datadogConnector]) {
    assert.equal(
      c.verify({ headers: { [TOKEN_HEADER]: "s3cret" }, rawBody: "{}", secret: "s3cret" }).ok,
      true,
    )
    assert.equal(
      c.verify({ headers: { [TOKEN_HEADER]: "s3cre" }, rawBody: "{}", secret: "s3cret" }).ok,
      false,
    )
    assert.equal(c.verify({ headers: {}, rawBody: "{}", secret: "s3cret" }).ok, false)
  }
})

test("Opsgenie: a created alert is dated by its epoch-ms createdAt; other actions by arrival", () => {
  const body = {
    action: "Create",
    alert: {
      alertId: "a-1",
      tinyId: "12",
      message: "DB down",
      entity: "orders-db",
      createdAt: 1790164680000,
    },
    integrationName: "Webhook",
  }
  const e = opsgenieConnector.normalize({ connectionId: "c", body, receivedAt: now })
  assert.equal(e?.kind, "opsgenie.alert.create")
  assert.equal(e?.at.getTime(), 1790164680000)
  assert.equal(e?.subjectRef, "orders-db")
  const close = opsgenieConnector.normalize({
    connectionId: "c",
    body: { ...body, action: "Close" },
    receivedAt: now,
  })
  assert.equal(close?.kind, "opsgenie.alert.close")
  assert.equal(close?.at, now)
  assert.notEqual(
    opsgenieConnector.eventId({}, body),
    opsgenieConnector.eventId({}, { ...body, action: "Close" }),
  )
})

test("Datadog: transitions map to kinds; an unsubstituted template is not an event", () => {
  const mk = (transition: string) => ({
    id: "7654321",
    title: "[Triggered] High latency",
    transition,
    monitor: "123",
    date: "1790164680000",
  })
  assert.equal(
    datadogConnector.normalize({ connectionId: "c", body: mk("Triggered"), receivedAt: now })?.kind,
    "datadog.alert.triggered",
  )
  assert.equal(
    datadogConnector.normalize({ connectionId: "c", body: mk("Re-Triggered"), receivedAt: now })?.kind,
    "datadog.alert.retriggered",
  )
  assert.equal(
    datadogConnector.normalize({ connectionId: "c", body: mk("Recovered"), receivedAt: now })?.kind,
    "datadog.alert.recovered",
  )
  assert.equal(
    datadogConnector.normalize({ connectionId: "c", body: mk("Triggered"), receivedAt: now })?.at.getTime(),
    1790164680000,
  )
  const raw = JSON.parse(DATADOG_PAYLOAD_TEMPLATE) as Record<string, string>
  assert.equal(datadogConnector.normalize({ connectionId: "c", body: raw, receivedAt: now }), null)
  assert.equal(datadogConnector.eventId({}, raw), null)
})
