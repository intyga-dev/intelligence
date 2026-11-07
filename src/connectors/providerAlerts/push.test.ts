import assert from "node:assert/strict"
import { test } from "node:test"
import {
  awsEventBridgeConnector as aws,
  googleMonitoringConnector as google,
  grafanaConnector as grafana,
  alertmanagerConnector as prometheus,
  stripeConnector as stripe,
} from "./push.ts"
import { hmacHex } from "../shared.ts"

const now = new Date(),
  at = now.toISOString(),
  secret = "test-secret",
  connectionId = "test"
const normalize = (connector: typeof aws, body: unknown) =>
  connector.normalize({ connectionId, body, receivedAt: now })
const envelope = (source: string, type: string, detail: unknown) => ({
  id: "event-1",
  account: "123456789012",
  region: "eu-west-1",
  time: at,
  source,
  "detail-type": type,
  detail,
  resources: ["arn:aws:test:eu-west-1:123456789012:resource"],
})
const alarm = (state = "ALARM") =>
  envelope("aws.cloudwatch", "CloudWatch Alarm State Change", {
    alarmName: "High errors",
    state: { value: state, timestamp: at },
  })

test("AWS authenticates API Destination headers and normalizes CloudWatch state without treating unknown as recovery", () => {
  assert.equal(aws.verify({ headers: { "x-intelligence-token": secret }, secret, rawBody: "{}" }).ok, true)
  assert.equal(aws.verify({ headers: { "x-intelligence-token": "bad" }, secret, rawBody: "{}" }).ok, false)
  assert.equal(normalize(aws, alarm())?.attrs.status, "firing")
  assert.equal(normalize(aws, alarm("OK"))?.attrs.status, "resolved")
  assert.equal(normalize(aws, alarm("INSUFFICIENT_DATA")), null)
  assert.equal(normalize(aws, { ...alarm(), account: "" }), null)
  assert.equal(normalize(aws, alarm())?.sourceId, normalize(aws, alarm())?.sourceId)
})
test("AWS distinguishes failed backups, successful completions, health issues and scheduled maintenance", () => {
  for (const state of ["FAILED", "ABORTED", "EXPIRED"]) {
    const e = normalize(
      aws,
      envelope("aws.backup", "Backup Job State Change", { state, backupJobId: "backup-1" }),
    )
    assert.equal(e?.attrs.status, "firing")
    assert.equal(e?.attrs.severity, "high")
  }
  assert.equal(
    normalize(
      aws,
      envelope("aws.backup", "Backup Job State Change", { state: "COMPLETED", backupJobId: "backup-1" }),
    )?.attrs.status,
    "resolved",
  )
  assert.equal(normalize(aws, envelope("aws.backup", "Backup Job State Change", { state: "FAILED" })), null)
  assert.equal(
    normalize(
      aws,
      envelope("aws.health", "AWS Health Event", {
        eventTypeCategory: "issue",
        eventArn: "issue",
        statusCode: "open",
      }),
    )?.attrs.status,
    "firing",
  )
  assert.equal(
    normalize(
      aws,
      envelope("aws.health", "AWS Health Event", {
        eventTypeCategory: "scheduledChange",
        eventArn: "maintenance",
        statusCode: "open",
      }),
    ),
    null,
  )
})
test("GuardDuty retains provider severity and explicit archive state", () => {
  for (const [score, level] of [
    [2, "low"],
    [5, "medium"],
    [8, "high"],
    [9, "critical"],
  ] as const) {
    assert.equal(
      normalize(
        aws,
        envelope("aws.guardduty", "GuardDuty Finding", {
          id: "g1",
          title: "Threat",
          severity: score,
          service: { archived: false },
        }),
      )?.attrs.severity,
      level,
    )
  }
  assert.equal(
    normalize(
      aws,
      envelope("aws.guardduty", "GuardDuty Finding", { id: "g1", severity: 8, service: { archived: true } }),
    )?.attrs.status,
    "resolved",
  )
})
test("Google Monitoring uses HTTP Basic and native incident states", () => {
  const auth = `Basic ${Buffer.from(`intelligence:${secret}`).toString("base64")}`
  assert.equal(google.verify({ headers: { authorization: auth }, secret, rawBody: "{}" }).ok, true)
  assert.equal(
    google.verify({ headers: { authorization: `Bearer ${secret}` }, secret, rawBody: "{}" }).ok,
    false,
  )
  const body = {
    incident: {
      incident_id: "i1",
      started_at: Math.floor(now.getTime() / 1000),
      state: "open",
      severity: "ERROR",
      policy_name: "Cloud Run errors",
    },
  }
  assert.equal(normalize(google, body)?.attrs.severity, "high")
  assert.equal(
    normalize(google, {
      incident: { ...body.incident, state: "closed", ended_at: Math.floor(now.getTime() / 1000) + 60 },
    })?.attrs.status,
    "resolved",
  )
  assert.equal(
    normalize(google, { incident: { ...body.incident, state: "closed" } }),
    null,
    "a closure without its timestamp is not invented",
  )
  assert.equal(normalize(google, { message: "test" }), null)
})
test("Grafana and Alertmanager preserve each member and reject truncated batches", () => {
  const alerts = [
    {
      fingerprint: "one",
      labels: { alertname: "CPU", severity: "critical" },
      annotations: { summary: "CPU high" },
      startsAt: at,
      status: "firing",
    },
    { fingerprint: "two", labels: { alertname: "Queue" }, endsAt: at, status: "resolved" },
  ]
  for (const connector of [grafana, prometheus]) {
    const events = connector.normalizeBatch!({ connectionId, body: { alerts }, receivedAt: now })
    assert.equal(events.length, 2)
    assert.equal(events[0]!.attrs.severity, "critical")
    assert.equal(events[1]!.attrs.status, "resolved")
    assert.notEqual(events[0]!.sourceId, events[1]!.sourceId)
    assert.throws(
      () =>
        connector.normalizeBatch!({ connectionId, body: { alerts, truncatedAlerts: 1 }, receivedAt: now }),
      /Incomplete/,
    )
    assert.throws(
      () =>
        connector.normalizeBatch!({
          connectionId,
          body: { alerts: Array(201).fill(alerts[0]) },
          receivedAt: now,
        }),
      /Incomplete/,
    )
    assert.equal(
      connector.normalizeBatch!({ connectionId, body: { alerts: [null, {}] }, receivedAt: now }).length,
      0,
    )
  }
})
test("Stripe verifies raw-body signatures, rotation candidates and timestamp tolerance", () => {
  const rawBody = JSON.stringify({ id: "evt_1" }),
    t = Math.floor(Date.now() / 1000)
  const valid = `t=${t},v1=${hmacHex(secret, `${t}.${rawBody}`)}`
  assert.equal(stripe.verify({ headers: { "stripe-signature": valid }, secret, rawBody }).ok, true)
  assert.equal(
    stripe.verify({
      headers: { "stripe-signature": `t=${t},v1=bad,v1=${hmacHex(secret, `${t}.${rawBody}`)}` },
      secret,
      rawBody,
    }).ok,
    true,
  )
  assert.equal(
    stripe.verify({ headers: { "stripe-signature": valid }, secret, rawBody: `${rawBody} ` }).ok,
    false,
  )
  assert.equal(
    stripe.verify({
      headers: { "stripe-signature": `t=${t - 600},v1=${hmacHex(secret, `${t - 600}.${rawBody}`)}` },
      secret,
      rawBody,
    }).ok,
    false,
  )
})
test("Stripe payout/dispute lifecycle excludes ordinary payment failures and customer payloads", () => {
  const body = {
    id: "evt_1",
    created: Math.floor(now.getTime() / 1000),
    livemode: true,
    type: "payout.failed",
    data: { object: { id: "po_1", customer: { email: "do-not-copy@example.com" } } },
  }
  const e = normalize(stripe, body)
  assert.equal(e?.attrs.category, "business")
  assert.equal(e?.attrs.status, "firing")
  assert.doesNotMatch(JSON.stringify(e), /do-not-copy/)
  assert.equal(normalize(stripe, { ...body, type: "payout.paid" })?.attrs.status, "resolved")
  assert.equal(normalize(stripe, { ...body, type: "charge.dispute.created" })?.attrs.severity, "medium")
  assert.equal(normalize(stripe, { ...body, type: "charge.dispute.closed" })?.attrs.status, "resolved")
  assert.equal(normalize(stripe, { ...body, type: "payment_intent.payment_failed" }), null)
  assert.equal(normalize(stripe, { ...body, type: "invoice.payment_failed" }), null)
})
test("malformed and unsupported webhook shapes never manufacture findings", () => {
  for (const c of [aws, google, grafana, prometheus, stripe])
    for (const body of [null, [], "x", {}, { incident: {} }, { detail: {} }]) {
      assert.equal(normalize(c, body), null)
    }
})
