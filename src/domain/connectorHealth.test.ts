import assert from "node:assert/strict"
import { test } from "node:test"
import { connectorHealth, type ConnectorHealthInput } from "./connectorHealth.ts"

const now = new Date("2026-11-06T12:00:00Z")
const base: ConnectorHealthInput = {
  active: true,
  supported: true,
  mode: "poll",
  activatedAt: null,
  lastEventAt: null,
  lastPolledAt: null,
  lastPollSuccessAt: null,
  lastPollError: null,
  failedDeliveries: 0,
}

test("setup, missing polls, errors and stalled scheduling have distinct guidance", () => {
  assert.equal(connectorHealth({ ...base, active: false }, now).label, "Setup pending")
  assert.equal(connectorHealth(base, now).label, "Awaiting first poll")
  assert.equal(
    connectorHealth({ ...base, lastPolledAt: now, lastPollError: "Check credentials" }, now).detail,
    "Check credentials",
  )
  assert.equal(
    connectorHealth({ ...base, lastPolledAt: new Date(now.getTime() - 16 * 60_000) }, now).label,
    "Polling overdue",
  )
  assert.equal(connectorHealth({ ...base, lastPolledAt: now }, now).label, "Poll successful")
})

test("push silence is not treated as a failed poll and reactivation awaits new evidence", () => {
  const old = new Date("2026-01-01")
  assert.equal(connectorHealth({ ...base, mode: "push" }, now).label, "Awaiting delivery")
  assert.equal(connectorHealth({ ...base, mode: "push", lastEventAt: old }, now).tone, "on")
  assert.equal(
    connectorHealth({ ...base, mode: "push", lastEventAt: old, activatedAt: now }, now).label,
    "Awaiting delivery",
  )
  assert.equal(
    connectorHealth({ ...base, lastPolledAt: old, activatedAt: now }, now).label,
    "Awaiting first poll",
  )
})

test("normalization failures and unsupported connectors are visible", () => {
  assert.equal(connectorHealth({ ...base, mode: "push", failedDeliveries: 2 }, now).label, "Delivery errors")
  assert.equal(connectorHealth({ ...base, supported: false }, now).label, "Unavailable")
})

test("provider test deliveries confirm authentication without claiming detector coverage", () => {
  const health = connectorHealth({ ...base, mode: "push", lastVerifiedDeliveryAt: now }, now)
  assert.equal(health.label, "Delivery verified")
  assert.match(health.detail, /no supported event/)
  assert.equal(
    connectorHealth(
      { ...base, mode: "push", lastVerifiedDeliveryAt: new Date("2026-01-01"), activatedAt: now },
      now,
    ).label,
    "Awaiting delivery",
  )
})
