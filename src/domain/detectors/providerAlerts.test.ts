import assert from "node:assert/strict"
import test from "node:test"
import { detectProviderAlerts } from "./providerAlerts.ts"
import { alertEvent } from "../../connectors/providerAlerts/common.ts"
const now = new Date("2026-11-07T12:00:00Z"),
  source = {
    id: "source",
    label: "AWS",
    active: true,
    activatedAt: new Date("2026-11-07T10:00:00Z"),
    serviceId: null,
  }
const event = (status: "firing" | "resolved", at: string) =>
  alertEvent("source", "aws-eventbridge", {
    id: at,
    incident: "incident",
    at,
    title: "Alarm",
    status,
    severity: "high",
  })!
const firing = event("firing", "2026-11-07T11:00:00Z"),
  resolved = event("resolved", "2026-11-07T11:30:00Z")
const input = (events: (typeof firing)[]) => ({ tenantId: "tenant", now, sources: [source], events })
test("provider alerts preserve evidence and latest explicit state regardless of delivery order", () => {
  const result = detectProviderAlerts(input([firing]))
  assert.equal(result.findings.length, 1)
  assert.equal(result.findings[0]!.severity, "high")
  assert.equal(result.findings[0]!.evidence[0]!.kind, "eventRef")
  for (const events of [
    [firing, resolved],
    [resolved, firing],
    [firing, firing, resolved],
  ]) {
    const r = detectProviderAlerts(input(events))
    assert.equal(r.findings.length, 0)
    assert.equal(r.resolved.length, 1)
  }
})
test("low severity, forged source families, inactive sources and future data are excluded", () => {
  for (const e of [
    { ...firing, attrs: { ...firing.attrs, severity: "low" } },
    { ...firing, source: "webhook" },
    { ...firing, connectionId: "other" },
    { ...firing, serviceId: "other" },
    { ...firing, at: new Date("2027-01-01") },
  ])
    assert.equal(detectProviderAlerts(input([e])).findings.length, 0)
  assert.equal(
    detectProviderAlerts({ ...input([firing]), sources: [{ ...source, active: false }] }).findings.length,
    0,
  )
})
test("recovery never closes another connector's incident and does not mean quiet sources are healthy", () => {
  const r = detectProviderAlerts({
    ...input([firing, { ...resolved, connectionId: "other" }]),
    sources: [source, { ...source, id: "other" }],
  })
  assert.equal(r.findings.length, 1)
  assert.equal(r.resolved.length, 1)
  assert.equal(detectProviderAlerts(input([])).resolved.length, 0)
})
