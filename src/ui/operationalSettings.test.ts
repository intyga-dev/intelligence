import assert from "node:assert/strict"
import test from "node:test"
import { operationalSettingsForms } from "./operationalSettings.ts"

test("operational forms expose signed configuration and escape stored names and source labels", () => {
  const html = operationalSettingsForms({
    sources: [
      {
        id: "00000000-0000-4000-8000-000000000001",
        kind: "webhook",
        label: '<script>alert("source")</script>',
      },
    ],
    settings: {
      "job-overdue": {
        targets: [
          {
            connectionId: "00000000-0000-4000-8000-000000000001",
            job: '"><script>alert("job")</script>',
            startsAt: "2026-11-07T12:00:00Z",
          },
        ],
      },
    },
  })
  assert.match(html, /intelligence\.detector\.configure/)
  assert.match(html, /Save with INTYGA/)
  assert.match(html, /data-detector="service-degradation"/)
  assert.doesNotMatch(html, /<script>alert/)
  assert.match(html, /&lt;script&gt;/)
  assert.match(html, /data-field="maintenanceUntil"/)
})

test("invalid retained settings render an explicit repair state instead of breaking the page", () => {
  const html = operationalSettingsForms({ sources: [], settings: { "ci-health": { failures: -1 } } })
  assert.match(html, /Saved configuration is invalid/)
  assert.match(html, /data-detector="ci-health"/)
})
