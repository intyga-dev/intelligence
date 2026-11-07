import assert from "node:assert/strict"
import { test } from "node:test"
import { metricQueries, metricsConnector } from "./index.ts"

test("PromQL commas are preserved, with legacy bare-name lists still supported", () => {
  const expression = 'sum(rate(http_requests_total{job="api",status="500"}[5m]))'
  assert.deepEqual(metricQueries(expression), [expression])
  assert.deepEqual(metricQueries(`${expression}\nlabel_replace(up, "a", "b", "c", "d")`), [
    expression,
    'label_replace(up, "a", "b", "c", "d")',
  ])
  assert.deepEqual(metricQueries("metric_a, metric_b\nmetric_c"), ["metric_a", "metric_b", "metric_c"])
  assert.equal(metricQueries("").length, 10)
})

test("unsupported Prometheus responses report a polling error", async (t) => {
  t.mock.method(
    globalThis,
    "fetch",
    async () => new Response(JSON.stringify({ status: "error", error: "sensitive upstream body" })),
  )
  const messages: string[] = []
  const events = await metricsConnector.poll({
    connectionId: "c",
    tenantId: "t",
    config: { baseUrl: "https://metrics.example", queries: "up" },
    secret: null,
    getCursor: async () => null,
    setCursor: async () => {},
    log: (message) => {
      messages.push(message)
    },
  })
  assert.equal(events.length, 0)
  assert.equal(messages.length, 1)
  assert.doesNotMatch(messages[0]!, /sensitive/)
})
