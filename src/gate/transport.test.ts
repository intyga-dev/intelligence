import assert from "node:assert/strict"
import { test } from "node:test"
import { gatewayTransportUrl } from "./transport.ts"

test("only the configured public gateway gets the private route, including after a rebind", () => {
  const routing = { publicUrl: "http://localhost:8787", internalUrl: "http://host.docker.internal:8787" }
  assert.equal(gatewayTransportUrl("http://localhost:8787", routing), routing.internalUrl)
  assert.equal(gatewayTransportUrl("http://localhost:8787/", routing), routing.internalUrl)
  for (const url of [
    "https://another-gateway.test",
    "http://localhost:9000",
    "http://localhost:8787/another",
  ]) {
    assert.equal(gatewayTransportUrl(url, routing), url)
  }
  assert.equal(gatewayTransportUrl(routing.publicUrl, { ...routing, publicUrl: null }), routing.publicUrl)
  assert.equal(gatewayTransportUrl(routing.publicUrl, { ...routing, internalUrl: null }), routing.publicUrl)
})
