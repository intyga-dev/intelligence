import assert from "node:assert/strict"
import { test } from "node:test"
import { embeddedApprovalLink, readApprovalTicket } from "./approval-link.ts"
import { testDeployment } from "../test/deployment.ts"
import { resolveConnectionConfig } from "../gate/deployment.ts"

test("shared approval view capabilities are bound to one nonce, deployment and expiry", () => {
  const d = testDeployment()
  try {
    const cfg = resolveConnectionConfig()
    const url = new URL(embeddedApprovalLink(cfg, "nonce-123456", Date.now() + 60_000))
    assert.equal(url.origin, cfg.origin)
    assert.equal(url.search, "")
    const ticket = new URLSearchParams(url.hash.slice(1)).get("ticket") ?? ""
    assert.equal(readApprovalTicket(cfg, ticket).nonce, "nonce-123456")
    assert.throws(() => readApprovalTicket({ ...cfg, bindingId: "different" }, ticket), /invalid or expired/)
    assert.throws(() => readApprovalTicket(cfg, ticket.slice(0, -3)), /invalid or expired/)
    const expired = new URL(embeddedApprovalLink(cfg, "nonce-123456", Date.now() - 1))
    assert.throws(
      () => readApprovalTicket(cfg, new URLSearchParams(expired.hash.slice(1)).get("ticket") ?? ""),
      /invalid or expired/,
    )
  } finally {
    d.dispose()
  }
})
