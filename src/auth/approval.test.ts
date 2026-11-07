import assert from "node:assert/strict"
import { after, before, beforeEach, test } from "node:test"
import { resolveGateConfig, type DeploymentConfig } from "../gate/deployment.ts"
import { testDeployment } from "../test/deployment.ts"
import { signedReceipt, stubGateway } from "../test/intyga.ts"
import { decryptSecret, encryptSecret } from "../store/crypto.ts"
import { beginApprovalLogin, completeApprovalLogin, stampApprovalCredential } from "./approval.ts"

let gateway: Awaited<ReturnType<typeof stubGateway>>
let deployment: ReturnType<typeof testDeployment>
let cfg: DeploymentConfig
before(async () => {
  gateway = await stubGateway()
  deployment = testDeployment(gateway.baseUrl, gateway.config.serviceClientId, gateway.config.serviceSecret)
  cfg = resolveGateConfig()
})
beforeEach(() => gateway.reset())
after(async () => {
  await gateway.app.close()
  deployment.dispose()
})

test("normal approval sign-in binds the browser, origin, administrator access and duration", async () => {
  const opened = await beginApprovalLogin(cfg)
  const request = gateway.state.authorizeCalls[0]
  assert.ok(request)
  assert.equal(request.actionType, "intelligence.session.create")
  assert.equal(request.target, "intelligence:localhost:4100")
  assert.equal(request.params.role, "ADMIN")
  assert.equal(request.params.origin, cfg.origin)
  assert.equal(request.params.sessionHours, 12)
  assert.equal(String(request.params.browserId).slice(0, 8), opened.browserCode)
  assert.equal((await completeApprovalLogin(cfg, opened.cookie)).status, "pending")
  gateway.state.status = "APPROVED"
  gateway.state.receipt = signedReceipt(gateway.state.nonce, request)
  assert.deepEqual(await completeApprovalLogin(cfg, opened.cookie), {
    status: "approved",
    nonce: gateway.state.nonce,
  })
  assert.equal(gateway.state.consumeCalls.length, 1)
  gateway.state.consumeOk = false
  await assert.rejects(completeApprovalLogin(cfg, opened.cookie), /already consumed/)
})

test("missing, garbled, expired and wrong-deployment cookies cannot read or redeem approvals", async () => {
  const opened = await beginApprovalLogin(cfg)
  const state = JSON.parse(decryptSecret(opened.cookie) ?? "null")
  gateway.state.requests = []
  for (const cookie of [
    undefined,
    "garbled",
    encryptSecret("null"),
    encryptSecret("[]"),
    encryptSecret(JSON.stringify({ ...state, expiresAt: Date.now() - 1 })),
    encryptSecret(JSON.stringify({ ...state, bindingId: "other" })),
  ]) {
    await assert.rejects(completeApprovalLogin(cfg, cookie), /expired or does not belong/)
  }
  assert.deepEqual(gateway.state.requests, [])
})

for (const status of ["DENIED", "EXPIRED", "CONSUMED", "bad receipt", "other browser", "rejected key"]) {
  test(`approval sign-in refuses ${status}`, async () => {
    const opened = await beginApprovalLogin(cfg)
    const request = gateway.state.authorizeCalls[0]
    assert.ok(request)
    gateway.state.status = ["DENIED", "EXPIRED", "CONSUMED"].includes(status) ? status : "APPROVED"
    gateway.state.receipt = signedReceipt(gateway.state.nonce, request)
    if (status === "bad receipt")
      gateway.state.receipt = { ...(gateway.state.receipt as object), signature: "AAAA" }
    if (status === "other browser")
      gateway.state.receipt = signedReceipt(gateway.state.nonce, {
        ...request,
        params: { ...request.params, browserId: "another-browser" },
      })
    if (status === "rejected key") gateway.state.tokenStatus = 401
    await assert.rejects(completeApprovalLogin(cfg, opened.cookie))
    assert.equal(gateway.state.consumeCalls.length, 0)
  })
}

test("embedded sign-in preserves the real member role and requires this browser's verified credential", async () => {
  const embedded = { ...cfg, embeddedApplicationId: "123e4567-e89b-42d3-a456-426614174000" }
  const opened = await beginApprovalLogin(embedded)
  const request = gateway.state.authorizeCalls[0]
  assert.ok(request)
  assert.equal(request.params.role, "workspace-membership")
  gateway.state.status = "APPROVED"
  gateway.state.receipt = signedReceipt(gateway.state.nonce, request)
  await assert.rejects(completeApprovalLogin(embedded, opened.cookie), /active workspace member/)
  assert.equal(gateway.state.consumeCalls.length, 0)
  const cookie = stampApprovalCredential(embedded, opened.cookie, gateway.state.embeddedCredentialId)
  const result = await completeApprovalLogin(embedded, cookie)
  assert.equal(result.status, "approved")
  if (result.status === "approved") assert.equal(result.member?.role, "MEMBER")
  assert.equal(gateway.state.consumeCalls.length, 1)
})
