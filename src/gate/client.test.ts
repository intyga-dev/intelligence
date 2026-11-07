import assert from "node:assert/strict"
import { after, before, beforeEach, test } from "node:test"
import { anchor, signedReceipt, stubGateway } from "../test/intyga.ts"
import {
  approvalState,
  GateRefused,
  openApproval,
  parseTrustAnchor,
  testConnection,
  verifyAndConsume,
} from "./client.ts"

let gateway: Awaited<ReturnType<typeof stubGateway>>
before(async () => {
  gateway = await stubGateway()
})
beforeEach(() => gateway.reset())
after(async () => gateway.app.close())
const action = {
  target: "intelligence:localhost:4100",
  actionType: "intelligence.service.create",
  params: { name: "API" },
}

test("trust anchors parse from JSON or objects and require online keys and WebAuthn pinning", () => {
  for (const value of [anchor, JSON.stringify(anchor)]) {
    const result = parseTrustAnchor(value)
    assert.equal(result.ok, true)
    if (result.ok) assert.deepEqual(result.anchor, anchor)
  }
  for (const value of [
    null,
    "garbled",
    {},
    { ...anchor, v: 2 },
    { ...anchor, purpose: "offline" },
    { ...anchor, approvers: [] },
    { ...anchor, webauthn: undefined },
  ]) {
    const result = parseTrustAnchor(value)
    assert.equal(result.ok, false, JSON.stringify(value))
    if (!result.ok) assert.match(result.error, /trust anchor/)
  }
})

test("an opened approval uses the console and the gateway nonce", async () => {
  const result = await openApproval(gateway.config, {
    ...action,
    description: "Create API",
    timeoutSeconds: 60,
  })
  assert.equal(result.nonce, gateway.state.nonce)
  assert.equal(new URL(result.approveUrl).origin, gateway.config.consoleUrl)
  assert.equal(new URL(result.approveUrl).searchParams.get("nonce"), result.nonce)
  assert.equal(gateway.state.authorizeCalls[0]?.target, action.target)
})

test("a valid receipt is checked then consumed against the frozen action", async () => {
  await verifyAndConsume(
    gateway.config,
    gateway.state.nonce,
    action,
    signedReceipt(gateway.state.nonce, action),
  )
  assert.deepEqual(gateway.state.consumeCalls, [{ nonce: gateway.state.nonce, ...action }])
})

test("bad signatures, wrong nonces, changed parameters and untrusted signers never reach redemption", async () => {
  const receipt = signedReceipt(gateway.state.nonce, action)
  for (const bad of [
    null,
    {},
    { ...receipt, signature: "AAAA" },
    signedReceipt("another-nonce", action),
    signedReceipt(gateway.state.nonce, { ...action, params: { name: "other" } }),
    { ...receipt, signerDid: "did:intyga:untrusted" },
  ]) {
    await assert.rejects(verifyAndConsume(gateway.config, gateway.state.nonce, action, bad), GateRefused)
  }
  assert.deepEqual(gateway.state.requests, [])
})

test("even a valid receipt fails if the gateway already consumed it", async () => {
  gateway.state.consumeOk = false
  await assert.rejects(
    verifyAndConsume(gateway.config, gateway.state.nonce, action, signedReceipt(gateway.state.nonce, action)),
    /already consumed/,
  )
  assert.equal(gateway.state.consumeCalls.length, 1)
})

for (const status of [401, 403]) {
  test(`a rejected service key (${status}) blocks redemption`, async () => {
    gateway.state.tokenStatus = status
    await assert.rejects(
      verifyAndConsume(
        gateway.config,
        gateway.state.nonce,
        action,
        signedReceipt(gateway.state.nonce, action),
      ),
      /refused the service key/,
    )
    assert.equal(gateway.state.consumeCalls.length, 0)
    assert.equal((await testConnection(gateway.config)).ok, false)
  })
}

test("connection probe accepts only successful auth, including an unknown approval", async () => {
  gateway.state.statusCode = 404
  assert.deepEqual(await testConnection(gateway.config), { ok: true })
  gateway.state.statusCode = 500
  assert.equal((await testConnection(gateway.config)).ok, false)
})

test("an APPROVED response without a receipt is refused", async () => {
  gateway.state.status = "APPROVED"
  await assert.rejects(approvalState(gateway.config, gateway.state.nonce), /without a receipt/)
})
