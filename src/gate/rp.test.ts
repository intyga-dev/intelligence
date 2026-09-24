import assert from "node:assert/strict"
import crypto from "node:crypto"
import test from "node:test"
import { canonicalize } from "./jcs.ts"
import { intentDigest } from "./intent.ts"

// The digest is the entire binding between "a human tapped their key" and "this specific action
// happened". If two different intents could produce one digest, an approval for a harmless action
// would redeem a dangerous one.

test("the digest is lowercase 64-hex, which is the only spelling the platform plane accepts", () => {
  const d = intentDigest({ action: "intelligence.judgment.enable", params: { provider: "typesafe" } })
  assert.match(d, /^[0-9a-f]{64}$/)
})

test("key order does not change the digest", () => {
  const a = intentDigest({
    action: "intelligence.connector.activate",
    params: { connectionId: "c1", kind: "intyga" },
  })
  const b = intentDigest({
    action: "intelligence.connector.activate",
    params: { kind: "intyga", connectionId: "c1" },
  })
  assert.equal(a, b)
})

test("a different action produces a different digest", () => {
  const params = { connectionId: "c1" }
  assert.notEqual(
    intentDigest({ action: "intelligence.connector.activate", params }),
    intentDigest({ action: "intelligence.connector.deactivate", params }),
  )
})

test("a different parameter produces a different digest", () => {
  assert.notEqual(
    intentDigest({ action: "intelligence.connector.activate", params: { connectionId: "c1" } }),
    intentDigest({ action: "intelligence.connector.activate", params: { connectionId: "c2" } }),
  )
})

test("adding a parameter produces a different digest", () => {
  // Approving "purge tenant X" must not redeem "purge tenant X, including findings".
  assert.notEqual(
    intentDigest({ action: "intelligence.data.purge", params: { tenantId: "t1" } }),
    intentDigest({ action: "intelligence.data.purge", params: { tenantId: "t1", findings: true } }),
  )
})

test("the digest is reproducible by anyone with the intent and a SHA-256", () => {
  // An approver's client, an auditor, or a reviewer must be able to re-derive this independently —
  // so it is pinned against a hand-computed value rather than against intentDigest itself.
  const intent = { action: "intelligence.judgment.enable" as const, params: { provider: "typesafe" } }
  const expected = crypto
    .createHash("sha256")
    .update(canonicalize({ action: intent.action, params: intent.params }), "utf8")
    .digest("hex")
  assert.equal(intentDigest(intent), expected)
  assert.equal(
    canonicalize({ action: intent.action, params: intent.params }),
    '{"action":"intelligence.judgment.enable","params":{"provider":"typesafe"}}',
  )
})

test("nested parameters are canonicalized too, not stringified ad hoc", () => {
  const a = intentDigest({
    action: "intelligence.member.add",
    params: { member: { label: "Ada", externalId: "ada" } },
  })
  const b = intentDigest({
    action: "intelligence.member.add",
    params: { member: { externalId: "ada", label: "Ada" } },
  })
  assert.equal(a, b)
})
