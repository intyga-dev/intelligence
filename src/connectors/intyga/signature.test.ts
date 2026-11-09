import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import test from "node:test"
import { verifyWebhookSignature } from "./signature.ts"

/**
 * Cross-implementation fixture: the MAC was produced by OpenSSL, not by this codebase and not by
 * Intyga's. If our reading of the scheme were wrong, this would not verify.
 */
const fx: { secret: string; t: number; body: string; header: string } = JSON.parse(
  readFileSync(new URL("../../../test/fixtures/webhook-signature.json", import.meta.url), "utf8"),
)

/** A time just after the fixture was signed, so it is inside the freshness window. */
const NOW = new Date((fx.t + 5) * 1000)

test("accepts a signature produced by an independent implementation (OpenSSL)", () => {
  const r = verifyWebhookSignature({ header: fx.header, rawBody: fx.body, secret: fx.secret, now: NOW })
  assert.equal(r.ok, true)
  if (r.ok) assert.deepEqual(r.signedAt, new Date(fx.t * 1000))
})

test("rejects a tampered body", () => {
  const tampered = fx.body.replace('"requiredApprovals":2', '"requiredApprovals":1')
  assert.notEqual(tampered, fx.body)
  const r = verifyWebhookSignature({ header: fx.header, rawBody: tampered, secret: fx.secret, now: NOW })
  assert.deepEqual(r, { ok: false, reason: "mismatch" })
})

test("rejects the wrong secret", () => {
  const r = verifyWebhookSignature({ header: fx.header, rawBody: fx.body, secret: "whsec_wrong", now: NOW })
  assert.deepEqual(r, { ok: false, reason: "mismatch" })
})

test("re-serialized JSON does NOT verify — the MAC covers raw bytes", () => {
  // The trap this test exists to pin: parsing and re-stringifying reorders nothing here, but it
  // does drop the exact byte sequence guarantee. Proven with a whitespace-preserving round trip.
  const reserialized = JSON.stringify(JSON.parse(fx.body), null, 2)
  const r = verifyWebhookSignature({
    header: fx.header,
    rawBody: reserialized,
    secret: fx.secret,
    now: NOW,
  })
  assert.equal(r.ok, false)
})

test("rejects a replayed signature once it falls outside the freshness window", () => {
  // The body and MAC are perfectly valid — this is a genuine captured request being replayed.
  const late = new Date((fx.t + 301) * 1000)
  assert.deepEqual(
    verifyWebhookSignature({ header: fx.header, rawBody: fx.body, secret: fx.secret, now: late }),
    { ok: false, reason: "stale" },
  )
})

test("rejects a signature from the future", () => {
  const early = new Date((fx.t - 301) * 1000)
  assert.deepEqual(
    verifyWebhookSignature({ header: fx.header, rawBody: fx.body, secret: fx.secret, now: early }),
    { ok: false, reason: "future" },
  )
})

test("tolerance is configurable and inclusive at the boundary", () => {
  const edge = new Date((fx.t + 300) * 1000)
  assert.equal(
    verifyWebhookSignature({ header: fx.header, rawBody: fx.body, secret: fx.secret, now: edge }).ok,
    true,
  )
  assert.equal(
    verifyWebhookSignature({
      header: fx.header,
      rawBody: fx.body,
      secret: fx.secret,
      now: edge,
      toleranceSeconds: 299,
    }).ok,
    false,
  )
})

test("rejects malformed or absent headers without throwing", () => {
  for (const header of [
    undefined,
    "",
    "garbage",
    "t=abc,v1=deadbeef",
    `t=${fx.t}`,
    "v1=deadbeef",
    `t=${fx.t},v1=nothex!!`,
    `t=${fx.t},v1=abc`, // odd-length hex
  ]) {
    const r = verifyWebhookSignature({ header, rawBody: fx.body, secret: fx.secret, now: NOW })
    assert.equal(r.ok, false, `header ${JSON.stringify(header)} must not verify`)
  }
})

test("ignores unknown scheme keys so a future v2= cannot break a v1 verifier", () => {
  const withExtra = `${fx.header},v2=00ff`
  assert.equal(
    verifyWebhookSignature({ header: withExtra, rawBody: fx.body, secret: fx.secret, now: NOW }).ok,
    true,
  )
})

test("a MAC of the right shape but wrong value is a mismatch, not a crash", () => {
  const wrong = `t=${fx.t},v1=${"0".repeat(64)}`
  assert.deepEqual(verifyWebhookSignature({ header: wrong, rawBody: fx.body, secret: fx.secret, now: NOW }), {
    ok: false,
    reason: "mismatch",
  })
})
