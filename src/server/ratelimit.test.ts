import assert from "node:assert/strict"
import test from "node:test"
import { createLimiter } from "./ratelimit.ts"

/** A clock we control, so the refill is tested rather than slept through. */
function clock(start = 1_000_000) {
  let t = start
  return { now: () => t, advance: (ms: number) => (t += ms) }
}

test("a burst is allowed and the next call over it is refused", () => {
  const c = clock()
  const l = createLimiter({ ratePerMinute: 60, burst: 3, maxKeys: 10 }, c.now)

  assert.equal(l.take("a"), true)
  assert.equal(l.take("a"), true)
  assert.equal(l.take("a"), true)
  assert.equal(l.take("a"), false)
})

test("tokens refill at the configured rate", () => {
  const c = clock()
  const l = createLimiter({ ratePerMinute: 60, burst: 2, maxKeys: 10 }, c.now)

  l.take("a")
  l.take("a")
  assert.equal(l.take("a"), false)

  c.advance(1_000) // 60/min == one token per second
  assert.equal(l.take("a"), true)
  assert.equal(l.take("a"), false)
})

test("refill is capped at the burst size", () => {
  const c = clock()
  const l = createLimiter({ ratePerMinute: 60, burst: 2, maxKeys: 10 }, c.now)

  l.take("a")
  c.advance(60_000) // a full minute idle: 60 tokens earned, 2 is the ceiling
  assert.equal(l.take("a"), true)
  assert.equal(l.take("a"), true)
  assert.equal(l.take("a"), false)
})

test("keys are independent", () => {
  const c = clock()
  const l = createLimiter({ ratePerMinute: 60, burst: 1, maxKeys: 10 }, c.now)

  assert.equal(l.take("a"), true)
  assert.equal(l.take("a"), false)
  assert.equal(l.take("b"), true, "b must not pay for a's burst")
})

test("retryAfter reports a whole number of seconds and never zero", () => {
  const c = clock()
  const l = createLimiter({ ratePerMinute: 60, burst: 1, maxKeys: 10 }, c.now)

  assert.equal(l.retryAfter("unknown"), 1, "a key with no bucket is not a wait")
  l.take("a")
  assert.equal(l.retryAfter("a"), 1)
  assert.equal(l.size(), 1, "retryAfter must not admit a key of its own")
})

test("the key map is bounded, and an unadmittable key is passed rather than refused", () => {
  const c = clock()
  const l = createLimiter({ ratePerMinute: 60, burst: 1, maxKeys: 2 }, c.now)

  // Two keys fill the map, each spending its only token so neither is idle.
  assert.equal(l.take("a"), true)
  assert.equal(l.take("b"), true)
  assert.equal(l.size(), 2)

  // A third distinct key cannot be admitted. It is allowed through — bounding invented keys is the
  // global bucket's job, and the alternative is a trivial denial of service against real senders.
  assert.equal(l.take("invented"), true)
  assert.equal(l.size(), 2, "an invented key must not grow the map")

  // Once the held keys go idle they are evictable, and a new key takes the slot.
  c.advance(60_000)
  assert.equal(l.take("c"), true)
  assert.ok(l.size() <= 2)
})

test("an idle key is evicted rather than starving a new one", () => {
  const c = clock()
  const l = createLimiter({ ratePerMinute: 600, burst: 1, maxKeys: 1 }, c.now)

  l.take("old")
  c.advance(10_000)
  assert.equal(l.take("new"), true)
  assert.equal(l.size(), 1)
})
