import assert from "node:assert/strict"
import test from "node:test"
import { canonicalize } from "./jcs.ts"

test("sorts object keys by code unit, not insertion order", () => {
  assert.equal(canonicalize({ b: 1, a: 2 }), '{"a":2,"b":1}')
  // Two objects that differ only in key order must produce identical bytes — the whole point.
  assert.equal(canonicalize({ x: 1, y: 2 }), canonicalize({ y: 2, x: 1 }))
})

test("RFC 8785 sorts by UTF-16 code unit, so uppercase precedes lowercase", () => {
  assert.equal(canonicalize({ a: 1, A: 2 }), '{"A":2,"a":1}')
})

test("preserves array order", () => {
  assert.equal(canonicalize([3, 1, 2]), "[3,1,2]")
})

test("drops undefined properties, matching JSON.stringify", () => {
  assert.equal(canonicalize({ a: 1, b: undefined }), '{"a":1}')
  assert.equal(canonicalize({ a: 1, b: undefined }), canonicalize({ a: 1 }))
})

test("escapes control characters as lowercase \\uXXXX", () => {
  assert.equal(canonicalize("\u0001"), '"\\u0001"')
  assert.equal(canonicalize("a\nb"), '"a\\nb"')
  assert.equal(canonicalize('q"q'), '"q\\"q"')
})

test("refuses non-finite numbers rather than silently emitting null", () => {
  // JSON.stringify turns these into null, which would be a DIFFERENT signed payload than intended.
  assert.throws(() => canonicalize({ n: Number.NaN }), TypeError)
  assert.throws(() => canonicalize({ n: Number.POSITIVE_INFINITY }), TypeError)
})

test("serializes -0 as 0", () => {
  assert.equal(canonicalize(-0), "0")
})

test("nests deterministically", () => {
  const a = { outer: { z: [1, { b: 2, a: 1 }], y: "s" } }
  const b = { outer: { y: "s", z: [1, { a: 1, b: 2 }] } }
  assert.equal(canonicalize(a), canonicalize(b))
  assert.equal(canonicalize(a), '{"outer":{"y":"s","z":[1,{"a":1,"b":2}]}}')
})

test("handles non-ASCII without escaping it", () => {
  // RFC 8785 keeps literal UTF-8 for anything above the control range.
  assert.equal(canonicalize({ k: "vär" }), '{"k":"vär"}')
})
