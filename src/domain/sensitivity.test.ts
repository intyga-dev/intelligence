import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import test from "node:test"
import { classifyChangedPaths, isNoise, matchesGlob } from "./sensitivity.ts"

/** Real changed-file lists from the repository this map describes. Fixtures, not inventions. */
const fixture = (name: string): string[] =>
  JSON.parse(readFileSync(new URL(`../../test/fixtures/${name}`, import.meta.url), "utf8"))

test("matchesGlob: ** spans separators, * does not", () => {
  assert.equal(matchesGlob("packages/verify/src/index.ts", "packages/verify/src/**"), true)
  assert.equal(matchesGlob("packages/verify/src/a/b.ts", "packages/verify/src/**"), true)
  assert.equal(matchesGlob("apps/gateway/src/auth.ts", "apps/gateway/src/*.ts"), true)
  assert.equal(matchesGlob("apps/gateway/src/platform/signing.ts", "apps/gateway/src/*.ts"), false)
  assert.equal(matchesGlob("packages/db/prisma/rls.sql", "**/rls.sql"), true)
  assert.equal(matchesGlob("rls.sql", "**/rls.sql"), true, "**/ must also match at the root")
})

test("matchesGlob: a dot in a pattern is literal, not 'any character'", () => {
  assert.equal(matchesGlob("apps/gateway/src/authxts", "apps/gateway/src/auth.ts"), false)
})

test("noise exclusion catches the paths that made the first draft over-fire", () => {
  for (const p of [
    "packages/verify/CHANGELOG.md",
    "packages/verify-go/README.md",
    "packages/verify-go/go.sum",
    "packages/verify-rust/Cargo.lock",
    "packages/verify-rust/Cargo.toml",
    "packages/verify/src/approval-policy.test.ts",
  ]) {
    assert.equal(isNoise(p), true, `${p} should be noise`)
  }
})

test("pinned vectors are NOT noise — a changed vector means the canonical payload moved", () => {
  assert.equal(isNoise("packages/mcp-schemas/vectors/canonical-vectors.json"), false)
  assert.equal(isNoise("packages/mcp-schemas/src/index.ts"), false)
})

test("real PR #100: noise is stripped before anything is judged", () => {
  const r = classifyChangedPaths(fixture("pr-100-files.json"))
  assert.ok(r.excluded.length > 0, "the real PR does contain noise")
  assert.ok(
    !r.considered.some((p) => p.endsWith("CHANGELOG.md") || p.endsWith("go.sum")),
    "no changelog or lockfile may reach the component matcher",
  )
})

test("real PR #100 is correctly read as a COMPLETE six-port mirror update", () => {
  const r = classifyChangedPaths(fixture("pr-100-files.json"))
  assert.ok(r.mirror, "this PR touches mirrored ports, so the rule applies")
  assert.equal(r.mirror.vectorsUpdated, true, "it updates the pinned vectors")
  assert.deepEqual(r.mirror.missing, [], "all six ports moved together")
  assert.equal(r.mirror.complete, true)
})

test("real PR #100 also lands on gateway enforcement and canonicalization", () => {
  const r = classifyChangedPaths(fixture("pr-100-files.json"))
  const ids = r.hits.map((h) => h.component.id)
  assert.ok(ids.includes("gateway-enforcement"), "it changes apps/gateway/src/authorization.ts")
  assert.ok(ids.includes("canonicalization"))
  assert.ok(ids.includes("receipt-verification"))
  assert.equal(r.severityFloor, "critical")
})

test("a PARTIAL mirror update is the defect the rule exists to catch", () => {
  // One port moves, the others do not. This is the shape that ships a verifier that disagrees
  // with the producer — undetectable from any single package's tests.
  const r = classifyChangedPaths(["packages/verify-go/verify.go"])
  assert.ok(r.mirror)
  assert.equal(r.mirror.complete, false)
  assert.equal(r.mirror.vectorsUpdated, false)
  assert.ok(r.mirror.missing.includes("verify"))
  assert.ok(r.mirror.missing.includes("mcp-schemas"))
  assert.equal(r.mirror.touched.length, 1)
})

test("a mirror update that forgets the pinned vectors is still incomplete", () => {
  const all = [
    "packages/mcp-schemas/src/index.ts",
    "packages/verify/src/index.ts",
    "packages/verify-go/verify.go",
    "packages/verify-rust/src/lib.rs",
    "packages/verify-java/src/main/java/com/intyga/verify/Verify.java",
    "packages/sdk-python/intyga/verify.py",
  ]
  const r = classifyChangedPaths(all)
  assert.deepEqual(r.mirror?.missing, [])
  assert.equal(r.mirror?.vectorsUpdated, false)
  assert.equal(r.mirror?.complete, false, "six ports without vectors is not a complete mirror")
})

test("the mirror rule does not apply to a diff that touches no port", () => {
  const r = classifyChangedPaths(["apps/marketing/app/page.tsx"])
  assert.equal(r.mirror, null)
  assert.equal(r.severityFloor, null)
  assert.deepEqual(r.hits, [])
})

test("a changelog-only diff produces no finding at all", () => {
  const r = classifyChangedPaths(["packages/verify/CHANGELOG.md", "packages/verify-go/README.md"])
  assert.deepEqual(r.considered, [])
  assert.deepEqual(r.hits, [])
  assert.equal(r.mirror, null, "noise must not even trigger the mirror rule")
})

test("real PR #99 classifies without throwing and reports a floor", () => {
  const r = classifyChangedPaths(fixture("pr-99-files.json"))
  assert.ok(r.considered.length > 0)
  assert.ok(r.severityFloor === null || ["medium", "high", "critical"].includes(r.severityFloor))
})

test("a truncated path list is marked unreliable, so absence cannot be read as a partial mirror", () => {
  // The same input, twice: complete, it is a genuine partial-mirror defect; truncated, we simply
  // do not know, and reporting it as critical would be a fabricated finding.
  const paths = ["packages/verify-go/verify.go"]

  const complete = classifyChangedPaths(paths)
  assert.equal(complete.mirror?.reliable, true)
  assert.ok(complete.mirror!.missing.length > 0)

  const truncated = classifyChangedPaths(paths, { truncated: true })
  assert.equal(truncated.mirror?.reliable, false, "absence is unknowable when the list was cut off")
})

test("a COMPLETE mirror is still trustworthy on a truncated list", () => {
  // Truncation can only hide paths, never invent them. Seeing all six ports plus the vectors is a
  // positive observation and stays valid; only the inference from absence is lost.
  const all = [
    "packages/mcp-schemas/src/index.ts",
    "packages/mcp-schemas/vectors/canonical-vectors.json",
    "packages/verify/src/index.ts",
    "packages/verify-go/verify.go",
    "packages/verify-rust/src/lib.rs",
    "packages/verify-java/src/main/java/com/intyga/verify/Verify.java",
    "packages/sdk-python/intyga_sdk/crypto.py",
  ]
  const r = classifyChangedPaths(all, { truncated: true })
  assert.equal(r.mirror?.complete, true)
  assert.deepEqual(r.mirror?.missing, [])
})
