import assert from "node:assert/strict"
import test from "node:test"
import { classifyChangedPaths, isNoise, matchesGlob, PATH_MAPS, pathMapFor } from "./sensitivity.ts"

test("glob matching respects separators, root paths and literal punctuation", () => {
  assert.equal(matchesGlob("lib/auth/a/b.ts", "lib/auth/**"), true)
  assert.equal(matchesGlob("lib/auth/session.ts", "lib/auth/*.ts"), true)
  assert.equal(matchesGlob("lib/auth/nested/session.ts", "lib/auth/*.ts"), false)
  assert.equal(matchesGlob("schema.sql", "**/*.sql"), true)
  assert.equal(matchesGlob("lib/authxts", "lib/auth.ts"), false)
  assert.equal(matchesGlob("lib/a.ts", "lib/?.ts"), true)
  assert.equal(matchesGlob("lib/ab.ts", "lib/?.ts"), false)
})

test("documentation, styling and language tests do not inflate review observations", () => {
  const paths = [
    "website/blog/authors.ts",
    "src/authors.ts",
    "website/blog/articles/session-management.ts",
    "ui/login/page.module.css",
    "client/tests/test_guard.py",
    "lib/session_test.rs",
    "checks/auth.test.mts",
    "auth/CHANGELOG.md",
    "auth/go.sum",
    "auth/Cargo.lock",
    "auth/Cargo.toml",
  ]
  const result = classifyChangedPaths(paths)
  assert.deepEqual(result.hits, [])
  assert.equal(result.excluded.length, paths.length)
  assert.ok(paths.every(isNoise))
})

test("noise is excluded before component matching while executable paths remain", () => {
  const result = classifyChangedPaths(["src/auth/README.md", "src/auth/login.test.ts", "src/auth/login.ts"])
  assert.deepEqual(result.considered, ["src/auth/login.ts"])
  assert.equal(result.hits.length, 1)
  assert.equal(result.hits[0]?.component.id, "authentication")
  assert.deepEqual(result.hits[0]?.paths, ["src/auth/login.ts"])
})

test("unknown saved map settings cannot enable repository-specific rules", () => {
  for (const value of [undefined, null, "retired-custom-map", "generic", {}]) {
    assert.equal(pathMapFor(value), PATH_MAPS.generic)
    assert.deepEqual(classifyChangedPaths(["lib/contracts/index.ts"], { map: pathMapFor(value) }).hits, [])
  }
})

test("truncated input only describes paths actually present", () => {
  const paths = ["src/auth/login.ts", "lib/contracts/index.ts"]
  assert.deepEqual(classifyChangedPaths(paths, { truncated: true }), classifyChangedPaths(paths))
  assert.equal(isNoise("data/examples.json"), false)
})
