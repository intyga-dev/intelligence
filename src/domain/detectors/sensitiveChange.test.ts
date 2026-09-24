import assert from "node:assert/strict"
import test from "node:test"
import type { NormalizedEvent } from "../../connectors/types.ts"
import { classifyChangedPaths, PATH_MAPS, pathMapFor } from "../sensitivity.ts"
import { detectSensitiveChanges } from "./sensitiveChange.ts"

const NOW = new Date("2026-09-23T12:00:00Z")
const generic = () => PATH_MAPS.generic

function pr(n: number, paths: string[], extra: Record<string, unknown> = {}, at = NOW): NormalizedEvent {
  return {
    connectionId: "c1",
    source: "github",
    sourceId: `pr:acme/app#${n}@sha${n}`,
    kind: "github.pull_request.updated",
    at,
    subjectRef: "dev",
    correlationRef: `sha${n}`,
    attrs: {
      repo: "acme/app",
      number: n,
      title: `PR ${n}`,
      sha: `sha${n}`,
      draft: false,
      merged: false,
      paths: JSON.stringify(paths),
      pathsTruncated: false,
      ...extra,
    },
  }
}

test("the generic map fires on conventional names in any repository", () => {
  const r = classifyChangedPaths([
    "src/auth/session.ts",
    "services/api/middleware/permissions.go",
    "db/migrations/0042_add_roles.sql",
    ".github/workflows/deploy.yml",
    "src/components/Button.tsx",
  ])
  assert.deepEqual(r.hits.map((h) => h.component.id).sort(), [
    "authentication",
    "authorization",
    "ci-supply-chain",
    "data-schema",
  ])
  assert.equal(r.severityFloor, "high")
  assert.equal(r.mirror, null, "the generic map declares no mirror, so it never reasons from absence")
})

test("the generic map avoids the substrings that match unrelated code", () => {
  const r = classifyChangedPaths(["lib/oracle.ts", "lib/diameter.ts", "lib/tokenizer.ts", "docs/auth.md"])
  assert.equal(r.hits.length, 0, JSON.stringify(r.hits.map((h) => h.paths)))
})

test("an unknown map name falls back to the generic map, never to nothing", () => {
  assert.equal(pathMapFor("something-else").id, "generic")
  assert.equal(pathMapFor(undefined).id, "generic")
  assert.equal(pathMapFor("intyga-core").id, "intyga-core")
})

test("a PR touching auth produces one finding with the hit paths as evidence", () => {
  const found = detectSensitiveChanges({
    tenantId: "t",
    events: [pr(7, ["src/auth/login.ts", "src/ui/page.tsx"])],
    now: NOW,
    mapFor: generic,
  })
  assert.equal(found.length, 1)
  const f = found[0]
  assert.ok(f)
  assert.equal(f.severity, "high")
  assert.equal(f.dedupeKey, "sensitive:c1:acme/app#7")
  const ev = f.evidence[0]
  assert.equal(ev.kind, "codeChange")
  assert.deepEqual(ev.kind === "codeChange" ? ev.paths : [], ["src/auth/login.ts"])
})

test("drafts, noise-only diffs and unreadable events produce nothing", () => {
  const broken = pr(3, [])
  ;(broken.attrs as Record<string, unknown>).paths = "{not json"
  const found = detectSensitiveChanges({
    tenantId: "t",
    events: [
      pr(1, ["src/auth/x.ts"], { draft: true }),
      pr(2, ["src/auth/README.md", "CHANGELOG.md"]),
      broken,
    ],
    now: NOW,
    mapFor: generic,
  })
  assert.equal(found.length, 0)
})

test("two pushes to one PR in a batch are one observation, from the latest", () => {
  const early = pr(5, ["src/auth/a.ts"], {}, new Date(NOW.getTime() - 60_000))
  const late = pr(5, ["src/crypto/b.ts"], { sha: "later" })
  const found = detectSensitiveChanges({ tenantId: "t", events: [late, early], now: NOW, mapFor: generic })
  assert.equal(found.length, 1)
  assert.match(found[0]?.title ?? "", /crypto-and-secrets/)
})

test("the intyga-core map reports a partial mirror update, but not from a truncated list", () => {
  const core = () => PATH_MAPS["intyga-core"]
  const partial = pr(9, ["packages/verify-go/verify.go"])
  const found = detectSensitiveChanges({ tenantId: "t", events: [partial], now: NOW, mapFor: core })
  const mirror = found.find((f) => f.dedupeKey.startsWith("mirror:"))
  assert.ok(mirror)
  assert.equal(mirror.severity, "critical")

  const truncated = pr(10, ["packages/verify-go/verify.go"], { pathsTruncated: true })
  const none = detectSensitiveChanges({ tenantId: "t", events: [truncated], now: NOW, mapFor: core })
  assert.equal(none.filter((f) => f.dedupeKey.startsWith("mirror:")).length, 0)
})
