import assert from "node:assert/strict"
import test from "node:test"
import type { NormalizedEvent } from "../../connectors/types.ts"
import { classifyChangedPaths, PATH_MAPS, pathMapFor } from "../sensitivity.ts"
import { detectSensitiveChanges } from "./sensitiveChange.ts"

const NOW = new Date("2026-09-23T12:00:00Z")
const generic = () => PATH_MAPS.generic

test("a source reassignment does not merge an earlier service's code finding into a new one", () => {
  const event = pr(7, ["src/auth/login.ts"])
  const findings = detectSensitiveChanges({
    tenantId: "t",
    mapFor: generic,
    now: NOW,
    events: [
      { ...event, serviceId: "api" },
      { ...event, serviceId: "worker", sourceId: "new-delivery", at: new Date(NOW.getTime() + 1) },
    ],
  })
  assert.equal(findings.length, 2)
  assert.notEqual(findings[0]?.dedupeKey, findings[1]?.dedupeKey)
  assert.deepEqual(new Set(findings.map((f) => f.serviceId)), new Set(["api", "worker"]))
})

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
})

test("the generic map avoids the substrings that match unrelated code", () => {
  const r = classifyChangedPaths(["lib/oracle.ts", "lib/diameter.ts", "lib/tokenizer.ts", "docs/auth.md"])
  assert.equal(r.hits.length, 0, JSON.stringify(r.hits.map((h) => h.paths)))
})

test("an unknown map name falls back to the generic map, never to nothing", () => {
  assert.equal(pathMapFor("something-else").id, "generic")
  assert.equal(pathMapFor(undefined).id, "generic")
})

test("a PR touching auth produces an informational review observation with the hit paths as evidence", () => {
  const found = detectSensitiveChanges({
    tenantId: "t",
    events: [pr(7, ["src/auth/login.ts", "src/ui/page.tsx"])],
    now: NOW,
    mapFor: generic,
  })
  assert.equal(found.length, 1)
  const f = found[0]
  assert.ok(f)
  assert.equal(f.severity, "info")
  assert.equal(f.category, "engineering")
  assert.match(f.title, /^Review observation:/)
  assert.equal(f.dedupeKey, "sensitive:c1:acme/app#7")
  const ev = f.evidence[0]
  assert.equal(ev.kind, "codeChange")
  assert.deepEqual(ev.kind === "codeChange" ? ev.paths : [], ["src/auth/login.ts"])
})

test("merging sensitive code does not establish an anomaly or increase severity", () => {
  for (const merged of [false, true]) {
    const found = detectSensitiveChanges({
      tenantId: "t",
      events: [pr(8, ["src/auth/login.ts"], { merged })],
      now: NOW,
      mapFor: generic,
    })
    assert.equal(found[0]?.severity, "info")
    assert.match(found[0]?.summary ?? "", /does not establish unusual behavior/)
    assert.ok(!found[0]?.evidence.some((e) => e.kind === "assessment"))
  }
})

test("closed unmerged PRs are not labelled open", () => {
  const found = detectSensitiveChanges({
    tenantId: "t",
    events: [pr(8, ["src/auth/login.ts"], { state: "closed" })],
    now: NOW,
    mapFor: generic,
  })
  assert.match(found[0]?.title ?? "", /closed PR/)
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

test("schema and content paths do not imply cross-package incompatibility", () => {
  for (const pathsTruncated of [false, true]) {
    const found = detectSensitiveChanges({
      tenantId: "t",
      events: [pr(9, ["lib/contracts/index.ts", "website/landing.tsx"], { pathsTruncated })],
      now: NOW,
      mapFor: () => pathMapFor("retired-custom-map"),
    })
    assert.deepEqual(found, [])
  }
})
