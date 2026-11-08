import assert from "node:assert/strict"
import test from "node:test"
import type { ConnectorContext } from "../registry.ts"
import { pollRuleSuites } from "./ruleSuites.ts"

function fixture() {
  const cursors = new Map<string, string>(),
    logs: string[] = [],
    paths: string[] = []
  const ctx: ConnectorContext = {
    connectionId: "source",
    tenantId: "tenant",
    config: {},
    secret: null,
    getCursor: async (k) => cursors.get(k) ?? null,
    setCursor: async (k, v) => {
      cursors.set(k, v)
    },
    log: (m) => {
      logs.push(m)
    },
  }
  const suite = {
    id: 1,
    ref: "refs/heads/main",
    pushed_at: "2026-11-07T11:00:00Z",
    after_sha: "sha",
    result: "bypass",
  }
  const get =
    (routes: Record<string, unknown>) =>
    async <T>(path: string): Promise<T | null> => {
      paths.push(path)
      return (routes[path] ?? null) as T | null
    }
  const list =
    "/repos/a/b/rulesets/rule-suites?ref=refs%2Fheads%2Fmain&time_period=day&evaluate_status=active&per_page=100&page=1"
  return { ctx, cursors, logs, paths, suite, get, list }
}
test("rule suites distinguish active failed controls from evaluate-only rules and rejected pushes", async () => {
  const f = fixture()
  const events = await pollRuleSuites(
    f.ctx,
    [{ repo: "a/b", branch: "main" }],
    f.get({
      [f.list]: [f.suite, { ...f.suite, id: 2, result: "fail" }, { ...f.suite, id: 3 }],
      "/repos/a/b/rulesets/rule-suites/1": {
        ...f.suite,
        rule_evaluations: [{ enforcement: "active", result: "fail", rule_type: "pull_request" }],
      },
      "/repos/a/b/rulesets/rule-suites/3": {
        ...f.suite,
        id: 3,
        rule_evaluations: [
          { enforcement: "evaluate", result: "fail", rule_type: "required_status_checks" },
          { enforcement: "active", result: "pass", rule_type: "pull_request" },
        ],
      },
    }),
  )
  assert.equal(events.length, 2)
  assert.equal(events[0]!.attrs.activeMergeRuleFailed, true)
  assert.equal(events[1]!.attrs.activeMergeRuleFailed, false)
  assert.equal(f.cursors.get("rule-suite:a/b:main"), f.suite.pushed_at)
  assert.ok(!f.paths.some((p) => p.endsWith("/2")))
})
test("rule suite detail failure retains cursor for retry; targets are opt-in", async () => {
  const f = fixture()
  await pollRuleSuites(f.ctx, [], f.get({}))
  assert.equal(f.paths.length, 0)
  await pollRuleSuites(f.ctx, [{ repo: "a/b", branch: "main" }], f.get({ [f.list]: [f.suite] }))
  assert.equal(f.cursors.size, 0)
})
test("rule suite pagination reads beyond full pages without dropping equal-timestamp evaluations", async () => {
  const f = fixture()
  f.cursors.set("rule-suite:a/b:main", f.suite.pushed_at)
  const routes = {
    [f.list]: Array.from({ length: 100 }, (_, id) => ({ ...f.suite, id, result: "pass" })),
    [f.list.replace("&page=1", "&page=2")]: [f.suite],
    "/repos/a/b/rulesets/rule-suites/1": {
      ...f.suite,
      rule_evaluations: [{ enforcement: "active", result: "fail", rule_type: "workflows" }],
    },
  }
  const events = await pollRuleSuites(f.ctx, [{ repo: "a/b", branch: "main" }], f.get(routes))
  assert.equal(events.length, 1)
  assert.equal(f.logs.length, 0)
  assert.ok(f.paths.includes(f.list.replace("&page=1", "&page=2")))
})
