import assert from "node:assert/strict"
import test, { mock } from "node:test"
import type { ConnectorContext } from "../registry.ts"
import { githubConnector } from "./index.ts"

// The GitHub connector is poll-mode, so the thing worth testing is what it asks for, what it emits,
// and whether it advances its cursor correctly. `fetch` is stubbed — a test that needs the network
// is a test nobody runs.

const NOW = Date.now()
const iso = (msAgo: number) => new Date(NOW - msAgo).toISOString()

function ctx(
  config: Record<string, unknown>,
  cursors = new Map<string, string>(),
): ConnectorContext & { cursors: Map<string, string>; logs: string[] } {
  const logs: string[] = []
  return {
    connectionId: "conn-1",
    tenantId: "t1",
    config,
    secret: "ghp_test",
    getCursor: async (n) => cursors.get(n) ?? null,
    setCursor: async (n, v) => void cursors.set(n, v),
    log: (m) => void logs.push(m),
    cursors,
    logs,
  }
}

function stubGitHub(routes: Record<string, unknown>) {
  mock.method(globalThis, "fetch", async (url: string | URL) => {
    const path = new URL(String(url)).pathname + new URL(String(url)).search
    // LONGEST match, not first: "/repos/a/b/pulls" is a prefix of "/repos/a/b/pulls/1/files", so a
    // first-match stub silently serves the wrong fixture and the assertion fails for a reason that
    // has nothing to do with the code under test.
    const key = Object.keys(routes)
      .filter((k) => path.startsWith(k))
      .sort((a, b) => b.length - a.length)[0]
    if (!key) return new Response("[]", { status: 200, headers: { "content-type": "application/json" } })
    return new Response(JSON.stringify(routes[key]), {
      status: 200,
      headers: { "content-type": "application/json" },
    })
  })
}

test("emits a pull request event carrying the changed-path list", async (t) => {
  t.after(() => mock.restoreAll())
  stubGitHub({
    "/repos/acme/core/pulls": [
      {
        number: 184,
        title: "Harden receipt verification",
        state: "open",
        updated_at: iso(60_000),
        merged_at: null,
        head: { sha: "abc123def456" },
        user: { login: "ada" },
        additions: 40,
        deletions: 12,
      },
    ],
    "/repos/acme/core/pulls/184/files": [
      { filename: "packages/verify/src/index.ts" },
      { filename: "packages/verify/CHANGELOG.md" },
    ],
    "/repos/acme/core/actions/runs": { workflow_runs: [] },
  })

  const c = ctx({ repos: "acme/core" })
  const events = await githubConnector.poll(c)
  const pr = events.find((e) => e.kind.startsWith("github.pull_request"))
  assert.ok(pr, "a pull request event must be emitted")
  assert.equal(pr.source, "github")
  assert.equal(pr.subjectRef, "ada")
  assert.equal(pr.correlationRef, "abc123def456")
  assert.equal(pr.attrs.number, 184)
  // The path list is what the sensitivity map runs over — it must survive normalization intact.
  assert.deepEqual(JSON.parse(String(pr.attrs.paths)), [
    "packages/verify/src/index.ts",
    "packages/verify/CHANGELOG.md",
  ])
  assert.equal(pr.attrs.pathCount, 2)
})

test("sourceId includes the head SHA so a re-pushed PR is a new observation", async (t) => {
  t.after(() => mock.restoreAll())
  const pr = (sha: string) => ({
    number: 7,
    title: "wip",
    state: "open",
    updated_at: iso(1000),
    merged_at: null,
    head: { sha },
    user: { login: "ada" },
  })
  stubGitHub({ "/repos/a/b/pulls": [pr("sha-one")], "/repos/a/b/actions/runs": { workflow_runs: [] } })
  const first = (await githubConnector.poll(ctx({ repos: "a/b" })))[0]

  mock.restoreAll()
  stubGitHub({ "/repos/a/b/pulls": [pr("sha-two")], "/repos/a/b/actions/runs": { workflow_runs: [] } })
  const second = (await githubConnector.poll(ctx({ repos: "a/b" })))[0]

  assert.notEqual(first?.sourceId, second?.sourceId, "deduping on PR number alone would hide pushes")
})

test("a run of a named deploy workflow becomes a deployment event", async (t) => {
  t.after(() => mock.restoreAll())
  stubGitHub({
    "/repos/a/b/pulls": [],
    "/repos/a/b/actions/runs": {
      workflow_runs: [
        {
          id: 99,
          name: "Deploy Gateway (Staging)",
          head_sha: "deadbeef",
          status: "completed",
          conclusion: "success",
          created_at: iso(120_000),
          updated_at: iso(60_000),
          event: "push",
          html_url: "https://github.com/a/b/actions/runs/99",
        },
        {
          id: 100,
          name: "CI Pipeline",
          head_sha: "cafe",
          status: "completed",
          conclusion: "failure",
          created_at: iso(120_000),
          updated_at: iso(60_000),
          event: "pull_request",
          html_url: "https://github.com/a/b/actions/runs/100",
        },
      ],
    },
  })

  const events = await githubConnector.poll(
    ctx({ repos: "a/b", deployWorkflows: "Deploy Gateway (Staging)" }),
  )
  const deploy = events.find((e) => e.kind === "github.deployment")
  const ci = events.find((e) => e.kind === "github.workflow_run")
  assert.ok(deploy, "the named workflow must be recognised as a deployment")
  assert.equal(deploy.attrs.sha, "deadbeef")
  assert.equal(deploy.attrs.isDeploy, true)
  assert.ok(ci, "an unnamed workflow stays an ordinary run")
  assert.equal(ci.attrs.conclusion, "failure")
})

test("an in-progress run is not emitted — only completed outcomes are facts", async (t) => {
  t.after(() => mock.restoreAll())
  stubGitHub({
    "/repos/a/b/pulls": [],
    "/repos/a/b/actions/runs": {
      workflow_runs: [
        {
          id: 1,
          name: "CI",
          head_sha: "x",
          status: "in_progress",
          conclusion: null,
          created_at: iso(60_000),
          updated_at: iso(30_000),
          event: "push",
          html_url: "u",
        },
      ],
    },
  })
  assert.deepEqual(await githubConnector.poll(ctx({ repos: "a/b" })), [])
})

test("cursors advance so the next tick does not re-fetch the same work", async (t) => {
  t.after(() => mock.restoreAll())
  stubGitHub({
    "/repos/a/b/pulls": [
      {
        number: 1,
        title: "t",
        state: "open",
        updated_at: iso(60_000),
        merged_at: null,
        head: { sha: "s" },
        user: { login: "ada" },
      },
    ],
    "/repos/a/b/actions/runs": { workflow_runs: [] },
  })
  const cursors = new Map<string, string>()
  const first = await githubConnector.poll(ctx({ repos: "a/b" }, cursors))
  assert.equal(first.length, 1)
  assert.ok(cursors.get("pr:a/b"), "the pull-request cursor must be set")

  // Same data, second tick: the cursor must suppress it.
  const second = await githubConnector.poll(ctx({ repos: "a/b" }, cursors))
  assert.deepEqual(second, [], "an unchanged PR must not be re-emitted")
})

test("malformed repository names are ignored rather than sent to the API", async (t) => {
  t.after(() => mock.restoreAll())
  const calls: string[] = []
  mock.method(globalThis, "fetch", async (url: string | URL) => {
    calls.push(String(url))
    return new Response("[]", { status: 200, headers: { "content-type": "application/json" } })
  })
  await githubConnector.poll(ctx({ repos: "not-a-repo, ../../etc/passwd, acme/core" }))
  assert.ok(
    calls.every((u) => u.includes("acme/core")),
    `only the well-formed repo may be requested, got: ${calls.join(", ")}`,
  )
})

test("a rate-limited response degrades to nothing rather than throwing the tick away", async (t) => {
  t.after(() => mock.restoreAll())
  mock.method(globalThis, "fetch", async () => new Response("{}", { status: 429 }))
  const c = ctx({ repos: "a/b" })
  assert.deepEqual(await githubConnector.poll(c), [])
  assert.ok(c.logs.some((l) => l.includes("rate limited")))
})

test("the connector declares a read-only token requirement in its own setup text", () => {
  // The token scope is a security property, and the place a person actually reads it is the form.
  const tokenField = githubConnector.fields.find((f) => f.secret)
  assert.ok(tokenField)
  assert.match(tokenField.help ?? "", /read-only/i)
  assert.ok(githubConnector.setup.some((s) => /read-only/i.test(s)))
})
