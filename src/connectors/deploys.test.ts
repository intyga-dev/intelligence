import assert from "node:assert/strict"
import crypto from "node:crypto"
import { afterEach, test } from "node:test"
import { asDeploy } from "../domain/detectors/deployRegression.ts"
import { cloudflareConnector, normalizeCloudflare } from "./cloudflare/index.ts"
import { gitlabConnector, normalizeDeployment } from "./gitlab/index.ts"
import { netlifyConnector, verifyNetlifySignature } from "./netlify/index.ts"
import type { ConnectorContext } from "./registry.ts"

// Netlify, Cloudflare Pages and GitLab: deploy anchors (and, for GitLab, merge requests).

const now = new Date("2026-09-23T12:00:00Z")
const realFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = realFetch
})

// ─── Netlify ─────────────────────────────────────────────────────────────────────────────────────

const NL_SECRET = "netlify_jws_secret"
const DEPLOY = {
  id: "d1",
  site_id: "s1",
  name: "marketing",
  state: "ready",
  context: "production",
  commit_ref: "abc1234",
  branch: "main",
  published_at: "2026-09-23T11:59:00Z",
}
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url")
function jws(body: string, opts: { alg?: string; iss?: string; secret?: string; sha?: string } = {}) {
  const h = b64({ alg: opts.alg ?? "HS256", typ: "JWT" })
  const p = b64({
    iss: opts.iss ?? "netlify",
    sha256: opts.sha ?? crypto.createHash("sha256").update(body).digest("hex"),
  })
  const s = crypto
    .createHmac("sha256", opts.secret ?? NL_SECRET)
    .update(`${h}.${p}`)
    .digest("base64url")
  return `${h}.${p}.${s}`
}

test("Netlify: a correctly signed JWS over this exact body verifies", () => {
  const body = JSON.stringify(DEPLOY)
  assert.deepEqual(verifyNetlifySignature(jws(body), body, NL_SECRET), { ok: true })
})

test("Netlify: wrong secret, wrong issuer, another body's digest, alg none and junk are refused", () => {
  const body = JSON.stringify(DEPLOY)
  const unsignedNone = `${b64({ alg: "none" })}.${b64({ iss: "netlify", sha256: "x" })}.`
  for (const [token, why] of [
    [jws(body, { secret: "other" }), "mismatch"],
    [jws(body, { iss: "evil" }), "wrong-issuer"],
    [jws(body, { sha: "0".repeat(64) }), "body-mismatch"],
    [jws(body, { alg: "HS512" }), "unexpected-alg"],
    [unsignedNone, "unexpected-alg"],
    ["not.a-jwt", "malformed-header"],
  ] as const) {
    const r = verifyNetlifySignature(token, body, NL_SECRET)
    assert.equal(r.ok, false, why)
    assert.equal(r.ok === false ? r.reason : "", why)
  }
})

test("Netlify: only finished deploys are events; production and success follow the shared convention", () => {
  const e = netlifyConnector.normalize({ connectionId: "c", body: DEPLOY, receivedAt: now })
  assert.ok(e)
  assert.equal(asDeploy(e)?.sha, "abc1234")
  const preview = netlifyConnector.normalize({
    connectionId: "c",
    body: { ...DEPLOY, context: "deploy-preview" },
    receivedAt: now,
  })
  assert.ok(preview)
  assert.equal(asDeploy(preview), null)
  const failed = netlifyConnector.normalize({
    connectionId: "c",
    body: { ...DEPLOY, state: "error" },
    receivedAt: now,
  })
  assert.ok(failed)
  assert.equal(asDeploy(failed), null)
  assert.equal(
    netlifyConnector.normalize({
      connectionId: "c",
      body: { ...DEPLOY, state: "building" },
      receivedAt: now,
    }),
    null,
  )
})

// ─── Cloudflare Pages ────────────────────────────────────────────────────────────────────────────

function ctx(
  config: Record<string, unknown>,
  secret = "tok",
): ConnectorContext & { cursors: Map<string, string> } {
  const cursors = new Map<string, string>()
  return {
    connectionId: "c",
    tenantId: "t",
    config,
    secret,
    cursors,
    getCursor: async (n) => cursors.get(n) ?? null,
    setCursor: async (n, v) => {
      cursors.set(n, v)
    },
    log: () => {},
  }
}

const cf = (id: string, modified: string, stage: { name: string; status: string }, env = "production") => ({
  id,
  environment: env,
  created_on: modified,
  modified_on: modified,
  latest_stage: stage,
  deployment_trigger: { type: "github:push", metadata: { branch: "main", commit_hash: `sha-${id}` } },
})

test("Cloudflare: finished production deploys anchor; in-flight ones are not events yet", () => {
  const ok = normalizeCloudflare(
    "c",
    { ...cf("a", "2026-09-23T11:00:00Z", { name: "deploy", status: "success" }), project_name: "site" },
    now,
  )
  assert.ok(ok)
  assert.equal(asDeploy(ok)?.sha, "sha-a")
  assert.equal(
    normalizeCloudflare("c", cf("b", "2026-09-23T11:00:00Z", { name: "build", status: "active" }), now),
    null,
  )
  const failed = normalizeCloudflare(
    "c",
    cf("f", "2026-09-23T11:00:00Z", { name: "build", status: "failure" }),
    now,
  )
  assert.equal(failed?.attrs.succeeded, false)
})

test("Cloudflare: polling filters by its own cursor, not by list order, and never re-emits", async () => {
  const pages = [
    [
      cf("new", "2026-09-23T11:50:00Z", { name: "deploy", status: "success" }),
      cf("old", "2026-09-22T09:00:00Z", { name: "deploy", status: "success" }),
      cf("running", "2026-09-23T11:55:00Z", { name: "build", status: "active" }),
    ],
  ]
  let urls: string[] = []
  globalThis.fetch = (async (url: string) => {
    urls.push(String(url))
    return new Response(JSON.stringify({ success: true, result: pages[0] }), { status: 200 })
  }) as typeof fetch
  const c = ctx({ accountId: "0123456789abcdef0123456789abcdef", projects: "site" })
  c.cursors.set("deployments:site", "2026-09-23T00:00:00Z")
  const first = await cloudflareConnector.poll(c)
  assert.deepEqual(
    first.map((e) => e.attrs.deployment),
    ["new"],
  )
  assert.match(
    urls[0] ?? "",
    /\/accounts\/0123456789abcdef0123456789abcdef\/pages\/projects\/site\/deployments/,
  )
  urls = []
  const second = await cloudflareConnector.poll(c)
  assert.equal(second.length, 0, "the cursor moved past what was emitted")
})

// ─── GitLab ──────────────────────────────────────────────────────────────────────────────────────

test("GitLab: a merged MR carries its squash/merge commit so a deploy of it can be matched", async () => {
  const mr = {
    iid: 12,
    title: "Tighten permission checks",
    state: "merged",
    updated_at: "2026-09-23T11:00:00Z",
    merged_at: "2026-09-23T11:00:00Z",
    draft: false,
    sha: "head1",
    merge_commit_sha: null,
    squash_commit_sha: "squash1",
    author: { username: "dev" },
  }
  const seen: string[] = []
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    const u = String(url)
    seen.push(u)
    assert.equal(new Headers(init?.headers).get("private-token"), "glpat")
    if (u.includes("/merge_requests?")) return Response.json([mr])
    if (u.includes("/diffs") && u.endsWith("&page=1")) {
      return new Response(
        JSON.stringify([{ new_path: "src/permissions/check.ts", old_path: "src/permissions/check.ts" }]),
        {
          headers: { "x-next-page": "2" },
        },
      )
    }
    if (u.includes("/diffs") && u.endsWith("&page=2")) {
      return new Response(JSON.stringify([{ new_path: "src/auth/new.ts", old_path: "src/auth/old.ts" }]), {
        headers: { "x-next-page": "" },
      })
    }
    if (u.includes("/deployments?")) return Response.json([])
    return new Response("not found", { status: 404 })
  }) as typeof fetch

  const c = ctx({ projects: "acme/platform/api" }, "glpat")
  const events = await gitlabConnector.poll(c)
  assert.ok(seen[0]?.startsWith("https://gitlab.com/api/v4/projects/acme%2Fplatform%2Fapi/merge_requests?"))
  assert.equal(events.length, 1)
  const e = events[0]
  assert.ok(e)
  assert.equal(e.kind, "gitlab.merge_request.merged")
  assert.equal(e.attrs.mergeSha, "squash1")
  assert.equal(e.attrs.pathsTruncated, false)
  assert.deepEqual(JSON.parse(String(e.attrs.paths)), [
    "src/permissions/check.ts",
    "src/auth/new.ts",
    "src/auth/old.ts",
  ])
})

test("GitLab: a diff page that fails marks the list truncated, so absence is never trusted", async () => {
  globalThis.fetch = (async (url: string) => {
    const u = String(url)
    if (u.includes("/merge_requests?")) {
      return Response.json([
        {
          iid: 1,
          title: "t",
          state: "opened",
          updated_at: "2026-09-23T11:00:00Z",
          merged_at: null,
          sha: "h",
        },
      ])
    }
    if (u.includes("/diffs")) return new Response("rate limited", { status: 429 })
    return Response.json([])
  }) as typeof fetch
  const [e] = await gitlabConnector.poll(ctx({ projects: "acme/app" }, "glpat"))
  assert.equal(e?.attrs.pathsTruncated, true)
})

test("GitLab: refuses to send the token to a plain-http host", async () => {
  let called = false
  globalThis.fetch = (async () => {
    called = true
    return Response.json([])
  }) as typeof fetch
  assert.deepEqual(
    await gitlabConnector.poll(ctx({ projects: "a/b", baseUrl: "http://gitlab.example.com" }, "glpat")),
    [],
  )
  assert.equal(called, false)
})

test("GitLab: deployments to configured environments anchor; others and unfinished ones do not", () => {
  const envs = new Set(["production", "prod-eu"])
  const d = (status: string, env: string) => ({
    id: 5,
    status,
    sha: "s",
    updated_at: "2026-09-23T11:00:00Z",
    environment: { name: env },
  })
  const prod = normalizeDeployment("c", "a/b", d("success", "prod-eu"), envs)
  assert.ok(prod)
  assert.ok(asDeploy(prod))
  const staging = normalizeDeployment("c", "a/b", d("success", "staging"), envs)
  assert.ok(staging)
  assert.equal(asDeploy(staging), null)
  assert.equal(normalizeDeployment("c", "a/b", d("running", "production"), envs), null)
})
