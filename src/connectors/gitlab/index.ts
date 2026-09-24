import type { ConnectorContext, PollConnector } from "../registry.ts"
import { dateOr } from "../shared.ts"
import type { NormalizedEvent } from "../types.ts"

// GitLab (poll; gitlab.com or self-managed).
//
// The GitHub connector's counterpart, and deliberately the same SHAPE: merge requests are emitted
// with the attrs the code-change detector reads (repo, number, sha, mergeSha, draft, merged, paths,
// pathsTruncated), and deployments with the shared deploy convention (production, succeeded, sha,
// name). No detector has a GitLab branch in it.
//
// Token: a READ-ONLY token with the `read_api` scope — a project or group access token is better
// than a personal one. Nothing here writes.
//
// API notes, from GitLab's own docs and source:
//   · changed paths come from `/merge_requests/:iid/diffs` (paginated); `/changes` is deprecated
//   · pagination follows `x-next-page`, never `x-total`, which GitLab omits past 10,000 rows
//   · deployments filtered by `updated_after` MUST be sorted by `updated_at`, or GitLab refuses
//   · `updated_after` is inclusive, so the cursor comparison here is strict

const MAX_PROJECTS = 20
const MAX_MRS_PER_PROJECT = 30
const MAX_DEPLOYS_PER_PROJECT = 50
/** Each MR's diff list is extra requests, so it is capped separately and per tick. */
const MAX_DIFF_FETCHES = 25
/** 100 files per page; 5 pages covers 500-file MRs, past which the list is marked truncated. */
const MAX_DIFF_PAGES = 5
const TIMEOUT_MS = 15_000

interface GlMr {
  iid: number
  title: string
  state: string
  updated_at: string
  merged_at: string | null
  draft?: boolean
  sha: string
  merge_commit_sha?: string | null
  squash_commit_sha?: string | null
  author?: { username?: string } | null
}

interface GlDeployment {
  id: number
  status: string
  sha: string
  ref?: string
  updated_at: string
  finished_at?: string | null
  environment?: { name?: string }
}

function baseUrl(ctx: ConnectorContext): string | null {
  const raw = String(ctx.config.baseUrl ?? "").trim() || "https://gitlab.com"
  try {
    const u = new URL(raw)
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)
    // The token is sent here, so it must travel over TLS unless it never leaves the machine.
    if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) return null
    return u.origin
  } catch {
    return null
  }
}

function projects(ctx: ConnectorContext): string[] {
  return String(ctx.config.projects ?? "")
    .split(/[\s,]+/)
    .map((p) => p.trim().replace(/^\/+|\/+$/g, ""))
    .filter((p) => /^[\w.-]+(\/[\w.-]+)+$/.test(p))
    .slice(0, MAX_PROJECTS)
}

function environments(ctx: ConnectorContext): Set<string> {
  const list = String(ctx.config.deployEnvironments ?? "")
    .split(/[\s,]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
  return new Set(list.length > 0 ? list : ["production"])
}

async function gl<T>(
  ctx: ConnectorContext,
  base: string,
  path: string,
): Promise<{ data: T; nextPage: string | null } | null> {
  try {
    const res = await fetch(`${base}/api/v4${path}`, {
      headers: ctx.secret ? { "private-token": ctx.secret } : {},
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
    if (!res.ok) {
      // 429 and 403 included: skipping a resource for one tick beats discarding the whole tick.
      ctx.log("gitlab request failed", { path, status: res.status })
      return null
    }
    const next = res.headers.get("x-next-page")
    return { data: (await res.json()) as T, nextPage: next && next.trim() !== "" ? next : null }
  } catch (err) {
    ctx.log("gitlab request errored", { path, err: (err as Error).message })
    return null
  }
}

export function normalizeMr(
  connectionId: string,
  project: string,
  mr: GlMr,
  paths: string[],
  pathsTruncated: boolean,
): NormalizedEvent {
  const merged = Boolean(mr.merged_at)
  return {
    connectionId,
    source: "gitlab",
    // Includes the head SHA: a push to an MR is a new observation, as on GitHub.
    sourceId: `mr:${project}!${mr.iid}@${mr.sha}`,
    kind: merged ? "gitlab.merge_request.merged" : "gitlab.merge_request.updated",
    at: new Date(mr.updated_at),
    subjectRef: mr.author?.username ?? null,
    correlationRef: mr.sha,
    attrs: {
      repo: project,
      number: mr.iid,
      title: mr.title,
      sha: mr.sha,
      // A merge or squash commit is what a deploy of this MR actually runs.
      mergeSha: merged ? mr.squash_commit_sha || mr.merge_commit_sha || "" : "",
      state: mr.state,
      draft: mr.draft ?? false,
      merged,
      paths: JSON.stringify(paths),
      pathCount: paths.length,
      pathsTruncated,
    },
  }
}

export function normalizeDeployment(
  connectionId: string,
  project: string,
  d: GlDeployment,
  productionEnvs: Set<string>,
): NormalizedEvent | null {
  if (d.status !== "success" && d.status !== "failed") return null
  const env = d.environment?.name ?? ""
  return {
    connectionId,
    source: "gitlab",
    sourceId: `deploy:${project}#${d.id}:${d.status}`,
    kind: "gitlab.deployment",
    at: dateOr(d.finished_at ?? d.updated_at, new Date(d.updated_at)),
    subjectRef: project,
    correlationRef: d.sha,
    attrs: {
      production: productionEnvs.has(env.toLowerCase()),
      succeeded: d.status === "success",
      sha: d.sha,
      name: `${project} → ${env}`,
      environment: env,
      ref: d.ref ?? "",
      deployment: d.id,
    },
  }
}

export const gitlabConnector: PollConnector = {
  kind: "gitlab",
  mode: "poll",
  label: "GitLab",
  blurb: "Merge requests with changed paths, and deployments — gitlab.com or self-managed.",

  fields: [
    {
      name: "baseUrl",
      label: "GitLab URL",
      placeholder: "https://gitlab.com",
      help: "Leave blank for gitlab.com. For self-managed, the instance's https origin.",
    },
    {
      name: "projects",
      label: "Projects",
      placeholder: "acme/core, acme/platform/api",
      help: "Full project paths, comma separated. Up to 20.",
      required: true,
    },
    {
      name: "deployEnvironments",
      label: "Production environments",
      placeholder: "production",
      help: "Deployments to these environments anchor deploy-regression. Defaults to `production`.",
    },
    {
      name: "pathMap",
      label: "Sensitive-path map",
      placeholder: "generic",
      help: "Which paths count as security-sensitive: `generic` (default, any repository) or `intyga-core`.",
    },
    {
      name: "token",
      label: "Access token",
      placeholder: "glpat-…",
      help: "READ-ONLY: the `read_api` scope only. A project or group access token is better than a personal one.",
      required: true,
      secret: true,
    },
  ],

  setup: [
    "Create a project or group access token with the Reporter role and ONLY the read_api scope.",
    "Paste it as the token. It is encrypted at rest and never returned by the API.",
    "List the production environment names your deployments use, if not `production`.",
    "Merge requests and deployments appear within a tick or two.",
  ],

  async poll(ctx: ConnectorContext): Promise<NormalizedEvent[]> {
    const base = baseUrl(ctx)
    if (!base || !ctx.secret) return []
    const envs = environments(ctx)
    const out: NormalizedEvent[] = []
    let diffFetches = 0

    for (const project of projects(ctx)) {
      const id = encodeURIComponent(project)

      // ─── merge requests ──────────────────────────────────────────────────────────────────────
      const mrCursor = await ctx.getCursor(`mr:${project}`)
      const since = mrCursor ?? new Date(Date.now() - 7 * 86_400_000).toISOString()
      const mrs = await gl<GlMr[]>(
        ctx,
        base,
        `/projects/${id}/merge_requests?state=all&order_by=updated_at&sort=desc` +
          `&per_page=${MAX_MRS_PER_PROJECT}&updated_after=${encodeURIComponent(since)}`,
      )
      let newestMr = mrCursor
      for (const mr of mrs?.data ?? []) {
        if (new Date(mr.updated_at) <= new Date(since)) continue
        if (!newestMr || new Date(mr.updated_at) > new Date(newestMr)) newestMr = mr.updated_at

        // As on GitHub: a TRUNCATED path list must say so, because the mirror rule reasons from
        // absence and would otherwise invent a partial update on exactly the largest changes.
        const paths: string[] = []
        let truncated = false
        if (diffFetches < MAX_DIFF_FETCHES) {
          let page: string | null = "1"
          for (let n = 0; page && n < MAX_DIFF_PAGES; n++) {
            diffFetches++
            const diffs: { data: { new_path: string; old_path: string }[]; nextPage: string | null } | null =
              await gl<{ new_path: string; old_path: string }[]>(
                ctx,
                base,
                `/projects/${id}/merge_requests/${mr.iid}/diffs?per_page=100&page=${page}`,
              )
            if (!diffs) {
              truncated = true
              break
            }
            for (const f of diffs.data) {
              paths.push(f.new_path)
              // A rename out of a sensitive directory is a change to it, too.
              if (f.old_path !== f.new_path) paths.push(f.old_path)
            }
            page = diffs.nextPage
          }
          if (page) truncated = true
        } else {
          truncated = true
        }
        out.push(normalizeMr(ctx.connectionId, project, mr, paths, truncated))
      }
      if (newestMr && newestMr !== mrCursor) await ctx.setCursor(`mr:${project}`, newestMr)

      // ─── deployments ─────────────────────────────────────────────────────────────────────────
      const depCursor = await ctx.getCursor(`deploy:${project}`)
      const depSince = depCursor ?? new Date(Date.now() - 86_400_000).toISOString()
      const deps = await gl<GlDeployment[]>(
        ctx,
        base,
        `/projects/${id}/deployments?order_by=updated_at&sort=desc` +
          `&per_page=${MAX_DEPLOYS_PER_PROJECT}&updated_after=${encodeURIComponent(depSince)}`,
      )
      let newestDep = depCursor
      for (const d of deps?.data ?? []) {
        if (new Date(d.updated_at) <= new Date(depSince)) continue
        // A running deployment is updated again when it finishes, so moving past it is safe.
        if (!newestDep || new Date(d.updated_at) > new Date(newestDep)) newestDep = d.updated_at
        const e = normalizeDeployment(ctx.connectionId, project, d, envs)
        if (e) out.push(e)
      }
      if (newestDep && newestDep !== depCursor) await ctx.setCursor(`deploy:${project}`, newestDep)
    }
    return out
  },
}
