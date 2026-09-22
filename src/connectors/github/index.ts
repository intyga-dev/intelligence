import { config } from "../../config.ts"
import type { ConnectorContext, PollConnector } from "../registry.ts"
import type { NormalizedEvent } from "../types.ts"

// The GitHub connector.
//
// Poll, not webhook, and that is a deliberate trade. A webhook would be lower latency, but it needs
// a public ingress, an App registration and a rotating secret per repository. Polling needs one
// read-only token and nothing else, and at the volume an engineering org actually produces — tens
// of pull requests and workflow runs a day — a one-minute tick is indistinguishable from real time.
// Revisit if someone is waiting on the latency; do not revisit for tidiness.
//
// The token must be FINE-GRAINED and READ-ONLY: contents:read, pull_requests:read, actions:read.
// Nothing here writes, and a token that could write would be a standing risk for no benefit.
//
// Two event families:
//   · github.pull_request  — with the changed-path list the sensitivity map runs over
//   · github.workflow_run  — CI outcomes, and the deploy records regression correlation needs

const API_VERSION = "2022-11-28"

/** Bounded per tick: a connector that can fan out without limit is an outage waiting for a busy day. */
const MAX_REPOS = 20
const MAX_PRS_PER_REPO = 30
const MAX_RUNS_PER_REPO = 50
/** Each PR's file list is an extra request, so it is capped separately and independently. */
const MAX_FILE_FETCHES = 25
/** 100 files per page; 5 pages covers 500-file PRs, past which we mark the list truncated. */
const MAX_FILE_PAGES = 5

interface GhPull {
  number: number
  title: string
  state: string
  updated_at: string
  merged_at: string | null
  draft?: boolean
  head: { sha: string }
  user: { login: string } | null
  additions?: number
  deletions?: number
}

interface GhRun {
  id: number
  name: string | null
  head_sha: string
  status: string
  conclusion: string | null
  created_at: string
  updated_at: string
  event: string
  html_url: string
}

function repos(ctx: ConnectorContext): string[] {
  const raw = String(ctx.config.repos ?? "")
  return raw
    .split(/[\s,]+/)
    .map((r) => r.trim())
    .filter((r) => /^[\w.-]+\/[\w.-]+$/.test(r))
    .slice(0, MAX_REPOS)
}

function deployWorkflows(ctx: ConnectorContext): string[] {
  return String(ctx.config.deployWorkflows ?? "")
    .split(/[\n,]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
}

async function gh<T>(ctx: ConnectorContext, path: string): Promise<T | null> {
  const ac = new AbortController()
  const timer = setTimeout(() => ac.abort(), 15_000)
  try {
    const res = await fetch(`${config.github.apiBase}${path}`, {
      headers: {
        accept: "application/vnd.github+json",
        "x-github-api-version": API_VERSION,
        ...(ctx.secret ? { authorization: `Bearer ${ctx.secret}` } : {}),
      },
      signal: ac.signal,
    })
    if (res.status === 403 || res.status === 429) {
      // Rate limited. Returning null skips this resource for the tick rather than throwing away
      // everything else the tick collected.
      ctx.log("github rate limited", { path, status: res.status })
      return null
    }
    if (!res.ok) {
      ctx.log("github request failed", { path, status: res.status })
      return null
    }
    return (await res.json()) as T
  } catch (err) {
    ctx.log("github request errored", { path, err: (err as Error).message })
    return null
  } finally {
    clearTimeout(timer)
  }
}

export const githubConnector: PollConnector = {
  kind: "github",
  mode: "poll",
  label: "GitHub",
  blurb: "Pull requests with changed paths, CI outcomes, and deployments for regression correlation.",

  fields: [
    {
      name: "repos",
      label: "Repositories",
      placeholder: "acme/core, acme/deploy",
      help: "owner/name, comma separated. Up to 20.",
      required: true,
    },
    {
      name: "deployWorkflows",
      label: "Deploy workflow names",
      placeholder: "Deploy Gateway (Staging), Deploy Gateway (Production)",
      help: "Runs of these workflows are treated as deployments, which is what regression correlation anchors on.",
    },
    {
      name: "token",
      label: "GitHub token",
      placeholder: "github_pat_…",
      help: "Fine-grained, READ-ONLY: contents:read, pull_requests:read, actions:read. Nothing here writes.",
      required: true,
      secret: true,
    },
  ],

  setup: [
    "Create a fine-grained personal access token scoped to the repositories above.",
    "Grant read-only: Contents, Pull requests, Actions. Grant nothing else.",
    "Paste it as the token. It is encrypted at rest and never returned by the API.",
    "Events appear within a minute or two of the next tick.",
  ],

  async poll(ctx: ConnectorContext): Promise<NormalizedEvent[]> {
    const out: NormalizedEvent[] = []
    const deploys = deployWorkflows(ctx)
    let fileFetches = 0

    for (const repo of repos(ctx)) {
      // ─── pull requests ───────────────────────────────────────────────────────────────────────
      const prCursor = await ctx.getCursor(`pr:${repo}`)
      const since = prCursor ? new Date(prCursor) : new Date(Date.now() - 7 * 86_400_000)
      const pulls = await gh<GhPull[]>(
        ctx,
        `/repos/${repo}/pulls?state=all&sort=updated&direction=desc&per_page=${MAX_PRS_PER_REPO}`,
      )
      let newestPr = prCursor

      for (const pr of pulls ?? []) {
        const updated = new Date(pr.updated_at)
        // Sorted newest-first, so the first one at or below the cursor means the rest are too.
        if (updated <= since) break
        if (!newestPr || updated > new Date(newestPr)) newestPr = pr.updated_at

        // GitHub caps a page at 100 files, and a TRUNCATED list is dangerous rather than merely
        // incomplete: the six-port mirror rule concludes "this PR updated some ports but not
        // others" from absence, so a cut-off list manufactures a critical-severity false positive
        // on exactly the large refactors most likely to hit the cap. Paginate, and if the PR is
        // bigger than we are willing to fetch, say so explicitly so the detector can decline to
        // reason from absence.
        const paths: string[] = []
        let pathsTruncated = false
        if (fileFetches < MAX_FILE_FETCHES) {
          for (let pageNo = 1; pageNo <= MAX_FILE_PAGES; pageNo++) {
            fileFetches++
            const files = await gh<{ filename: string }[]>(
              ctx,
              `/repos/${repo}/pulls/${pr.number}/files?per_page=100&page=${pageNo}`,
            )
            if (!files) {
              // A failed or rate-limited page means we cannot claim the list is complete.
              pathsTruncated = true
              break
            }
            paths.push(...files.map((f) => f.filename))
            if (files.length < 100) break
            if (pageNo === MAX_FILE_PAGES) pathsTruncated = true
          }
        } else {
          pathsTruncated = true
        }

        out.push({
          connectionId: ctx.connectionId,
          source: "github",
          // Includes the head SHA: a PR that is updated is a genuinely new observation, and
          // deduping on the PR number alone would hide every push after the first.
          sourceId: `pr:${repo}#${pr.number}@${pr.head.sha}`,
          kind: pr.merged_at ? "github.pull_request.merged" : "github.pull_request.updated",
          at: updated,
          subjectRef: pr.user?.login ?? null,
          correlationRef: pr.head.sha,
          attrs: {
            repo,
            number: pr.number,
            title: pr.title,
            sha: pr.head.sha,
            state: pr.state,
            draft: pr.draft ?? false,
            merged: Boolean(pr.merged_at),
            additions: pr.additions ?? 0,
            deletions: pr.deletions ?? 0,
            // Stored as JSON text: `attrs` is a flat bag by design, and the alternative is a
            // second table for something only one detector reads.
            paths: JSON.stringify(paths),
            pathCount: paths.length,
            /** True when the list may be incomplete — detectors must not infer absence from it. */
            pathsTruncated,
          },
        })
      }
      if (newestPr) await ctx.setCursor(`pr:${repo}`, newestPr)

      // ─── workflow runs ───────────────────────────────────────────────────────────────────────
      const runCursor = await ctx.getCursor(`run:${repo}`)
      const runsSince = runCursor ? new Date(runCursor) : new Date(Date.now() - 7 * 86_400_000)
      const runs = await gh<{ workflow_runs: GhRun[] }>(
        ctx,
        `/repos/${repo}/actions/runs?per_page=${MAX_RUNS_PER_REPO}`,
      )
      let newestRun = runCursor

      for (const run of runs?.workflow_runs ?? []) {
        const at = new Date(run.updated_at)
        if (at <= runsSince) continue
        if (!newestRun || at > new Date(newestRun)) newestRun = run.updated_at
        if (run.status !== "completed") continue

        const name = (run.name ?? "").toLowerCase()
        const isDeploy = deploys.some((d) => name.includes(d))

        out.push({
          connectionId: ctx.connectionId,
          source: "github",
          sourceId: `run:${repo}#${run.id}`,
          kind: isDeploy ? "github.deployment" : "github.workflow_run",
          at,
          subjectRef: run.name,
          correlationRef: run.head_sha,
          attrs: {
            repo,
            workflow: run.name,
            sha: run.head_sha,
            conclusion: run.conclusion ?? "unknown",
            event: run.event,
            url: run.html_url,
            isDeploy,
          },
        })
      }
      if (newestRun) await ctx.setCursor(`run:${repo}`, newestRun)
    }

    return out
  },
}
