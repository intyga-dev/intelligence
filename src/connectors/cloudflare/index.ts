import type { ConnectorContext, PollConnector } from "../registry.ts"
import { dateOr } from "../shared.ts"
import type { NormalizedEvent } from "../types.ts"

// Cloudflare Pages deployments (poll).
//
// Poll rather than webhook: the deployments API is documented field by field, needs one read-only
// token, and a deploy is minutes long, so a tick-sized delay costs nothing. A finished production
// deploy anchors deploy-regression exactly like Vercel's or Netlify's.
//
// Cloudflare does not document the ORDER of the deployments list, so nothing here assumes one: each
// tick reads one bounded page, keeps only finished deployments modified after the project's cursor,
// and moves the cursor to the newest it saw. More than a page of deploys between two ticks would
// be missed; at one tick a minute and one page of 25 that means 25 production deploys per minute.

const API = "https://api.cloudflare.com/client/v4"
const MAX_PROJECTS = 20
const PAGE_SIZE = 25
const TIMEOUT_MS = 15_000

interface CfDeployment {
  id?: string
  short_id?: string
  project_name?: string
  environment?: string
  created_on?: string
  modified_on?: string
  url?: string
  latest_stage?: { name?: string; status?: string }
  deployment_trigger?: { type?: string; metadata?: { branch?: string; commit_hash?: string } }
}

function projects(ctx: ConnectorContext): string[] {
  return String(ctx.config.projects ?? "")
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter((p) => /^[a-z0-9-]{1,58}$/.test(p))
    .slice(0, MAX_PROJECTS)
}

/** A deployment whose last stage finished — succeeded or failed. Anything in flight is not a fact yet. */
export function finished(d: CfDeployment): { succeeded: boolean } | null {
  const s = d.latest_stage
  if (s?.name === "deploy" && s.status === "success") return { succeeded: true }
  if (s?.status === "failure") return { succeeded: false }
  return null
}

export function normalizeCloudflare(
  connectionId: string,
  d: CfDeployment,
  now: Date,
): NormalizedEvent | null {
  const f = finished(d)
  if (!d.id || !f) return null
  const sha = d.deployment_trigger?.metadata?.commit_hash ?? ""
  const project = d.project_name ?? ""
  return {
    connectionId,
    source: "cloudflare",
    sourceId: `${d.id}:${f.succeeded ? "success" : "failure"}`,
    kind: "cloudflare.deployment",
    at: dateOr(d.modified_on ?? d.created_on, now),
    subjectRef: project || null,
    correlationRef: sha || null,
    attrs: {
      production: d.environment === "production",
      succeeded: f.succeeded,
      sha,
      name: project,
      deployment: d.id,
      branch: d.deployment_trigger?.metadata?.branch ?? "",
      url: d.url ?? "",
    },
  }
}

/** One bounded page of a project's deployments, or null on any failure (logged, never thrown). */
async function listDeployments(
  ctx: ConnectorContext,
  account: string,
  project: string,
): Promise<CfDeployment[] | null> {
  try {
    const res = await fetch(
      `${API}/accounts/${account}/pages/projects/${encodeURIComponent(project)}/deployments?per_page=${PAGE_SIZE}&page=1`,
      { headers: { authorization: `Bearer ${ctx.secret}` }, signal: AbortSignal.timeout(TIMEOUT_MS) },
    )
    if (!res.ok) {
      ctx.log("cloudflare request failed", { project, status: res.status })
      return null
    }
    const body = (await res.json()) as { success?: boolean; result?: CfDeployment[] }
    return body.success === false ? null : (body.result ?? [])
  } catch (err) {
    ctx.log("cloudflare request errored", { project, err: (err as Error).message })
    return null
  }
}

export const cloudflareConnector: PollConnector = {
  kind: "cloudflare",
  mode: "poll",
  label: "Cloudflare Pages",
  blurb: "Pages deployments that finished, mapped to commit SHAs — anchors for regression correlation.",

  fields: [
    {
      name: "accountId",
      label: "Account ID",
      placeholder: "0123456789abcdef0123456789abcdef",
      help: "Shown on your Cloudflare dashboard's account overview.",
      required: true,
    },
    {
      name: "projects",
      label: "Pages projects",
      placeholder: "marketing-site, docs",
      help: "Project names, comma separated. Up to 20.",
      required: true,
    },
    {
      name: "token",
      label: "API token",
      help: "A token with ONLY the 'Cloudflare Pages Read' permission on this account. Nothing here writes.",
      required: true,
      secret: true,
    },
  ],

  setup: [
    "In Cloudflare: My Profile → API Tokens → Create Token → Custom token.",
    "Grant Account → Cloudflare Pages → Read, for this account only. Grant nothing else.",
    "Paste it as the token. It is encrypted at rest and never returned by the API.",
    "Finished deploys appear within a tick. Production ones anchor deploy-regression.",
  ],

  async poll(ctx: ConnectorContext): Promise<NormalizedEvent[]> {
    const account = String(ctx.config.accountId ?? "").trim()
    if (!/^[0-9a-f]{32}$/.test(account) || !ctx.secret) return []
    const out: NormalizedEvent[] = []
    const now = new Date()

    for (const project of projects(ctx)) {
      const cursorKey = `deployments:${project}`
      const since = (await ctx.getCursor(cursorKey)) ?? new Date(Date.now() - 86_400_000).toISOString()
      const list = await listDeployments(ctx, account, project)
      if (!list) continue

      let newest = since
      for (const d of list) {
        const modified = d.modified_on ?? d.created_on
        if (!modified || modified <= since) continue
        const e = normalizeCloudflare(
          ctx.connectionId,
          { ...d, project_name: d.project_name ?? project },
          now,
        )
        if (!e) continue // still in flight: seen again next tick, when it has finished
        out.push(e)
        if (modified > newest) newest = modified
      }
      if (newest !== since) await ctx.setCursor(cursorKey, newest)
    }
    return out
  },
}
