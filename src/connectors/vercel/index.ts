import crypto from "node:crypto"
import type { PushConnector } from "../registry.ts"
import type { NormalizedEvent } from "../types.ts"

// Vercel deployments, by webhook.
//
// This connector was originally written to POLL the REST API, and that was a mistake worth
// recording. Vercel has no read-only API tokens — project-scoped is the narrowest option and within
// that project the token can still deploy, delete and rewrite environment variables. So the poll
// version asked a customer to paste, into a monitoring add-on, a credential that could take their
// production site down. For a product whose whole claim is "we never hold your keys", that is not a
// UX wrinkle; it is a contradiction.
//
// The webhook needs only a signing secret, which grants nothing: it lets us VERIFY that a delivery
// came from Vercel and cannot be used to call anything. Same signal, none of the risk.
//
// Note the scheme: HMAC-**SHA1**, not SHA-256, over the raw body, in `x-vercel-signature`. Vercel's
// choice, not ours. SHA-1 is weak against collision attacks but this is HMAC, where the security
// rests on the key rather than on collision resistance — HMAC-SHA1 has no practical break. Recorded
// so nobody "fixes" it to SHA-256 and silently rejects every delivery.

interface VercelHook {
  id?: string
  type?: string
  createdAt?: number
  payload?: {
    deployment?: {
      id?: string
      name?: string
      url?: string
      meta?: {
        githubCommitSha?: string
        githubCommitRef?: string
        githubCommitAuthorLogin?: string
      }
    }
    project?: { id?: string; name?: string }
    target?: string | null
    url?: string
    name?: string
    errorMessage?: string
  }
}

const TERMINAL_TYPES = new Set(["deployment.succeeded", "deployment.error", "deployment.canceled"])

function firstHeader(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v
}

export const vercelConnector: PushConnector = {
  kind: "vercel",
  mode: "push",
  label: "Vercel",
  blurb: "Deployments with the commit behind them — including ones that never went through CI.",
  // The secret comes from Vercel, shown once when the webhook is created there.
  generatesSecret: false,

  fields: [
    {
      name: "secret",
      label: "Webhook signing secret",
      help: "Shown once by Vercel when you create the webhook. It only verifies deliveries — it cannot call the Vercel API or touch a deployment.",
      required: true,
      secret: true,
    },
  ],

  setup: [
    "In Vercel: Account or Team Settings → Webhooks → Create.",
    "Set the endpoint to the URL shown below.",
    "Subscribe to deployment.succeeded, deployment.error and deployment.canceled.",
    "Copy the signing secret — Vercel shows it exactly once — into the field above.",
    "No API token is needed, and none should be created for this.",
  ],

  verify: ({ headers, rawBody, secret }) => {
    const provided = firstHeader(headers["x-vercel-signature"])
    if (!provided || !/^[0-9a-f]+$/i.test(provided) || provided.length % 2 !== 0) {
      return { ok: false, reason: "malformed-header" }
    }
    // SHA-1 on purpose — see the file header before changing it.
    const expected = crypto.createHmac("sha1", secret).update(rawBody, "utf8").digest("hex")
    const a = Buffer.from(expected, "hex")
    const b = Buffer.from(provided.toLowerCase(), "hex")
    if (a.length !== b.length) {
      crypto.timingSafeEqual(a, a)
      return { ok: false, reason: "mismatch" }
    }
    return crypto.timingSafeEqual(a, b) ? { ok: true } : { ok: false, reason: "mismatch" }
  },

  eventId: (headers, body) => {
    const delivery = firstHeader(headers["x-vercel-id"])
    const b = body as VercelHook
    // Vercel's own event id is the right key; the deployment id plus type is a stable fallback so a
    // delivery without the header is still deduplicated rather than stored twice.
    if (b?.id) return b.id
    const dep = b?.payload?.deployment?.id
    if (dep && b?.type) return `${b.type}:${dep}`
    return delivery ?? null
  },

  normalize: ({ connectionId, body, receivedAt }): NormalizedEvent | null => {
    const b = body as VercelHook
    const type = b?.type ?? ""
    // In-flight events carry no outcome; only a terminal state is a fact worth correlating.
    if (!TERMINAL_TYPES.has(type)) return null

    const dep = b.payload?.deployment
    const project = b.payload?.project?.name ?? b.payload?.name ?? dep?.name ?? "unknown"
    const sha = dep?.meta?.githubCommitSha ?? null
    const at = b.createdAt ? new Date(b.createdAt) : receivedAt

    return {
      connectionId,
      source: "vercel",
      sourceId: b.id ?? `${type}:${dep?.id ?? crypto.randomUUID()}`,
      kind: "vercel.deployment",
      at: Number.isNaN(at.getTime()) ? receivedAt : at,
      // The project is the subject — a deployment is an event in a service's life.
      subjectRef: project,
      // The join key to GitHub: a Vercel deployment and a pull request sharing a SHA are the same
      // change arriving by two routes, which is what lets correlation point at a diff rather than a
      // timestamp. Null for a CLI deploy with no git metadata, which correlation must then decline
      // to attribute.
      correlationRef: sha,
      attrs: {
        project,
        deployment: dep?.id ?? "",
        url: dep?.url ?? b.payload?.url ?? "",
        state: type.replace("deployment.", "").toUpperCase(),
        // "production" vs a preview: a preview failing is routine, production failing is not.
        target: b.payload?.target ?? "preview",
        isProduction: b.payload?.target === "production",
        succeeded: type === "deployment.succeeded",
        sha: sha ?? "",
        ref: dep?.meta?.githubCommitRef ?? "",
        author: dep?.meta?.githubCommitAuthorLogin ?? "",
        errorMessage: b.payload?.errorMessage ?? "",
      },
    }
  },
}
