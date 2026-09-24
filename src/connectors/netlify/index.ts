import crypto from "node:crypto"
import type { PushConnector } from "../registry.ts"
import { dateOr, firstHeader, safeEqual } from "../shared.ts"
import type { NormalizedEvent } from "../types.ts"

// Netlify (outgoing deploy notifications).
//
// A production deploy that went live anchors deploy-regression, exactly as Vercel's does.
//
// Signature: `X-Webhook-Signature` is a JWS (compact JWT) signed HS256 with the secret configured on
// the notification, carrying `iss: "netlify"` and `sha256`: the hex SHA-256 of the raw body. Verified
// here by hand rather than with a JWT library, because the whole check is four comparisons and a
// dependency would be the largest thing in it:
//   · the header's `alg` must be exactly HS256 — never `none`, never whatever the token asks for
//   · the HMAC over `<header>.<payload>` must match, in constant time
//   · `iss` must be `netlify`
//   · `sha256` must equal the digest of the bytes actually received
// There is no timestamp claim, so as with Sentry a captured delivery stays valid; idempotency on
// deploy id + state contains replays.
//
// Netlify documents no event-name header, and a deploy's `state` is what distinguishes a success
// from a failure. Only terminal states are modelled; `building` and friends are stored raw.

interface NetlifyDeploy {
  id?: string
  site_id?: string
  name?: string
  state?: string
  context?: string
  commit_ref?: string | null
  branch?: string
  created_at?: string
  published_at?: string | null
  updated_at?: string
  deploy_ssl_url?: string
  error_message?: string | null
}

const TERMINAL = new Set(["ready", "error"])

function b64urlJson(part: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(Buffer.from(part, "base64url").toString("utf8"))
    return v && typeof v === "object" ? (v as Record<string, unknown>) : null
  } catch {
    return null
  }
}

export function verifyNetlifySignature(token: string | undefined, rawBody: string, secret: string) {
  const parts = (token ?? "").split(".")
  if (parts.length !== 3) return { ok: false as const, reason: "malformed-header" }
  const [h, p, sig] = parts as [string, string, string]
  const header = b64urlJson(h)
  if (header?.alg !== "HS256") return { ok: false as const, reason: "unexpected-alg" }
  const expected = crypto.createHmac("sha256", secret).update(`${h}.${p}`, "utf8").digest("base64url")
  if (!safeEqual(sig, expected)) return { ok: false as const, reason: "mismatch" }
  const claims = b64urlJson(p)
  if (claims?.iss !== "netlify") return { ok: false as const, reason: "wrong-issuer" }
  const digest = crypto.createHash("sha256").update(rawBody, "utf8").digest("hex")
  if (typeof claims.sha256 !== "string" || !safeEqual(claims.sha256.toLowerCase(), digest)) {
    return { ok: false as const, reason: "body-mismatch" }
  }
  return { ok: true as const }
}

export const netlifyConnector: PushConnector = {
  kind: "netlify",
  mode: "push",
  label: "Netlify",
  blurb: "Deploys that went live or failed, mapped to commit SHAs — anchors for regression correlation.",
  generatesSecret: true,

  fields: [],

  setup: [
    "In Netlify: Site configuration → Build & deploy → Deploy notifications → Add notification → Outgoing webhook.",
    "Add one for 'Deploy succeeded' and one for 'Deploy failed', both pointing at the endpoint shown below.",
    "Set the JWS secret token on each to the secret shown here.",
    "Only production deploys anchor deploy-regression; previews and branch deploys are stored but ignored.",
  ],

  verify: ({ headers, rawBody, secret }) =>
    verifyNetlifySignature(firstHeader(headers["x-webhook-signature"]), rawBody, secret),

  eventId: (_headers, body) => {
    const d = body as NetlifyDeploy
    return d?.id && d.state ? `${d.id}:${d.state}` : null
  },

  normalize: ({ connectionId, body, receivedAt }): NormalizedEvent | null => {
    const d = body as NetlifyDeploy
    if (!d?.id || !d.state || !TERMINAL.has(d.state)) return null
    const succeeded = d.state === "ready"
    const sha = d.commit_ref ?? ""
    return {
      connectionId,
      source: "netlify",
      sourceId: `${d.id}:${d.state}`,
      kind: "netlify.deployment",
      at: dateOr(succeeded ? (d.published_at ?? d.updated_at) : d.updated_at, receivedAt),
      subjectRef: d.name ?? d.site_id ?? null,
      correlationRef: sha || null,
      attrs: {
        // The shared deploy convention read by deploy-regression.
        production: d.context === "production",
        succeeded,
        sha,
        name: d.name ?? "",
        deploy: d.id,
        context: d.context ?? "",
        branch: d.branch ?? "",
        url: d.deploy_ssl_url ?? "",
        error: d.error_message ?? "",
      },
    }
  },
}
