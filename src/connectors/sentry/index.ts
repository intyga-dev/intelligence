import crypto from "node:crypto"
import type { PushConnector } from "../registry.ts"
import type { NormalizedEvent } from "../types.ts"

// Sentry.
//
// Deployment regression currently correlates a deploy against REFUSALS, which is an indirect
// signal — an exception rate moving eight minutes after a release is the direct one. This is the
// connector that makes detector 6 about what actually broke rather than about what got denied.
//
// Sentry's signature scheme differs from Intyga's in a way worth naming: it is a bare HMAC-SHA256
// hex digest of the raw body, with NO timestamp. So there is no freshness bound and a captured
// delivery is replayable forever. We cannot fix that from this side — the mitigation is the
// receiver's idempotency on the event id, which turns a replay into a no-op rather than a
// duplicate. Stated here rather than left for someone to discover.

interface SentryHook {
  action?: string
  installation?: { uuid?: string }
  data?: {
    issue?: {
      id?: string
      title?: string
      culprit?: string
      level?: string
      project?: { slug?: string }
      count?: string | number
      shortId?: string
      permalink?: string
      firstSeen?: string
      lastSeen?: string
    }
    error?: { event_id?: string; title?: string; level?: string; timestamp?: number }
  }
}

function firstHeader(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v
}

export const sentryConnector: PushConnector = {
  kind: "sentry",
  mode: "push",
  label: "Sentry",
  blurb: "Issues and error spikes, so a deployment regression can be correlated against what broke.",
  generatesSecret: false,

  fields: [
    {
      name: "clientSecret",
      label: "Client secret",
      help: "From your Sentry internal integration. Used only to verify inbound deliveries.",
      required: true,
      secret: true,
    },
  ],

  setup: [
    "In Sentry: Settings → Developer Settings → New Internal Integration.",
    "Set the webhook URL to the endpoint shown below.",
    "Enable the Issue and Error webhooks. Grant read-only permissions only.",
    "Copy the Client Secret into the field above.",
  ],

  verify: ({ headers, rawBody, secret }) => {
    // Sentry sends a bare hex digest with no timestamp, so this is an authenticity check only —
    // there is nothing to bound freshness against. Replay protection comes from event-id
    // idempotency downstream, not from here.
    const provided = firstHeader(headers["sentry-hook-signature"])
    if (!provided || !/^[0-9a-f]+$/i.test(provided) || provided.length % 2 !== 0) {
      return { ok: false, reason: "malformed-header" }
    }
    const expected = crypto.createHmac("sha256", secret).update(rawBody, "utf8").digest("hex")
    const a = Buffer.from(expected, "hex")
    const b = Buffer.from(provided.toLowerCase(), "hex")
    if (a.length !== b.length) {
      crypto.timingSafeEqual(a, a)
      return { ok: false, reason: "mismatch" }
    }
    return crypto.timingSafeEqual(a, b) ? { ok: true } : { ok: false, reason: "mismatch" }
  },

  eventId: (headers, body) => {
    // Prefer Sentry's own delivery id; fall back to the issue/error identity so a payload without
    // the header is still deduplicated rather than stored repeatedly.
    const delivery = firstHeader(headers["request-id"]) ?? firstHeader(headers["sentry-hook-resource"])
    const b = body as SentryHook
    const issue = b?.data?.issue?.id
    const error = b?.data?.error?.event_id
    const resource = issue ?? error
    if (resource) return `${b.action ?? "event"}:${resource}`
    return delivery ?? null
  },

  normalize: ({ connectionId, body, receivedAt }): NormalizedEvent | null => {
    const b = body as SentryHook
    const issue = b?.data?.issue
    const error = b?.data?.error
    if (!issue && !error) return null

    if (issue) {
      const at = issue.lastSeen ? new Date(issue.lastSeen) : receivedAt
      return {
        connectionId,
        source: "sentry",
        sourceId: `${b.action ?? "issue"}:${issue.id ?? issue.shortId ?? "unknown"}`,
        kind: `sentry.issue.${b.action ?? "updated"}`,
        at: Number.isNaN(at.getTime()) ? receivedAt : at,
        // The project is the subject: an error rate is a property of a service, not of one issue.
        subjectRef: issue.project?.slug ?? null,
        correlationRef: issue.shortId ?? issue.id ?? null,
        attrs: {
          title: issue.title ?? "",
          culprit: issue.culprit ?? "",
          level: issue.level ?? "error",
          count: Number(issue.count ?? 0),
          project: issue.project?.slug ?? "",
        },
      }
    }

    const at = error?.timestamp ? new Date(error.timestamp * 1000) : receivedAt
    return {
      connectionId,
      source: "sentry",
      sourceId: `error:${error?.event_id ?? crypto.randomUUID()}`,
      kind: "sentry.error",
      at: Number.isNaN(at.getTime()) ? receivedAt : at,
      subjectRef: null,
      correlationRef: error?.event_id ?? null,
      attrs: { title: error?.title ?? "", level: error?.level ?? "error" },
    }
  },
}
