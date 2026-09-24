import crypto from "node:crypto"
import { z } from "zod"
import type { PushConnector } from "../registry.ts"
import type { NormalizedEvent } from "../types.ts"

// The custom webhook: any system that can send a signed HTTP POST becomes a source, with no code.
//
// It exists so that a CI system, an error tracker or an in-house service we do not ship a connector
// for can still feed the detectors. The body is a small documented shape (docs/CONNECTORS.md), and
// three kinds carry meaning to a detector today:
//
//   · deployment  — anchors deploy-regression (attrs: production, succeeded, sha, name)
//   · error       — counts as an error signal after a deploy
//   · crash       — counts as a crash signal after a deploy
//
// Any other kind is stored and shown, and waits for a detector that reads it.
//
// EVERY KIND IS PREFIXED `custom.` — not a convenience, a boundary. Without it, a producer holding
// this connector's secret could send `challenge.denied` and manufacture a denial-burst finding
// against any INTYGA subject it names. A custom event can only ever be a custom event.
//
// Signature: `x-intelligence-signature: t=<unix seconds>,v1=<hex>`, HMAC-SHA256 over
// `"<t>.<raw body>"` — the same scheme Intelligence uses for its OUTBOUND alerts, so one helper
// serves both directions. Unlike Sentry's, it carries a timestamp, so a captured delivery goes stale
// after five minutes instead of replaying forever.

export const SIGNATURE_HEADER = "x-intelligence-signature"
/** How old a signed delivery may be. Also bounds how far in the future its clock may run. */
const TOLERANCE_S = 300

const attrValue = z.union([z.string().max(2000), z.number(), z.boolean(), z.null()])

export const CUSTOM_EVENT = z.object({
  /** The producer's own id for this event — the idempotency key. Resending it is a no-op. */
  id: z.string().min(1).max(200),
  kind: z
    .string()
    .min(1)
    .max(100)
    .regex(/^[a-z0-9][a-z0-9._-]*$/, "kind: lowercase letters, digits, '.', '_' and '-'"),
  /** ISO 8601. Defaults to when the delivery arrived. */
  at: z.iso.datetime({ offset: true }).optional(),
  /** Who or what the event is about — a service, a user, a job. */
  subject: z.string().max(300).nullish(),
  /** Ties related events together — a commit SHA, a trace id. */
  correlation: z.string().max(300).nullish(),
  /** A flat bag. Nested objects are refused rather than flattened, so nothing is silently lost. */
  attrs: z.record(z.string().max(100), attrValue).optional(),
})

function firstHeader(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v
}

export function verifyCustomSignature(
  input: { header: string | undefined; rawBody: string; secret: string },
  nowSeconds: number = Math.floor(Date.now() / 1000),
): { ok: true } | { ok: false; reason: string } {
  const m = /^t=(\d{1,12}),v1=([0-9a-f]{64})$/.exec(input.header ?? "")
  if (!m) return { ok: false, reason: "malformed-header" }
  const t = Number(m[1])
  if (Math.abs(nowSeconds - t) > TOLERANCE_S) return { ok: false, reason: "stale" }
  const expected = crypto.createHmac("sha256", input.secret).update(`${t}.${input.rawBody}`, "utf8").digest()
  const provided = Buffer.from(m[2] as string, "hex")
  // Both are 32 bytes by construction (the regex pins 64 hex characters), so the comparison is total.
  return crypto.timingSafeEqual(expected, provided) ? { ok: true } : { ok: false, reason: "mismatch" }
}

export const webhookConnector: PushConnector = {
  kind: "webhook",
  mode: "push",
  label: "Custom webhook",
  blurb: "Send signed JSON events from any system — deploys, errors, crashes, anything else.",
  generatesSecret: true,

  fields: [],

  setup: [
    "Copy the endpoint and the signing secret shown here into the system that will send events.",
    "POST one JSON event per request: { id, kind, at?, subject?, correlation?, attrs? }.",
    'Sign each request: x-intelligence-signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<raw body>">.',
    "Kinds deployment, error and crash feed the deploy-regression detector; see docs/CONNECTORS.md.",
    "Turn the connector on. Deliveries to a switched-off connector are verified and then ignored.",
  ],

  verify: ({ headers, rawBody, secret }) =>
    verifyCustomSignature({ header: firstHeader(headers[SIGNATURE_HEADER]), rawBody, secret }),

  eventId: (_headers, body) => {
    const parsed = CUSTOM_EVENT.safeParse(body)
    return parsed.success ? parsed.data.id : null
  },

  normalize: ({ connectionId, body, receivedAt }): NormalizedEvent | null => {
    const parsed = CUSTOM_EVENT.safeParse(body)
    // Null rather than a throw: a malformed event is the producer's bug, and answering 2xx keeps
    // their queue from retrying it forever. The raw delivery is retained for inspection.
    if (!parsed.success) return null
    const e = parsed.data
    const at = e.at ? new Date(e.at) : receivedAt
    return {
      connectionId,
      source: "webhook",
      sourceId: e.id,
      kind: `custom.${e.kind}`,
      at,
      subjectRef: e.subject ?? null,
      correlationRef: e.correlation ?? null,
      attrs: e.attrs ?? {},
    }
  },
}
