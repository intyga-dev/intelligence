import type { PushConnector } from "../registry.ts"
import { dateOr, firstHeader, hexEqual, hmacHex } from "../shared.ts"
import type { NormalizedEvent } from "../types.ts"

// PagerDuty (Webhooks v3).
//
// Incidents are the strongest "something broke" signal a team has — a human decided it was worth
// paging on — so `incident.triggered` feeds deploy-regression with a floor of one.
//
// Signature: `X-PagerDuty-Signature: v1=<hex>`, HMAC-SHA256 of the RAW body with the subscription's
// secret. During secret rotation the header carries several comma-separated signatures; any one
// matching is sufficient, which is how PagerDuty's own verifier behaves. Entries that are not `v1=`
// are ignored rather than failing the delivery, so a future scheme does not break ingestion.
//
// Like Sentry, there is NO timestamp in what is signed: a captured delivery is authentic forever.
// Replays are contained by idempotency on `event.id`, not by this check. Stated, not fixed — it is
// the vendor's scheme.

interface PdEvent {
  event?: {
    id?: string
    event_type?: string
    resource_type?: string
    occurred_at?: string
    data?: {
      id?: string
      title?: string
      urgency?: string
      status?: string
      html_url?: string
      service?: { id?: string; summary?: string }
    }
  }
}

export function verifyPagerDutySignature(header: string | undefined, rawBody: string, secret: string) {
  if (!header) return { ok: false as const, reason: "missing-header" }
  const expected = hmacHex(secret, rawBody)
  const candidates = header
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.startsWith("v1="))
    .map((s) => s.slice(3))
  if (candidates.length === 0) return { ok: false as const, reason: "malformed-header" }
  // Every candidate is compared, match or not, so timing does not reveal which position matched.
  let ok = false
  for (const c of candidates) ok = hexEqual(c, expected) || ok
  return ok ? { ok: true as const } : { ok: false as const, reason: "mismatch" }
}

export const pagerdutyConnector: PushConnector = {
  kind: "pagerduty",
  mode: "push",
  label: "PagerDuty",
  blurb: "Incidents as they are triggered — a page right after a deploy is a regression signal.",
  generatesSecret: false,

  fields: [
    {
      name: "secret",
      label: "Webhook signing secret",
      help: "Shown once when you create the v3 webhook subscription in PagerDuty. Used only to verify deliveries.",
      required: true,
      secret: true,
    },
  ],

  setup: [
    "In PagerDuty: Integrations → Generic Webhooks (v3) → New Webhook.",
    "Set the webhook URL to the endpoint shown below, scoped to the services you want watched.",
    "Subscribe to incident events — at least incident.triggered and incident.resolved.",
    "Copy the signing secret PagerDuty shows into the field above.",
  ],

  verify: ({ headers, rawBody, secret }) =>
    verifyPagerDutySignature(firstHeader(headers["x-pagerduty-signature"]), rawBody, secret),

  eventId: (_headers, body) => (body as PdEvent)?.event?.id ?? null,

  normalize: ({ connectionId, body, receivedAt }): NormalizedEvent | null => {
    const e = (body as PdEvent)?.event
    // Only incident events are modelled; service or other resource events are stored raw.
    if (!e?.id || !e.event_type?.startsWith("incident.")) return null
    const d = e.data ?? {}
    return {
      connectionId,
      source: "pagerduty",
      sourceId: e.id,
      kind: `pagerduty.${e.event_type}`,
      at: dateOr(e.occurred_at, receivedAt),
      // The service is the subject: an incident is a property of a service, not of one responder.
      subjectRef: d.service?.summary ?? d.service?.id ?? null,
      correlationRef: d.id ?? null,
      attrs: {
        incident: d.id ?? "",
        title: d.title ?? "",
        urgency: d.urgency ?? "",
        status: d.status ?? "",
        service: d.service?.summary ?? "",
        url: d.html_url ?? "",
      },
    }
  },
}
