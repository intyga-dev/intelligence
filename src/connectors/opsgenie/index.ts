import type { PushConnector } from "../registry.ts"
import { dateOr, TOKEN_HEADER, verifyTokenHeader } from "../shared.ts"
import type { NormalizedEvent } from "../types.ts"

// Opsgenie (outgoing Webhook integration).
//
// PRODUCT STATUS: Atlassian ended sales on 4 June 2025 and shuts Opsgenie down on 5 April 2027, when
// remaining data is deleted; the migration path is Jira Service Management or Compass. This
// connector exists for teams still on it until then, and says so in the catalogue.
//
// Opsgenie does not sign webhook requests, but it does send custom headers. So the connector MINTS a
// secret that is configured as `x-intelligence-token` — a bearer secret, not a signature: it proves
// the sender knows the secret, it does not bind the body, and it replays forever. Replays are
// contained by idempotency (the alert id plus the action and time); TLS carries the secret.
//
// `alert.createdAt` is epoch MILLISECONDS; `updatedAt` in Atlassian's own sample is a 19-digit
// nanosecond value, so it is not used as a timestamp here.

interface OgHook {
  action?: string
  alert?: {
    alertId?: string
    tinyId?: string
    message?: string
    alias?: string
    entity?: string
    tags?: string[]
    priority?: string
    createdAt?: number
  }
  integrationName?: string
}

export const opsgenieConnector: PushConnector = {
  kind: "opsgenie",
  mode: "push",
  label: "Opsgenie",
  blurb: "Alerts as they are created. Opsgenie shuts down on 5 April 2027 — this is for teams still on it.",
  generatesSecret: true,

  fields: [],

  setup: [
    "In Opsgenie: Settings → Integrations → Add integration → Webhook.",
    "Set the Webhook URL to the endpoint shown below.",
    `Add a custom header named ${TOKEN_HEADER} whose value is the secret shown here.`,
    "Enable 'Add Alert Description to Payload' only if you want it stored — nothing here needs it.",
    "Select at least the Create and Close alert actions.",
  ],

  verify: ({ headers, secret }) => verifyTokenHeader(headers, secret),

  eventId: (_headers, body) => {
    const b = body as OgHook
    const id = b?.alert?.alertId
    // An alert receives many actions over its life; each (alert, action) pair is one event. Opsgenie
    // does not send a delivery id, so a repeated action of the same kind on the same alert (a second
    // AddNote) is folded — acceptable, since only Create feeds a detector.
    return id && b.action ? `${id}:${b.action}` : null
  },

  normalize: ({ connectionId, body, receivedAt }): NormalizedEvent | null => {
    const b = body as OgHook
    const a = b?.alert
    if (!a?.alertId || !b.action) return null
    const action = b.action.toLowerCase()
    return {
      connectionId,
      source: "opsgenie",
      sourceId: `${a.alertId}:${b.action}`,
      kind: `opsgenie.alert.${action}`,
      // Only a creation has a meaningful time of its own; other actions are dated on arrival.
      at: action === "create" ? dateOr(a.createdAt, receivedAt) : receivedAt,
      subjectRef: a.entity || b.integrationName || null,
      correlationRef: a.alias || a.alertId,
      attrs: {
        alert: a.alertId,
        tinyId: a.tinyId ?? "",
        message: a.message ?? "",
        priority: a.priority ?? "",
        tags: (a.tags ?? []).join(","),
      },
    }
  },
}
