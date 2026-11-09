import type { PushConnector } from "../registry.ts"
import { dateOr, TOKEN_HEADER, verifyTokenHeader } from "../shared.ts"
import type { NormalizedEvent } from "../types.ts"

// Datadog (Webhooks integration, from monitor notifications).
//
// Datadog does not sign webhook requests. It supports custom headers, so — as with Opsgenie — the
// connector mints a secret sent as `x-intelligence-token`. A bearer secret, not a signature; the
// same caveats apply and are repeated in the setup text.
//
// The body is not fixed by Datadog: the user pastes a payload TEMPLATE into the webhook definition,
// and Datadog substitutes its variables. The template below is the contract. `$ID` is the per-
// notification event id (idempotency); `$DATE` is epoch MILLISECONDS; `$ALERT_TRANSITION` is
// `Triggered`, `Re-Triggered`, `Recovered` and so on. Datadog retries only on 5xx, which is one more
// reason a malformed body is answered 2xx and stored raw rather than rejected.

export const DATADOG_PAYLOAD_TEMPLATE = `{
  "id": "$ID",
  "title": "$EVENT_TITLE",
  "transition": "$ALERT_TRANSITION",
  "monitor": "$ALERT_ID",
  "type": "$ALERT_TYPE",
  "priority": "$ALERT_PRIORITY",
  "date": "$DATE",
  "host": "$HOSTNAME",
  "tags": "$TAGS",
  "cycle": "$ALERT_CYCLE_KEY"
}`

interface DdHook {
  id?: string
  title?: string
  transition?: string
  monitor?: string
  type?: string
  priority?: string
  date?: string
  host?: string
  tags?: string
  cycle?: string
}

/** `Re-Triggered` → `retriggered`, `No Data` → `no_data`. */
function transitionKind(t: string): string {
  return t
    .toLowerCase()
    .replace(/-/g, "")
    .replace(/\s+/g, "_")
    .replace(/[^a-z_]/g, "")
}

export const datadogConnector: PushConnector = {
  kind: "datadog",
  mode: "push",
  label: "Datadog",
  blurb:
    "Monitor alerts as they trigger and recover — a monitor firing after a deploy is a regression signal.",
  generatesSecret: true,

  fields: [],

  setup: [
    "In Datadog: Integrations → Webhooks → New webhook. Set the URL to the endpoint shown below.",
    `Under Custom Headers, add {"${TOKEN_HEADER}": "<the secret shown here>"}. Datadog cannot sign requests; this header is how deliveries are authenticated.`,
    `Paste this as the Payload:  ${DATADOG_PAYLOAD_TEMPLATE.replace(/\s+/g, " ")}`,
    "Mention @webhook-<name> in the notification of each monitor you want watched.",
  ],

  verify: ({ headers, secret }) => verifyTokenHeader(headers, secret),

  eventId: (_headers, body) => {
    const id = (body as DdHook)?.id
    // An unsubstituted template variable is not an id.
    return id && !id.startsWith("$") ? id : null
  },

  normalize: ({ connectionId, body, receivedAt }): NormalizedEvent | null => {
    const b = body as DdHook
    if (!b?.id || b.id.startsWith("$") || !b.transition) return null
    const ms = Number(b.date)
    const transition = transitionKind(b.transition)
    return {
      connectionId,
      source: "datadog",
      sourceId: b.id,
      // `retriggered` is a separate kind on purpose: a monitor flapping is not a new incident.
      kind: `datadog.alert.${transition}`,
      at: Number.isFinite(ms) && ms > 0 ? dateOr(ms, receivedAt) : receivedAt,
      subjectRef: b.monitor ?? null,
      correlationRef: b.cycle || b.monitor || null,
      attrs: {
        title: b.title ?? "",
        monitor: b.monitor ?? "",
        type: b.type ?? "",
        priority: b.priority ?? "",
        host: b.host ?? "",
        tags: b.tags ?? "",
      },
    }
  },
}
