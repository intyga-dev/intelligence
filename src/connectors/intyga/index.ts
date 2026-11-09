import type { PushConnector } from "../registry.ts"
import { normalizeIntygaEvent } from "./normalize.ts"
import { verifyWebhookSignature } from "./signature.ts"

// The Intyga connector.
//
// Built in, because every Intelligence tenant already has an Intyga relationship — it is what
// authenticates their administrators. So this is not configured from nothing; it is switched on.
//
// Push, not poll: Intyga's existing webhook pipeline already provides delivery, retries, backoff,
// auto-disable and an encrypted per-endpoint secret. Consuming it needs no change to Intyga at all.

export const intygaConnector: PushConnector = {
  kind: "intyga",
  mode: "push",
  label: "INTYGA",
  blurb: "Approvals, refusals, expiries and approval latency from your INTYGA workspace.",
  builtIn: true,
  generatesSecret: true,

  // No fields: the endpoint URL and secret are generated here, and everything else about the
  // relationship already exists. A form asking a customer to retype what we already know is how
  // setup becomes something people abandon.
  fields: [],

  setup: [
    "Open your INTYGA console and go to Webhooks.",
    "Add an endpoint with the URL shown below and paste the signing secret.",
    "Subscribe to: challenge.created, challenge.approved, challenge.denied, challenge.expired, challenge.consumed, challenge.escalated.",
    'Leave "include params" OFF — action descriptions and parameters are not needed here and should not leave INTYGA.',
  ],

  verify: ({ headers, rawBody, secret }) => {
    const header = headers["x-intyga-signature"]
    return verifyWebhookSignature({
      header: Array.isArray(header) ? header[0] : header,
      rawBody,
      secret,
    })
  },

  eventId: (headers) => {
    const id = headers["x-intyga-event-id"]
    return (Array.isArray(id) ? id[0] : id) ?? null
  },

  normalize: (input) => normalizeIntygaEvent(input),
}
