export interface ConnectorHealthInput {
  active: boolean
  supported: boolean
  mode: "push" | "poll"
  activatedAt: Date | null
  lastEventAt: Date | null
  lastVerifiedDeliveryAt?: Date | null
  lastPolledAt: Date | null
  lastPollSuccessAt: Date | null
  lastPollError: string | null
  failedDeliveries: number
}

export function connectorHealth(
  c: ConnectorHealthInput,
  now = new Date(),
): {
  label: string
  tone: "on" | "off" | "high"
  detail: string
} {
  if (!c.supported)
    return { label: "Unavailable", tone: "high", detail: "This connector is not supported by this build." }
  if (!c.active)
    return {
      label: "Setup pending",
      tone: "off",
      detail: "Follow the setup steps, then turn this connector on with your passkey.",
    }
  if (c.failedDeliveries > 0)
    return {
      label: "Delivery errors",
      tone: "high",
      detail: `${c.failedDeliveries} verified delivery(s) could not be normalized. Check the sender's payload and server logs. Raw deliveries are retained for diagnosis.`,
    }
  if (c.mode === "poll") {
    if (!c.lastPolledAt || (c.activatedAt && c.lastPolledAt < c.activatedAt)) {
      return {
        label: "Awaiting first poll",
        tone: "off",
        detail: "The next detection tick will fetch observations. Check the tick scheduler if this persists.",
      }
    }
    if (c.lastPollError) return { label: "Poll needs attention", tone: "high", detail: c.lastPollError }
    if (now.getTime() - c.lastPolledAt.getTime() > 15 * 60_000) {
      return {
        label: "Polling overdue",
        tone: "high",
        detail: "No poll in the last 15 minutes. Check the detection tick scheduler and service logs.",
      }
    }
    return {
      label: "Poll successful",
      tone: "on",
      detail: "The last poll completed without a reported error. No new events can be normal.",
    }
  }
  if (!c.lastEventAt || (c.activatedAt && c.lastEventAt < c.activatedAt)) {
    if (c.lastVerifiedDeliveryAt && (!c.activatedAt || c.lastVerifiedDeliveryAt >= c.activatedAt))
      return {
        label: "Delivery verified",
        tone: "on",
        detail:
          "An authenticated delivery arrived, but it contained no supported event. Send a real provider alert to verify detector coverage.",
      }
    return {
      label: "Awaiting delivery",
      tone: "off",
      detail:
        "Send a test event from your provider. Check the webhook URL and authentication secret if it does not arrive.",
    }
  }
  return {
    label: "Delivery received",
    tone: "on",
    detail:
      "A verified event has been stored. Webhooks arrive when something happens; silence alone is not a failure.",
  }
}
