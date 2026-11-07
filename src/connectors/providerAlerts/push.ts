import type { PushConnector } from "../registry.ts"
import { firstHeader, hexEqual, hmacHex, verifyTokenHeader } from "../shared.ts"
import { alertEvent, hash, object, present, severity, string, timestamp, verifyBasic } from "./common.ts"

export const awsEventBridgeConnector: PushConnector = {
  kind: "aws-eventbridge",
  mode: "push",
  label: "AWS EventBridge",
  category: "Cloud",
  coverage: "CloudWatch alarms, Backup job failures, Health issues and GuardDuty findings → provider alerts",
  docsUrl: "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html",
  blurb:
    "Forward selected AWS alarms and operational/security events without giving Intelligence access keys.",
  generatesSecret: true,
  fields: [],
  setup: [
    "Create an EventBridge Connection using API Key authorization. Header name: x-intelligence-token; value: the connector secret shown here.",
    "Create an HTTPS API Destination with method POST and the endpoint below. Use the connection you just created.",
    "Create rules for CloudWatch Alarm State Change, AWS Backup job state changes, AWS Health issue events or GuardDuty Finding. Forward the original event JSON without an input transformer.",
    "Choose accounts, regions and resources in your EventBridge rules. Configure retries and a dead-letter queue. Backup events are best effort; absence is not proof that a backup failed.",
    "Turn this connector on with INTYGA, then send a representative event. ALARM/failure/active issue records produce findings; OK/closed/archived records resolve matching findings. Scheduled maintenance is ignored.",
  ],
  verify: ({ headers, secret }) => verifyTokenHeader(headers, secret),
  eventId: (_h, b) => string(object(b).id) || null,
  normalize: ({ connectionId, body }) => {
    const b = object(body),
      d = object(b.detail),
      type = string(b["detail-type"]),
      src = string(b.source),
      id = string(b.id)
    if (!id || !/^\d{12}$/.test(string(b.account))) return null
    const resources = Array.isArray(b.resources) ? b.resources : []
    const base = { id, at: b.time, resource: string(resources[0]) || string(d.resourceArn) }
    if (src === "aws.cloudwatch" && type === "CloudWatch Alarm State Change") {
      const state = object(d.state),
        status = state.value
      if (status !== "ALARM" && status !== "OK") return null
      const name = string(d.alarmName),
        incident = string(resources[0]) || `${string(b.account)}:${string(b.region)}:${name}`
      if (!name) return null
      return alertEvent(connectionId, "aws-eventbridge", {
        ...base,
        at: state.timestamp ?? b.time,
        incident,
        title: `CloudWatch: ${name}`,
        status: status === "OK" ? "resolved" : "firing",
        severity: "medium",
      })
    }
    if (
      src === "aws.backup" &&
      ["Backup Job State Change", "Copy Job State Change", "Restore Job State Change"].includes(type)
    ) {
      const state = string(d.state ?? d.status),
        job = string(d.backupJobId ?? d.copyJobId ?? d.restoreJobId)
      if (!job) return null
      if (!["FAILED", "ABORTED", "EXPIRED", "COMPLETED"].includes(state)) return null
      return alertEvent(connectionId, "aws-eventbridge", {
        ...base,
        incident: `${string(b.account)}:${type}:${job}`,
        title: `AWS ${type.replace(" State Change", "")}: ${state}`,
        status: state === "COMPLETED" ? "resolved" : "firing",
        severity: "high",
      })
    }
    if (src === "aws.health" && type === "AWS Health Event" && d.eventTypeCategory === "issue") {
      if (!["open", "closed"].includes(string(d.statusCode))) return null
      return alertEvent(connectionId, "aws-eventbridge", {
        ...base,
        incident: string(d.eventArn),
        title: `AWS Health: ${string(d.service)} ${string(d.eventTypeCode)}`,
        status: d.statusCode === "closed" ? "resolved" : "firing",
        severity: "medium",
      })
    }
    if (src === "aws.guardduty" && type === "GuardDuty Finding") {
      const score = Number(d.severity),
        service = object(d.service)
      if (!Number.isFinite(score) || (!string(d.arn) && !string(d.id))) return null
      return alertEvent(connectionId, "aws-eventbridge", {
        ...base,
        incident: string(d.arn) || `${string(b.account)}:${string(d.id)}`,
        title: `GuardDuty: ${string(d.title) || string(d.type)}`,
        status: service.archived === true ? "resolved" : "firing",
        severity: score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low",
        category: "security",
      })
    }
    return null
  },
}

export const googleMonitoringConnector: PushConnector = {
  kind: "google-monitoring",
  mode: "push",
  label: "Google Cloud Monitoring",
  category: "Cloud",
  coverage:
    "Monitoring incident open/close → provider alerts (Cloud Run, GKE, Cloud SQL and other monitored resources)",
  docsUrl: "https://docs.cloud.google.com/monitoring/support/notification-options#webhooks",
  basicAuth: true,
  blurb: "Receive Google Cloud Monitoring incidents from the alert policies you already use.",
  generatesSecret: true,
  fields: [],
  setup: [
    "In Google Cloud Monitoring, create a Webhook notification channel with the HTTPS endpoint below.",
    "Enable Basic authentication: username intelligence; password is the connector secret shown here. Do not put the secret in the URL.",
    "Attach the channel to selected alerting policies and enable notifications for incident closure. This uses native webhook JSON, not a Pub/Sub envelope.",
    "Turn the connector on, then test the notification channel. Real open incidents produce findings; matching closed incidents resolve them. A test without an incident is retained without a finding.",
  ],
  verify: ({ headers, secret }) => verifyBasic(headers, secret),
  eventId: (_h, b) => hash(b),
  normalize: ({ connectionId, body }) => {
    const i = object(object(body).incident)
    if (!["open", "closed"].includes(string(i.state))) return null
    return alertEvent(connectionId, "google-monitoring", {
      id: hash(i),
      incident: string(i.incident_id),
      at: i.state === "closed" ? i.ended_at : i.started_at,
      title: `Google Cloud: ${string(i.policy_name) || string(i.resource_display_name) || "Monitoring incident"}`,
      status: i.state === "closed" ? "resolved" : "firing",
      severity: severity(i.severity),
      resource: string(i.resource_name),
      url: string(i.url),
    })
  },
}

function grouped(kind: "grafana" | "alertmanager", label: string): PushConnector {
  return {
    kind,
    mode: "push",
    label,
    category: "Observability",
    coverage: "Individual firing/resolved alerts, including grouped deliveries → provider alerts",
    basicAuth: true,
    docsUrl:
      kind === "grafana"
        ? "https://grafana.com/docs/grafana/latest/alerting/configure-notifications/manage-contact-points/integrations/webhook-notifier/"
        : "https://prometheus.io/docs/alerting/latest/configuration/#webhook_config",
    blurb: `Receive ${label} alerts for infrastructure, applications, Kubernetes and databases.`,
    generatesSecret: true,
    fields: [],
    setup: [
      kind === "grafana"
        ? "Create a Webhook contact point with method POST and the HTTPS endpoint below. Keep the default payload."
        : "Add a webhook_configs receiver using the HTTPS endpoint below. Keep the default payload.",
      kind === "grafana"
        ? "Set Basic Authentication Username to intelligence and Password to the connector secret."
        : "Set http_config.basic_auth.username to intelligence and http_config.basic_auth.password to the connector secret.",
      "Enable resolved notifications. Send at most 200 alerts per group and do not truncate groups; split larger groups in routing.",
      "Use a severity label: critical, high, warning/medium or low/info. Unlabelled firing alerts default to medium. Only medium or higher create findings.",
      "Turn the connector on and send a test from the provider. Each alert is deduplicated separately, and resolved alerts close only their matching finding.",
    ],
    verify: ({ headers, secret }) => verifyBasic(headers, secret),
    eventId: (_h, b) => hash(b),
    normalize: () => null,
    normalizeBatch: ({ connectionId, body }) => {
      const b = object(body)
      if (!Array.isArray(b.alerts)) return []
      if (b.alerts.length > 200 || Number(b.truncatedAlerts) > 0) throw new Error("Incomplete alert group")
      return b.alerts
        .map((raw) => {
          const a = object(raw),
            labels = object(a.labels),
            notes = object(a.annotations)
          if (!["firing", "resolved"].includes(string(a.status))) return null
          const incident =
            string(a.fingerprint) || hash(Object.entries(labels).sort(([a], [b]) => a.localeCompare(b)))
          if (!Object.keys(labels).length && !a.fingerprint) return null
          const at = a.status === "resolved" ? a.endsAt : a.startsAt
          return alertEvent(connectionId, kind, {
            id: hash([incident, a.status, at]),
            incident,
            at,
            title: `${label}: ${string(notes.summary) || string(labels.alertname) || "Alert"}`,
            status: a.status === "resolved" ? "resolved" : "firing",
            severity: severity(labels.severity),
            resource: string(labels.service) || string(labels.instance) || string(labels.job),
            url: string(a.generatorURL),
          })
        })
        .filter(present)
    },
  }
}
export const grafanaConnector = grouped("grafana", "Grafana Alerting")
export const alertmanagerConnector = grouped("alertmanager", "Prometheus Alertmanager")

export const stripeConnector: PushConnector = {
  kind: "stripe",
  mode: "push",
  label: "Stripe",
  category: "Business",
  coverage: "Failed payouts and disputes → provider alerts; ordinary payment declines are ignored",
  docsUrl: "https://docs.stripe.com/webhooks",
  blurb: "Track failed payouts and payment disputes without treating every declined card as an anomaly.",
  generatesSecret: false,
  fields: [
    {
      name: "secret",
      label: "Webhook signing secret",
      secret: true,
      required: true,
      help: "The whsec_ signing secret for this Stripe endpoint, not a Stripe API key.",
    },
  ],
  setup: [
    "Create a Stripe webhook destination using snapshot events and the HTTPS endpoint below.",
    "Subscribe to payout.failed, payout.paid, charge.dispute.created and charge.dispute.closed. Copy the destination's signing secret into this connector.",
    "Use separate connectors for test and live mode. No payment/customer API credential is required.",
    "Turn the connector on and use Stripe's test delivery or CLI. Signatures are checked against the raw body with a five-minute timestamp tolerance. Payout recovery/dispute closure resolves the matching finding; closure does not imply the dispute was won.",
  ],
  verify: ({ headers, rawBody, secret }) => {
    const parts = (firstHeader(headers["stripe-signature"]) ?? "").split(",").map((s) => s.trim()),
      t = parts.find((s) => s.startsWith("t="))?.slice(2)
    if (!t || !/^\d+$/.test(t) || Math.abs(Date.now() / 1000 - Number(t)) > 300)
      return { ok: false, reason: "stale-or-missing-timestamp" }
    const expected = hmacHex(secret, `${t}.${rawBody}`)
    return parts.filter((s) => s.startsWith("v1=")).some((s) => hexEqual(s.slice(3), expected))
      ? { ok: true }
      : { ok: false, reason: "signature-mismatch" }
  },
  eventId: (_h, b) => string(object(b).id) || null,
  normalize: ({ connectionId, body }) => {
    const b = object(body),
      d = object(object(b.data).object),
      type = string(b.type)
    if (
      !["payout.failed", "payout.paid", "charge.dispute.created", "charge.dispute.closed"].includes(type) ||
      !string(d.id) ||
      !timestamp(b.created)
    )
      return null
    const payout = type.startsWith("payout.")
    return alertEvent(connectionId, "stripe", {
      id: string(b.id),
      incident: `${string(b.account) || "account"}:${b.livemode === true ? "live" : "test"}:${string(d.id)}`,
      at: b.created,
      title: `Stripe: ${type.replaceAll(".", " ")}`,
      status: type === "payout.paid" || type.endsWith(".closed") ? "resolved" : "firing",
      severity: payout ? "high" : "medium",
      category: "business",
      resource: string(d.id),
    })
  },
}
