import type { NormalizedEvent } from "../../connectors/types.ts"
import { createFinding, type Finding, type Category } from "../finding.ts"
import type { OperationalInput } from "./operational.ts"

export const PROVIDER_ALERT_SOURCES = [
  "aws-eventbridge",
  "google-monitoring",
  "google-workspace",
  "azure-monitor",
  "grafana",
  "alertmanager",
  "stripe",
  "better-stack",
] as const
export const PROVIDER_ALERT_KINDS = PROVIDER_ALERT_SOURCES.map((s) => `${s}.provider.alert`)
export const providerAlertKey = (e: NormalizedEvent) =>
  `provider-alert:${JSON.stringify([e.connectionId, e.serviceId ?? null, e.attrs.incident])}`

export function detectProviderAlerts(input: OperationalInput): {
  findings: Finding[]
  resolved: NormalizedEvent[]
} {
  const latest = new Map<string, NormalizedEvent>()
  for (const e of input.events) {
    const s = input.sources.find((s) => s.id === e.connectionId && s.active)
    if (
      !s ||
      !PROVIDER_ALERT_KINDS.includes(e.kind) ||
      e.kind !== `${e.source}.provider.alert` ||
      !e.attrs.incident ||
      !Number.isFinite(e.at.getTime()) ||
      e.at > input.now ||
      (s.activatedAt && e.at < s.activatedAt) ||
      (e.serviceId ?? null) !== s.serviceId
    )
      continue
    const key = providerAlertKey(e),
      prev = latest.get(key)
    if (!prev || e.at > prev.at || (e.at.getTime() === prev.at.getTime() && e.attrs.status === "resolved"))
      latest.set(key, e)
  }
  const findings: Finding[] = [],
    resolved: NormalizedEvent[] = []
  for (const e of latest.values()) {
    if (e.attrs.status === "resolved") {
      resolved.push(e)
      continue
    }
    if (e.attrs.status !== "firing" || !["medium", "high", "critical"].includes(String(e.attrs.severity)))
      continue
    const category = ["engineering", "security", "business"].includes(String(e.attrs.category))
      ? (e.attrs.category as Category)
      : "engineering"
    const key = providerAlertKey(e)
    findings.push(
      createFinding({
        id: key,
        tenantId: input.tenantId,
        serviceId: e.serviceId ?? null,
        dedupeKey: key,
        category,
        severity: e.attrs.severity as "medium" | "high" | "critical",
        detectedAt: e.at,
        title: String(e.attrs.title || "Provider alert"),
        summary: `${e.source} reported an active alert${e.attrs.resource ? ` for ${String(e.attrs.resource)}` : ""}. This finding reflects the provider's alert condition, not an independent anomaly assessment. Check the source event and provider console. Only an explicit provider recovery closes it automatically.`,
        evidence: [
          {
            kind: "eventRef",
            connectionId: e.connectionId,
            sourceId: e.sourceId,
            at: e.at,
            eventKind: e.kind,
          },
        ],
      }),
    )
  }
  return { findings, resolved }
}
