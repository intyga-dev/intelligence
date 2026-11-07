import type { ConnectorDefinition } from "./registry.ts"

const existing: Record<string, [string, string]> = {
  intyga: ["Identity", "Approval denials and deployment correlation"],
  github: ["Development", "Sensitive-change observations, CI health, merge controls and deploy correlation"],
  gitlab: ["Development", "Sensitive-change observations and deploy correlation"],
  metrics: [
    "Observability",
    "Known INTYGA health metrics; other PromQL queries are collected without automatic interpretation",
  ],
  sentry: ["Observability", "Error events for deployment regression correlation"],
  fly: ["Cloud", "Machine crashes and OOM events for deployment regression correlation"],
  vercel: ["Cloud", "Production deployments for regression correlation"],
  netlify: ["Cloud", "Production deployments for regression correlation"],
  cloudflare: ["Cloud", "Cloudflare Pages deployments for regression correlation"],
  pagerduty: ["Observability", "Triggered incidents for deployment regression correlation"],
  opsgenie: ["Observability", "Triggered alerts for deployment regression correlation"],
  datadog: ["Observability", "Monitor alerts for deployment regression correlation"],
  webhook: ["Custom", "Signed deployments, errors, CI outcomes, job completions and service aggregates"],
}
export function catalogueDetails(def: ConnectorDefinition) {
  return {
    category: def.category ?? existing[def.kind]?.[0] ?? "Other",
    coverage: def.coverage ?? existing[def.kind]?.[1] ?? "Stored events",
    ...(def.docsUrl ? { docsUrl: def.docsUrl } : {}),
  }
}
