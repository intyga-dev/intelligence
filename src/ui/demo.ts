import type { ServiceDetail } from "../store/services.ts"
import { servicePage } from "./services.ts"

/** Authored sample, rendered only. Never enters the store, detector cursor or alert pipeline. */
export function demoPage(now = new Date()): string {
  const at = (minutesAgo: number) => new Date(now.getTime() - minutesAgo * 60_000)
  const detail: ServiceDetail = {
    service: {
      id: "example",
      tenantId: "example",
      name: "Production API",
      description: "Example: investigate an error increase following a production deployment.",
      createdAt: at(90),
      connections: [
        { id: "code", label: "GitHub · API", kind: "github", active: true },
        { id: "errors", label: "Sentry · API", kind: "sentry", active: true },
      ],
    },
    findings: [
      {
        id: "example",
        serviceId: "example",
        category: "engineering",
        severity: "high",
        status: "new",
        count: 1,
        title: "Errors rose after deploying API v2.8.1",
        summary:
          "42 errors in the 30 minutes after deployment, against 3 for a comparable baseline window. The matching pull request changed permission checks. Investigate the release and upstream dependencies; this timing is not proof of cause.",
        detectedAt: at(10),
        lastSeenAt: at(10),
        feedback: [],
        evidence: [
          {
            kind: "metric",
            label: "Errors after deployment",
            value: 42,
            baseline: 3,
            window: { from: at(40), to: at(10) },
          },
        ],
      },
    ],
    events: [
      {
        id: "error",
        kind: "sentry.error",
        at: at(15),
        source: "sentry",
        attrs: { title: "Permission check rejected requests" },
        correlationRef: null,
        connection: { label: "Sentry · API" },
      },
      {
        id: "deploy",
        kind: "github.deployment",
        at: at(40),
        source: "github",
        attrs: { name: "API v2.8.1", sha: "a91c328ef401" },
        correlationRef: null,
        connection: { label: "GitHub · API" },
      },
      {
        id: "pr",
        kind: "github.pull_request.merged",
        at: at(50),
        source: "github",
        attrs: { title: "PR #42 · Update permissions", sha: "a91c328ef401" },
        correlationRef: null,
        connection: { label: "GitHub · API" },
      },
    ],
    totalEvents: 3,
  }
  return servicePage({ detail, demo: true })
}
