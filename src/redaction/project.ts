import { connectorGroups, judgmentGuidance, QUESTION_SET } from "./guidance.ts"
import crypto from "node:crypto"
import type { Evidence } from "../domain/finding.ts"
import type { FindingListItem } from "../store/repo.ts"

// The provider boundary: what a finding looks like by the time a model sees it.
//
// This is an ALLOWLIST, not a redaction pass. A redaction pass removes what you thought to remove;
// an allowlist ships only what you thought to include, which fails safe when a new field appears
// upstream. Adding a field here is a data-protection decision, not a refactor.
//
// Two things never cross, even though a detector uses them freely:
//   · subject identifiers (an agent DID names a real integration, often a real person's service)
//   · source event ids (they are correlation handles into someone else's audit log)
// Subjects become salted digests; source event IDs are omitted entirely.

export interface JudgmentState {
  finding: {
    category: string
    /** Deterministic severity, so the model is refining a judgement rather than inventing one. */
    severity: string
    /** Fixed description; the original free-text title is never forwarded. */
    title: string
    occurrences: number
  }
  context?: {
    questionSet: string
    connectorGroups: string[]
    basis: "provider-alert" | "detector-evidence"
    status: string
  }
  measurements: {
    label: string
    value: number
    baseline?: number
    windowSeconds?: number
    comparison?: "unspecified"
  }[]
  /** Counts only. Never the ids themselves. */
  events: { kind: string; count: number }[]
  subjectDigest: string | null
}

function digest(salt: string, value: string): string {
  return crypto.createHmac("sha256", salt).update(value).digest("hex").slice(0, 16)
}

/** Only product-owned vocabulary can leave; arbitrary event suffixes are private text. */
export function safeEventKind(kind: string): string {
  const allowed =
    /^(?:github\.(?:workflow_run|deployment|rule_suite|pull_request\.(?:updated|merged))|gitlab\.(?:pipeline|deployment|merge_request\.(?:updated|merged))|(?:vercel|cloudflare|netlify)\.deployment|fly\.machine\.(?:started|stopped|destroyed|crashed)|sentry\.(?:error|issue\.(?:created|resolved|unresolved|updated))|(?:challenge|operation)\.(?:created|approved|denied|expired|consumed|escalated)|metrics\.sample|intelligence\.poll|custom\.(?:ci_run|deployment|job\.completed|slo\.sample)|(?:aws-eventbridge|google-monitoring|azure-monitor|google-workspace|stripe|grafana|alertmanager|better-stack)\.provider\.alert|pagerduty\.incident\.(?:triggered|acknowledged|resolved)|opsgenie\.alert\.(?:created|acknowledged|closed)|datadog\.alert\.(?:alert|warn|no_data|recovered))$/
  return allowed.test(kind) ? kind : "other"
}

export function safeMetricLabel(label: string): string {
  if (
    [
      "refusals in window",
      "consecutive failed polls",
      "minutes without a poll",
      "failed runs without a later success",
      "configured completion interval including grace (minutes)",
    ].includes(label)
  )
    return label
  if (/^\d{1,5}m error-budget burn rate$/.test(label)) return label
  if (/^(?:errors|crashes|incidents|refusal rate) in the \d{1,5}m after deploy$/.test(label)) return label
  if (label.startsWith("action: ")) return "refusals for one action type"
  if (label.startsWith("action types never seen from this subject before:"))
    return "previously unseen action types"
  if (/^intyga_[a-z_]+: new failures between samples$/.test(label)) return "new failures between samples"
  if (/^intyga_[a-z_]+: broken objects observed$/.test(label)) return "broken objects observed"
  return "detector measurement"
}

export function projectForJudgment(f: FindingListItem, salt: string): JudgmentState {
  if (f.kind === "observation") throw new Error("Review observations are not anomaly evidence")
  const measurements: JudgmentState["measurements"] = []
  const eventCounts = new Map<string, number>()
  let subject: string | null = null

  for (const e of f.evidence as Evidence[]) {
    if (e.kind === "metric" && Number.isFinite(e.value) && measurements.length < 50) {
      measurements.push({
        // The label can carry an action type, which is tenant-supplied free text and may contain
        // anything at all. Use only controlled measurement descriptions.
        label: safeMetricLabel(e.label),
        value: e.value,
        ...(e.baseline !== undefined && Number.isFinite(e.baseline)
          ? { baseline: e.baseline, comparison: "unspecified" as const }
          : {}),
        ...(Number.isFinite(new Date(e.window.to).getTime() - new Date(e.window.from).getTime())
          ? {
              windowSeconds: Math.max(
                0,
                (new Date(e.window.to).getTime() - new Date(e.window.from).getTime()) / 1000,
              ),
            }
          : {}),
      })
    } else if (e.kind === "eventRef") {
      const kind = safeEventKind(e.eventKind)
      eventCounts.set(kind, (eventCounts.get(kind) ?? 0) + 1)
    }
    // deployment / codeChange / correlation / assessment are deliberately not forwarded in V0:
    // repository paths and SHAs identify a private codebase, and re-sending an assessment would
    // let a model's own previous output feed back in as if it were evidence.
  }

  const m = /did:[A-Za-z0-9._:-]+/.exec(f.title)
  if (m) subject = digest(salt, m[0])

  const kinds = [...eventCounts.keys()]
  const providerAlert = kinds.some((kind) => kind.endsWith(".provider.alert"))
  return {
    context: {
      questionSet: QUESTION_SET,
      connectorGroups: connectorGroups(kinds),
      basis: providerAlert ? "provider-alert" : "detector-evidence",
      status: ["new", "investigating", "resolved", "dismissed"].includes(f.status) ? f.status : "unknown",
    },
    finding: {
      category: ["security", "engineering", "product", "customer", "business"].includes(f.category)
        ? f.category
        : "other",
      severity: ["info", "low", "medium", "high", "critical"].includes(f.severity) ? f.severity : "unknown",
      title: providerAlert ? "Provider-reported alert condition" : "Detector-reported condition",
      occurrences: Number.isSafeInteger(f.count) && f.count >= 0 ? f.count : 0,
    },
    measurements,
    events: [...eventCounts.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([kind, count]) => ({ kind, count })),
    subjectDigest: subject,
  }
}

/** The exact request body that would be sent — rendered without sending it. */
export function previewRequest(state: JudgmentState, model: string): string {
  const guidance = judgmentGuidance(state.events.map((event) => event.kind))
  return JSON.stringify(
    {
      model,
      state,
      questions: {
        anomalous: {
          type: "noul",
          instructions: `${guidance}
How likely is the observed pattern to be anomalous relative to expected operation? Do not equate an alert firing or detector severity with established anomalousness.`,
        },
        likely_expected_behavior: {
          type: "noul",
          instructions: `${guidance}
How likely is this expected behavior? Consider routine activity and functioning safety controls without assuming missing maintenance or change approvals.`,
        },
        requires_human_attention: {
          type: "noul",
          instructions: `${guidance}
Does the supplied evidence justify human investigation now? Account for the finding status: resolved or dismissed is not an active incident unless new evidence explicitly contradicts it. This is a prioritization assessment, never authorization to change a system.`,
        },
        severity: {
          type: "score",
          instructions: `${guidance}
Rate supported impact: informational = context only; low = limited concern; medium = investigation warranted with unclear or limited impact; high = evidence of significant disruption or policy failure; critical = evidence of severe ongoing harm requiring immediate response. Do not infer critical impact from a provider label alone. Severity confidence describes this severity assessment, not the anomaly answer.`,
          criteria: ["informational", "low", "medium", "high", "critical"],
        },
      },
    },
    null,
    2,
  )
}
