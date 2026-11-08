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
// Both become salted digests, so the model can still reason about "the same subject, repeatedly"
// without being told who that is.

export interface JudgmentState {
  finding: {
    category: string
    /** Deterministic severity, so the model is refining a judgement rather than inventing one. */
    severity: string
    /** Structural title with identifiers stripped — see `redactTitle`. */
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

/**
 * Strip identifiers out of a human-written title.
 *
 * Titles are built by detectors and contain DIDs by design ("17 refused operations from
 * did:intyga:agent-001") because a human reading the console needs to know WHO. A model does not,
 * and a DID in a prompt is an identifier leaving the building.
 */
export function redactTitle(title: string): string {
  return title
    .replace(/did:[A-Za-z0-9._:-]+/g, "<subject>")
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<id>")
    .replace(/\b[\w.+-]+@[\w-]+\.[\w.]+\b/g, "<email>")
}

export function projectForJudgment(f: FindingListItem, salt: string): JudgmentState {
  if (f.kind === "observation") throw new Error("Review observations are not anomaly evidence")
  const measurements: JudgmentState["measurements"] = []
  const eventCounts = new Map<string, number>()
  let subject: string | null = null

  for (const e of f.evidence as Evidence[]) {
    if (e.kind === "metric") {
      measurements.push({
        // The label can carry an action type, which is tenant-supplied free text and may contain
        // anything at all. Redacted on the same rules as the title.
        label: redactTitle(e.label),
        value: e.value,
        ...(e.baseline !== undefined ? { baseline: e.baseline, comparison: "unspecified" as const } : {}),
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
      eventCounts.set(e.eventKind, (eventCounts.get(e.eventKind) ?? 0) + 1)
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
      status: f.status,
    },
    finding: {
      category: f.category,
      severity: f.severity,
      title: providerAlert ? "Provider-reported alert condition" : redactTitle(f.title),
      occurrences: f.count,
    },
    measurements,
    events: [...eventCounts.entries()].map(([kind, count]) => ({ kind, count })),
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
