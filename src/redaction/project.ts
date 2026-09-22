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
  measurements: { label: string; value: number; baseline?: number }[]
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
        ...(e.baseline !== undefined ? { baseline: e.baseline } : {}),
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

  return {
    finding: {
      category: f.category,
      severity: f.severity,
      title: redactTitle(f.title),
      occurrences: f.count,
    },
    measurements,
    events: [...eventCounts.entries()].map(([kind, count]) => ({ kind, count })),
    subjectDigest: subject,
  }
}

/** The exact request body that would be sent — rendered without sending it. */
export function previewRequest(state: JudgmentState, model: string): string {
  return JSON.stringify(
    {
      model,
      state,
      questions: {
        anomalous: {
          type: "noul",
          instructions: "Is this pattern anomalous rather than ordinary variation?",
        },
        likely_expected_behavior: {
          type: "noul",
          instructions: "Is this most likely expected behaviour for a system of this kind?",
        },
        requires_human_attention: {
          type: "noul",
          instructions: "Should a human investigate this now?",
        },
        severity: {
          type: "score",
          instructions: "How serious is this?",
          criteria: ["informational", "low", "medium", "high", "critical"],
        },
      },
    },
    null,
    2,
  )
}
