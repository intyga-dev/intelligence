import type { NormalizedEvent } from "../../connectors/types.ts"
import { createFinding, type DeterministicEvidence, type EvidenceList, type Finding } from "../finding.ts"
import { classifyChangedPaths, type PathMap } from "../sensitivity.ts"

// Detector 2 — a pull request that touches security-sensitive code.
//
// Arithmetic over a changed-file list, nothing more: which configured components the diff lands
// on, after noise is removed. It does not judge whether the change is GOOD — that is a reviewer's
// job, and the point is that a reviewer who owns that area sees it. The optional judgment layer may
// later calibrate severity; it can never be why this fires.
//
// Two finding kinds per pull request:
//   · `sensitive:` — the diff touches one or more components. Severity is the highest floor hit.
//   · `mirror:`    — the map declares paths that must change together, and this diff changed some
//                    but not all of them. Only for maps that declare a mirror (intyga-core today),
//                    and never from a truncated file list: that rule reasons from ABSENCE.
//
// One finding per pull request, not per push. A new push arrives as a new event with a new head SHA,
// and folds into the same finding (count + 1, evidence replaced with the latest diff). The caller
// feeds each event once — see DetectorCursor.

/** Pull requests (GitHub) and merge requests (GitLab). Both connectors emit the same attrs shape. */
export const SENSITIVE_PR_KINDS = [
  "github.pull_request.updated",
  "github.pull_request.merged",
  "gitlab.merge_request.updated",
  "gitlab.merge_request.merged",
] as const

/** How a change is written in a title: `acme/app#12` on GitHub, `group/app!12` on GitLab. */
export function changeRef(e: NormalizedEvent, repo: string, n: number): { noun: string; ref: string } {
  return e.source === "gitlab" ? { noun: "MR", ref: `${repo}!${n}` } : { noun: "PR", ref: `${repo}#${n}` }
}

/** Listing every changed path would bury the ones that matter; the hit paths are what a reader needs. */
const MAX_EVIDENCE_PATHS = 50

export interface SensitiveChangeInput {
  tenantId: string
  events: readonly NormalizedEvent[]
  now: Date
  /** The component map for each GitHub connection. A connection absent here gets the generic map. */
  mapFor: (connectionId: string) => PathMap
  idFor?: (dedupeKey: string) => string
}

interface PrAttrs {
  repo: string
  number: number
  title: string
  sha: string
  draft: boolean
  merged: boolean
  paths: string[]
  truncated: boolean
}

/** Read a pull-request event's attrs, or null if it is not one this detector can use. */
export function prAttrs(e: NormalizedEvent): PrAttrs | null {
  const a = e.attrs as Record<string, unknown>
  if (typeof a.repo !== "string" || typeof a.number !== "number") return null
  let paths: unknown
  try {
    paths = JSON.parse(String(a.paths ?? "[]"))
  } catch {
    return null
  }
  if (!Array.isArray(paths) || !paths.every((p) => typeof p === "string")) return null
  return {
    repo: a.repo,
    number: a.number,
    title: String(a.title ?? ""),
    sha: String(a.sha ?? ""),
    draft: a.draft === true,
    merged: a.merged === true,
    paths,
    truncated: a.pathsTruncated === true,
  }
}

export function detectSensitiveChanges(input: SensitiveChangeInput): Finding[] {
  // Latest event per pull request only: two pushes in one batch are one observation of the PR.
  const latest = new Map<string, NormalizedEvent>()
  for (const e of input.events) {
    if (!(SENSITIVE_PR_KINDS as readonly string[]).includes(e.kind)) continue
    const a = prAttrs(e)
    if (!a) continue
    const key = `${e.connectionId}\u0000${a.repo}#${a.number}`
    const prev = latest.get(key)
    if (!prev || e.at > prev.at) latest.set(key, e)
  }

  const findings: Finding[] = []
  for (const e of latest.values()) {
    const a = prAttrs(e) as PrAttrs
    // A draft is a work in progress its author has not asked anyone to look at yet. It is judged
    // when it is marked ready, which arrives as a new event.
    if (a.draft) continue

    const res = classifyChangedPaths(a.paths, { truncated: a.truncated, map: input.mapFor(e.connectionId) })
    const { noun, ref: pr } = changeRef(e, a.repo, a.number)
    const ref: DeterministicEvidence = {
      kind: "eventRef",
      connectionId: e.connectionId,
      sourceId: e.sourceId,
      at: e.at,
      eventKind: e.kind,
    }

    if (res.hits.length > 0 && res.severityFloor) {
      const hitPaths = [...new Set(res.hits.flatMap((h) => h.paths))]
      const dedupeKey = `sensitive:${e.connectionId}:${pr}`
      const evidence: EvidenceList = [
        {
          kind: "codeChange",
          repo: a.repo,
          pr: a.number,
          sha: a.sha,
          paths: hitPaths.slice(0, MAX_EVIDENCE_PATHS),
        },
        ref,
      ]
      findings.push(
        createFinding({
          id: input.idFor?.(dedupeKey) ?? dedupeKey,
          tenantId: input.tenantId,
          category: "security",
          severity: res.severityFloor,
          title: `${a.merged ? "Merged" : "Open"} ${noun} ${pr} changes ${res.hits.map((h) => h.component.id).join(", ")}`,
          summary:
            `"${a.title}" touches ${hitPaths.length} security-sensitive file(s). ` +
            res.hits.map((h) => `${h.component.id}: ${h.component.rationale}`).join(" ") +
            (a.truncated ? " The file list was truncated, so more may be affected." : ""),
          evidence,
          detectedAt: input.now,
          dedupeKey,
        }),
      )
    }

    const m = res.mirror
    if (m && !m.complete && m.reliable) {
      const dedupeKey = `mirror:${e.connectionId}:${pr}`
      const total = m.touched.length + m.missing.length
      const evidence: EvidenceList = [
        {
          kind: "codeChange",
          repo: a.repo,
          pr: a.number,
          sha: a.sha,
          paths: res.considered.slice(0, MAX_EVIDENCE_PATHS),
        },
        ref,
      ]
      findings.push(
        createFinding({
          id: input.idFor?.(dedupeKey) ?? dedupeKey,
          tenantId: input.tenantId,
          category: "security",
          severity: "critical",
          title:
            m.missing.length > 0
              ? `${noun} ${pr} updates ${m.touched.length} of ${total} mirrored ports`
              : `${noun} ${pr} updates every mirrored port but not the pinned vectors`,
          summary:
            `"${a.title}" changes code that must move together. ` +
            (m.missing.length > 0 ? `Not touched: ${m.missing.join(", ")}. ` : "") +
            (m.vectorsUpdated ? "" : "The pinned vectors were not updated. ") +
            "A partial update makes artefacts produced by one port fail verification in another.",
          evidence,
          detectedAt: input.now,
          dedupeKey,
        }),
      )
    }
  }
  return findings
}
