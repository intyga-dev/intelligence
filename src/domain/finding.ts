// The Finding domain. Pure — no IO, no Prisma, no network — so every rule here is unit-testable
// without a database, and so the rules cannot quietly acquire a dependency on a live system.
//
// The load-bearing idea is the Evidence union: exactly ONE variant carries model output, and the
// type system refuses a Finding that rests only on it. "The AI thinks this is dangerous" is not a
// finding; it is at most an annotation on one.

/** What kind of attention a finding asks for. Only "security"/"engineering" have detectors in V0. */
export type Category = "security" | "engineering" | "product" | "customer" | "business"

export type Severity = "info" | "low" | "medium" | "high" | "critical"

export type FindingStatus = "new" | "investigating" | "resolved" | "dismissed"

/** Half-open observation window: `from` included, `to` excluded. */
export interface Window {
  from: Date
  to: Date
}

/** A pointer at something observable in a connected source. */
export interface Ref {
  connectionId: string
  sourceId: string
}

// ─── Evidence ────────────────────────────────────────────────────────────────────────────────────
// Split deliberately into two exported unions rather than one flat type. `DeterministicEvidence` is
// "a thing we measured or read"; `AssessmentEvidence` is "a thing a model said". Keeping them
// separate at the type level is what lets `EvidenceList` below encode the house rule.

/** A number we computed, with the baseline it is being judged against. */
export interface MetricEvidence {
  kind: "metric"
  label: string
  value: number
  /** Absent when there is no prior period to compare with — a first observation, not a zero. */
  baseline?: number
  window: Window
}

/** One specific source event, so a reader can go and look at it. */
export interface EventRefEvidence {
  kind: "eventRef"
  connectionId: string
  sourceId: string
  at: Date
  eventKind: string
}

export interface DeploymentEvidence {
  kind: "deployment"
  sha: string
  workflow: string
  at: Date
  conclusion: string
}

export interface CodeChangeEvidence {
  kind: "codeChange"
  repo: string
  pr: number
  sha: string
  paths: string[]
}

/** A deterministic join — two observed things and the relationship we computed between them. */
export interface CorrelationEvidence {
  kind: "correlation"
  left: Ref
  right: Ref
  relation: string
  lagMs: number
}

/**
 * Model output. Carries its own calibration so a reader can weigh it, and `stateDigest` so anyone
 * can re-derive exactly what the model was shown. Never a fact — always an opinion about facts.
 */
export interface AssessmentEvidence {
  kind: "assessment"
  provider: string
  model: string
  question: string
  answer: number | string
  probability?: number
  confidence?: number
  /** sha256 of the exact request state, so "what did it see" is answerable after the fact. */
  stateDigest: string
}

export type DeterministicEvidence =
  | MetricEvidence
  | EventRefEvidence
  | DeploymentEvidence
  | CodeChangeEvidence
  | CorrelationEvidence

export type Evidence = DeterministicEvidence | AssessmentEvidence

/**
 * A non-empty evidence list whose FIRST element cannot be an assessment.
 *
 * This is the house rule as a type: a Finding backed only by model output is unrepresentable, so it
 * is a compile error rather than a runtime check someone can forget to call. `isDeterministic`
 * below is the runtime half, for evidence that arrives from the database as `Evidence[]`.
 */
export type EvidenceList = readonly [DeterministicEvidence, ...Evidence[]]

export function isDeterministic(e: Evidence): e is DeterministicEvidence {
  return e.kind !== "assessment"
}

// ─── Finding ─────────────────────────────────────────────────────────────────────────────────────

export interface Finding {
  id: string
  tenantId: string
  category: Category
  severity: Severity
  title: string
  summary?: string
  evidence: EvidenceList
  /** 0..1. Detector confidence, NOT model confidence — that lives on the assessment. */
  confidence?: number
  detectedAt: Date
  lastSeenAt: Date
  /** How many times this same condition has been observed. Upserts increment it. */
  count: number
  status: FindingStatus
  /**
   * Stable identity of the CONDITION, not the occurrence. Two runs of the same detector over an
   * ongoing condition must produce the same key, or the list grows once per tick and the product
   * (a short prioritised list) stops existing.
   */
  dedupeKey: string
}

export class FindingRuleError extends Error {}

export const SEVERITY_RANK: Readonly<Record<Severity, number>> = Object.freeze({
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
})

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_RANK[a] - SEVERITY_RANK[b]
}

/** Most severe first; ties broken by most recently seen. The order the UI renders in. */
export function prioritise(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => compareSeverity(b.severity, a.severity) || b.lastSeenAt.getTime() - a.lastSeenAt.getTime(),
  )
}

export interface NewFinding {
  id: string
  tenantId: string
  category: Category
  severity: Severity
  title: string
  summary?: string
  evidence: EvidenceList
  confidence?: number
  detectedAt: Date
  dedupeKey: string
}

/**
 * Construct a Finding, enforcing the rules the type system cannot reach.
 *
 * The assessment-only rule is already a compile error via `EvidenceList`, but evidence read back
 * from the database arrives as a plain array, so `fromStoredEvidence` re-checks it at the boundary.
 */
export function createFinding(input: NewFinding): Finding {
  if (input.title.trim() === "") throw new FindingRuleError("a finding needs a title")
  if (input.dedupeKey.trim() === "") throw new FindingRuleError("a finding needs a dedupeKey")
  if (input.confidence !== undefined && (input.confidence < 0 || input.confidence > 1)) {
    throw new FindingRuleError(`confidence must be in 0..1, got ${input.confidence}`)
  }
  return {
    ...input,
    lastSeenAt: input.detectedAt,
    count: 1,
    status: "new",
  }
}

/**
 * Validate evidence coming back from storage, where the tuple type has been erased.
 *
 * Deliberately a throw rather than a filter: silently dropping the assessment would hide that the
 * row is malformed, and silently keeping it would let an assessment-only finding exist after a
 * round-trip — the exact thing `EvidenceList` exists to prevent.
 */
export function fromStoredEvidence(rows: readonly Evidence[]): EvidenceList {
  const first = rows[0]
  if (!first) throw new FindingRuleError("a finding needs at least one piece of evidence")
  if (!isDeterministic(first)) {
    const deterministic = rows.find(isDeterministic)
    if (!deterministic) {
      throw new FindingRuleError(
        "a finding needs at least one deterministic piece of evidence — model output alone is not a finding",
      )
    }
    return [deterministic, ...rows.filter((r) => r !== deterministic)] as const as EvidenceList
  }
  return [first, ...rows.slice(1)] as const as EvidenceList
}

/** Fold a repeat observation into an existing finding rather than creating a second one. */
export function observeAgain(finding: Finding, at: Date, severity?: Severity): Finding {
  return {
    ...finding,
    count: finding.count + 1,
    lastSeenAt: at > finding.lastSeenAt ? at : finding.lastSeenAt,
    severity: severity && compareSeverity(severity, finding.severity) > 0 ? severity : finding.severity,
  }
}
