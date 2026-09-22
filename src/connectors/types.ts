// The connector seam. Every source — Intyga, GitHub, and whatever comes later — reduces to a
// NormalizedEvent, and detectors only ever see this shape. That is what makes "Intyga is one
// connector" true in the code rather than only in the README.

/**
 * The connector kind, as a free string.
 *
 * Deliberately not a closed union. A union would mean adding a connector edits this file, the
 * Prisma enum and a migration — which is exactly the friction that keeps sources from being added.
 * The in-code registry is the source of truth, and an unrecognised kind is inert rather than fatal.
 */
export type SourceKind = string

/**
 * One observed thing from a connected source.
 *
 * Deliberately narrow. `attrs` is a bag, but everything a detector groups or correlates on is a
 * named column: adding a new grouping dimension should be a schema change someone reviews, not a
 * new string key that silently appears.
 */
export interface NormalizedEvent {
  connectionId: string
  source: SourceKind
  /** Idempotency key within the source. Unique per (connectionId, sourceId). */
  sourceId: string
  /** Source-qualified event name, e.g. "challenge.denied" or "github.pull_request.opened". */
  kind: string
  at: Date
  /** The identity a finding is attributed to (an agent DID, a PR author). Null when not applicable. */
  subjectRef: string | null
  /** Ties related events together within a source (a challenge nonce, a commit SHA). */
  correlationRef: string | null
  attrs: Record<string, string | number | boolean | null>
}

/** A configured source for one Intelligence tenant. */
export interface Connection {
  id: string
  tenantId: string
  kind: SourceKind
  label: string
  active: boolean
}
