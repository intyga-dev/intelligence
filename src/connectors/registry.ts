import type { NormalizedEvent } from "./types.ts"

// The connector seam.
//
// Adding a source is writing ONE file and registering it — no migration, no schema change, no edit
// to the ingest route or the tick job. `Connection.kind` is free text resolved against this
// registry, so an unknown kind is an inert row rather than a failed deploy, and a connector can be
// removed from a build without orphaning data.
//
// Two modes, because sources genuinely differ:
//   · push — the source calls us (Intyga webhooks). Authentication is per-request, by signature.
//   · poll — we call the source (GitHub API). Authentication is a stored token, position is a cursor.
//
// Everything reduces to NormalizedEvent. Detectors never learn where an event came from, which is
// what makes "Intyga is one connector among several" true in the code rather than only in prose.

export interface ConnectorField {
  name: string
  label: string
  placeholder?: string
  help?: string
  required?: boolean
  /** Rendered as a password input and never echoed back to the client. */
  secret?: boolean
}

export interface ConnectorContext {
  connectionId: string
  tenantId: string
  config: Record<string, unknown>
  /** Decrypted. Null when the connector needs none. */
  secret: string | null
  getCursor(name: string): Promise<string | null>
  setCursor(name: string, value: string): Promise<void>
  log(message: string, data?: Record<string, unknown>): void
}

export type VerifyOutcome = { ok: true } | { ok: false; reason: string }

interface Base {
  kind: string
  label: string
  /** One line, shown on the connector catalogue. */
  blurb: string
  /** Fields the "add connector" form renders. */
  fields: ConnectorField[]
  /** Step-by-step setup shown after the connector is created. */
  setup: string[]
  /**
   * Built-in connectors are provisioned with the tenant and cannot be removed, only switched off.
   * Intyga is built in because every tenant already has the relationship.
   */
  builtIn?: boolean
}

export interface PushConnector extends Base {
  mode: "push"
  /**
   * Whether this connector MINTS its shared secret, or is given one.
   *
   * Intyga mints: we generate the signing key and the producer is told it, so nothing travels back.
   * Sentry is given: the secret already exists in their integration and is pasted in. The
   * difference decides whether the add-form shows a secret field or a one-time reveal.
   */
  generatesSecret: boolean
  verify(input: {
    headers: Record<string, string | string[] | undefined>
    rawBody: string
    secret: string
  }): VerifyOutcome
  /** The source's own id for this delivery — the idempotency key. */
  eventId(headers: Record<string, string | string[] | undefined>, body: unknown): string | null
  normalize(input: { connectionId: string; body: unknown; receivedAt: Date }): NormalizedEvent | null
}

export interface PollConnector extends Base {
  mode: "poll"
  /**
   * Fetch what is new. MUST be bounded and MUST advance its cursor only after the events it
   * returns have been handed back — the caller persists them, so advancing early loses data on a
   * crash between the two.
   */
  poll(ctx: ConnectorContext): Promise<NormalizedEvent[]>
}

export type ConnectorDefinition = PushConnector | PollConnector

const registry = new Map<string, ConnectorDefinition>()

export function registerConnector(def: ConnectorDefinition): void {
  if (registry.has(def.kind)) throw new Error(`connector already registered: ${def.kind}`)
  registry.set(def.kind, def)
}

/** Null for an unknown kind — a row for a connector this build does not ship is inert, not fatal. */
export function connectorFor(kind: string): ConnectorDefinition | null {
  return registry.get(kind) ?? null
}

export function allConnectors(): ConnectorDefinition[] {
  return [...registry.values()].sort((a, b) => {
    if (a.builtIn !== b.builtIn) return a.builtIn ? -1 : 1
    return a.label.localeCompare(b.label)
  })
}

export function isPush(d: ConnectorDefinition): d is PushConnector {
  return d.mode === "push"
}
export function isPoll(d: ConnectorDefinition): d is PollConnector {
  return d.mode === "poll"
}
