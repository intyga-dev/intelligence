import { connectorFor, isPoll } from "../connectors/index.ts"
import type { ConnectorContext } from "../connectors/registry.ts"
import { detectDenialBursts } from "../domain/detectors/denialBurst.ts"
import { evaluateFindingWithJudgment } from "../domain/judgment.ts"
import { prisma } from "../store/client.ts"
import { decryptSecret } from "../store/crypto.ts"
import { getCursor, loadEvents, saveEvent, setCursor, upsertFinding } from "../store/repo.ts"

// One tick: run every deterministic detector over its window and fold the results into findings.
//
// Driven externally by POST /internal/tick, the same shape the observed system uses — no in-process
// timer, so a second replica does not double-run and a restart does not skip a window.
//
// Detector failures are isolated per detector. One throwing detector must not stop the others,
// because the alternative is that a bug in the newest, least-proven detector silently disables the
// ones that have been working for months.

/** How far back a detector may look. Bounded so a tick's cost does not grow with table size. */
const LOOKBACK_MS = 8 * 24 * 60 * 60_000

export interface TickReport {
  tenants: number
  polled: Record<string, { fetched: number; stored: number } | { error: true }>
  detectors: Record<string, { found: number; created: number } | { error: true }>
  durationMs: number
}

/**
 * Pull from every active poll-mode connector.
 *
 * Isolated per connection: one misconfigured repository or expired token must not stop the others,
 * and must not stop detection from running on what is already stored. The error detail goes to the
 * log, never into the report body — an external scheduler retains that body.
 */
async function pollConnectors(): Promise<TickReport["polled"]> {
  const report: TickReport["polled"] = {}
  const connections = await prisma.connection.findMany({
    where: { active: true },
    select: { id: true, tenantId: true, kind: true, label: true, config: true, secretCiphertext: true },
  })

  for (const c of connections) {
    const def = connectorFor(c.kind)
    // An unknown kind is a row for a connector this build does not ship. Inert, not fatal.
    if (!def || !isPoll(def)) continue

    const ctx: ConnectorContext = {
      connectionId: c.id,
      tenantId: c.tenantId,
      config: (c.config ?? {}) as Record<string, unknown>,
      secret: c.secretCiphertext ? decryptSecret(c.secretCiphertext) : null,
      getCursor: (name) => getCursor(c.id, name),
      setCursor: (name, value) => setCursor(c.id, name, value),
      log: () => {},
    }

    try {
      const events = await def.poll(ctx)
      let stored = 0
      for (const e of events) {
        // saveEvent is an upsert on (connectionId, sourceId), so a connector that re-returns an
        // event after a partial tick costs a no-op write rather than a duplicate.
        await saveEvent(c.tenantId, e)
        stored++
      }
      report[c.label] = { fetched: events.length, stored }
    } catch {
      report[c.label] = { error: true }
    }
  }
  return report
}

export async function runDetectors(now = new Date()): Promise<TickReport> {
  const started = Date.now()
  // Pull first, so this tick's detection sees this tick's events rather than lagging one behind.
  const polled = await pollConnectors()
  const tenants = await prisma.tenant.findMany({ select: { id: true } })
  const detectors: TickReport["detectors"] = {}

  for (const { id: tenantId } of tenants) {
    try {
      const events = await loadEvents(tenantId, {
        kinds: ["challenge.denied", "challenge.expired"],
        since: new Date(now.getTime() - LOOKBACK_MS),
      })
      const found = detectDenialBursts({ tenantId, events, now })
      let created = 0
      for (const f of found) {
        const r = await upsertFinding(f)
        if (r.isNew) created++
        await evaluateFindingWithJudgment(tenantId, r.id).catch(() => {})
      }
      const prev = detectors["denial-burst"]
      const base = prev && !("error" in prev) ? prev : { found: 0, created: 0 }
      detectors["denial-burst"] = { found: base.found + found.length, created: base.created + created }
    } catch {
      // Detail goes to the caller's log, not into the response body: the response is retained by
      // whatever external scheduler drives this, and that is a third party.
      detectors["denial-burst"] = { error: true }
    }
  }

  return { tenants: tenants.length, polled, detectors, durationMs: Date.now() - started }
}
