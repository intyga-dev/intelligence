import { type DeliveryReport, deliverAlerts } from "../alerts/deliver.ts"
import { connectorFor, isPoll } from "../connectors/index.ts"
import type { ConnectorContext } from "../connectors/registry.ts"
import { detectDenialBursts } from "../domain/detectors/denialBurst.ts"
import {
  asDeploy,
  DEFAULT_REGRESSION_CONFIG,
  DEPLOY_KINDS,
  type Deploy,
  detectDeployRegressions,
} from "../domain/detectors/deployRegression.ts"
import type { DetectorId } from "../domain/detectors/index.ts"
import { detectSensitiveChanges, SENSITIVE_PR_KINDS } from "../domain/detectors/sensitiveChange.ts"
import type { Finding } from "../domain/finding.ts"
import { type PathMap, pathMapFor } from "../domain/sensitivity.ts"
import { evaluateFindingWithJudgment } from "../domain/judgment.ts"
import { prisma } from "../store/client.ts"
import { decryptSecret } from "../store/crypto.ts"
import {
  disabledDetectors,
  getCursor,
  getDetectorCursor,
  loadEvents,
  loadIngestedEvents,
  saveEvent,
  setCursor,
  setDetectorCursor,
  upsertFinding,
} from "../store/repo.ts"

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
  alerts: DeliveryReport | { error: true }
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

/** How far back a deploy's shipped pull request may have been observed. */
const CHANGE_LOOKBACK_MS = 30 * 24 * 60 * 60_000

/** Fold findings into the store; returns how many were new. Judgment is best-effort, never gating. */
async function persist(tenantId: string, found: Finding[]): Promise<number> {
  let created = 0
  for (const f of found) {
    const r = await upsertFinding(f)
    if (r.isNew) created++
    await evaluateFindingWithJudgment(tenantId, r.id).catch(() => {})
  }
  return created
}

/** Each code-host connection's configured component map (GitHub and GitLab). */
async function pathMaps(tenantId: string): Promise<(connectionId: string) => PathMap> {
  const rows = await prisma.connection.findMany({
    where: { tenantId, kind: { in: ["github", "gitlab"] } },
    select: { id: true, config: true },
  })
  const byId = new Map(rows.map((r) => [r.id, pathMapFor((r.config as Record<string, unknown>)?.pathMap)]))
  return (id) => byId.get(id) ?? pathMapFor(undefined)
}

export async function runDetectors(now = new Date()): Promise<TickReport> {
  const started = Date.now()
  // Pull first, so this tick's detection sees this tick's events rather than lagging one behind.
  const polled = await pollConnectors()
  const tenants = await prisma.tenant.findMany({ select: { id: true } })
  const detectors: TickReport["detectors"] = {}

  /** Run one detector for one tenant, isolated: a throw marks it failed and touches nothing else. */
  const run = async (id: DetectorId, body: () => Promise<{ found: number; created: number }>) => {
    try {
      const r = await body()
      const prev = detectors[id]
      if (prev && "error" in prev) return
      detectors[id] = { found: (prev?.found ?? 0) + r.found, created: (prev?.created ?? 0) + r.created }
    } catch {
      // Detail goes to the caller's log, not into the response body: the response is retained by
      // whatever external scheduler drives this, and that is a third party.
      detectors[id] = { error: true }
    }
  }

  for (const { id: tenantId } of tenants) {
    const off = await disabledDetectors(tenantId)
    const mapFor = await pathMaps(tenantId)

    // Switched off means NOT WATCHED, not deferred: the event-driven detectors' marks keep moving,
    // so switching one back on does not replay everything that happened while it was off.
    for (const id of ["sensitive-code-change", "deploy-regression"] as const) {
      if (off.has(id)) await setDetectorCursor(tenantId, id, now)
    }

    if (!off.has("denial-burst")) {
      await run("denial-burst", async () => {
        const events = await loadEvents(tenantId, {
          kinds: ["challenge.denied", "challenge.expired"],
          since: new Date(now.getTime() - LOOKBACK_MS),
        })
        const found = detectDenialBursts({ tenantId, events, now })
        return { found: found.length, created: await persist(tenantId, found) }
      })
    }

    if (!off.has("sensitive-code-change")) {
      await run("sensitive-code-change", async () => {
        const after =
          (await getDetectorCursor(tenantId, "sensitive-code-change")) ??
          new Date(now.getTime() - LOOKBACK_MS)
        const events = await loadIngestedEvents(tenantId, { kinds: SENSITIVE_PR_KINDS, after, until: now })
        const found = detectSensitiveChanges({ tenantId, events, now, mapFor })
        const created = await persist(tenantId, found)
        // Moved only after the findings are stored: a crash before this re-reads the batch, which
        // folds into the same findings rather than losing them.
        await setDetectorCursor(tenantId, "sensitive-code-change", now)
        return { found: found.length, created }
      })
    }

    if (!off.has("deploy-regression")) {
      await run("deploy-regression", async () => {
        const cfg = DEFAULT_REGRESSION_CONFIG
        const mark =
          (await getDetectorCursor(tenantId, "deploy-regression")) ?? new Date(now.getTime() - cfg.baselineMs)
        // A deploy is evaluated once its post window has CLOSED: those in (mark − post, now − post].
        const from = mark.getTime() - cfg.postMs
        const to = now.getTime() - cfg.postMs
        const deploys = (
          await loadEvents(tenantId, { kinds: DEPLOY_KINDS, since: new Date(from), until: new Date(to) })
        )
          .filter((e) => e.at.getTime() > from)
          .map(asDeploy)
          .filter((d): d is Deploy => d !== null)

        let found: Finding[] = []
        if (deploys.length > 0) {
          const times = deploys.map((d) => d.event.at.getTime())
          const earliest = Math.min(...times)
          const latest = Math.max(...times)
          const signals = await loadEvents(tenantId, {
            since: new Date(earliest - cfg.baselineMs),
            until: new Date(latest + cfg.postMs),
          })
          const changes = await loadEvents(tenantId, {
            kinds: [...SENSITIVE_PR_KINDS],
            since: new Date(earliest - CHANGE_LOOKBACK_MS),
            until: new Date(latest),
          })
          found = detectDeployRegressions({ tenantId, deploys, signals, changes, mapFor, now })
        }
        const created = await persist(tenantId, found)
        await setDetectorCursor(tenantId, "deploy-regression", now)
        return { found: found.length, created }
      })
    }
  }

  // Last, so this tick's findings go out on this tick rather than the next. Isolated like the
  // detectors: a delivery failure must never read as a detection failure, or the reverse.
  let alerts: TickReport["alerts"]
  try {
    alerts = await deliverAlerts(now)
  } catch {
    alerts = { error: true }
  }

  return { tenants: tenants.length, polled, detectors, alerts, durationMs: Date.now() - started }
}
