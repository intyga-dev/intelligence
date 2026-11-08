import type { NormalizedEvent } from "../connectors/types.ts"
import {
  detectCiHealth,
  detectCollectionHealth,
  detectMergePolicy,
  detectOverdueJobs,
  detectServiceDegradation,
} from "../domain/detectors/operational.ts"
import { operationalSettings, type OperationalDetector } from "../domain/detectors/operationalSettings.ts"
import type { DetectorId } from "../domain/detectors/index.ts"
import type { Finding } from "../domain/finding.ts"
import { prisma } from "../store/client.ts"
import { loadEvents, upsertFinding } from "../store/repo.ts"
import {
  detectProviderAlerts,
  PROVIDER_ALERT_KINDS,
  providerAlertKey,
} from "../domain/detectors/providerAlerts.ts"

type Runner = (id: DetectorId, body: () => Promise<{ found: number; created: number }>) => Promise<void>
const DAY = 86_400_000

/** Replay-safe persistence: repeated ticks over the same evidence never reopen dismissed incidents. */
async function persistFresh(found: Finding[]) {
  let created = 0,
    changed = 0
  for (const f of found) {
    const existing = await prisma.finding.findUnique({
      where: { tenantId_dedupeKey: { tenantId: f.tenantId, dedupeKey: f.dedupeKey } },
      select: { lastSeenAt: true },
    })
    if (existing && existing.lastSeenAt >= f.lastSeenAt) continue
    const result = await upsertFinding(f)
    changed++
    if (result.isNew) created++
  }
  // These detectors already state a concrete failure condition. No speculative anomaly scoring.
  return { found: changed, created }
}

export async function runOperationalDetectors(tenantId: string, now: Date, off: Set<string>, run: Runner) {
  const sources = await prisma.connection.findMany({
    where: { tenantId, active: true },
    select: {
      id: true,
      label: true,
      kind: true,
      active: true,
      activatedAt: true,
      serviceId: true,
      lastPollSuccessAt: true,
      lastPollError: true,
    },
  })
  const rows = await prisma.detectorConfig.findMany({ where: { tenantId } })
  const raw = (id: OperationalDetector) => rows.find((r) => r.detector === id)?.settings ?? {}
  const settingsStart = (id: OperationalDetector) => rows.find((r) => r.detector === id)?.updatedAt
  if (!off.has("provider-alerts"))
    await run("provider-alerts", async () => {
      const start = rows.find((r) => r.detector === "provider-alerts")?.updatedAt
      const events = await loadEvents(tenantId, {
        kinds: PROVIDER_ALERT_KINDS,
        since: new Date(Math.max(now.getTime() - 7 * DAY, start?.getTime() ?? 0)),
        until: now,
      })
      if (events.length >= 50_000) throw new Error("Provider alert window exceeds limit")
      const detected = detectProviderAlerts({ tenantId, now, sources, events })
      const result = await persistFresh(detected.findings)
      for (const event of detected.resolved) {
        await prisma.$transaction(async (tx) => {
          const existing = await tx.finding.findUnique({
            where: { tenantId_dedupeKey: { tenantId, dedupeKey: providerAlertKey(event) } },
          })
          if (
            !existing ||
            existing.lastSeenAt > event.at ||
            !["new", "investigating"].includes(existing.status)
          )
            return
          await tx.finding.update({
            where: { id: existing.id },
            data: {
              status: "resolved",
              lastSeenAt: event.at,
              summary: `${event.source} explicitly reported this alert resolved at ${event.at.toISOString()}. Provider closure does not imply that every consequence of the incident has been remediated.`,
            },
          })
          const ordinal = await tx.evidence.count({ where: { findingId: existing.id } })
          await tx.evidence.create({
            data: {
              findingId: existing.id,
              kind: "eventRef",
              ordinal,
              data: {
                kind: "eventRef",
                connectionId: event.connectionId,
                sourceId: event.sourceId,
                at: event.at.toISOString(),
                eventKind: event.kind,
              },
            },
          })
        })
      }
      return result
    })
  const watchedSources = (id: OperationalDetector) =>
    sources.map((s) => ({
      ...s,
      activatedAt: new Date(Math.max(s.activatedAt?.getTime() ?? 0, settingsStart(id)?.getTime() ?? 0)),
    }))
  const data = async (id: OperationalDetector, kinds: string[], since: Date) => {
    const events = await loadEvents(tenantId, { kinds, since, until: now })
    if (events.length >= 50_000) throw new Error("Operational event window exceeds collection limit")
    return { tenantId, now, sources: watchedSources(id), events }
  }
  // Capture observed poll history only; never reinterpret a silent push connector as a failed poll.
  if (!off.has("collection-health"))
    await run("collection-health", async () =>
      persistFresh(
        detectCollectionHealth(
          await data("collection-health", ["intelligence.poll"], new Date(now.getTime() - DAY)),
          operationalSettings("collection-health", raw("collection-health")),
        ),
      ),
    )
  if (!off.has("ci-health"))
    await run("ci-health", async () => {
      const input = await data(
        "ci-health",
        ["github.workflow_run", "github.deployment", "custom.ci_run"],
        new Date(now.getTime() - 7 * DAY),
      )
      // Failure to collect CI is unknown CI state, not proof that the branch is still broken.
      input.sources = input.sources.filter(
        (s) =>
          s.kind !== "github" ||
          (!s.lastPollError &&
            s.lastPollSuccessAt &&
            now.getTime() - s.lastPollSuccessAt.getTime() < 15 * 60_000),
      )
      return persistFresh(detectCiHealth(input, operationalSettings("ci-health", raw("ci-health"))))
    })
  if (!off.has("merge-policy"))
    await run("merge-policy", async () =>
      persistFresh(
        detectMergePolicy(
          await data("merge-policy", ["github.rule_suite"], settingsStart("merge-policy") ?? now),
          operationalSettings("merge-policy", raw("merge-policy")),
        ),
      ),
    )
  if (!off.has("job-overdue"))
    await run("job-overdue", async () => {
      const cfg = operationalSettings("job-overdue", raw("job-overdue"))
      const events: NormalizedEvent[] = []
      for (const t of cfg.targets) {
        // Last completion may predate the ordinary detector lookback; do not invent a missed job by truncating history.
        const source = sources.find((s) => s.id === t.connectionId)
        if (!source) continue
        const event = await prisma.event.findFirst({
          where: {
            tenantId,
            connectionId: t.connectionId,
            serviceId: source.serviceId,
            kind: "custom.job.completed",
            at: { lte: now },
            AND: [
              { attrs: { path: ["job"], equals: t.job } },
              { attrs: { path: ["succeeded"], equals: true } },
            ],
          },
          orderBy: { at: "desc" },
        })
        if (event) events.push({ ...event, attrs: event.attrs as NormalizedEvent["attrs"] })
      }
      return persistFresh(
        detectOverdueJobs({ tenantId, now, sources: watchedSources("job-overdue"), events }, cfg),
      )
    })
  if (!off.has("service-degradation"))
    await run("service-degradation", async () =>
      persistFresh(
        detectServiceDegradation(
          await data(
            "service-degradation",
            ["custom.slo.sample"],
            new Date(now.getTime() - DAY - 2 * 60_000),
          ),
          operationalSettings("service-degradation", raw("service-degradation")),
        ),
      ),
    )
}
