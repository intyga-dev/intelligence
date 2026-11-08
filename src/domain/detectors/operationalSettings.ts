import { z } from "zod"

const connectionId = z.uuid()
const name = z.string().trim().min(1).max(200)
const repo = z.string().regex(/^[\w.-]+\/[\w.-]+$/)
const minutes = z.number().int().min(1).max(10_080)
const uniqueTargets = (targets: Record<string, unknown>[]) =>
  new Set(
    targets.map((t) => JSON.stringify([t.connectionId, t.repo, t.branch, t.workflow, t.job, t.objective])),
  ).size === targets.length

export const OPERATIONAL_SCHEMAS = {
  "collection-health": z
    .object({ failures: z.number().int().min(2).max(20).default(3), overdueMinutes: minutes.default(15) })
    .strict(),
  "ci-health": z
    .object({
      failures: z.number().int().min(2).max(20).default(3),
      brokenMinutes: minutes.default(30),
      targets: z
        .array(z.object({ connectionId, repo, branch: name.default("main"), workflow: name }).strict())
        .max(20)
        .default([])
        .refine(uniqueTargets, "Each monitored target must be unique"),
    })
    .strict(),
  "merge-policy": z
    .object({
      targets: z
        .array(z.object({ connectionId, repo, branch: name.default("main") }).strict())
        .max(20)
        .default([])
        .refine(uniqueTargets, "Each monitored target must be unique"),
    })
    .strict(),
  "job-overdue": z
    .object({
      targets: z
        .array(
          z
            .object({
              connectionId,
              job: name,
              startsAt: z.iso.datetime({ offset: true }),
              intervalMinutes: minutes.default(1440),
              graceMinutes: z.number().int().min(0).max(1440).default(30),
              maintenanceUntil: z.iso.datetime({ offset: true }).nullable().default(null),
            })
            .strict(),
        )
        .max(20)
        .default([])
        .refine(uniqueTargets, "Each monitored target must be unique"),
    })
    .strict(),
  "service-degradation": z
    .object({
      targets: z
        .array(
          z
            .object({
              connectionId,
              objective: name,
              successPercent: z.number().min(90).max(99.9999).default(99.9),
              shortMinutes: z.number().int().min(1).max(60).default(5),
              longMinutes: z.number().int().min(2).max(1440).default(60),
              burnRate: z.number().min(1).max(1000).default(14.4),
              minRequests: z.number().int().min(1).max(1_000_000).default(100),
              maintenanceUntil: z.iso.datetime({ offset: true }).nullable().default(null),
            })
            .strict()
            .refine((t) => t.longMinutes > t.shortMinutes, "Long window must exceed short window"),
        )
        .max(20)
        .default([])
        .refine(uniqueTargets, "Each monitored target must be unique"),
    })
    .strict(),
} as const

export type OperationalDetector = keyof typeof OPERATIONAL_SCHEMAS
export type OperationalSettings<K extends OperationalDetector> = z.infer<(typeof OPERATIONAL_SCHEMAS)[K]>
export const CONFIGURE_DETECTOR = z.discriminatedUnion("detector", [
  z
    .object({ detector: z.literal("collection-health"), settings: OPERATIONAL_SCHEMAS["collection-health"] })
    .strict(),
  z.object({ detector: z.literal("ci-health"), settings: OPERATIONAL_SCHEMAS["ci-health"] }).strict(),
  z.object({ detector: z.literal("merge-policy"), settings: OPERATIONAL_SCHEMAS["merge-policy"] }).strict(),
  z.object({ detector: z.literal("job-overdue"), settings: OPERATIONAL_SCHEMAS["job-overdue"] }).strict(),
  z
    .object({
      detector: z.literal("service-degradation"),
      settings: OPERATIONAL_SCHEMAS["service-degradation"],
    })
    .strict(),
])

export function operationalSettings<K extends OperationalDetector>(
  id: K,
  raw: unknown,
): OperationalSettings<K> {
  return OPERATIONAL_SCHEMAS[id].parse(raw ?? {}) as OperationalSettings<K>
}
