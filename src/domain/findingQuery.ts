import { z } from "zod"

export const FINDING_STATUSES = ["new", "investigating", "resolved", "dismissed"] as const
export const FINDING_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const
export const FINDING_CATEGORIES = ["security", "engineering", "product", "customer", "business"] as const

export const FINDING_QUERY = z.object({
  kind: z.enum(["finding", "observation", "all"]).default("finding"),
  service: z.union([z.literal(""), z.uuid()]).default(""),
  status: z
    .string()
    .default("open")
    .refine(
      (s) =>
        s === "open" ||
        s === "all" ||
        s.split(",").every((v) => (FINDING_STATUSES as readonly string[]).includes(v)),
    ),
  severity: z.enum(["", ...FINDING_SEVERITIES]).default(""),
  category: z.enum(["", ...FINDING_CATEGORIES]).default(""),
  q: z.string().trim().max(200).default(""),
  sort: z.enum(["priority", "recent"]).default("priority"),
  page: z.coerce.number().int().min(1).max(10_000).default(1),
  limit: z.coerce.number().int().min(1).max(500).default(25),
})

export type FindingQuery = z.infer<typeof FINDING_QUERY>

export function findingOptions(q: FindingQuery) {
  return {
    kind: q.kind,
    ...(q.service ? { serviceId: q.service } : {}),
    status: q.status === "all" ? [] : q.status === "open" ? ["new", "investigating"] : q.status.split(","),
    ...(q.severity ? { severity: q.severity } : {}),
    ...(q.category ? { category: q.category } : {}),
    query: q.q,
    sort: q.sort,
    limit: q.limit,
    offset: (q.page - 1) * q.limit,
  }
}

/** Filters live in the URL so a view can be bookmarked or shared, including after feedback. */
export function findingsUrl(q: FindingQuery, changes: Partial<FindingQuery> = {}): string {
  const next = { ...q, ...changes }
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(next)) {
    if (value !== "") params.set(key, String(value))
  }
  return `/findings?${params}`
}

export function findingUrl(id: string): string {
  return `/findings?kind=all&status=all&q=${encodeURIComponent(id)}#${encodeURIComponent(id)}`
}
