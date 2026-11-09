import { createHash } from "node:crypto"
import type { Category, Severity } from "../../domain/finding.ts"
import type { NormalizedEvent } from "../types.ts"
import { firstHeader, safeEqual, type Headers } from "../shared.ts"

export const object = (v: unknown): Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
export const string = (v: unknown) => (typeof v === "string" ? v : "")
export const hash = (v: unknown) =>
  createHash("sha256")
    .update(JSON.stringify(v) ?? "null")
    .digest("hex")
export const severity = (v: unknown, fallback: Severity = "medium"): Severity =>
  new Map<string, Severity>(
    Object.entries({
      critical: "critical",
      high: "high",
      error: "high",
      medium: "medium",
      warning: "medium",
      warn: "medium",
      low: "low",
      info: "info",
      informational: "info",
    }),
  ).get(string(v).toLowerCase()) ?? fallback
export function timestamp(v: unknown): Date | null {
  if (typeof v !== "string" && typeof v !== "number") return null
  const d = new Date(typeof v === "number" ? v * 1000 : v)
  return Number.isFinite(d.getTime()) && d.getTime() > 0 ? d : null
}
export function verifyBasic(headers: Headers, secret: string) {
  const header = firstHeader(headers.authorization) ?? ""
  const expected = `Basic ${Buffer.from(`intelligence:${secret}`).toString("base64")}`
  return safeEqual(header, expected)
    ? { ok: true as const }
    : { ok: false as const, reason: "invalid-basic-credentials" }
}
export interface AlertInput {
  id: string
  incident: string
  at: unknown
  title: string
  status: "firing" | "resolved"
  severity: Severity
  resource?: string
  category?: Category
  url?: string
}
export function alertEvent(connectionId: string, source: string, a: AlertInput): NormalizedEvent | null {
  const at = timestamp(a.at)
  if (!a.id || !a.incident || !at) return null
  return {
    connectionId,
    source,
    sourceId: hash([a.id, a.status, at.toISOString()]),
    kind: `${source}.provider.alert`,
    at,
    subjectRef: a.resource?.slice(0, 500) ?? null,
    correlationRef: a.incident,
    attrs: {
      incident: a.incident,
      title: a.title.slice(0, 500),
      status: a.status,
      severity: a.severity,
      category: a.category ?? "engineering",
      resource: (a.resource ?? "").slice(0, 1000),
      url: (a.url ?? "").slice(0, 2000),
    },
  }
}
export const present = (e: NormalizedEvent | null): e is NormalizedEvent => e !== null
