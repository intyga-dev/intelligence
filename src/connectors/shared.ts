import crypto from "node:crypto"
import type { VerifyOutcome } from "./registry.ts"

// Small helpers shared by connectors. Each existing connector predates this file and keeps its own
// copy on purpose — a verifier is easier to review when it reads top to bottom in one file — so
// only the newer connectors import from here.

export type Headers = Record<string, string | string[] | undefined>

export function firstHeader(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v
}

/**
 * Header a sender without request signing is told to carry: `x-intelligence-token: <secret>`.
 *
 * For vendors that cannot sign (Opsgenie, Datadog) but can attach a custom header. This is a
 * bearer secret, not a signature: it proves the sender knows the secret, not that the body is
 * unaltered, and it replays forever. TLS carries it, the per-event idempotency key contains replays,
 * and each such connector says so in its setup text rather than letting it pass for an HMAC.
 */
export const TOKEN_HEADER = "x-intelligence-token"

/** Constant-time string equality, for any lengths: both sides are digested first. */
export function safeEqual(a: string, b: string): boolean {
  const da = crypto.createHash("sha256").update(a, "utf8").digest()
  const db = crypto.createHash("sha256").update(b, "utf8").digest()
  return crypto.timingSafeEqual(da, db)
}

export function verifyTokenHeader(headers: Headers, secret: string): VerifyOutcome {
  const given = firstHeader(headers[TOKEN_HEADER])
  if (!given) return { ok: false, reason: "missing-token" }
  return safeEqual(given, secret) ? { ok: true } : { ok: false, reason: "mismatch" }
}

/** HMAC-SHA256 of `payload` as lowercase hex. */
export function hmacHex(secret: string, payload: string): string {
  return crypto.createHmac("sha256", secret).update(payload, "utf8").digest("hex")
}

/** Constant-time comparison of two hex digests; false for anything that is not equal-length hex. */
export function hexEqual(a: string, b: string): boolean {
  if (!/^[0-9a-f]+$/i.test(a) || !/^[0-9a-f]+$/i.test(b) || a.length !== b.length || a.length % 2 !== 0) {
    return false
  }
  return crypto.timingSafeEqual(Buffer.from(a.toLowerCase(), "hex"), Buffer.from(b.toLowerCase(), "hex"))
}

/** Parse a Date, or fall back when the input is missing or not a real instant. */
export function dateOr(input: string | number | null | undefined, fallback: Date): Date {
  if (input === null || input === undefined || input === "") return fallback
  const d = new Date(input)
  return Number.isNaN(d.getTime()) ? fallback : d
}
