import crypto from "node:crypto"

// Verification of Intyga's outbound webhook signature.
//
// The scheme is Stripe-style and fixed by the producer, which we do not control and are not
// changing: `t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<rawBody>")>`.
//
// Three things here are load-bearing and easy to get wrong:
//   1. The MAC covers the RAW request bytes. Re-serializing the parsed JSON changes key order and
//      whitespace and will not verify — so the caller must hand us the body as received.
//   2. Comparison is constant-time. A byte-wise early return leaks the expected MAC under timing.
//   3. `t` is inside the MAC, so it cannot be edited without invalidating the signature. That is
//      what makes the freshness window a replay bound rather than decoration.

/** How far out of date a signature may be. Matches the producer's retry cadence with headroom. */
export const DEFAULT_TOLERANCE_SECONDS = 300

export type VerifyFailure =
  | "malformed-header"
  | "unsupported-scheme"
  | "bad-timestamp"
  | "stale"
  | "future"
  | "mismatch"

export type VerifyResult = { ok: true; signedAt: Date } | { ok: false; reason: VerifyFailure }

interface ParsedHeader {
  t: number
  v1: string
}

function parseHeader(header: string): ParsedHeader | null {
  let t: number | null = null
  let v1: string | null = null
  for (const part of header.split(",")) {
    const eq = part.indexOf("=")
    if (eq === -1) return null
    const key = part.slice(0, eq).trim()
    const value = part.slice(eq + 1).trim()
    if (key === "t") {
      if (!/^\d{1,15}$/.test(value)) return null
      t = Number(value)
    } else if (key === "v1") {
      // Hex, even length, non-empty. Enforced here so timingSafeEqual below is never handed a
      // buffer of a surprising length.
      if (!/^[0-9a-f]+$/i.test(value) || value.length % 2 !== 0) return null
      v1 = value.toLowerCase()
    }
    // Unknown keys are ignored on purpose: a future v2= must not break a v1 verifier.
  }
  return t !== null && v1 !== null ? { t, v1 } : null
}

/** Constant-time hex compare that does not leak length through an early return. */
function safeEqualHex(a: string, b: string): boolean {
  const ab = Buffer.from(a, "hex")
  const bb = Buffer.from(b, "hex")
  // Unequal lengths cannot be compared by timingSafeEqual, and a length mismatch is already a
  // guaranteed non-match — but still hash both sides so the work is length-independent.
  if (ab.length !== bb.length) {
    crypto.timingSafeEqual(ab, ab)
    return false
  }
  return crypto.timingSafeEqual(ab, bb)
}

export function verifyWebhookSignature(input: {
  header: string | undefined
  /** The body exactly as received. A parsed-and-restringified object will NOT verify. */
  rawBody: string
  secret: string
  now?: Date
  toleranceSeconds?: number
}): VerifyResult {
  if (!input.header) return { ok: false, reason: "malformed-header" }
  const parsed = parseHeader(input.header)
  if (!parsed) return { ok: false, reason: "malformed-header" }

  const nowSec = Math.floor((input.now ?? new Date()).getTime() / 1000)
  const tolerance = input.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS
  const age = nowSec - parsed.t
  if (!Number.isFinite(age)) return { ok: false, reason: "bad-timestamp" }
  // Checked BEFORE the MAC so an attacker replaying a captured body is rejected on freshness
  // regardless of whether they can produce a valid MAC (they can — it is the original one).
  if (age > tolerance) return { ok: false, reason: "stale" }
  if (age < -tolerance) return { ok: false, reason: "future" }

  const expected = crypto
    .createHmac("sha256", input.secret)
    .update(`${parsed.t}.${input.rawBody}`)
    .digest("hex")

  if (!safeEqualHex(expected, parsed.v1)) return { ok: false, reason: "mismatch" }
  return { ok: true, signedAt: new Date(parsed.t * 1000) }
}
