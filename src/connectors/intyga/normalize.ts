import { z } from "zod"
import type { NormalizedEvent } from "../types.ts"

// Turn one Intyga webhook delivery into a source-agnostic NormalizedEvent.
//
// This is the second place minimization happens. Intyga already strips actionDescription and params
// at delivery time unless the endpoint opts in (we do not), but the payload still carries fields we
// have no detection use for — so we drop them here rather than storing everything and hoping.
// `verificationCode` in particular is a human-facing approval-matching code: it buys no signal and
// is exactly the kind of thing that should not accumulate in a third system.

/** The six lifecycle events an Intyga webhook endpoint can carry. */
export const INTYGA_EVENT_KINDS = [
  "challenge.created",
  "challenge.approved",
  "challenge.denied",
  "challenge.expired",
  "challenge.consumed",
  "challenge.escalated",
] as const

export type IntygaEventKind = (typeof INTYGA_EVENT_KINDS)[number]

/** Kinds that mean "this request did not result in an approval". The burst detector's input. */
export const REFUSAL_KINDS: readonly IntygaEventKind[] = ["challenge.denied", "challenge.expired"]

/**
 * Deliberately permissive about unknown keys and strict about the ones we use.
 *
 * The producer may add fields; a new field must not turn into a 400 that makes Intyga retry, back
 * off and eventually disable the endpoint. Unknown keys are simply not read.
 */
const envelope = z.object({
  id: z.string().min(1).max(200),
  type: z.string().min(1).max(100),
  createdAt: z.iso.datetime(),
  data: z
    .object({
      nonce: z.string().min(1).max(200).optional(),
      actionType: z.string().max(200).nullish(),
      requesterDid: z.string().max(500).nullish(),
      requiredApprovals: z.number().int().min(0).max(1000).optional(),
      approvalsCount: z.number().int().min(0).max(1000).optional(),
      createdAt: z.iso.datetime().optional(),
      // actionDescription / params may appear if someone enables includeParams on the endpoint.
      // They are NOT read and NOT stored — declaring them here documents that choice rather than
      // leaving a reader to wonder whether they were forgotten.
    })
    .loose(),
})

export type IntygaWebhookEnvelope = z.infer<typeof envelope>

export class NormalizeError extends Error {}

export function isIntygaEventKind(t: string): t is IntygaEventKind {
  return (INTYGA_EVENT_KINDS as readonly string[]).includes(t)
}

/**
 * Parse and normalize. Returns null for a well-formed event of a kind we do not model, so an
 * endpoint subscribed to everything does not become an error source.
 */
export function normalizeIntygaEvent(input: {
  connectionId: string
  body: unknown
  /** When the delivery arrived, used only if the producer omitted a timestamp. */
  receivedAt: Date
}): NormalizedEvent | null {
  const parsed = envelope.safeParse(input.body)
  if (!parsed.success) {
    throw new NormalizeError(`unparseable Intyga webhook payload: ${parsed.error.issues[0]?.message}`)
  }
  const e = parsed.data
  if (!isIntygaEventKind(e.type)) return null

  const at = new Date(e.createdAt)
  const challengeCreatedAt = e.data.createdAt ? new Date(e.data.createdAt) : null

  // Approval latency is the one derived number this feed gives us for free, and it is only
  // meaningful on a terminal event. Guard against a negative value rather than storing nonsense:
  // the two timestamps come from different clocks (challenge row vs outbound event).
  const latencyMs =
    challengeCreatedAt && e.type !== "challenge.created"
      ? Math.max(0, at.getTime() - challengeCreatedAt.getTime())
      : null

  return {
    connectionId: input.connectionId,
    source: "intyga",
    sourceId: e.id,
    kind: e.type,
    at: Number.isNaN(at.getTime()) ? input.receivedAt : at,
    // The requester DID is the subject a burst is attributed to. Absent on some paths, in which
    // case the event still counts toward totals but cannot anchor a per-subject finding.
    subjectRef: e.data.requesterDid ?? null,
    correlationRef: e.data.nonce ?? null,
    attrs: {
      actionType: e.data.actionType ?? null,
      requiredApprovals: e.data.requiredApprovals ?? null,
      approvalsCount: e.data.approvalsCount ?? null,
      challengeCreatedAt: challengeCreatedAt?.toISOString() ?? null,
      latencyMs,
    },
  }
}
