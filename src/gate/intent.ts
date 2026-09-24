import crypto from "node:crypto"
import { canonicalize } from "./jcs.ts"

// What an Intelligence admin actually signs.
//
// Deliberately in its own module with no config and no IO: this is the binding between "a human
// tapped their key" and "this exact action happened", and it must be reproducible by anyone holding
// the intent and a SHA-256 — an approver's client, an auditor, a reviewer. A function like that
// should not require a database URL to be importable.

/** Privileged Intelligence actions. The value is signed, so it binds the action to its parameters. */
export type GatedAction =
  | "intelligence.connector.activate"
  | "intelligence.connector.deactivate"
  | "intelligence.judgment.enable"
  | "intelligence.judgment.disable"
  | "intelligence.data.purge"
  | "intelligence.member.add"
  | "intelligence.member.invite"
  | "intelligence.member.remove"
  | "intelligence.workspace.rebind"
  | "intelligence.alert.activate"
  | "intelligence.alert.deactivate"
  | "intelligence.detector.enable"
  | "intelligence.detector.disable"

export interface GateIntent {
  action: GatedAction
  /** Everything that defines WHAT is being approved. Digested; never sent to Intyga in the clear. */
  params: Record<string, unknown>
}

/**
 * The digest of an intent.
 *
 * Canonicalized first, so the same intent always produces the same digest regardless of key order.
 * Lowercase hex because the platform plane refuses any other spelling — two spellings of one digest
 * would be two different signed byte strings.
 */
export function intentDigest(intent: GateIntent): string {
  const payload = canonicalize({ action: intent.action, params: intent.params })
  return crypto.createHash("sha256").update(payload, "utf8").digest("hex")
}
