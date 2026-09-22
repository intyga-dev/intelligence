import { z } from "zod"
import type { GatedAction } from "../gate/intent.ts"
import { prisma } from "../store/client.ts"
import { encryptSecret } from "../store/crypto.ts"

// Every privileged action in one table.
//
// A registry rather than scattered route handlers, because the property that matters is uniform:
// nothing here executes without a redeemed human signature, and the parameters that were SIGNED are
// the parameters that get executed. Defining the schema and the executor together means adding an
// action cannot accidentally skip the gate — there is no path to `run` that does not go through the
// ceremony in routes.ts.
//
// `summary` is what a human reads before they tap their key. It must describe the effect in plain
// words: an approver deciding on the strength of an opaque action name is not really approving.

export interface ActionDef<S extends z.ZodTypeAny = z.ZodTypeAny> {
  schema: S
  /** Shown to the approver. Written in the imperative — "Turn on …", not "toggles the …". */
  summary: (params: z.infer<S>) => string
  /** Runs only after the signature is redeemed, with the exact params that were signed. */
  run: (tenantId: string, params: z.infer<S>, receipt: { nonce: string }) => Promise<void>
  /** Consequence class, used to style the confirmation. */
  impact: "low" | "medium" | "high"
}

/**
 * Identity helper that preserves each action's inferred parameter type.
 *
 * Annotating the map as `Record<GatedAction, ActionDef>` instead would collapse every `params` to
 * `unknown` at the definition site, so each `run` would have to re-parse or cast — losing exactly
 * the guarantee that the executed parameters are the validated ones.
 */
function defineAction<S extends z.ZodTypeAny>(def: ActionDef<S>): ActionDef<S> {
  return def
}

const connectorParams = z.object({ connectionId: z.uuid() })

export const ACTIONS = {
  "intelligence.connector.activate": defineAction({
    impact: "medium",
    schema: connectorParams,
    summary: () => "Turn ON a data connector. Intelligence will begin ingesting and analysing its events.",
    run: async (tenantId, p: { connectionId: string }, receipt) => {
      // Scoped by tenantId: a connectionId from another tenant must not be reachable even with a
      // valid signature from this one.
      const res = await prisma.connection.updateMany({
        where: { id: p.connectionId, tenantId },
        data: { active: true, activatedAt: new Date(), activationReceipt: receipt.nonce },
      })
      if (res.count !== 1) throw new Error("connector not found in this tenant")
    },
  }),

  "intelligence.connector.deactivate": defineAction({
    impact: "medium",
    schema: connectorParams,
    summary: () =>
      "Turn OFF a data connector. Existing findings are kept; no new events will be ingested from it.",
    run: async (tenantId, p: { connectionId: string }, receipt) => {
      const res = await prisma.connection.updateMany({
        where: { id: p.connectionId, tenantId },
        data: { active: false, activationReceipt: receipt.nonce },
      })
      if (res.count !== 1) throw new Error("connector not found in this tenant")
    },
  }),

  "intelligence.judgment.enable": defineAction({
    impact: "high",
    schema: z.object({ provider: z.literal("typesafe") }),
    summary: () =>
      "Turn ON semantic classification. Minimised, non-identifying summaries of findings will be " +
      "sent to TypeSafe AI (JEV), a third-party processor outside Intyga's infrastructure.",
    run: async (tenantId, _p, receipt) => {
      await prisma.detectorConfig.upsert({
        where: { tenantId_detector: { tenantId, detector: "judgment" } },
        create: { tenantId, detector: "judgment", enabled: true, settings: { receipt: receipt.nonce } },
        update: { enabled: true, settings: { receipt: receipt.nonce } },
      })
    },
  }),

  "intelligence.judgment.disable": defineAction({
    impact: "low",
    schema: z.object({}),
    summary: () => "Turn OFF semantic classification. No further data will leave for the model provider.",
    run: async (tenantId) => {
      await prisma.detectorConfig.upsert({
        where: { tenantId_detector: { tenantId, detector: "judgment" } },
        create: { tenantId, detector: "judgment", enabled: false },
        update: { enabled: false },
      })
    },
  }),

  "intelligence.data.purge": defineAction({
    impact: "high",
    schema: z.object({
      scope: z.enum(["events", "findings", "all"]),
      olderThanDays: z.number().int().min(0).max(3650),
    }),
    summary: (p: { scope: string; olderThanDays: number }) =>
      `PERMANENTLY DELETE ${p.scope === "all" ? "all events and findings" : p.scope} older than ` +
      `${p.olderThanDays} days. This cannot be undone.`,
    run: async (tenantId, p: { scope: string; olderThanDays: number }) => {
      const cutoff = new Date(Date.now() - p.olderThanDays * 86_400_000)
      if (p.scope === "events" || p.scope === "all") {
        await prisma.event.deleteMany({ where: { tenantId, at: { lt: cutoff } } })
      }
      if (p.scope === "findings" || p.scope === "all") {
        await prisma.finding.deleteMany({ where: { tenantId, lastSeenAt: { lt: cutoff } } })
      }
    },
  }),

  "intelligence.member.add": defineAction({
    impact: "high",
    schema: z.object({
      externalId: z
        .string()
        .min(1)
        .max(200)
        .regex(/^[A-Za-z0-9._:@+=-]+$/),
      label: z.string().min(1).max(200),
    }),
    summary: (p: { label: string }) =>
      `Add "${p.label}" as an Intelligence administrator. They will be able to approve privileged ` +
      "actions once they enrol a passkey.",
    run: async (tenantId, p: { externalId: string; label: string }) => {
      await prisma.member.upsert({
        where: { tenantId_externalId: { tenantId, externalId: p.externalId } },
        create: { tenantId, externalId: p.externalId, label: p.label },
        update: { label: p.label, active: true },
      })
    },
  }),

  /**
   * Repoint this tenant at a different Intyga workspace.
   *
   * The most consequential action here: the workspace is what authenticates every administrator,
   * so rebinding it is the one change that could hand control of this tenant to someone else. It
   * is therefore signed by the CURRENT workspace's passkey — you must still be who you were to say
   * who you will be.
   *
   * The private key is deliberately NOT a parameter. Signed parameters are stored in PendingAction
   * in the clear, so routing a credential through the digest would write it to disk unencrypted —
   * worse than what the signature was protecting. The key is submitted separately and encrypted on
   * arrival; what is signed is the workspace IDENTITY, which is what actually matters.
   */
  "intelligence.workspace.rebind": defineAction({
    impact: "high",
    schema: z.object({
      baseUrl: z.url(),
      clientId: z.string().min(1).max(200),
      rpId: z.string().min(1).max(253),
      origin: z.url(),
    }),
    summary: (p: { baseUrl: string; rpId: string }) =>
      `Repoint Intelligence at a DIFFERENT Intyga workspace (${p.baseUrl}, RP ${p.rpId}). ` +
      "Administrators of the current workspace will no longer be able to approve anything here.",
    run: async (tenantId, p: { baseUrl: string; clientId: string; rpId: string; origin: string }) => {
      await prisma.tenant.update({
        where: { id: tenantId },
        data: {
          intygaBaseUrl: p.baseUrl,
          intygaClientId: p.clientId,
          intygaRpId: p.rpId,
          intygaOrigin: p.origin,
        },
      })
    },
  }),

  "intelligence.member.remove": defineAction({
    impact: "high",
    schema: z.object({ externalId: z.string().min(1).max(200) }),
    summary: (p: { externalId: string }) =>
      `Remove administrator "${p.externalId}". They will no longer be able to approve anything here.`,
    run: async (tenantId, p: { externalId: string }) => {
      const res = await prisma.member.updateMany({
        where: { tenantId, externalId: p.externalId },
        data: { active: false },
      })
      if (res.count !== 1) throw new Error("member not found in this tenant")
    },
  }),
} satisfies Record<GatedAction, ActionDef>

/** Runtime lookup with the generic erased — the executor parses before it calls `run`. */
export function actionDef(action: string): ActionDef | null {
  return (ACTIONS as Record<string, ActionDef>)[action] ?? null
}

export const ALERT_RULE_INPUT = z.object({
  name: z.string().min(1).max(120),
  minSeverity: z.enum(["info", "low", "medium", "high", "critical"]),
  channel: z.enum(["webhook", "slack", "email"]),
  target: z.string().min(1).max(2000),
  cooldownMinutes: z.number().int().min(0).max(10_080),
})

/**
 * Alert rules are NOT gated by a signature.
 *
 * Deliberate: creating a rule cannot cause an action, disclose data or change what is recorded — at
 * worst it sends a notification to somewhere useless. Requiring a passkey tap for every threshold
 * tweak would train people to approve reflexively, which is how a signature stops meaning anything.
 * Gate what has consequence; leave the rest to RBAC.
 */
export async function createAlertRule(
  tenantId: string,
  input: z.infer<typeof ALERT_RULE_INPUT>,
): Promise<void> {
  await prisma.alertRule.create({
    data: {
      tenantId,
      name: input.name,
      minSeverity: input.minSeverity,
      channel: input.channel,
      targetCipher: encryptSecret(input.target),
      cooldownMinutes: input.cooldownMinutes,
    },
  })
}
