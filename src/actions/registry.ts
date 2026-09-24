import { z } from "zod"
import { newSigningSecret, parseTarget } from "../alerts/deliver.ts"
import { issueInvite } from "../auth/invite.ts"
import { DETECTORS } from "../domain/detectors/index.ts"
import { isProdLike } from "../config.ts"
import type { GatedAction } from "../gate/intent.ts"
import { prisma } from "../store/client.ts"
import { decryptSecret, encryptSecret } from "../store/crypto.ts"

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
  // biome-ignore lint/suspicious/noConfusingVoidType: `void` is what lets most actions return nothing; `undefined` would make every one of them write `return undefined`.
  run: (tenantId: string, params: z.infer<S>, receipt: { nonce: string }) => Promise<void | ActionOutcome>
  /** Consequence class, used to style the confirmation. */
  impact: "low" | "medium" | "high"
}

/**
 * What an action hands back to the approver who ran it, beyond "applied".
 *
 * Today only an enrolment invite: minted INSIDE `run`, after the signature is redeemed, so the token
 * never appears in the signed (and stored-in-the-clear) parameters. Shown once in the response and
 * stored only as a hash.
 */
export interface ActionOutcome {
  invite?: { token: string; label: string; expiresAt: string }
}

/** Issue an invite for an active member, or fail the action if there is none. */
async function inviteFor(tenantId: string, externalId: string): Promise<ActionOutcome> {
  const member = await prisma.member.findFirst({
    where: { tenantId, externalId, active: true },
    select: { id: true, label: true },
  })
  if (!member) throw new Error("no active administrator with that subject id")
  const invite = await issueInvite(prisma, { tenantId, memberId: member.id })
  return { invite: { token: invite.token, label: member.label, expiresAt: invite.expiresAt.toISOString() } }
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
      `Add "${p.label}" as an Intelligence administrator and create a one-time enrolment link for ` +
      "them. They will be able to approve privileged actions once they enrol a passkey with it.",
    run: async (tenantId, p: { externalId: string; label: string }) => {
      await prisma.member.upsert({
        where: { tenantId_externalId: { tenantId, externalId: p.externalId } },
        create: { tenantId, externalId: p.externalId, label: p.label },
        update: { label: p.label, active: true },
      })
      return inviteFor(tenantId, p.externalId)
    },
  }),

  /**
   * A fresh enrolment link for an existing administrator: never enrolled, a lost link, a new device.
   *
   * High impact, and signed, because the link is the power to add a passkey to that account — the
   * same power as approving as them. Issuing one supersedes any link still open for that member.
   */
  "intelligence.member.invite": defineAction({
    impact: "high",
    schema: z.object({ externalId: z.string().min(1).max(200) }),
    summary: (p: { externalId: string }) =>
      `Create a one-time enrolment link for administrator "${p.externalId}". Whoever opens it can add ` +
      "a passkey to that administrator — send it only to them. Any earlier link for them stops working.",
    run: async (tenantId, p: { externalId: string }) => inviteFor(tenantId, p.externalId),
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

  /**
   * Turn an alert rule ON — the moment finding titles, severities and timestamps start leaving this
   * host for its destination.
   *
   * The destination HOST is a signed parameter, and `run` refuses unless it matches the stored
   * destination. The approver is shown where data will go, and the signature binds that: a rule
   * cannot be approved for one host and deliver to another.
   */
  "intelligence.alert.activate": defineAction({
    impact: "high",
    schema: z.object({ ruleId: z.uuid(), host: z.string().min(1).max(300) }),
    summary: (p: { host: string }) =>
      `Turn ON an alert rule. Matching findings — titles, severities and timestamps, which can name ` +
      `the subject involved — will be sent to ${p.host}.`,
    run: async (tenantId, p: { ruleId: string; host: string }, receipt) => {
      const rule = await prisma.alertRule.findFirst({
        where: { id: p.ruleId, tenantId },
        select: { targetCipher: true, signingSecretCipher: true },
      })
      if (!rule) throw new Error("alert rule not found in this tenant")
      const target = decryptSecret(rule.targetCipher)
      if (!target || !rule.signingSecretCipher) {
        throw new Error("this rule predates alert delivery and cannot be turned on — recreate it")
      }
      if (new URL(target).host !== p.host) throw new Error("the approved host is not this rule's destination")
      await prisma.alertRule.update({
        where: { id: p.ruleId },
        data: { active: true, activatedAt: new Date(), activationReceipt: receipt.nonce, lastError: null },
      })
    },
  }),

  "intelligence.alert.deactivate": defineAction({
    impact: "low",
    schema: z.object({ ruleId: z.uuid() }),
    summary: () => "Turn OFF an alert rule. Nothing further will be sent to its destination.",
    run: async (tenantId, p: { ruleId: string }, receipt) => {
      const res = await prisma.alertRule.updateMany({
        where: { id: p.ruleId, tenantId },
        data: { active: false, activationReceipt: receipt.nonce },
      })
      if (res.count !== 1) throw new Error("alert rule not found in this tenant")
    },
  }),

  /**
   * Switching a detector OFF is signed for the same reason the rest is: silencing the thing that
   * would notice is the first move of anyone who has taken over a session. On is signed too, so the
   * record of who changed it is symmetric.
   */
  "intelligence.detector.disable": defineAction({
    impact: "high",
    schema: z.object({ detector: z.enum(DETECTORS) }),
    summary: (p: { detector: string }) =>
      `Turn OFF the ${p.detector} detector. It will stop producing findings, and what happens while ` +
      "it is off is not reviewed later.",
    run: async (tenantId, p: { detector: string }) => {
      await prisma.detectorConfig.upsert({
        where: { tenantId_detector: { tenantId, detector: p.detector } },
        create: { tenantId, detector: p.detector, enabled: false },
        update: { enabled: false },
      })
    },
  }),

  "intelligence.detector.enable": defineAction({
    impact: "low",
    schema: z.object({ detector: z.enum(DETECTORS) }),
    summary: (p: { detector: string }) => `Turn ON the ${p.detector} detector.`,
    run: async (tenantId, p: { detector: string }) => {
      await prisma.detectorConfig.upsert({
        where: { tenantId_detector: { tenantId, detector: p.detector } },
        create: { tenantId, detector: p.detector, enabled: true },
        update: { enabled: true },
      })
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
  // No `email`: there is no mail sender, and a rule that is stored but can never fire is worse than
  // no rule. The enum value stays in the schema for when there is one.
  channel: z.enum(["webhook", "slack"], {
    error: "Choose webhook or Slack — email delivery is not available yet",
  }),
  target: z.string().min(1).max(2000),
  cooldownMinutes: z.number().int().min(0).max(10_080),
})

/**
 * Creating a rule is NOT gated by a signature; turning it ON is.
 *
 * The same split as connectors: a rule that is off sends nothing, so creating one has no consequence,
 * and requiring a passkey tap for every draft would train people to approve reflexively. Activation
 * is the moment data leaves the host, and that is signed (`intelligence.alert.activate`).
 *
 * Returns the signing secret for the `x-intelligence-signature` header, in plaintext exactly once.
 * It is stored encrypted and never shown again.
 */
export async function createAlertRule(
  tenantId: string,
  input: z.infer<typeof ALERT_RULE_INPUT>,
): Promise<{ id: string; host: string; signingSecret: string }> {
  // Throws UnsafeTargetError with an authored message the form can show.
  const target = parseTarget(input.target, { allowLoopbackHttp: !isProdLike })
  const signingSecret = newSigningSecret()
  const created = await prisma.alertRule.create({
    data: {
      tenantId,
      name: input.name,
      minSeverity: input.minSeverity,
      channel: input.channel,
      targetCipher: encryptSecret(target.url),
      targetHost: target.host,
      signingSecretCipher: encryptSecret(signingSecret),
      cooldownMinutes: input.cooldownMinutes,
      active: false,
    },
    select: { id: true },
  })
  return { id: created.id, host: target.host, signingSecret }
}
