import { z } from "zod"
import { createHash } from "node:crypto"
import { newSigningSecret, parseTarget } from "../alerts/deliver.ts"
import { DETECTORS } from "../domain/detectors/index.ts"
import { CONFIGURE_DETECTOR } from "../domain/detectors/operationalSettings.ts"
import { isProdLike } from "../config.ts"
import { prisma } from "../store/client.ts"
import { decryptSecret, encryptSecret } from "../store/crypto.ts"
import { CONFIGURE_CONNECTOR, GITHUB_REPOS } from "./connectorSettings.ts"

/** Privileged Intelligence actions. The value is the signed actionType, so it binds the action to its parameters. */
export type GatedAction =
  | "intelligence.service.create"
  | "intelligence.connector.assign-service"
  | "intelligence.connector.configure-github"
  | "intelligence.connector.configure"
  | "intelligence.connector.activate"
  | "intelligence.connector.deactivate"
  | "intelligence.connector.remove"
  | "intelligence.judgment.enable"
  | "intelligence.judgment.disable"
  | "intelligence.data.purge"
  | "intelligence.alert.activate"
  | "intelligence.alert.deactivate"
  | "intelligence.detector.enable"
  | "intelligence.detector.disable"
  | "intelligence.detector.configure"

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

interface ActionReceipt {
  nonce: string
  secretCiphertext?: string | null
}

export interface ActionDef<S extends z.ZodTypeAny = z.ZodTypeAny> {
  schema: S
  /** Shown to the approver. Written in the imperative — "Turn on …", not "toggles the …". */
  summary: (params: z.infer<S>) => string
  /** Runs only after the signature is redeemed, with the exact params that were signed. */
  // biome-ignore lint/suspicious/noConfusingVoidType: `void` is what lets most actions return nothing; `undefined` would make every one of them write `return undefined`.
  run: (tenantId: string, params: z.infer<S>, receipt: ActionReceipt) => Promise<void | ActionOutcome>
  /** Consequence class, used to style the confirmation. */
  impact: "low" | "medium" | "high"
}

/** What an action hands back beyond "applied". Nothing today; kept so `run` has a stable shape. */
export type ActionOutcome = { note?: string }

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

function verifiedReplacement(digest: string | undefined, receipt: ActionReceipt): string | undefined {
  if (!digest) return undefined
  if (
    !receipt.secretCiphertext ||
    createHash("sha256").update(receipt.secretCiphertext).digest("hex") !== digest ||
    !decryptSecret(receipt.secretCiphertext)
  )
    throw new Error("The approved replacement credential is unavailable or has changed")
  return receipt.secretCiphertext
}

export const ACTIONS = {
  "intelligence.connector.configure": defineAction({
    impact: "medium",
    schema: CONFIGURE_CONNECTOR,
    summary: (p) =>
      `Configure ${p.kind} connector ${p.connectionId} (${p.label}): ${JSON.stringify(p.config)}. ${p.secretDigest ? "Replace its credential. For webhook sources, update the sender to use the replacement after approval." : "Keep its existing credential."} Keep collected history and polling cursors.`,
    run: async (tenantId, p, receipt) => {
      const replacement = verifiedReplacement(p.secretDigest, receipt)
      await prisma.$transaction(async (tx) => {
        const where = { id: p.connectionId, tenantId, kind: p.kind, removedAt: null }
        const source = await tx.connection.findFirst({ where, select: { config: true } })
        if (!source) throw new Error("Connector not found in this tenant")
        const updated = await tx.connection.updateMany({
          where,
          data: {
            label: p.label,
            config: { ...(source.config as Record<string, string>), ...p.config },
            ...(replacement ? { secretCiphertext: replacement } : {}),
          },
        })
        if (updated.count !== 1) throw new Error("Connector not found in this tenant")
      })
    },
  }),
  "intelligence.connector.configure-github": defineAction({
    impact: "medium",
    schema: z
      .object({
        connectionId: z.uuid(),
        label: z.string().trim().min(1).max(80),
        repos: GITHUB_REPOS,
        deployWorkflows: z.string().trim().max(2000),
        pathMap: z.enum(["generic", "intyga-core"]),
        tokenDigest: z
          .string()
          .regex(/^[a-f0-9]{64}$/)
          .optional(),
      })
      .strict(),
    summary: (p) =>
      `Configure GitHub source ${p.connectionId} (${p.label}): repositories ${p.repos}; deploy workflows ${p.deployWorkflows || "none"}; sensitive-path map ${p.pathMap}. ${p.tokenDigest ? "Replace its GitHub token." : "Keep its existing token."} Keep collected history.`,
    run: async (tenantId, p, receipt) => {
      const replacement = verifiedReplacement(p.tokenDigest, receipt)
      await prisma.$transaction(async (tx) => {
        const connection = await tx.connection.findFirst({
          where: { id: p.connectionId, tenantId, kind: "github", builtIn: false, removedAt: null },
          select: { config: true },
        })
        if (!connection) throw new Error("GitHub connector not found in this tenant")
        const updated = await tx.connection.updateMany({
          where: { id: p.connectionId, tenantId, kind: "github", builtIn: false, removedAt: null },
          data: {
            label: p.label,
            ...(replacement ? { secretCiphertext: replacement } : {}),
            config: {
              ...(connection.config as Record<string, string>),
              repos: p.repos,
              deployWorkflows: p.deployWorkflows,
              pathMap: p.pathMap,
            },
          },
        })
        if (updated.count !== 1) throw new Error("GitHub connector not found in this tenant")
      })
    },
  }),
  "intelligence.connector.remove": defineAction({
    impact: "high",
    schema: connectorParams.strict(),
    summary: (p) =>
      `Remove connector ${p.connectionId}. Stop collection, erase its saved credential and remove it from the connector list. Keep historical events and findings. Any collection already in progress may finish.`,
    run: async (tenantId, p, receipt) => {
      const result = await prisma.connection.updateMany({
        where: { id: p.connectionId, tenantId, builtIn: false, removedAt: null },
        data: {
          removedAt: new Date(),
          active: false,
          secretCiphertext: null,
          activationReceipt: receipt.nonce,
        },
      })
      if (result.count !== 1) throw new Error("Removable connector not found in this tenant")
    },
  }),
  "intelligence.detector.configure": defineAction({
    impact: "high",
    schema: CONFIGURE_DETECTOR,
    summary: (p) =>
      `Configure ${p.detector} with these monitoring expectations: ${JSON.stringify(p.settings)}. This changes when findings are raised; it does not enable external alert delivery.`,
    run: async (tenantId, p) => {
      if ("targets" in p.settings) {
        const ids = [...new Set(p.settings.targets.map((t) => t.connectionId))]
        const sources = await prisma.connection.findMany({
          where: { tenantId, id: { in: ids }, removedAt: null },
          select: { id: true, kind: true, config: true },
        })
        if (sources.length !== ids.length)
          throw new Error("A configured source does not belong to this workspace")
        for (const target of p.settings.targets) {
          const source = sources.find((s) => s.id === target.connectionId)
          if (!source) throw new Error("Configured source is unavailable")
          if (p.detector === "merge-policy" && source.kind !== "github")
            throw new Error("Merge-policy monitoring requires a GitHub connector")
          if (["job-overdue", "service-degradation"].includes(p.detector) && source.kind !== "webhook")
            throw new Error("This detector requires a custom webhook source")
          if (p.detector === "ci-health" && !["github", "webhook"].includes(source.kind))
            throw new Error("CI monitoring requires GitHub or a custom webhook")
          if (source.kind === "github" && "repo" in target) {
            const repos = String((source.config as Record<string, unknown>)?.repos ?? "").split(/[\s,]+/)
            if (!repos.includes(target.repo))
              throw new Error("The repository is not configured on this source")
          }
        }
      }
      await prisma.detectorConfig.upsert({
        where: { tenantId_detector: { tenantId, detector: p.detector } },
        create: { tenantId, detector: p.detector, enabled: true, settings: p.settings },
        update: { settings: p.settings },
      })
    },
  }),
  "intelligence.service.create": defineAction({
    impact: "low",
    schema: z.object({
      name: z.string().trim().min(1).max(80),
      description: z.string().trim().max(300).default(""),
    }),
    summary: (p) => `Create the service “${p.name}” to group its sources and findings.`,
    run: async (tenantId, p) => {
      await prisma.service.create({ data: { tenantId, name: p.name, description: p.description } })
    },
  }),
  "intelligence.connector.assign-service": defineAction({
    impact: "medium",
    schema: z.object({ connectionId: z.uuid(), serviceId: z.uuid().nullable() }),
    summary: (p) =>
      p.serviceId
        ? `Assign source ${p.connectionId} to service ${p.serviceId}. Group its unassigned history and correlate future observations within this service.`
        : `Remove the service assignment from source ${p.connectionId}. Previously grouped history stays with its service.`,
    run: async (tenantId, p) => {
      await prisma.$transaction(async (tx) => {
        if (
          p.serviceId &&
          !(await tx.service.findFirst({ where: { id: p.serviceId, tenantId }, select: { id: true } }))
        ) {
          throw new Error("service not found in this tenant")
        }
        const updated = await tx.connection.updateMany({
          where: { id: p.connectionId, tenantId, removedAt: null },
          data: { serviceId: p.serviceId },
        })
        if (updated.count !== 1) throw new Error("connector not found in this tenant")
        if (p.serviceId) {
          // Fill unassigned history only. Reassigning a source never moves earlier incidents.
          await tx.event.updateMany({
            where: { tenantId, connectionId: p.connectionId, serviceId: null },
            data: { serviceId: p.serviceId },
          })
          await tx.finding.updateMany({
            where: {
              tenantId,
              serviceId: null,
              OR: [
                {
                  evidence: {
                    some: { kind: "eventRef", data: { path: ["connectionId"], equals: p.connectionId } },
                  },
                },
                { dedupeKey: { startsWith: `regression:${p.connectionId}:` } },
              ],
            },
            data: { serviceId: p.serviceId },
          })
        }
      })
    },
  }),
  "intelligence.connector.activate": defineAction({
    impact: "medium",
    schema: connectorParams,
    summary: () => "Turn ON a data connector. Intelligence will begin ingesting and analysing its events.",
    run: async (tenantId, p: { connectionId: string }, receipt) => {
      // Scoped by tenantId: a connectionId from another tenant must not be reachable even with a
      // valid signature from this one.
      const res = await prisma.connection.updateMany({
        where: { id: p.connectionId, tenantId, removedAt: null },
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
        where: { id: p.connectionId, tenantId, removedAt: null },
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
