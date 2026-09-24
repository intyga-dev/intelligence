import crypto from "node:crypto"
import { SEVERITY_RANK, type Severity } from "../domain/finding.ts"
import { prisma } from "../store/client.ts"
import { decryptSecret } from "../store/crypto.ts"

// Alert delivery: the moment a finding leaves this host.
//
// An alert rule is a FILTER over findings, not a second detector. Each tick, every active rule whose
// cooldown has elapsed gathers the open findings seen since its last successful delivery, and POSTs
// them to its destination in one request. Nothing is delivered for a rule that is not active, and a
// rule only becomes active through a signed action, because that is when data starts flowing out.
//
// Delivery is AT-LEAST-ONCE. The watermark (`lastFiredAt`) only moves on a 2xx, so a failed
// delivery is retried on the next tick, and a receiver that times out after processing sees the
// batch again. Receivers should de-duplicate on the finding id plus `lastSeenAt`.
//
// What leaves, and only this: finding id, title, severity, category, status, occurrence count,
// timestamps, and a link back to the console. No evidence, no summary, no raw events. Titles can
// name the subject involved (a denial burst names who was refused), which is why activation shows
// the approver where data will go before they sign.
//
// Two channels. `webhook` is a signed JSON body for anything you run yourself. `slack` is the
// `{ text }` body Slack incoming webhooks require. There is no email: no mail sender exists here,
// and the channel is refused at creation rather than silently stored.

/** One POST carries at most this many findings; the rest are counted and linked, not listed. */
export const MAX_FINDINGS_PER_DELIVERY = 20
const TIMEOUT_MS = 5_000
export const SIGNATURE_HEADER = "x-intelligence-signature"

export type DeliveryChannel = "webhook" | "slack"

export class UnsafeTargetError extends Error {}

/**
 * Validate a destination before it is stored, and return the host an approver will be shown.
 *
 * HTTPS only. Plain HTTP is allowed for loopback outside production, so a local receiver works
 * while developing. Credentials in the URL are refused: they would be shown to the approver as part
 * of the host and they are not how any webhook provider authenticates.
 *
 * Private and internal addresses are NOT blocked. This is a self-hosted service, the destination is
 * set by its own administrator, and an internal receiver is a legitimate choice. What stops a
 * stranger's destination being used is that turning a rule on requires an administrator's passkey.
 */
export function parseTarget(
  raw: string,
  opts: { allowLoopbackHttp: boolean },
): { url: string; host: string } {
  let u: URL
  try {
    u = new URL(raw.trim())
  } catch {
    throw new UnsafeTargetError("The destination is not a valid URL.")
  }
  if (u.username || u.password)
    throw new UnsafeTargetError("The destination must not contain a username or password.")
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname)
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback && opts.allowLoopbackHttp)) {
    throw new UnsafeTargetError("The destination must use https.")
  }
  return { url: u.toString(), host: u.host }
}

export function newSigningSecret(): string {
  return `whsig_${crypto.randomBytes(32).toString("base64url")}`
}

/**
 * `t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`.
 *
 * The timestamp is inside the MAC so a receiver can refuse old deliveries (replay); the body is the
 * exact bytes sent, so verify before parsing.
 */
export function signBody(secret: string, body: string, unixSeconds: number): string {
  const mac = crypto.createHmac("sha256", secret).update(`${unixSeconds}.${body}`, "utf8").digest("hex")
  return `t=${unixSeconds},v1=${mac}`
}

export interface AlertFinding {
  id: string
  title: string
  severity: Severity
  category: string
  status: string
  count: number
  detectedAt: Date
  lastSeenAt: Date
}

/** Every severity at or above `min`. */
export function severitiesAtLeast(min: Severity): Severity[] {
  return (Object.keys(SEVERITY_RANK) as Severity[]).filter((s) => SEVERITY_RANK[s] >= SEVERITY_RANK[min])
}

/** Whether a rule's cooldown has elapsed. A rule that has never delivered is always due. */
export function isDue(rule: { lastFiredAt: Date | null; cooldownMinutes: number }, now: Date): boolean {
  if (!rule.lastFiredAt) return true
  return now.getTime() - rule.lastFiredAt.getTime() >= rule.cooldownMinutes * 60_000
}

/**
 * The findings a delivery may carry are those seen after this instant.
 *
 * The later of activation and last success: a freshly activated rule starts from now rather than
 * replaying every open finding in history, and re-activating a rule does not replay what happened
 * while it was off.
 */
export function watermark(rule: { activatedAt: Date | null; lastFiredAt: Date | null }): Date {
  const a = rule.activatedAt?.getTime() ?? 0
  const f = rule.lastFiredAt?.getTime() ?? 0
  return new Date(Math.max(a, f))
}

/** Slack treats these three as markup; everything else in a title is shown as typed. */
function slackEscape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
}

export function buildBody(
  channel: DeliveryChannel,
  o: { ruleName: string; findings: AlertFinding[]; more: boolean; consoleOrigin: string | null; now: Date },
): string {
  const link = o.consoleOrigin ? `${o.consoleOrigin.replace(/\/+$/, "")}/findings` : null

  if (channel === "slack") {
    const lines = o.findings.map(
      (f) => `• *${f.severity.toUpperCase()}* ${slackEscape(f.title)}${f.count > 1 ? ` (×${f.count})` : ""}`,
    )
    const tail = o.more ? "\n…and more." : ""
    const open = link ? `\n<${link}|Open findings in Intelligence>` : ""
    const n = o.findings.length
    return JSON.stringify({
      text: `*${slackEscape(o.ruleName)}*: ${n}${o.more ? "+" : ""} finding${n === 1 ? "" : "s"}\n${lines.join("\n")}${tail}${open}`,
    })
  }

  return JSON.stringify({
    type: "intelligence.alert",
    rule: o.ruleName,
    sentAt: o.now.toISOString(),
    findings: o.findings.map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      category: f.category,
      status: f.status,
      count: f.count,
      detectedAt: f.detectedAt.toISOString(),
      lastSeenAt: f.lastSeenAt.toISOString(),
    })),
    more: o.more,
    link,
  })
}

export interface DeliveryReport {
  attempted: number
  delivered: number
  failed: number
}

type Send = (url: string, init: RequestInit) => Promise<Response>

/**
 * Deliver every due alert. Isolated per rule: one dead endpoint must not stop the others.
 *
 * The destination URL is never logged or recorded — it is a credential. What is recorded on failure
 * is an authored reason: a status code, "timed out", "unreachable".
 */
export async function deliverAlerts(now: Date = new Date(), send: Send = fetch): Promise<DeliveryReport> {
  const report: DeliveryReport = { attempted: 0, delivered: 0, failed: 0 }
  const rules = await prisma.alertRule.findMany({
    where: { active: true, channel: { in: ["webhook", "slack"] } },
    include: { tenant: { select: { intygaOrigin: true } } },
  })

  for (const rule of rules) {
    if (!isDue(rule, now)) continue

    const found = await prisma.finding.findMany({
      where: {
        tenantId: rule.tenantId,
        status: { in: ["new", "investigating"] },
        severity: { in: severitiesAtLeast(rule.minSeverity) },
        ...(rule.categories.length > 0 ? { category: { in: rule.categories } } : {}),
        lastSeenAt: { gt: watermark(rule), lte: now },
      },
      orderBy: { lastSeenAt: "desc" },
      take: MAX_FINDINGS_PER_DELIVERY + 1,
      select: {
        id: true,
        title: true,
        severity: true,
        category: true,
        status: true,
        count: true,
        detectedAt: true,
        lastSeenAt: true,
      },
    })
    if (found.length === 0) continue

    report.attempted++
    const more = found.length > MAX_FINDINGS_PER_DELIVERY
    const findings = found
      .slice(0, MAX_FINDINGS_PER_DELIVERY)
      .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])

    const error = await attempt(rule, findings, more, now, send)
    await prisma.alertRule.update({
      where: { id: rule.id },
      data: error
        ? { lastAttemptAt: now, lastError: error }
        : { lastAttemptAt: now, lastFiredAt: now, lastError: null },
    })
    if (error) report.failed++
    else report.delivered++
  }
  return report
}

/** One delivery. Returns null on success, or the authored reason it failed. */
async function attempt(
  rule: {
    name: string
    channel: string
    targetCipher: string
    signingSecretCipher: string | null
    tenant: { intygaOrigin: string | null }
  },
  findings: AlertFinding[],
  more: boolean,
  now: Date,
  send: Send,
): Promise<string | null> {
  const target = decryptSecret(rule.targetCipher)
  if (!target) return "the destination could not be decrypted — was SECRETS_ENC_KEY changed?"

  const body = buildBody(rule.channel as DeliveryChannel, {
    ruleName: rule.name,
    findings,
    more,
    consoleOrigin: rule.tenant.intygaOrigin,
    now,
  })
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "user-agent": "intyga-intelligence",
  }
  const secret = rule.signingSecretCipher ? decryptSecret(rule.signingSecretCipher) : null
  if (secret) headers[SIGNATURE_HEADER] = signBody(secret, body, Math.floor(now.getTime() / 1000))

  try {
    const res = await send(target, {
      method: "POST",
      headers,
      body,
      // A redirect is not followed: it would send the findings to a host nobody approved.
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    })
    // The response body is never read — nothing in it is needed, and it may be large or hostile.
    await res.body?.cancel().catch(() => {})
    if (res.status >= 200 && res.status < 300) return null
    if (res.status >= 300 && res.status < 400)
      return `redirected (HTTP ${res.status}) — redirects are not followed`
    return `HTTP ${res.status}`
  } catch (err) {
    const name = (err as Error).name
    return name === "TimeoutError" || name === "AbortError" ? "timed out" : "unreachable"
  }
}
