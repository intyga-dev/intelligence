import { createPrivateKey, sign } from "node:crypto"
import { z } from "zod"
import type { ConnectorContext, PollConnector } from "../registry.ts"
import type { NormalizedEvent } from "../types.ts"
import { alertEvent, hash, object, severity, string, type AlertInput } from "./common.ts"

const credentialCache = new Map<string, { token: string; expires: number }>()
async function json(url: string, init: RequestInit = {}): Promise<Record<string, unknown>> {
  const r = await fetch(url, { ...init, redirect: "error", signal: AbortSignal.timeout(15000) })
  if (!r.ok) throw new Error(`Provider returned HTTP ${r.status}`)
  const text = await r.text()
  if (text.length > 2_000_000) throw new Error("Provider response exceeds limit")
  const result = JSON.parse(text)
  if (!result || typeof result !== "object" || Array.isArray(result))
    throw new Error("Invalid provider response")
  return result
}
async function cachedToken(key: string, get: () => Promise<Record<string, unknown>>): Promise<string> {
  const prev = credentialCache.get(key)
  if (prev && prev.expires > Date.now() + 60000) return prev.token
  const result = await get(),
    token = string(result.access_token),
    seconds = Number(result.expires_in)
  if (!token || !Number.isFinite(seconds) || seconds <= 0)
    throw new Error("Provider did not return an expiring access token")
  if (credentialCache.size >= 100) credentialCache.clear()
  credentialCache.set(key, { token, expires: Date.now() + Math.min(seconds, 3600) * 1000 })
  return token
}
const form = (body: URLSearchParams): RequestInit => ({
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: body.toString(),
})
export async function googleAlertToken(ctx: ConnectorContext): Promise<string> {
  const subject = z.email().parse(ctx.config.adminEmail)
  const credentials = z
    .object({ type: z.literal("service_account"), client_email: z.email(), private_key: z.string().min(100) })
    .parse(JSON.parse(ctx.secret ?? "{}"))
  const cacheKey = hash(["google-workspace", ctx.connectionId, ctx.secret, subject])
  return cachedToken(cacheKey, async () => {
    const at = Math.floor(Date.now() / 1000),
      endpoint = "https://oauth2.googleapis.com/token"
    const encoded = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url")
    const payload = `${encoded({ alg: "RS256", typ: "JWT" })}.${encoded({ iss: credentials.client_email, sub: subject, aud: endpoint, scope: "https://www.googleapis.com/auth/apps.alerts", iat: at, exp: at + 3600 })}`
    const key = createPrivateKey(credentials.private_key)
    if (key.asymmetricKeyType !== "rsa") throw new Error("Expected an RSA service-account key")
    const assertion = `${payload}.${sign("RSA-SHA256", Buffer.from(payload), key).toString("base64url")}`
    return json(
      endpoint,
      form(new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion })),
    )
  })
}
async function azureToken(ctx: ConnectorContext): Promise<string> {
  const tenant = z.uuid().parse(ctx.config.azureTenantId),
    client = z.uuid().parse(ctx.config.clientId)
  if (!ctx.secret) throw new Error("Missing Azure credential")
  return cachedToken(hash(["azure", ctx.connectionId, tenant, client, ctx.secret]), () =>
    json(
      `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
      form(
        new URLSearchParams({
          client_id: client,
          client_secret: ctx.secret ?? "",
          scope: "https://management.azure.com/.default",
          grant_type: "client_credentials",
        }),
      ),
    ),
  )
}
function snapshot(ctx: ConnectorContext, source: string, a: AlertInput): NormalizedEvent | null {
  const event = alertEvent(ctx.connectionId, source, a)
  // This API reports current state. Observe it now, but retain a stable identity and native change time.
  return event
    ? { ...event, at: new Date(), attrs: { ...event.attrs, providerChangedAt: event.at.toISOString() } }
    : null
}
function nextUrl(value: unknown, current: string, origin: string, pathPrefix: string): string | null {
  if (!value) return null
  const url = new URL(string(value), current)
  if (url.origin !== origin || !url.pathname.startsWith(pathPrefix) || url.username || url.password)
    throw new Error("Unsafe provider pagination link")
  return url.toString()
}

export const googleWorkspaceConnector: PollConnector = {
  kind: "google-workspace",
  mode: "poll",
  label: "Google Workspace Alert Center",
  category: "Identity",
  coverage: "Medium/high Workspace security alerts and provider closure → provider alerts",
  docsUrl: "https://developers.google.com/workspace/admin/alertcenter/guides",
  blurb: "Import Google's detected Workspace security alerts without reading mailbox or Drive contents.",
  fields: [
    { name: "adminEmail", label: "Delegated Workspace administrator email", required: true },
    {
      name: "credentials",
      label: "Service-account JSON key",
      secret: true,
      required: true,
      help: "Full service-account JSON, encrypted at rest. This connector uses the apps.alerts scope, which is broader than read-only; the implementation only lists alerts.",
    },
  ],
  setup: [
    "Enable the Google Workspace Alert Center API in a Google Cloud project and create a service account for this integration.",
    "A Workspace super administrator must authorize domain-wide delegation for this account's client ID with scope https://www.googleapis.com/auth/apps.alerts. Configure the delegated administrator email above.",
    "Paste the dedicated service account's JSON key. Keep its Google Cloud roles minimal; no Gmail or Drive scopes are needed. Revoke the key when disconnecting.",
    "Turn the connector on and run the scheduler. It reads up to 500 alerts per tick, ordered by update time; larger results report incomplete coverage. Closed/deleted alerts resolve their matching findings.",
    "Only alert metadata is normalized. The provider's detailed user/message data is not copied into events. Unknown or low severity does not create a finding.",
  ],
  async poll(ctx) {
    const token = await googleAlertToken(ctx),
      out: NormalizedEvent[] = []
    let pageToken = ""
    for (let page = 0; page < 5; page++) {
      const q = new URLSearchParams({
        pageSize: "100",
        orderBy: "updateTime desc",
        ...(pageToken ? { pageToken } : {}),
      })
      const body = await json(`https://alertcenter.googleapis.com/v1beta1/alerts?${q}`, {
        headers: { authorization: `Bearer ${token}` },
      })
      if (body.alerts !== undefined && !Array.isArray(body.alerts))
        throw new Error("Invalid Workspace alerts list")
      for (const raw of (body.alerts ?? []) as unknown[]) {
        const a = object(raw),
          m = object(a.metadata),
          closed = m.status === "CLOSED" || a.deleted === true
        if (!closed && !["NOT_STARTED", "IN_PROGRESS"].includes(string(m.status))) continue
        const e = snapshot(ctx, "google-workspace", {
          id: string(a.alertId),
          incident: string(a.alertId),
          at: m.updateTime ?? a.updateTime ?? a.createTime,
          title: `Workspace: ${string(a.type) || "Security alert"}`,
          status: closed ? "resolved" : "firing",
          severity: severity(m.severity, "low"),
          category: "security",
          resource: string(a.source),
        })
        if (e) out.push(e)
      }
      pageToken = string(body.nextPageToken)
      if (!pageToken) return out
    }
    ctx.log("Workspace alert coverage truncated")
    return out
  },
}

export const azureMonitorConnector: PollConnector = {
  kind: "azure-monitor",
  mode: "poll",
  label: "Azure Monitor",
  category: "Cloud",
  coverage:
    "Azure Monitor fired/resolved alerts, including configured Service Health alerts → provider alerts",
  docsUrl: "https://learn.microsoft.com/en-us/rest/api/alerts-management/alerts/alerts/get-all",
  blurb: "Read alert state across an Azure subscription using a dedicated monitoring identity.",
  fields: [
    { name: "azureTenantId", label: "Microsoft Entra tenant ID", required: true },
    { name: "subscriptionId", label: "Azure subscription ID", required: true },
    { name: "clientId", label: "Application (client) ID", required: true },
    {
      name: "secret",
      label: "Client secret",
      secret: true,
      required: true,
      help: "Dedicated application with Monitoring Reader on the selected subscription. No write role is needed.",
    },
  ],
  setup: [
    "Create a dedicated Microsoft Entra application/service principal and grant Monitoring Reader on the selected subscription.",
    "Enter its tenant ID, application ID and client secret, plus the subscription ID. Rotate the credential before expiry.",
    "Configure Azure Monitor alert rules for the resources you want watched; this integration reads those alerts and does not create rules.",
    "Turn the connector on and run the scheduler. It reads up to 500 alerts from the last 30 days. Explicit monitorCondition=Resolved closes a finding; acknowledgement alone does not.",
    "This connector targets public Azure (management.azure.com). Sovereign-cloud endpoints are not supported in this version.",
  ],
  async poll(ctx) {
    const subscription = z.uuid().parse(ctx.config.subscriptionId),
      token = await azureToken(ctx),
      out: NormalizedEvent[] = []
    const path = `/subscriptions/${subscription}/providers/Microsoft.AlertsManagement/alerts`
    let url: string | null =
      `https://management.azure.com${path}?api-version=2019-03-01&timeRange=30d&pageCount=100&sortBy=lastModifiedDateTime&sortOrder=desc`
    for (let page = 0; url && page < 5; page++) {
      const body = await json(url, { headers: { authorization: `Bearer ${token}` } })
      if (!Array.isArray(body.value)) throw new Error("Invalid Azure alerts list")
      for (const raw of body.value) {
        const a = object(raw),
          e = object(object(a.properties).essentials),
          state = string(e.monitorCondition)
        if (!["Fired", "Resolved"].includes(state)) continue
        const value = snapshot(ctx, "azure-monitor", {
          id: string(a.id),
          incident: string(a.id),
          at: e.lastModifiedDateTime ?? e.startDateTime,
          title: `Azure: ${string(e.alertRule) || string(a.name)}`,
          status: state === "Resolved" ? "resolved" : "firing",
          severity:
            new Map<string, "critical" | "high" | "medium" | "low" | "info">([
              ["Sev0", "critical"],
              ["Sev1", "high"],
              ["Sev2", "medium"],
              ["Sev3", "low"],
              ["Sev4", "info"],
            ]).get(string(e.severity)) ?? "low",
          resource: string(e.targetResource),
        })
        if (value) out.push(value)
      }
      url = nextUrl(body.nextLink, url, "https://management.azure.com", path)
    }
    if (url) ctx.log("Azure alert coverage truncated")
    return out
  },
}

export const betterStackConnector: PollConnector = {
  kind: "better-stack",
  mode: "poll",
  label: "Better Stack",
  category: "Observability",
  coverage: "Confirmed monitor and heartbeat incidents and recovery → provider alerts",
  docsUrl: "https://betterstack.com/docs/uptime/api/list-all-incidents/",
  blurb: "Import confirmed uptime, certificate, domain and heartbeat incidents from Better Stack.",
  fields: [
    {
      name: "token",
      label: "Team API token",
      secret: true,
      required: true,
      help: "Use a token for the relevant team, not a global account token. The connector only makes GET requests; the token may have broader vendor permissions.",
    },
  ],
  setup: [
    "Create an API token scoped to the Better Stack team you want to monitor and paste it above.",
    "Configure uptime monitors or heartbeats in Better Stack first. This connector imports confirmed incidents from those monitors.",
    "Turn the connector on and run the scheduler. Up to 250 most recent incidents are read each tick; incomplete coverage is reported.",
    "Unconfirmed incidents are ignored. Only an explicit Resolved state closes a finding; acknowledged or validating incidents remain open. Response bodies and screenshots are not copied.",
  ],
  async poll(ctx) {
    if (!ctx.secret) throw new Error("Missing Better Stack token")
    const out: NormalizedEvent[] = []
    let url: string | null = "https://incidents.betterstack.com/api/v3/incidents?per_page=50"
    for (let page = 0; url && page < 5; page++) {
      const body = await json(url, { headers: { authorization: `Bearer ${ctx.secret}` } })
      if (!Array.isArray(body.data)) throw new Error("Invalid Better Stack incident list")
      for (const raw of body.data) {
        const a = object(raw),
          v = object(a.attributes)
        if (!["Started", "Acknowledged", "Validating", "Resolved"].includes(string(v.status))) continue
        const closed = v.status === "Resolved"
        const e = snapshot(ctx, "better-stack", {
          id: string(a.id),
          incident: string(a.id),
          at: closed ? v.resolved_at : v.started_at,
          title: `Better Stack: ${string(v.name) || string(v.cause) || "Incident"}`,
          status: closed ? "resolved" : "firing",
          severity: "medium",
          resource: string(v.name),
        })
        if (e) out.push(e)
      }
      url = nextUrl(
        object(body.pagination).next,
        url,
        "https://incidents.betterstack.com",
        "/api/v3/incidents",
      )
    }
    if (url) ctx.log("Better Stack incident coverage truncated")
    return out
  },
}
