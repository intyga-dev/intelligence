import type { Overview } from "../store/analytics.ts"
import type { FindingListItem } from "../store/repo.ts"
import { findingUrl } from "../domain/findingQuery.ts"
import { connectorHealth, type ConnectorHealthInput } from "../domain/connectorHealth.ts"
export { findingsPage } from "./findingsPage.ts"
import { areaChart, hBars, histogram, type Point } from "./charts.ts"
import { ago, authPage, esc, num, page } from "./layout.ts"

// Page renderers. Server-rendered strings — no client framework, no hydration, no build step.
//
// The organising principle is that CONFIGURING the service is as much the product as reading it:
// a findings list nobody can tune becomes noise, and noise gets ignored. So the nav has as much
// room for connectors, detectors and alerts as for the findings themselves.

const badge = (severity: string) => `<span class="badge ${esc(severity)}">${esc(severity)}</span>`

function actionBtn(o: {
  label: string
  action: string
  params: Record<string, unknown>
  cls?: string
}): string {
  // Every privileged control is the same shape: it carries the action and its parameters, and the
  // shell's ceremony turns that into a passkey signature. There is no unsigned path.
  return `<button class="${o.cls ?? ""}" data-action="${esc(o.action)}" data-params="${esc(
    JSON.stringify(o.params),
  )}">${esc(o.label)}</button>`
}

// ─── Onboarding ───────────────────────────────────────────────────────────────────────────────────

export type OnboardingValues = Partial<
  Record<
    | "setupToken"
    | "baseUrl"
    | "consoleUrl"
    | "workspaceId"
    | "origin"
    | "oidcClientId"
    | "serviceClientId"
    | "serviceSecret"
    | "trustAnchor",
    string
  >
>

export function onboardingPage(
  o: {
    error?: string
    setupEnabled?: boolean
    publicUrl?: string | null
    consoleUrl?: string
    values?: OnboardingValues
  } = {},
): string {
  const consoleUrl = o.consoleUrl ?? "https://app.intyga.com"
  const value = (name: keyof OnboardingValues, fallback = "") => esc(o.values?.[name] ?? fallback)
  if (o.setupEnabled === false) {
    return authPage({
      title: "Connect your INTYGA workspace",
      lede: "This instance is not connected to an INTYGA workspace yet.",
      ...(o.error ? { error: o.error } : {}),
      footnote: "Browser setup is off because SETUP_TOKEN is not set on the server.",
      body: `
<p>
  Browser setup is disabled on this server. Whoever operates it can either set
  <code>SETUP_TOKEN</code> and restart, then complete setup here, or bind the workspace from the
  command line with <code>scripts/bind-workspace.ts</code>.
</p>`,
    })
  }
  const callback = o.publicUrl ? `${o.publicUrl}/auth/callback` : "https://<this instance>/auth/callback"
  return authPage({
    title: "Connect your INTYGA workspace",
    lede: "Free operational insights on your infrastructure. Your team signs in and approves changes with INTYGA.",
    width: "wide",
    ...(o.error ? { error: o.error } : {}),
    footnote:
      "Intelligence has no accounts of its own: your INTYGA workspace's members are its users, and its " +
      "administrators are the workspace's administrators.",
    body: `
<div class="authSection">
  <p>Three things from your INTYGA console, then whoever is an administrator there signs in here.</p>
  <p><a href="${esc(consoleUrl)}/login?intent=intelligence" target="_blank" rel="noopener noreferrer">Create or open your INTYGA workspace ↗</a>
    · <a href="/demo">Explore an example incident</a></p>
</div>
<form method="post" action="/settings/bind">
  <div class="authSection">
    <h2>Setup token</h2>
    <p>
      The <code>SETUP_TOKEN</code> value from this server's environment. It proves you operate this
      instance — without it, whoever found a fresh deployment first could claim it.
    </p>
    <div class="field"><label>Setup token</label>
      <input name="setupToken" type="password" required autocomplete="off" value="${value("setupToken")}"></div>
  </div>
  <div class="authSection">
    <h2>Workspace</h2>
    <div class="grid g2">
      <div class="field"><label>INTYGA gateway URL</label>
        <input name="baseUrl" required placeholder="https://api.intyga.com" value="${value("baseUrl")}"></div>
      <div class="field"><label>INTYGA console URL</label>
        <input name="consoleUrl" required placeholder="https://app.intyga.com" value="${value("consoleUrl", consoleUrl)}"></div>
      <div class="field"><label>Workspace ID</label>
        <input name="workspaceId" required placeholder="shown at the top of API Keys in the console" value="${value("workspaceId")}"></div>
      <div class="field"><label>This instance's origin</label>
        <input name="origin" placeholder="https://intelligence.example.com" value="${value("origin", o.publicUrl ?? "")}">
        <div class="mut" style="font-size:11.5px;margin-top:5px">
          Scheme and port included. Sign-in returns here.</div></div>
    </div>
  </div>
  <div class="authSection">
    <h2>1 · Sign-in — an OIDC client</h2>
    <p>
      In the console, <b>Integrations → App sign-in</b>: register this instance with the redirect URI
      <code>${esc(callback)}</code>. Paste the client ID it shows (there is no secret).
    </p>
    <div class="field"><label>OIDC client ID</label>
      <input name="oidcClientId" required placeholder="oidc_…" value="${value("oidcClientId")}"></div>
  </div>
  <div class="authSection">
    <h2>2 · Approvals — a service key</h2>
    <p>
      In the console, <b>API Keys → Create a service and its key</b>. The key can only <i>ask</i> for
      an approval; every privileged change here is then approved under your workspace's rules by its
      members, at the console or on their phone.
    </p>
    <div class="grid g2">
      <div class="field"><label>Service client ID</label>
        <input name="serviceClientId" required placeholder="cid_…" value="${value("serviceClientId")}"></div>
      <div class="field"><label>Service secret</label>
        <input name="serviceSecret" type="password" required autocomplete="off" value="${value("serviceSecret")}">
        <div class="mut" style="font-size:11.5px;margin-top:5px">Encrypted at rest and never returned by the API.</div></div>
    </div>
  </div>
  <div class="authSection">
    <h2>3 · Trust — the approvers' keys</h2>
    <p>
      In the console, <b>Approval Rules → Export trust anchor</b>. Intelligence verifies every receipt
      against these keys itself, offline, before anything runs. Re-export it when approvers change.
    </p>
    <div class="field"><label>Trust anchor (JSON)</label>
      <textarea name="trustAnchor" rows="4" required placeholder='{"type":"intyga-trust-anchor", …}'>${value("trustAnchor")}</textarea></div>
  </div>
  <button class="primary" type="submit" style="margin-top:6px">Connect workspace</button>
</form>`,
  })
}

// ─── Overview ─────────────────────────────────────────────────────────────────────────────────────

export function overviewPage(o: {
  stats: Overview
  events: Point[]
  refusals: Point[]
  findings: FindingListItem[]
  counts: { findings: number; alerts: number; connectors: number }
  /** Who is signed in — rendered in the sidebar with the sign-out link. */
  actor?: { label: string; externalId: string }
  windowLabel: string
}): string {
  const s = o.stats
  const top = o.findings.slice(0, 5)
  return page({
    title: "Overview",
    lede: `What is worth your attention right now. Volume shown over the last ${o.windowLabel}.`,
    path: "/",
    counts: o.counts,
    ...(o.actor ? { actor: o.actor } : {}),
    body: `
${
  s.totalConnectors === 0 || s.eventsWindow === 0
    ? `<div class="card" style="margin-bottom:14px">
  <h2>Get your first useful finding</h2>
  <ol>
    <li><a href="/services">Create a service</a>, such as your production API.</li>
    <li><a href="/connectors">Connect deployment and error sources</a>, then assign them to that service.</li>
    <li>Enable the connectors and <a href="/detectors">choose detectors</a>. Each change uses your INTYGA passkey.</li>
    <li><a href="/services">Open the service timeline</a> to investigate evidence together.</li>
  </ol><p class="mut">Want to see what you are building toward? <a href="/demo">Explore an example incident.</a></p>
</div>`
    : ""
}
<div class="grid g4" style="margin-bottom:14px">
  <div class="stat"><div class="v">${num(s.openFindings)}</div><div class="l">Open findings</div>
    <div class="sub">${s.criticalFindings > 0 ? `${num(s.criticalFindings)} critical` : "none critical"}</div></div>
  <div class="stat"><div class="v">${num(s.eventsWindow)}</div><div class="l">Events observed</div>
    <div class="sub">${s.lastEventAt ? `last ${ago(s.lastEventAt)}` : "nothing yet"}</div></div>
  <div class="stat"><div class="v">${s.refusalRatePct === null ? "—" : `${s.refusalRatePct}%`}</div>
    <div class="l">Refusal rate</div><div class="sub">${num(s.refusalsWindow)} refused</div></div>
  <div class="stat"><div class="v">${num(s.activeConnectors)}<span class="mut" style="font-size:15px">/${num(s.totalConnectors)}</span></div>
    <div class="l">Connectors on</div><div class="sub"><a href="/connectors">manage</a></div></div>
</div>

<div class="grid g2" style="margin-bottom:14px">
  <div class="card"><h2>Events observed</h2>
    ${areaChart({ id: "c-ev", points: o.events, label: "Events per bucket", unit: "events" })}</div>
  <div class="card"><h2>Refused operations</h2>
    ${areaChart({ id: "c-rf", points: o.refusals, label: "Refusals per bucket", unit: "refused" })}</div>
</div>

<div class="card">
  <div class="row" style="margin-bottom:10px"><h2>Top findings</h2>
    <a class="right" href="/findings">All findings →</a></div>
  ${
    top.length === 0
      ? `<div class="empty">Nothing has crossed a threshold.<br>
           <span style="font-size:12px">An empty list is the normal state, not a broken one.</span></div>`
      : `<table><tbody>${top
          .map(
            (f) => `<tr>
              <td style="width:92px">${badge(f.severity)}</td>
              <td><a href="${esc(findingUrl(f.id))}">${esc(f.title)}</a>
                ${f.count > 1 ? `<span class="mut"> · seen ${num(f.count)}×</span>` : ""}</td>
              <td class="mut" style="width:96px;text-align:right">${ago(f.lastSeenAt)}</td></tr>`,
          )
          .join("")}</tbody></table>`
  }
</div>`,
  })
}

// ─── Activity ─────────────────────────────────────────────────────────────────────────────────────

export function activityPage(o: {
  events: Point[]
  refusals: Point[]
  subjects: { label: string; value: number }[]
  actions: { label: string; value: number }[]
  latency: { label: string; count: number }[]
  counts: { findings: number; alerts: number; connectors: number }
  /** Who is signed in — rendered in the sidebar with the sign-out link. */
  actor?: { label: string; externalId: string }
  windowLabel: string
}): string {
  return page({
    title: "Activity",
    lede: `What the connected sources have been doing over the last ${o.windowLabel}. Context for the findings, not a scoreboard.`,
    path: "/activity",
    counts: o.counts,
    ...(o.actor ? { actor: o.actor } : {}),
    body: `
<div class="grid g2" style="margin-bottom:14px">
  <div class="card"><h2>Events observed</h2><p class="mut" style="font-size:12px;margin:0 0 8px">All kinds.</p>
    ${areaChart({ id: "a-ev", points: o.events, label: "Events per bucket", unit: "events" })}</div>
  <div class="card"><h2>Refused operations</h2><p class="mut" style="font-size:12px;margin:0 0 8px">Denied or expired.</p>
    ${areaChart({ id: "a-rf", points: o.refusals, label: "Refusals per bucket", unit: "refused" })}</div>
</div>
<div class="grid g2">
  <div class="card"><h2>Most refused subjects</h2>
    <p class="mut" style="font-size:12px;margin:0 0 11px">Who is being turned away most.</p>${hBars(o.subjects)}</div>
  <div class="card"><h2>Most requested actions</h2>
    <p class="mut" style="font-size:12px;margin:0 0 11px">What is being attempted.</p>${hBars(o.actions)}</div>
  <div class="card"><h2>Approval latency</h2>
    <p class="mut" style="font-size:12px;margin:0 0 11px">Request to signature. A long tail means approvers are not seeing requests.</p>
    ${histogram(o.latency)}</div>
</div>`,
  })
}

// ─── Connectors ───────────────────────────────────────────────────────────────────────────────────

export interface ConnectorRow extends ConnectorHealthInput {
  id: string
  kind: string
  label: string
  builtIn: boolean
  active: boolean
  activatedAt: Date | null
  events: number
  lastEventAt: Date | null
  ingestUrl: string
  mode: "push" | "poll"
  setup: string[]
  /** Present once, immediately after creation. Never re-derivable. */
  freshSecret?: string
}

/**
 * Shown once, immediately after a push connector is created.
 *
 * Its own page rather than a redirect with the secret in the query string: URLs end up in logs,
 * browser history and proxies. This response is the only place the value ever appears.
 */
export function connectorCreatedPage(o: {
  connection: string
  def: { kind: string; label: string; setup: string[] }
  secret: string | null
  base: string
}): string {
  return page({
    title: `${o.def.label} connected`,
    lede: "Created and switched off. It ingests nothing until you turn it on.",
    path: "/connectors",
    body: `
<style>.setup{counter-reset:s;list-style:none;padding:0;margin:9px 0 0;display:grid;gap:6px}
.setup li{counter-increment:s;position:relative;padding-left:26px;font-size:12.5px;color:var(--muted)}
.setup li::before{content:counter(s);position:absolute;left:0;top:0;width:18px;height:18px;border-radius:999px;
  background:var(--panel-2);border:1px solid var(--border);color:var(--text);font-size:10px;
  display:flex;align-items:center;justify-content:center;font-weight:600}</style>
${
  o.secret
    ? `<div class="card" style="border-color:var(--amber)">
  <h2>Signing secret — shown once</h2>
  <p class="mut" style="font-size:13px;margin-top:0">
    Copy this now. It is stored encrypted and cannot be displayed again; a lost secret means
    creating a new connector.</p>
  <div style="background:var(--panel-2);border:1px solid var(--border);border-radius:8px;padding:12px">
    <code style="font-size:13px">${esc(o.secret)}</code></div>
</div>`
    : ""
}
<div class="card">
  <h2>Endpoint</h2>
  <div style="background:var(--panel-2);border:1px solid var(--border);border-radius:8px;padding:12px;margin-top:8px">
    <code>${esc(`${o.base}/ingest/${o.def.kind}/${o.connection}`)}</code></div>
</div>
<div class="card">
  <h2>Next</h2>
  <ol class="setup">${o.def.setup.map((x) => `<li>${esc(x)}</li>`).join("")}</ol>
  <div class="row" style="margin-top:14px">
    <a class="btn primary" href="/connectors">Back to connectors</a>
    <span class="mut" style="font-size:12px">Turn it on there when the source is configured.</span>
  </div>
</div>`,
  })
}

export interface AvailableConnector {
  kind: string
  label: string
  blurb: string
  mode: "push" | "poll"
  fields: {
    name: string
    label: string
    placeholder?: string
    help?: string
    required?: boolean
    secret?: boolean
  }[]
  /** True when Intelligence mints the secret itself — the form then has nothing else to ask for. */
  generatesSecret: boolean
  /** The steps shown after creation, previewed here so nobody creates a connector blind. */
  setup: string[]
  installed: boolean
  builtIn: boolean
}

export function connectorsPage(o: {
  rows: ConnectorRow[]
  available: AvailableConnector[]
  counts: { findings: number; alerts: number; connectors: number }
  /** Who is signed in — rendered in the sidebar with the sign-out link. */
  actor?: { label: string; externalId: string }
}): string {
  const addable = o.available
  const needsAttention = o.rows.filter((c) => connectorHealth(c).tone === "high").length
  const awaiting = o.rows.filter((c) => connectorHealth(c).tone === "off").length

  return page({
    title: "Connectors",
    lede:
      "Where observations come from. The INTYGA connector is built in — you already have the " +
      "relationship, this only decides whether Intelligence also watches it.",
    path: "/connectors",
    counts: o.counts,
    ...(o.actor ? { actor: o.actor } : {}),
    body: `
<style>
.setup{counter-reset:s;list-style:none;padding:0;margin:9px 0 0;display:grid;gap:6px}
.setup li{counter-increment:s;position:relative;padding-left:26px;font-size:12.5px;color:var(--muted)}
.setup li::before{content:counter(s);position:absolute;left:0;top:0;width:18px;height:18px;border-radius:999px;
  background:var(--panel-2);border:1px solid var(--border);color:var(--text);font-size:10px;
  display:flex;align-items:center;justify-content:center;font-weight:600}
.secret{background:var(--panel-2);border:1px solid var(--amber);border-radius:8px;padding:11px 13px;margin:10px 0 0}
.cat{display:grid;gap:10px}
.cat .c{display:flex;gap:12px;align-items:flex-start;border:1px solid var(--border);border-radius:10px;padding:13px 15px;background:var(--panel-2)}
.cat .c h3{margin:0 0 3px;font-size:13.5px;font-weight:650}
.cat .c p{margin:0;font-size:12.5px;color:var(--muted)}
</style>

<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(160px,1fr));margin-bottom:14px">
  <div class="stat"><div class="v">${num(o.rows.filter((c) => c.active).length)}</div><div class="l">Active sources</div></div>
  <div class="stat"><div class="v">${num(needsAttention)}</div><div class="l">Need attention</div></div>
  <div class="stat"><div class="v">${num(awaiting)}</div><div class="l">Awaiting setup or data</div></div>
</div>
<div class="card"><h2>From setup to your first finding</h2>
  <ol class="setup"><li>Configure a source below and turn it on with your passkey.</li>
    <li>For webhooks, send a test delivery. For polling sources, wait for the next scheduled detection tick.</li>
    <li>Check the health status below, then <a href="/detectors">review the detectors</a> that use your sources.</li></ol>
  <p class="mut" style="font-size:12px">An empty findings list is normal when no condition crosses a threshold. Connector health tells you whether observations are arriving.</p>
</div>

${o.rows
  .map((c) => {
    const health = connectorHealth(c)
    return `
<div class="card">
  <div class="row" style="margin-bottom:9px">
    <h2>${esc(c.label)}</h2>
    <span class="badge ${c.active ? "on" : "off"}">${c.active ? "active" : "inactive"}</span>
    ${c.builtIn ? `<span class="badge">built in</span>` : ""}
    <span class="badge">${c.mode}</span>
    <span class="right">${
      c.active
        ? actionBtn({
            label: "Turn off",
            action: "intelligence.connector.deactivate",
            params: { connectionId: c.id },
            cls: "ghost",
          })
        : actionBtn({
            label: "Turn on",
            action: "intelligence.connector.activate",
            params: { connectionId: c.id },
            cls: "primary",
          })
    }</span>
  </div>
  <div style="margin-bottom:12px"><span class="badge ${health.tone}">${esc(health.label)}</span>
    <p class="mut" style="margin:6px 0 0;font-size:12.5px">${esc(health.detail)}</p></div>
  <table><tbody>
    <tr><td class="mut" style="width:150px">Events ingested</td><td>${num(c.events)}${
      c.lastEventAt ? ` <span class="mut">· last ${ago(c.lastEventAt)}</span>` : ""
    }</td></tr>
    <tr><td class="mut">Activated</td><td>${c.activatedAt ? ago(c.activatedAt) : "—"}</td></tr>
    ${
      c.mode === "poll"
        ? `<tr><td class="mut">Last poll</td><td>${c.lastPolledAt ? ago(c.lastPolledAt) : "Not yet"}</td></tr>
      <tr><td class="mut">Last successful poll</td><td>${c.lastPollSuccessAt ? ago(c.lastPollSuccessAt) : "Not yet"}</td></tr>`
        : ""
    }
    ${
      c.mode === "push"
        ? `<tr><td class="mut">Webhook URL</td><td><code>${esc(c.ingestUrl)}</code></td></tr>`
        : ""
    }
  </tbody></table>
  ${
    c.freshSecret
      ? `<div class="secret"><b>Signing secret — shown once</b>
           <div style="margin-top:6px"><code>${esc(c.freshSecret)}</code></div>
           <div class="mut" style="font-size:12px;margin-top:6px">
             Store it now. It cannot be shown again; a lost secret means creating a new connector.</div></div>`
      : ""
  }
  ${c.setup.length > 0 ? `<details ${!c.active ? "open" : ""}><summary>Setup instructions</summary><ol class="setup">${c.setup.map((x) => `<li>${esc(x)}</li>`).join("")}</ol></details>` : ""}
</div>`
  })
  .join("")}

<div class="card">
  <h2>Add a connector</h2>
  <p class="mut" style="font-size:13px;margin-top:0">
    A new connector is created switched OFF and ingests nothing until you turn it on — which is a
    signed action, because that is the moment data starts flowing.
  </p>
  ${
    addable.length === 0
      ? `<div class="empty" style="margin-top:11px">Everything available is already connected.</div>`
      : `<div class="cat">${addable
          .map(
            (a) => `
      <div class="c">
        <div style="flex:1">
          <h3>${esc(a.label)} <span class="badge">${a.mode}</span></h3>
          <p>${esc(a.blurb)}</p>
        </div>
        <button class="btn" onclick="document.getElementById('add-${esc(a.kind)}').showModal()">${a.installed ? "Add another" : "Add"}</button>
      </div>
      <dialog id="add-${esc(a.kind)}">
        <form method="post" action="/connectors/add">
          <input type="hidden" name="kind" value="${esc(a.kind)}">
          <div class="head"><h3>Add ${esc(a.label)}</h3></div>
          <div class="body">
            <p class="mut" style="margin:0 0 13px;font-size:13px">${esc(a.blurb)}</p>
            <div class="field"><label>Label</label>
              <input name="label" placeholder="${esc(a.label)}" value="${esc(a.label)}">
              <div class="mut" style="font-size:11.5px;margin-top:4px">Name to identify this source (e.g. ${esc(a.label)} staging)</div>
            </div>
            ${a.fields
              .map(
                (f) => `<div class="field"><label>${esc(f.label)}</label>
                  ${
                    a.kind === "metrics" && f.name === "queries"
                      ? `<textarea name="queries" rows="4" placeholder="${esc(f.placeholder ?? "")}"></textarea>`
                      : `<input name="${esc(f.name)}" ${f.secret ? 'type="password" autocomplete="off"' : ""}
                    ${f.required ? "required" : ""} placeholder="${esc(f.placeholder ?? "")}">`
                  }
                  ${f.help ? `<div class="mut" style="font-size:11.5px;margin-top:4px">${esc(f.help)}</div>` : ""}
                </div>`,
              )
              .join("")}
            ${
              a.generatesSecret
                ? `<p class="mut" style="font-size:12.5px;margin:4px 0 10px">Nothing else to fill in: Intelligence
                generates this connector's signing secret and shows it once, with the endpoint URL, on the
                next page.</p>`
                : ""
            }
            <details style="font-size:12.5px"><summary class="mut">What you will set up in ${esc(a.label)}</summary>
              <ol style="margin:8px 0 0;padding-left:18px">${a.setup.map((s) => `<li class="mut">${esc(s)}</li>`).join("")}</ol>
            </details>
          </div>
          <div class="foot">
            <button class="ghost" type="button" onclick="this.closest('dialog').close()">Cancel</button>
            <button class="primary" type="submit">Create — switched off</button>
          </div>
        </form>
      </dialog>`,
          )
          .join("")}</div>`
  }
</div>`,
  })
}

// ─── Detectors, Alerts, Judgment, Members, Settings ──────────────────────────────────────────────

export function detectorsPage(o: {
  rows: { detector: string; enabled: boolean; description: string; settings: string; needs: string }[]
  counts: { findings: number; alerts: number; connectors: number }
  /** Who is signed in — rendered in the sidebar with the sign-out link. */
  actor?: { label: string; externalId: string }
}): string {
  return page({
    title: "Detectors",
    lede: "What Intelligence looks for. Thresholds exist so a finding means something — tune them until the list is worth reading.",
    path: "/detectors",
    counts: o.counts,
    ...(o.actor ? { actor: o.actor } : {}),
    body: `<div class="card"><table>
<thead><tr><th>Detector</th><th>What it finds</th><th>Thresholds</th><th style="width:170px">State</th></tr></thead>
<tbody>${o.rows
      .map(
        (
          d,
        ) => `<tr><td><b>${esc(d.detector)}</b><div class="mut" style="font-size:11.5px">needs: ${esc(d.needs)}</div></td>
      <td class="mut">${esc(d.description)}</td>
      <td><code>${esc(d.settings)}</code></td>
      <td><span class="badge ${d.enabled ? "on" : "off"}">${d.enabled ? "on" : "off"}</span> ${actionBtn(
        d.enabled
          ? {
              label: "Turn off",
              action: "intelligence.detector.disable",
              params: { detector: d.detector },
              cls: "danger",
            }
          : { label: "Turn on", action: "intelligence.detector.enable", params: { detector: d.detector } },
      )}</td></tr>`,
      )
      .join("")}</tbody></table>
  <p class="mut" style="font-size:12px;margin:12px 0 0">
    A detector with none of the sources it needs connected simply finds nothing. The code-change
    detector's path map is set per GitHub connector (<code>generic</code> or <code>intyga-core</code>).</p></div>`,
  })
}

export function alertsPage(o: {
  rules: {
    id: string
    name: string
    minSeverity: string
    channel: string
    targetHost: string
    cooldownMinutes: number
    active: boolean
    lastFiredAt: Date | null
    lastError: string | null
    /** False for a rule created before delivery existed: no signing secret, cannot be turned on. */
    deliverable: boolean
  }[]
  counts: { findings: number; alerts: number; connectors: number }
  /** Who is signed in — rendered in the sidebar with the sign-out link. */
  actor?: { label: string; externalId: string }
  /** A form error, shown above the form. Authored text only. */
  error?: string
}): string {
  const state = (r: (typeof o.rules)[number]): string => {
    if (!r.deliverable) return `<span class="mut">recreate to use</span>`
    // Turning ON is signed and binds the destination host; turning OFF is signed so the record of
    // who stopped the flow is as good as the record of who started it.
    return r.active
      ? `<span class="badge on">on</span> ${actionBtn({
          label: "Turn off",
          action: "intelligence.alert.deactivate",
          params: { ruleId: r.id },
        })}`
      : `<span class="badge">off</span> ${actionBtn({
          label: "Turn on",
          action: "intelligence.alert.activate",
          params: { ruleId: r.id, host: r.targetHost },
          cls: "primary",
        })}`
  }
  return page({
    title: "Alerts",
    lede: "Findings are recorded whatever you do here. Alerts decide which ones are worth interrupting someone for.",
    path: "/alerts",
    counts: o.counts,
    ...(o.actor ? { actor: o.actor } : {}),
    body: `
<div class="card">
  <h2>Rules</h2>
  ${
    o.rules.length === 0
      ? `<div class="empty" style="margin-top:11px">No alert rules. Findings are still recorded and visible here.</div>`
      : `<table style="margin-top:9px"><thead><tr><th>Name</th><th>Fires at</th><th>Destination</th><th>Cooldown</th><th>Last delivered</th><th style="width:170px"></th></tr></thead>
    <tbody>${o.rules
      .map(
        (r) => `<tr><td><b>${esc(r.name)}</b></td><td>${badge(r.minSeverity)} and above</td>
        <td>${esc(r.channel)} · <code>${esc(r.targetHost || "—")}</code></td><td class="mut">${r.cooldownMinutes}m</td>
        <td class="mut">${r.lastFiredAt ? ago(r.lastFiredAt) : "never"}${
          r.lastError
            ? `<div style="color:var(--red);font-size:12px">last attempt: ${esc(r.lastError)}</div>`
            : ""
        }</td><td>${state(r)}</td></tr>`,
      )
      .join("")}</tbody></table>`
  }
  <p class="mut" style="font-size:12px;margin:12px 0 0">
    Delivered on each detection tick, at most once per cooldown, in one batch. What is sent: each
    finding's id, title, severity, category, status, count and timestamps, plus a link back here —
    never evidence or raw events. Titles can name the subject involved.</p>
</div>
${o.error ? `<div class="card" style="border-color:var(--red);color:var(--red)">${esc(o.error)}</div>` : ""}
<form class="card" method="post" action="/alerts/create">
  <h2>New rule</h2>
  <div class="grid g2">
    <div class="field"><label>Name</label><input name="name" required placeholder="Page on critical"></div>
    <div class="field"><label>Minimum severity</label><select name="minSeverity">
      <option value="critical">critical</option><option value="high" selected>high</option>
      <option value="medium">medium</option><option value="low">low</option><option value="info">info</option></select></div>
    <div class="field"><label>Channel</label><select name="channel">
      <option value="webhook">webhook — signed JSON</option><option value="slack">Slack incoming webhook</option></select></div>
    <div class="field"><label>Cooldown (minutes)</label><input name="cooldownMinutes" type="number" value="60" min="0"></div>
  </div>
  <div class="field"><label>Destination (https)</label><input name="target" required placeholder="https://hooks.example.com/…">
    <div class="mut" style="font-size:12px;margin-top:4px">Stored encrypted — a webhook URL is a credential.
    The rule is created switched off; turning it on needs a passkey approval.</div></div>
  <button class="primary" type="submit">Create rule</button>
</form>`,
  })
}

export function alertCreatedPage(o: {
  name: string
  channel: string
  host: string
  signingSecret: string
  counts: { findings: number; alerts: number; connectors: number }
  actor?: { label: string; externalId: string }
}): string {
  return page({
    title: `${o.name} created`,
    lede: `Created and switched off. Nothing is sent to ${o.host} until you turn it on.`,
    path: "/alerts",
    counts: o.counts,
    ...(o.actor ? { actor: o.actor } : {}),
    body: `
${
  o.channel === "webhook"
    ? `<div class="card" style="border-color:var(--amber)">
  <h2>Signing secret — shown once</h2>
  <p class="mut" style="font-size:13px;margin-top:0">
    Every delivery carries <code>x-intelligence-signature: t=&lt;unix&gt;,v1=&lt;hex&gt;</code>, an
    HMAC-SHA256 of <code>&lt;t&gt;.&lt;raw body&gt;</code> under this secret. Verify it against the raw
    bytes before parsing, and refuse old timestamps. It is stored encrypted and cannot be shown again.</p>
  <div style="background:var(--panel-2);border:1px solid var(--border);border-radius:8px;padding:12px">
    <code style="font-size:13px">${esc(o.signingSecret)}</code></div>
</div>`
    : ""
}
<div class="card">
  <div class="row">
    <a class="btn primary" href="/alerts">Back to alerts</a>
    <span class="mut" style="font-size:12px">Turn it on there once the receiver is ready.</span>
  </div>
</div>`,
  })
}

export interface JudgmentAuditRow {
  id: string
  createdAt: Date
  findingId?: string
  findingTitle: string
  status: string
  model: string
  // `| undefined` on purpose — see JudgmentEvaluationResult. A request the provider answered only
  // partly has these absent, and under exactOptionalPropertyTypes that is a distinct type.
  anomalous?: number | undefined
  confidence?: number | undefined
  tokens?: { input_tokens: number; output_tokens: number } | null
  stateDigest?: string | null
  lastError?: string | null
}

export interface JudgmentPagination {
  page: number
  pageSize: number
  totalCount: number
  totalPages: number
}

export function judgmentPage(o: {
  enabled: boolean
  configured: boolean
  model: string
  endpoint: string
  preview: string
  requests?: JudgmentAuditRow[]
  pagination?: JudgmentPagination
  counts: { findings: number; alerts: number; connectors: number }
  /** Who is signed in — rendered in the sidebar with the sign-out link. */
  actor?: { label: string; externalId: string }
}): string {
  const reqs = o.requests ?? []

  return page({
    title: "Judgment",
    lede:
      "Optional semantic classification. Detectors decide what is true on their own — a model only " +
      "sharpens severity and filters expected behaviour.",
    path: "/judgment",
    counts: o.counts,
    ...(o.actor ? { actor: o.actor } : {}),
    body: `
<div class="card">
  <div class="row" style="margin-bottom:9px">
    <h2>TypeSafe AI · JEV</h2>
    <span class="badge ${o.enabled ? "on" : "off"}">${o.enabled ? "enabled" : "disabled"}</span>
    <span class="right">${
      o.enabled
        ? actionBtn({ label: "Turn off", action: "intelligence.judgment.disable", params: {}, cls: "ghost" })
        : actionBtn({
            label: "Turn on",
            action: "intelligence.judgment.enable",
            params: { provider: "typesafe" },
            cls: "primary",
          })
    }</span>
  </div>
  <table><tbody>
    <tr><td class="mut" style="width:150px">Model</td><td><code>${esc(o.model)}</code></td></tr>
    <tr><td class="mut">Endpoint</td><td><code>${esc(o.endpoint)}</code></td></tr>
    <tr><td class="mut">API key</td><td>${
      o.configured
        ? "configured"
        : `<span class="mut">not set — the null provider runs and nothing leaves</span>`
    }</td></tr>
  </tbody></table>
</div>

<div class="card">
  <h2>Audit log — Outbound requests</h2>
  <p class="mut" style="font-size:13px;margin-top:0">
    Every call dispatched to TypeSafe AI (JEV), with cryptographic state digest, model version, and outcome.
  </p>
  ${
    reqs.length === 0
      ? `<div class="empty" style="margin-top:11px">No judgment requests yet. Once a finding crosses a detection threshold, it will be evaluated and logged here.</div>`
      : `<table style="margin-top:9px"><thead><tr>
           <th>When</th>
           <th>Finding</th>
           <th>Status</th>
           <th>Model</th>
           <th>Assessment</th>
           <th>Tokens</th>
           <th>Digest</th>
         </tr></thead>
         <tbody>${reqs
           .map(
             (r) => `<tr>
               <td class="mut" style="white-space:nowrap">${ago(r.createdAt)}</td>
               <td>${
                 r.findingId
                   ? `<a href="${esc(findingUrl(r.findingId))}"><b>${esc(r.findingTitle)}</b></a>`
                   : `<b>${esc(r.findingTitle)}</b>`
               }</td>
               <td><span class="badge ${r.status === "DONE" ? "on" : r.status === "FAILED" ? "off" : ""}">${esc(r.status)}</span></td>
               <td><code>${esc(r.model)}</code></td>
               <td>${
                 r.anomalous !== undefined
                   ? `<b>anomalous ${(r.anomalous * 100).toFixed(0)}%</b>${
                       r.confidence !== undefined
                         ? ` <span class="mut">· ${(r.confidence * 100).toFixed(0)}% conf</span>`
                         : ""
                     }`
                   : r.lastError
                     ? `<span style="color:var(--red)">${esc(r.lastError)}</span>`
                     : "—"
               }</td>
               <td class="mut">${
                 r.tokens ? `${num(r.tokens.input_tokens)} / ${num(r.tokens.output_tokens)}` : "—"
               }</td>
               <td>${r.stateDigest ? `<code>${esc(r.stateDigest.slice(0, 10))}…</code>` : "—"}</td>
             </tr>`,
           )
           .join("")}</tbody></table>${
           o.pagination && o.pagination.totalCount > 0
             ? `<div class="row" style="margin-top:14px;justify-content:space-between">
                    <div class="mut" style="font-size:12px">
                      Showing ${(o.pagination.page - 1) * o.pagination.pageSize + 1}–${Math.min(
                        o.pagination.page * o.pagination.pageSize,
                        o.pagination.totalCount,
                      )} of ${num(o.pagination.totalCount)} requests
                    </div>
                    ${
                      o.pagination.totalPages > 1
                        ? `<div class="row" style="gap:6px">
                             ${
                               o.pagination.page > 1
                                 ? `<a class="btn ghost" style="min-height:26px;padding:3px 9px;font-size:11px" href="/judgment?page=${o.pagination.page - 1}">Previous</a>`
                                 : `<button class="ghost" disabled style="min-height:26px;padding:3px 9px;font-size:11px">Previous</button>`
                             }
                             <span class="mut" style="font-size:11.5px;padding:0 4px">Page ${o.pagination.page} of ${o.pagination.totalPages}</span>
                             ${
                               o.pagination.page < o.pagination.totalPages
                                 ? `<a class="btn ghost" style="min-height:26px;padding:3px 9px;font-size:11px" href="/judgment?page=${o.pagination.page + 1}">Next</a>`
                                 : `<button class="ghost" disabled style="min-height:26px;padding:3px 9px;font-size:11px">Next</button>`
                             }
                           </div>`
                        : ""
                    }
                  </div>`
             : ""
         }`
  }
</div>

<div class="card">
  <h2>Exactly what would be sent</h2>
  <p class="mut" style="font-size:13px;margin-top:0">
    Rendered from a real finding, without contacting anyone. If you cannot read this and be
    comfortable, it should not be enabled.
  </p>
  <pre style="background:var(--panel-2);border-radius:8px;padding:12px;overflow:auto;font-size:12px;margin:0"><code>${esc(
    o.preview,
  )}</code></pre>
</div>

<div class="card">
  <h2>Before enabling</h2>
  <p class="mut" style="font-size:13px;margin:0">
    TypeSafe AI is a third-party processor outside INTYGA's infrastructure. Sign the DPA, request
    zero data retention, and record it as a subprocessor first. Detectors work without it.
  </p>
</div>`,
  })
}

export function membersPage(o: {
  rows: { externalId: string; label: string; role: string; lastLoginAt: Date | null; active: boolean }[]
  consoleUrl: string
  counts: { findings: number; alerts: number; connectors: number }
  /** Who is signed in — rendered in the sidebar with the sign-out link. */
  actor?: { label: string; externalId: string }
}): string {
  return page({
    title: "Members",
    lede: "Everyone who has signed in with INTYGA. Membership and roles are the workspace's, managed there.",
    path: "/members",
    counts: o.counts,
    ...(o.actor ? { actor: o.actor } : {}),
    body: `
<div class="card"><table>
<thead><tr><th>Member</th><th>INTYGA email</th><th>Role</th><th>Last sign-in</th></tr></thead>
<tbody>${o.rows
      .map(
        (m) => `<tr><td><b>${esc(m.label)}</b></td><td><code>${esc(m.externalId)}</code></td>
    <td>${
      !m.active
        ? `<span class="mut">no longer a member</span>`
        : m.role === "ADMIN"
          ? `<span class="badge on">administrator</span>`
          : `<span class="badge">member</span>`
    }</td>
    <td>${m.lastLoginAt ? esc(ago(m.lastLoginAt)) : "—"}</td></tr>`,
      )
      .join("")}</tbody></table>
  ${o.rows.length === 0 ? `<p class="mut" style="margin:12px 0 0">Nobody has signed in yet.</p>` : ""}
</div>
<div class="card">
  <h2>Adding people</h2>
  <p class="mut" style="font-size:13px;margin:0">
    Add them to your INTYGA workspace — <a href="${esc(o.consoleUrl)}/directory" target="_blank" rel="noopener noreferrer">Directory ↗</a>.
    Workspace <b>administrators</b> can change anything here and approve privileged actions under the
    workspace's rules; <b>members</b> can read findings and services. A person's role is read from
    INTYGA at each sign-in; removing them from the workspace ends their access here at the next request.
  </p>
</div>`,
  })
}

export function settingsPage(o: {
  binding: {
    baseUrl: string | null
    consoleUrl: string | null
    workspaceId: string | null
    oidcClientId: string | null
    serviceClientId: string | null
    hasSecret: boolean
    trustAnchorAt: Date | null
    origin: string | null
  }
  retentionDays: number
  counts: { findings: number; alerts: number; connectors: number }
  /** Who is signed in — rendered in the sidebar with the sign-out link. */
  actor?: { label: string; externalId: string }
}): string {
  const b = o.binding
  const bound = Boolean(b.baseUrl && b.oidcClientId)
  // Repointing the workspace is an APPROVED action — you must still be who you were to say who you
  // will be. The secret and the trust anchor are never part of the signed parameters; see the action
  // registry for why. They are replaced below, by an administrator, without a signature.
  return page({
    title: "Settings",
    lede: "The INTYGA workspace this service runs on, and what it keeps.",
    path: "/settings",
    counts: o.counts,
    ...(o.actor ? { actor: o.actor } : {}),
    body: `
<div class="card">
  <div class="row" style="margin-bottom:4px">
    <h2>INTYGA workspace</h2>
    <span class="badge ${bound ? "on" : "off"}">${bound ? "connected" : "not connected"}</span>
  </div>
  <p class="mut" style="font-size:13px;margin:0 0 14px">
    Intelligence has no login of its own — this workspace's members sign in here with INTYGA, its
    administrators administer Intelligence, and every privileged change is approved under its rules.
    Repointing it is the one change that could hand this tenant to someone else, so it requires
    approval from the workspace you are leaving.
  </p>
  <table style="margin-bottom:12px">
    <tr><th>Gateway</th><td><code>${esc(b.baseUrl ?? "—")}</code></td></tr>
    <tr><th>Console</th><td><code>${esc(b.consoleUrl ?? "—")}</code></td></tr>
    <tr><th>Workspace ID</th><td><code>${esc(b.workspaceId ?? "—")}</code></td></tr>
    <tr><th>OIDC client</th><td><code>${esc(b.oidcClientId ?? "—")}</code> · redirect <code>${esc(
      b.origin ? `${b.origin}/auth/callback` : "—",
    )}</code></td></tr>
    <tr><th>Service key</th><td><code>${esc(b.serviceClientId ?? "—")}</code> · secret ${
      b.hasSecret ? "stored" : "<b>missing</b>"
    }</td></tr>
    <tr><th>Trust anchor</th><td>${
      b.trustAnchorAt ? `stored ${esc(ago(b.trustAnchorAt))}` : "<b>missing</b>"
    } — re-export it whenever the workspace's approvers change</td></tr>
  </table>
  <div class="row">
    <button id="test-binding">Test connection</button>
    <span id="test-result" class="mut" style="font-size:13px"></span>
    ${actionBtn({
      label: "Repoint to another workspace…",
      action: "intelligence.workspace.rebind",
      params: {
        baseUrl: b.baseUrl ?? "",
        consoleUrl: b.consoleUrl ?? "",
        workspaceId: b.workspaceId ?? "",
        oidcClientId: b.oidcClientId ?? "",
        serviceClientId: b.serviceClientId ?? "",
      },
      cls: "danger",
    })}
  </div>
  <script>
  document.getElementById("test-binding").addEventListener("click", async () => {
    const out = document.getElementById("test-result");
    out.textContent = "Testing…";
    const r = await fetch("/settings/test", { method: "POST", headers: { accept: "application/json" } });
    const b = await r.json().catch(() => ({ ok: false, error: "no answer" }));
    out.textContent = b.ok ? "Connected: the service key is accepted." : (b.error || "failed");
  });
  </script>
</div>
<div class="card">
  <h2>Credentials</h2>
  <p class="mut" style="font-size:13px;margin-top:0">
    Rotate the service secret or store a freshly exported trust anchor without changing which
    workspace this tenant belongs to. Not an approved action: a secret the workspace does not know
    simply fails at the next exchange. An administrator can paste arbitrary approver keys; a bad
    anchor makes actions fail. It can never skip approval: INTYGA still checks the approval when
    Intelligence redeems it, before the action runs. Administrators only.
  </p>
  <form method="post" action="/settings/credentials">
    <div class="grid g2">
      <div class="field"><label>New service secret (optional)</label>
        <input name="serviceSecret" type="password" autocomplete="off"></div>
      <div class="field"><label>Trust anchor JSON (optional)</label>
        <textarea name="trustAnchor" rows="3" placeholder='{"type":"intyga-trust-anchor", …}'></textarea></div>
    </div>
    <button type="submit">Save</button>
  </form>
</div>
<div class="card">
  <h2>Data retention</h2>
  <p class="mut" style="font-size:13px;margin-top:0">
    Raw and normalised events are kept for ${o.retentionDays} days. Findings live longer because
    they hold no raw content. Everything here is a copy of someone else's record — keep it no
    longer than they would.
  </p>
  <div class="row">
    ${actionBtn({
      label: "Purge events older than 90 days",
      action: "intelligence.data.purge",
      params: { scope: "events", olderThanDays: 90 },
      cls: "danger",
    })}
    ${actionBtn({
      label: "Purge everything older than 365 days",
      action: "intelligence.data.purge",
      params: { scope: "all", olderThanDays: 365 },
      cls: "danger",
    })}
  </div>
</div>

<div class="card">
  <h2>Trust boundary</h2>
  <p class="mut" style="font-size:13px;margin:0">
    Intelligence holds one INTYGA credential: a service key that can open an approval and nothing
    else. It cannot approve anything, read the workspace's ledger, or change its rules. Every
    privileged change here is signed by the workspace's own members under the workspace's own
    rules, and the receipt is verified on this server, against the exported approver keys, before
    anything runs. A build-time check (<code>pnpm check:boundary</code>) fails the build if a
    stronger credential ever appears.
  </p>
</div>`,
  })
}
