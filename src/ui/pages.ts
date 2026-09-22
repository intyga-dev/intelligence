import type { Evidence } from "../domain/finding.ts"
import type { Overview } from "../store/analytics.ts"
import type { FindingListItem } from "../store/repo.ts"
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

export function onboardingPage(o: { error?: string } = {}): string {
  return authPage({
    title: "Connect your INTYGA workspace",
    lede: "Intelligence is an add-on to INTYGA. It runs on the workspace you connect here.",
    width: "wide",
    ...(o.error ? { error: o.error } : {}),
    footnote:
      "Nothing is watched until you switch a connector on. Connecting only establishes who may sign in.",
    body: `
<form method="post" action="/settings/bind">
  <div class="authSection">
    <h2>Workspace</h2>
    <p>
      In your INTYGA console, register Intelligence as a Relying Party under <code>/platform</code>,
      then create a platform API key with <code>subjects:write</code>, <code>credentials:write</code>,
      <code>receipts:create</code> and <code>receipts:read</code>. Those scopes act only on
      Intelligence's own subjects — none of them can approve anything in INTYGA.
    </p>
    <div class="grid g2">
      <div class="field"><label>INTYGA base URL</label>
        <input name="baseUrl" required placeholder="https://api.intyga.com"></div>
      <div class="field"><label>Platform client ID</label>
        <input name="clientId" required placeholder="cid_…"></div>
      <div class="field"><label>RP ID — a bare host</label>
        <input name="rpId" required placeholder="intelligence.example.com">
        <div class="mut" style="font-size:11.5px;margin-top:5px">
          A hostname only: no scheme, no port, no path. Use <code>localhost</code> when developing.</div></div>
      <div class="field"><label>Origin — the full URL</label>
        <input name="origin" required placeholder="https://intelligence.example.com">
        <div class="mut" style="font-size:11.5px;margin-top:5px">
          Scheme and port included, e.g. <code>http://localhost:4100</code>. Its host must equal the
          RP ID or be a subdomain of it.</div></div>
    </div>
    <div class="field"><label>Private key — PKCS#8 PEM</label>
      <textarea name="privateKey" rows="3" required
        placeholder="-----BEGIN PRIVATE KEY-----&#10;…&#10;-----END PRIVATE KEY-----"></textarea>
      <div class="mut" style="font-size:11.5px;margin-top:5px">
        Encrypted at rest and never returned by the API.</div></div>
  </div>

  <div class="authSection">
    <h2>First administrator</h2>
    <p>
      Without one, nothing here could ever be approved — including adding one. They enrol a passkey
      after this.
    </p>
    <div class="grid g2">
      <div class="field"><label>INTYGA subject id</label>
        <input name="adminExternalId" required placeholder="ada"></div>
      <div class="field"><label>Name</label>
        <input name="adminLabel" required placeholder="Ada Lovelace"></div>
    </div>
  </div>

  <button class="primary" type="submit" style="margin-top:6px">Create workspace</button>
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
              <td><a href="/findings#${esc(f.id)}">${esc(f.title)}</a>
                ${f.count > 1 ? `<span class="mut"> · seen ${num(f.count)}×</span>` : ""}</td>
              <td class="mut" style="width:96px;text-align:right">${ago(f.lastSeenAt)}</td></tr>`,
          )
          .join("")}</tbody></table>`
  }
</div>`,
  })
}

// ─── Findings ─────────────────────────────────────────────────────────────────────────────────────

function renderEvidence(e: Evidence): string {
  switch (e.kind) {
    case "metric": {
      const cmp =
        e.baseline !== undefined && e.baseline > 0
          ? ` <span class="mut">vs ${num(e.baseline)} typical (${(e.value / e.baseline).toFixed(1)}×)</span>`
          : e.baseline === 0
            ? ` <span class="mut">vs none before</span>`
            : ""
      return `<li><span class="k">metric</span>${esc(e.label)} — <b>${num(e.value)}</b>${cmp}</li>`
    }
    case "eventRef":
      return `<li><span class="k">event</span><code>${esc(e.eventKind)}</code> <span class="mut">${esc(
        e.sourceId,
      )} · ${ago(e.at)}</span></li>`
    case "deployment":
      return `<li><span class="k">deploy</span><code>${esc(e.sha.slice(0, 8))}</code> ${esc(
        e.workflow,
      )} <span class="mut">${esc(e.conclusion)} · ${ago(e.at)}</span></li>`
    case "codeChange":
      return `<li><span class="k">code</span>${esc(e.repo)}#${e.pr} <span class="mut">${e.paths.length} paths</span></li>`
    case "correlation":
      return `<li><span class="k">link</span>${esc(e.relation)} <span class="mut">lag ${Math.round(
        e.lagMs / 1000,
      )}s</span></li>`
    case "assessment": {
      const p = e.probability !== undefined ? `${(e.probability * 100).toFixed(0)}%` : String(e.answer)
      const c =
        e.confidence !== undefined
          ? ` <span class="mut">confidence ${(e.confidence * 100).toFixed(0)}%</span>`
          : ""
      // Model output is styled apart from measured fact. A reader must never have to guess which is which.
      return `<li class="model"><span class="k model">assessment</span> ${esc(e.question)} — <b>${esc(p)}</b>${c}${e.model ? ` <span class="badge" style="background:var(--panel-2);border-color:var(--brand);color:var(--brand);margin-left:6px">${esc(e.model)}</span>` : ""}</li>`
    }
  }
}

const VERDICTS = ["useful", "not_useful", "investigating", "expected", "false_positive", "fixed"]

export function findingsPage(o: {
  findings: FindingListItem[]
  counts: { findings: number; alerts: number; connectors: number }
  /** Who is signed in — rendered in the sidebar with the sign-out link. */
  actor?: { label: string; externalId: string }
  filter: string
}): string {
  const tab = (v: string, label: string) =>
    `<a class="btn ${o.filter === v ? "primary" : ""}" href="/findings?status=${v}">${esc(label)}</a>`
  return page({
    title: "Findings",
    lede: "Evidence first. Every finding names what was measured, against what baseline, and when.",
    path: "/findings",
    counts: o.counts,
    ...(o.actor ? { actor: o.actor } : {}),
    body: `
<style>
.f{background:var(--panel);border:1px solid var(--border);border-left:3px solid var(--border);border-radius:12px;padding:15px 17px;margin:0 0 12px}
.f.critical{border-left-color:var(--red)} .f.high{border-left-color:var(--amber)}
.f.medium{border-left-color:var(--brand)} .f.low,.f.info{border-left-color:var(--border-interactive)}
.f header{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin-bottom:7px;font-size:11px}
.f h3{font-size:15px;font-weight:650;margin:0 0 5px}
.f .sum{color:var(--muted);font-size:13px;margin:0 0 11px}
.f ul{list-style:none;margin:0 0 11px;padding:10px 12px;background:var(--panel-2);border-radius:8px;display:grid;gap:5px;font-size:12.5px}
.f ul .k{display:inline-block;min-width:80px;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.08em}
.f ul li.model{color:var(--brand)} .f ul li.model .k.model{color:var(--brand);font-weight:700}
.f footer{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.f footer button{min-height:27px;padding:4px 9px;font-weight:500;font-size:11px;border-color:var(--border);color:var(--muted)}
.f footer button:hover{color:var(--text);border-color:var(--border-interactive)}
</style>
<div class="row" style="margin-bottom:14px">
  ${tab("open", "Open")}${tab("all", "All")}${tab("resolved", "Resolved")}${tab("dismissed", "Dismissed")}
</div>
${
  o.findings.length === 0
    ? `<div class="empty">No findings in this view.</div>`
    : o.findings
        .map(
          (f) => `<article class="f ${esc(f.severity)}" id="${esc(f.id)}">
  <header>${badge(f.severity)}<span class="mut">${esc(f.category)}</span>
    ${f.count > 1 ? `<span class="mut">seen ${num(f.count)}×</span>` : ""}
    <span class="mut">first ${ago(f.detectedAt)} · last ${ago(f.lastSeenAt)}</span>
    <span class="badge right ${f.status === "new" ? "" : "off"}">${esc(f.status)}</span></header>
  <h3>${esc(f.title)}</h3>
  ${f.summary ? `<p class="sum">${esc(f.summary)}</p>` : ""}
  <ul>${f.evidence.map(renderEvidence).join("")}</ul>
  <footer>${VERDICTS.map(
    (v) => `<button data-fb="${esc(f.id)}" data-v="${v}">${v.replace(/_/g, " ")}</button>`,
  ).join("")}
    ${f.feedback[0] ? `<span class="mut right">last: ${esc(f.feedback[0].verdict)} · ${esc(f.feedback[0].actor)}</span>` : ""}
  </footer>
</article>`,
        )
        .join("")
}
<script>
// Feedback is not a privileged action — it records an opinion, changes nothing, and gating it
// behind a passkey would train people to approve reflexively.
document.addEventListener("click", async (e) => {
  const b = e.target.closest("button[data-fb]"); if (!b) return;
  const row = b.closest("footer"); row.querySelectorAll("button").forEach(x => x.disabled = true);
  try {
    const r = await fetch("/api/findings/" + b.dataset.fb + "/feedback", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ actor: "console", verdict: b.dataset.v }),
    });
    if (!r.ok) throw new Error();
    location.reload();
  } catch { row.querySelectorAll("button").forEach(x => x.disabled = false); }
});
</script>`,
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

export interface ConnectorRow {
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

${o.rows
  .map(
    (c) => `
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
  <table><tbody>
    <tr><td class="mut" style="width:150px">Events ingested</td><td>${num(c.events)}${
      c.lastEventAt ? ` <span class="mut">· last ${ago(c.lastEventAt)}</span>` : ""
    }</td></tr>
    <tr><td class="mut">Activated</td><td>${c.activatedAt ? ago(c.activatedAt) : "—"}</td></tr>
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
  ${c.setup.length > 0 && !c.active ? `<ol class="setup">${c.setup.map((x) => `<li>${esc(x)}</li>`).join("")}</ol>` : ""}
</div>`,
  )
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
                  <input name="${esc(f.name)}" ${f.secret ? 'type="password" autocomplete="off"' : ""}
                    ${f.required ? "required" : ""} placeholder="${esc(f.placeholder ?? "")}">
                  ${f.help ? `<div class="mut" style="font-size:11.5px;margin-top:4px">${esc(f.help)}</div>` : ""}
                </div>`,
              )
              .join("")}
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
  rows: { detector: string; enabled: boolean; description: string; settings: string }[]
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
<thead><tr><th>Detector</th><th>What it finds</th><th>Thresholds</th><th style="width:86px">State</th></tr></thead>
<tbody>${o.rows
      .map(
        (d) => `<tr><td><b>${esc(d.detector)}</b></td><td class="mut">${esc(d.description)}</td>
      <td><code>${esc(d.settings)}</code></td>
      <td><span class="badge ${d.enabled ? "on" : "off"}">${d.enabled ? "on" : "off"}</span></td></tr>`,
      )
      .join("")}</tbody></table></div>`,
  })
}

export function alertsPage(o: {
  rules: {
    id: string
    name: string
    minSeverity: string
    channel: string
    cooldownMinutes: number
    active: boolean
    lastFiredAt: Date | null
  }[]
  counts: { findings: number; alerts: number; connectors: number }
  /** Who is signed in — rendered in the sidebar with the sign-out link. */
  actor?: { label: string; externalId: string }
}): string {
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
      : `<table style="margin-top:9px"><thead><tr><th>Name</th><th>Fires at</th><th>Channel</th><th>Cooldown</th><th>Last fired</th></tr></thead>
    <tbody>${o.rules
      .map(
        (r) => `<tr><td><b>${esc(r.name)}</b></td><td>${badge(r.minSeverity)} and above</td>
        <td>${esc(r.channel)}</td><td class="mut">${r.cooldownMinutes}m</td>
        <td class="mut">${r.lastFiredAt ? ago(r.lastFiredAt) : "never"}</td></tr>`,
      )
      .join("")}</tbody></table>`
  }
</div>
<form class="card" method="post" action="/alerts/create">
  <h2>New rule</h2>
  <div class="grid g2">
    <div class="field"><label>Name</label><input name="name" required placeholder="Page on critical"></div>
    <div class="field"><label>Minimum severity</label><select name="minSeverity">
      <option value="critical">critical</option><option value="high" selected>high</option>
      <option value="medium">medium</option><option value="low">low</option><option value="info">info</option></select></div>
    <div class="field"><label>Channel</label><select name="channel">
      <option value="webhook">webhook</option><option value="slack">slack</option><option value="email">email</option></select></div>
    <div class="field"><label>Cooldown (minutes)</label><input name="cooldownMinutes" type="number" value="60" min="0"></div>
  </div>
  <div class="field"><label>Destination</label><input name="target" required placeholder="https://hooks.example.com/…">
    <div class="mut" style="font-size:12px;margin-top:4px">Stored encrypted — a webhook URL is a credential.</div></div>
  <button class="primary" type="submit">Create rule</button>
</form>`,
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
                   ? `<a href="/findings#${esc(r.findingId)}"><b>${esc(r.findingTitle)}</b></a>`
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
  rows: { externalId: string; label: string; enrolledAt: Date | null; active: boolean }[]
  counts: { findings: number; alerts: number; connectors: number }
  /** Who is signed in — rendered in the sidebar with the sign-out link. */
  actor?: { label: string; externalId: string }
}): string {
  return page({
    title: "Members",
    lede: "Administrators are INTYGA platform subjects. A member cannot approve anything until they enrol a passkey.",
    path: "/members",
    counts: o.counts,
    ...(o.actor ? { actor: o.actor } : {}),
    body: `
<div class="card"><table>
<thead><tr><th>Member</th><th>INTYGA subject</th><th>Passkey</th><th style="width:150px"></th></tr></thead>
<tbody>${o.rows
      .map(
        (m) => `<tr><td><b>${esc(m.label)}</b></td><td><code>${esc(m.externalId)}</code></td>
    <td>${
      m.enrolledAt
        ? `<span class="badge on">enrolled</span>`
        : `<span class="badge">not enrolled</span> <a href="/members/enrol?id=${encodeURIComponent(m.externalId)}">enrol →</a>`
    }</td>
    <td>${
      m.active
        ? actionBtn({
            label: "Remove",
            action: "intelligence.member.remove",
            params: { externalId: m.externalId },
            cls: "danger",
          })
        : `<span class="mut">removed</span>`
    }</td></tr>`,
      )
      .join("")}</tbody></table></div>

<form class="card" id="add-member">
  <h2>Add administrator</h2>
  <div class="grid g2">
    <div class="field"><label>INTYGA subject id</label><input name="externalId" required placeholder="ada"></div>
    <div class="field"><label>Name</label><input name="label" required placeholder="Ada Lovelace"></div>
  </div>
  <button class="primary" type="submit">Add — requires approval</button>
</form>
<script>
document.getElementById("add-member").addEventListener("submit", (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const b = document.createElement("button");
  b.dataset.action = "intelligence.member.add";
  b.dataset.params = JSON.stringify({ externalId: f.get("externalId"), label: f.get("label") });
  b.style.display = "none"; document.body.appendChild(b); b.click(); b.remove();
});
</script>`,
  })
}

export function settingsPage(o: {
  binding: {
    baseUrl: string | null
    clientId: string | null
    rpId: string | null
    origin: string | null
    hasKey: boolean
  }
  retentionDays: number
  counts: { findings: number; alerts: number; connectors: number }
  /** Who is signed in — rendered in the sidebar with the sign-out link. */
  actor?: { label: string; externalId: string }
}): string {
  const b = o.binding
  const bound = Boolean(b.hasKey && b.baseUrl)

  // Unbound, the form is the SIGNUP: there is no tenant yet, so nobody exists who could approve it.
  // Bound, the same fields become a signed action — you must still be who you were to say who you
  // will be. The key is never part of the signed parameters; see the action registry for why.
  const fields = `
  <div class="grid g2">
    <div class="field"><label>INTYGA base URL</label>
      <input name="baseUrl" id="s-baseUrl" required placeholder="https://api.intyga.com"
             value="${esc(b.baseUrl ?? "")}"></div>
    <div class="field"><label>Platform client ID</label>
      <input name="clientId" id="s-clientId" required placeholder="cid_…"
             value="${esc(b.clientId ?? "")}"></div>
    <div class="field"><label>RP ID — a bare host</label>
      <input name="rpId" id="s-rpId" required placeholder="intelligence.example.com"
             value="${esc(b.rpId ?? "")}">
      <div class="mut" style="font-size:11.5px;margin-top:5px">
        Hostname only — no scheme, no port. <code>localhost</code> when developing.</div></div>
    <div class="field"><label>Origin — the full URL</label>
      <input name="origin" id="s-origin" required placeholder="https://intelligence.example.com"
             value="${esc(b.origin ?? "")}">
      <div class="mut" style="font-size:11.5px;margin-top:5px">
        Its host must equal the RP ID or be a subdomain of it.</div></div>
  </div>`

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
    Intelligence has no login of its own — your administrators are platform subjects in this
    workspace, and every privileged change here is signed with their passkey. Repointing it is the
    one change that could hand this tenant to someone else, so once connected it requires approval
    from the workspace you are leaving.
  </p>

  ${
    bound
      ? `<form id="rebind-form">${fields}
      <div class="row">
        <button type="button" class="ghost" id="test-conn">Test connection</button>
        <button type="submit" class="danger">Repoint workspace — requires approval</button>
        <span id="test-result" class="mut" style="font-size:12px"></span>
      </div>
    </form>`
      : `<form method="post" action="/settings/bind">${fields}
      <div class="field"><label>Private key — PKCS#8 PEM, for private_key_jwt</label>
        <textarea name="privateKey" rows="4" required
          placeholder="-----BEGIN PRIVATE KEY-----&#10;…&#10;-----END PRIVATE KEY-----"></textarea>
        <div class="mut" style="font-size:11.5px;margin-top:4px">
          Encrypted at rest and never returned by the API.</div></div>
      <button class="primary" type="submit">Connect workspace</button>
    </form>`
  }
</div>

${
  bound
    ? `<div class="card">
  <h2>Signing key</h2>
  <p class="mut" style="font-size:13px;margin-top:0">
    Rotate the private_key_jwt key without changing which workspace this tenant belongs to. Not a
    signed action: it proves possession of a NEW key against a workspace that already trusts you,
    and a key you cannot use is a key you cannot rotate with.
  </p>
  <form method="post" action="/settings/key">
    <div class="field"><label>New private key — PKCS#8 PEM</label>
      <textarea name="privateKey" rows="4" required
        placeholder="-----BEGIN PRIVATE KEY-----&#10;…&#10;-----END PRIVATE KEY-----"></textarea></div>
    <button type="submit">Replace key</button>
  </form>
</div>`
    : ""
}

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
    Intelligence holds platform-scoped credentials that act only on its own subjects. It cannot
    approve anything in INTYGA, read its audit log, or change policy — and signing is hash-only, so
    INTYGA receives a digest and never learns what was approved here. A build-time check fails the
    build if that stops being true.
  </p>
</div>

<script>
const testBtn = document.getElementById("test-conn");
if (testBtn) testBtn.addEventListener("click", async () => {
  const out = document.getElementById("test-result");
  testBtn.disabled = true; out.textContent = "Testing…"; out.style.color = "";
  try {
    const r = await fetch("/settings/test", { method: "POST" });
    const b = await r.json();
    out.textContent = b.ok ? "Reached INTYGA and exchanged a token." : (b.error || "Failed.");
    out.style.color = b.ok ? "var(--green)" : "var(--red)";
  } catch (e) { out.textContent = String(e); out.style.color = "var(--red)"; }
  testBtn.disabled = false;
});

const rebind = document.getElementById("rebind-form");
if (rebind) rebind.addEventListener("submit", (e) => {
  e.preventDefault();
  // Routed through the same passkey ceremony as every other privileged change.
  const b = document.createElement("button");
  b.dataset.action = "intelligence.workspace.rebind";
  b.dataset.params = JSON.stringify({
    baseUrl: document.getElementById("s-baseUrl").value.trim(),
    clientId: document.getElementById("s-clientId").value.trim(),
    rpId: document.getElementById("s-rpId").value.trim(),
    origin: document.getElementById("s-origin").value.trim(),
  });
  b.style.display = "none"; document.body.appendChild(b); b.click(); b.remove();
});
</script>`,
  })
}
