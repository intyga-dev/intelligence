import type { ServiceDetail, ServiceSummary } from "../store/services.ts"
import { findingUrl } from "../domain/findingQuery.ts"
import { ago, esc, num, page, type NavCounts } from "./layout.ts"

export function servicesPage(o: {
  services: ServiceSummary[]
  connections: { id: string; label: string; kind: string; serviceId: string | null }[]
  counts: NavCounts
  actor?: { label: string; externalId: string }
}): string {
  return page({
    title: "Services",
    path: "/services",
    counts: o.counts,
    ...(o.actor ? { actor: o.actor } : {}),
    lede: "Follow the systems your team runs. Each service brings its sources, changes and findings together.",
    body: `
<style>
.serviceCreate{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
.serviceCreate .field{margin:0;min-width:0}
.serviceCreate .actions{grid-column:1/-1}
@media(max-width:640px){.serviceCreate{grid-template-columns:1fr}}
</style>
<div class="card"><h2>Your first service</h2>
<p class="mut">Create a service such as “Production API”, assign its deployment and signal sources below, then turn those sources on in <a href="/connectors">Connectors</a>. Use separate connections for unrelated services or environments.</p>
<form id="create-service" class="serviceCreate">
  <div class="field"><label for="service-name">Service name</label><input id="service-name" name="name" required maxlength="80" placeholder="Production API"></div>
  <div class="field"><label for="service-description">Description (optional)</label><input id="service-description" name="description" maxlength="300" placeholder="Customer-facing API and its worker"></div>
  <div class="actions"><button type="submit" class="primary">Create service with INTYGA</button></div>
</form></div>
<div class="grid g2">${
      o.services.length
        ? o.services
            .map(
              (s) => `<div class="card">
  <h2><a href="/services/${esc(s.id)}">${esc(s.name)} →</a></h2><p class="mut">${esc(s.description)}</p>
  <div class="row"><span class="badge ${s.open ? "high" : ""}">${num(s.open)} open findings</span><span class="badge">${s.connections.filter((c) => c.active).length} active sources</span></div>
  <p class="mut">${s.lastEventAt ? `Last observation ${ago(s.lastEventAt)}` : "Awaiting observations. Assign and activate a source below."}</p>
</div>`,
            )
            .join("")
        : `<div class="empty">No services yet. <a href="/demo">Explore an example incident</a>, then group your own sources here.</div>`
    }</div>
<div class="card"><h2>Assign sources</h2>
<p class="mut">Assignment determines which signals a deployment can be correlated with. Previously unassigned history joins the service; history already assigned to another service stays there.</p>
${
  o.connections.length
    ? o.connections
        .map(
          (c) => `<form class="row source-assignment" style="margin-top:12px" data-connection="${esc(c.id)}">
  <label for="source-${esc(c.id)}" style="min-width:180px;margin:0">${esc(c.label)} <span class="mut">(${esc(c.kind)})</span></label>
  <select id="source-${esc(c.id)}" name="serviceId" style="width:auto;max-width:100%"><option value="">Unassigned</option>${o.services.map((s) => `<option value="${esc(s.id)}" ${s.id === c.serviceId ? "selected" : ""}>${esc(s.name)}</option>`).join("")}</select>
  <button type="submit">Save with INTYGA</button>
</form>`,
        )
        .join("")
    : `<p><a href="/connectors">Add your first connector →</a></p>`
}
</div>
<script>
// Reuse the same signed-action ceremony as every configuration change in the console.
document.addEventListener("submit", (e) => {
  const form = e.target;
  if (form.id !== "create-service" && !form.classList.contains("source-assignment")) return;
  e.preventDefault();
  const data = new FormData(form);
  const button = document.createElement("button"); button.type = "button"; button.hidden = true;
  button.dataset.action = form.id === "create-service" ? "intelligence.service.create" : "intelligence.connector.assign-service";
  button.dataset.params = JSON.stringify(form.id === "create-service"
    ? { name: data.get("name"), description: data.get("description") }
    : { connectionId: form.dataset.connection, serviceId: data.get("serviceId") || null });
  document.body.appendChild(button); button.click(); button.remove();
});
</script>`,
  })
}

function eventLabel(event: ServiceDetail["events"][number]): string {
  const attrs =
    event.attrs && typeof event.attrs === "object" && !Array.isArray(event.attrs) ? event.attrs : {}
  const title =
    typeof attrs.title === "string" ? attrs.title : typeof attrs.name === "string" ? attrs.name : ""
  const sha = typeof attrs.sha === "string" ? attrs.sha : event.correlationRef
  return `${event.kind}${title ? ` · ${title}` : ""}${sha && /deploy|pull_request|merge_request/.test(event.kind) ? ` · ${sha.slice(0, 12)}` : ""}`
}

export function servicePage(o: {
  detail: ServiceDetail
  counts?: NavCounts
  actor?: { label: string; externalId: string }
  demo?: boolean
}): string {
  const d = o.detail
  return page({
    title: d.service.name,
    path: "/services",
    lede: d.service.description,
    ...(o.counts ? { counts: o.counts } : {}),
    ...(o.actor ? { actor: o.actor } : {}),
    ...(o.demo ? { onboarding: true } : {}),
    body: `
${o.demo ? `<div class="card"><b>Example data · nothing is connected</b><p>This incident shows how a deployment, changed code and error signals appear together. No sample events are written to your database or sent to alert destinations.</p><a class="btn primary" href="/">Connect your INTYGA workspace →</a></div>` : `<p><a href="/services">← All services and source assignments</a></p>`}
<div class="row" style="margin-bottom:16px">${d.service.connections.map((c) => `<span class="badge ${c.active ? "on" : "off"}">${esc(c.label)}</span>`).join("") || '<span class="mut">No sources assigned yet</span>'}</div>
<div class="card"><div class="row"><h2>Needs attention</h2>${o.demo ? "" : `<a class="right" href="/findings?status=all&service=${esc(d.service.id)}">All service findings →</a>`}</div>
${
  d.findings.length
    ? d.findings
        .map(
          (f) => `<article style="margin-top:18px">
  <span class="badge ${esc(f.severity)}">${esc(f.severity)}</span> <span class="badge">${esc(f.status)}</span>
  <h3>${o.demo ? esc(f.title) : `<a href="${esc(findingUrl(f.id))}">${esc(f.title)} →</a>`}</h3>
  <p class="mut">${esc(f.summary)}</p>
  ${f.evidence
    .filter((e) => e.kind === "metric")
    .map((e) =>
      e.kind === "metric"
        ? `<p>${esc(e.label)}: <b>${num(e.value)}</b>${e.baseline === undefined ? "" : ` <span class="mut">vs ${num(e.baseline)} baseline</span>`}</p>`
        : "",
    )
    .join("")}
</article>`,
        )
        .join("")
    : `<p class="mut">No open findings. ${d.service.connections.length ? "This means no detected condition needs attention; it does not guarantee service availability." : "Assign a deployment source and a signal source to start correlating changes."}</p>`
}</div>
<div class="card"><h2>Observation timeline</h2><p class="mut">Last 7 days · showing ${d.events.length} of ${num(d.totalEvents)} observations. Timing suggests where to investigate; it does not prove a cause.</p>
${
  d.events.length
    ? `<ol style="padding-left:22px">${d.events
        .map(
          (e) => `<li style="padding:10px 0;border-bottom:1px solid var(--border);overflow-wrap:anywhere">
  <time datetime="${e.at.toISOString()}" title="${esc(e.at.toISOString())}" class="mut">${ago(e.at)}</time> · <b>${esc(eventLabel(e))}</b><div class="mut">${esc(e.connection.label)}</div>
</li>`,
        )
        .join("")}</ol>`
    : `<div class="empty">No observations in the last 7 days. <a href="/connectors">Check source health and setup →</a></div>`
}</div>`,
  })
}
