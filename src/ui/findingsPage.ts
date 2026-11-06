import type { Evidence } from "../domain/finding.ts"
import {
  FINDING_CATEGORIES,
  FINDING_SEVERITIES,
  findingUrl,
  findingsUrl,
  type FindingQuery,
} from "../domain/findingQuery.ts"
import type { FindingListItem } from "../store/repo.ts"
import { ago, esc, num, page } from "./layout.ts"

function renderEvidence(e: Evidence): string {
  switch (e.kind) {
    case "metric": {
      const comparison =
        e.baseline === undefined
          ? ""
          : e.baseline === 0
            ? "vs none before"
            : `vs ${num(e.baseline)} typical (${(e.value / e.baseline).toFixed(1)}×)`
      return `<li><span class="k">metric</span>${esc(e.label)} — <b>${num(e.value)}</b>
        <span class="mut">${comparison}</span></li>`
    }
    case "eventRef":
      return `<li><span class="k">event</span><code>${esc(e.eventKind)}</code>
        <span class="mut">${esc(e.sourceId)} · ${ago(e.at)}</span></li>`
    case "deployment":
      return `<li><span class="k">deploy</span><code title="${esc(e.sha)}">${esc(e.sha.slice(0, 8))}</code>
        ${esc(e.workflow)} <span class="mut">${esc(e.conclusion)} · ${ago(e.at)}</span></li>`
    case "codeChange":
      return `<li><span class="k">code</span>${esc(e.repo)}#${e.pr}
        <code title="${esc(e.sha)}">${esc(e.sha.slice(0, 8))}</code>
        <details><summary>${num(e.paths.length)} changed paths</summary>
        ${e.paths.map((p) => `<div><code>${esc(p)}</code></div>`).join("")}</details></li>`
    case "correlation":
      return `<li><span class="k">link</span>${esc(e.relation)}
        <span class="mut">lag ${Math.round(e.lagMs / 1000)}s</span></li>`
    case "assessment":
      // Measured evidence and model assessment must remain visually distinct.
      return `<li class="model"><span class="k">assessment</span>${esc(e.question)} —
        <b>${esc(e.probability === undefined ? String(e.answer) : `${(e.probability * 100).toFixed(0)}%`)}</b>
        ${e.confidence === undefined ? "" : `<span>confidence ${(e.confidence * 100).toFixed(0)}%</span>`}
        <span>${esc(e.model)}</span></li>`
  }
}

const VERDICTS = ["investigating", "fixed", "expected", "false_positive", "useful", "not_useful"]

export function findingsPage(o: {
  findings: FindingListItem[]
  counts: { findings: number; alerts: number; connectors: number }
  actor?: { label: string; externalId: string }
  query: FindingQuery
  total: number
}): string {
  const q = o.query
  const tab = (status: string, label: string) => `<a class="btn ${q.status === status ? "primary" : ""}"
    ${q.status === status ? 'aria-current="page"' : ""}
    href="${esc(findingsUrl(q, { status, page: 1 }))}">${label}</a>`
  const options = (values: readonly string[], selected: string) =>
    values.map((v) => `<option value="${v}" ${selected === v ? "selected" : ""}>${v}</option>`).join("")
  const offset = (q.page - 1) * q.limit
  const pages = Math.max(1, Math.ceil(o.total / q.limit))
  const navigation = `<nav class="row findingPagination" aria-label="Finding pages">
    ${q.page > 1 ? `<a class="btn" href="${esc(findingsUrl(q, { page: q.page - 1 }))}">← Previous</a>` : ""}
    <span class="mut">Page ${num(q.page)} of ${num(pages)}</span>
    ${q.page < pages ? `<a class="btn" href="${esc(findingsUrl(q, { page: q.page + 1 }))}">Next →</a>` : ""}
    ${q.page > pages ? `<a href="${esc(findingsUrl(q, { page: 1 }))}">Back to first page</a>` : ""}
  </nav>`
  return page({
    title: "Findings",
    lede: "Find what needs attention, inspect the evidence, and leave context for the next person.",
    path: "/findings",
    counts: o.counts,
    ...(o.actor ? { actor: o.actor } : {}),
    body: `
<style>
.findingFilters{display:flex;flex-wrap:wrap;gap:12px;align-items:end;margin-bottom:16px}
.findingFilters .field{flex:1 1 130px;margin:0}.findingFilters .field.search{flex:2 1 240px}
.findingPagination{margin:16px 0;position:static;width:auto;background:none;border:0;padding:0}
.finding{background:var(--panel);border:1px solid var(--border);border-left:3px solid var(--border);border-radius:12px;padding:16px 18px;margin:0 0 12px;scroll-margin-top:20px;overflow-wrap:anywhere}
.finding.critical{border-left-color:var(--red)}.finding.high{border-left-color:var(--amber)}
.finding.medium{border-left-color:var(--brand)}.finding:target{outline:2px solid var(--brand);outline-offset:2px}
.finding header{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin-bottom:8px;font-size:11px}
.finding h2{font-size:16px;margin:0 0 6px}.finding .sum{color:var(--muted);font-size:13px}
.finding .evidence{list-style:none;margin:12px 0;padding:12px;background:var(--panel-2);border-radius:8px;display:grid;gap:7px;font-size:12.5px}
.finding .k{display:inline-block;min-width:80px;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.08em}
.finding .model,.finding .model .k{color:var(--brand)}
.finding footer{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-top:12px}
.finding footer button{font-size:11px;padding:5px 9px}
.finding details{margin-top:8px}.finding summary{cursor:pointer;color:var(--muted);font-size:12px}
.finding textarea{margin-top:6px}.finding .note{white-space:pre-wrap;margin:5px 0 10px}
.finding .feedbackError{color:var(--red);font-size:12px}.finding .feedbackError:empty{display:none}
</style>
<div class="row" style="margin-bottom:14px">
  ${tab("open", "Open")}${tab("investigating", "Investigating")}${tab("all", "All")}
  ${tab("resolved", "Resolved")}${tab("dismissed", "Dismissed")}
</div>
<form class="card findingFilters" action="/findings" method="get" role="search">
  <input type="hidden" name="status" value="${esc(q.status)}">
  <input type="hidden" name="service" value="${esc(q.service)}">
  <input type="hidden" name="limit" value="${q.limit}">
  <div class="field search"><label for="finding-search">Search findings</label>
    <input id="finding-search" name="q" type="search" maxlength="200" value="${esc(q.q)}" placeholder="Title, summary, or finding ID"></div>
  <div class="field"><label for="finding-severity">Severity</label><select id="finding-severity" name="severity">
    <option value="">All severities</option>${options(FINDING_SEVERITIES, q.severity)}</select></div>
  <div class="field"><label for="finding-category">Category</label><select id="finding-category" name="category">
    <option value="">All categories</option>${options(FINDING_CATEGORIES, q.category)}</select></div>
  <div class="field"><label for="finding-sort">Sort by</label><select id="finding-sort" name="sort">
    <option value="priority" ${q.sort === "priority" ? "selected" : ""}>Highest priority</option>
    <option value="recent" ${q.sort === "recent" ? "selected" : ""}>Recently seen</option></select></div>
  <button class="primary" type="submit">Apply filters</button><a href="/findings">Reset</a>
</form>
<p class="mut" role="status">${o.findings.length ? `${num(offset + 1)}–${num(offset + o.findings.length)} of` : ""}
  ${num(o.total)} matching finding${o.total === 1 ? "" : "s"}.</p>
${
  o.findings.length === 0
    ? `<div class="empty">No findings in this view.
  <p>Try another status or clear your filters. If you are getting started, <a href="/connectors">check your connectors</a>.</p></div>`
    : o.findings
        .map(
          (f) => `
<article class="finding ${esc(f.severity)}" id="${esc(f.id)}">
  <header><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span><span class="mut">${esc(f.category)}</span>
    <span class="mut">seen ${num(f.count)}× · first ${ago(f.detectedAt)} · last ${ago(f.lastSeenAt)}</span>
    <span class="badge right">${esc(f.status)}</span></header>
  <h2><a href="${esc(findingUrl(f.id))}">${esc(f.title)}</a></h2>
  ${f.summary ? `<p class="sum">${esc(f.summary)}</p>` : ""}
  <ul class="evidence">${f.evidence.map(renderEvidence).join("")}</ul>
  <details><summary>Add investigation context</summary>
    <label for="note-${esc(f.id)}" style="margin-top:10px">Note (optional, saved with your next action)</label>
    <textarea id="note-${esc(f.id)}" maxlength="2000" rows="3" placeholder="What did you check? What should happen next?"></textarea>
  </details>
  <footer>${VERDICTS.map((v) => `<button type="button" data-fb="${esc(f.id)}" data-v="${v}">${v.replace(/_/g, " ")}</button>`).join("")}</footer>
  <p class="feedbackError" role="alert"></p>
  ${
    f.feedback.length
      ? `<details><summary>Recent activity · ${esc(f.feedback[0]?.verdict.replace(/_/g, " "))} by ${esc(f.feedback[0]?.actor)}</summary>
    ${f.feedback
      .map(
        (
          entry,
        ) => `<div style="margin-top:10px"><b>${esc(entry.actor)}</b> · ${esc(entry.verdict.replace(/_/g, " "))}
      <span class="mut">${ago(entry.createdAt)}</span>${entry.note ? `<p class="note">${esc(entry.note)}</p>` : ""}</div>`,
      )
      .join("")}</details>`
      : ""
  }
</article>`,
        )
        .join("")
}
${navigation}
<script>
// Feedback records investigation state, not a privileged configuration change.
document.addEventListener("click", async (e) => {
  const b = e.target.closest("button[data-fb]"); if (!b) return;
  const article = b.closest("article");
  const buttons = article.querySelectorAll("button[data-fb]");
  const error = article.querySelector(".feedbackError");
  const note = article.querySelector("textarea").value.trim();
  buttons.forEach(x => x.disabled = true); error.textContent = "";
  try {
    const r = await fetch("/api/findings/" + encodeURIComponent(b.dataset.fb) + "/feedback", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ verdict: b.dataset.v, ...(note ? { note } : {}) }),
    });
    if (!r.ok) throw new Error(r.status === 401 ? "Your session expired. Sign in again before saving." : "Could not save feedback. Your note is still here; please try again.");
    location.reload();
  } catch (err) {
    error.textContent = err.message || "Could not save feedback. Please try again.";
    buttons.forEach(x => x.disabled = false);
  }
});
</script>`,
  })
}
