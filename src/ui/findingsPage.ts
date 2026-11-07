import { stylesheetLinks } from "./styles.ts"
import { assessmentConfidenceLabel, type Evidence } from "../domain/finding.ts"
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
        ${e.confidence === undefined ? "" : `<span>${esc(assessmentConfidenceLabel(e))}</span>`}
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
    title: q.kind === "observation" ? "Observations" : "Findings",
    lede:
      q.kind === "observation"
        ? "Sensitive-code changes for review. These observations do not establish an anomaly and do not trigger alerts."
        : "Find what needs attention, inspect the evidence, and leave context for the next person.",
    path: "/findings",
    counts: o.counts,
    ...(o.actor ? { actor: o.actor } : {}),
    body: `
${stylesheetLinks("findings-page")}
<div class="row" style="margin-bottom:14px">
  ${(
    [
      ["finding", "Findings"],
      ["observation", "Observations"],
      ["all", "Everything"],
    ] as const
  )
    .map(
      ([kind, label]) =>
        `<a class="btn ${q.kind === kind ? "primary" : ""}" ${q.kind === kind ? 'aria-current="page"' : ""} href="${esc(findingsUrl(q, { kind, severity: "", category: "", page: 1 }))}">${label}</a>`,
    )
    .join("")}
</div>
<div class="row" style="margin-bottom:14px">
  ${tab("open", "Open")}${tab("investigating", "Investigating")}${tab("all", "All")}
  ${tab("resolved", "Resolved")}${tab("dismissed", "Dismissed")}
</div>
<form class="card findingFilters" action="/findings" method="get" role="search">
  <input type="hidden" name="kind" value="${esc(q.kind)}">
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
  ${num(o.total)} matching ${q.kind === "observation" ? "observation" : "finding"}${o.total === 1 ? "" : "s"}.</p>
${
  o.findings.length === 0
    ? `<div class="empty">No ${q.kind === "observation" ? "observations" : "findings"} in this view.
  <p>Routine code changes are available under <a href="/findings?kind=observation">Observations</a>.</p>
  <p>Try another status or clear your filters. If you are getting started, <a href="/connectors">check your connectors</a>.</p></div>`
    : o.findings
        .map(
          (f) => `
<article class="finding ${esc(f.severity)}" id="${esc(f.id)}">
  <header><span class="badge ${esc(f.severity)}">${f.kind === "observation" ? "review observation" : esc(f.severity)}</span><span class="mut">${esc(f.category)}</span>
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
      ? `<details><summary>Recent activity · ${esc(f.feedback[0]?.verdict.replace(/_/g, " "))} by ${esc(f.feedback[0]?.actorLabel ?? f.feedback[0]?.actor)}</summary>
    ${f.feedback
      .map(
        (
          entry,
        ) => `<div style="margin-top:10px"><b title="${esc(entry.actor)}">${esc(entry.actorLabel ?? entry.actor)}</b> · ${esc(entry.verdict.replace(/_/g, " "))}
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
  window.intelligenceToast("Saving feedback…", "pending", {id:"feedback"});
  try {
    const r = await fetch("/api/findings/" + encodeURIComponent(b.dataset.fb) + "/feedback", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ verdict: b.dataset.v, ...(note ? { note } : {}) }),
    });
    if (!r.ok) throw new Error(r.status === 401 ? "Your session expired. Sign in again before saving." : "Could not save feedback. Your note is still here; please try again.");
    window.intelligenceToast("Feedback saved.", "success", {id:"feedback",persist:true});
    location.reload();
  } catch (err) {
    error.textContent = err.message || "Could not save feedback. Please try again.";
    window.intelligenceToast(error.textContent, "error", {id:"feedback"});
    buttons.forEach(x => x.disabled = false);
  }
});
</script>`,
  })
}
