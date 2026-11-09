import { reviewEvidence } from "./review.ts"
import { stylesheetLinks } from "./styles.ts"
import { FEEDBACK_HTML, FEEDBACK_JS } from "./feedback.ts"
import type { Evidence } from "../domain/finding.ts"
import type { FindingListItem } from "../store/repo.ts"

// The internal findings page. Server-rendered, no framework, no build step, no charts.
//
// The product is the prioritised list, so the page is a list. The deliberate design choice is that
// evidence is visible WITHOUT a click and model assessments are visually distinct from measured
// facts — a reader must never have to wonder which is which.

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")
}

function ago(d: Date, now = new Date()): string {
  const s = Math.max(0, Math.round((now.getTime() - new Date(d).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.round(s / 60)}m ago`
  if (s < 86400) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}

function num(n: number): string {
  return n.toLocaleString("en-US")
}

/** One evidence row. The `assessment` branch is styled apart on purpose — see the file header. */
function renderEvidence(e: Evidence): string {
  switch (e.kind) {
    case "metric": {
      const delta =
        e.baseline !== undefined && e.baseline > 0
          ? ` <span class="mut">vs ${num(e.baseline)} typical (${(e.value / e.baseline).toFixed(1)}×)</span>`
          : e.baseline === 0
            ? ` <span class="mut">vs none previously</span>`
            : ""
      return `<li class="ev"><span class="k">metric</span> ${esc(e.label)} — <b>${num(e.value)}</b>${delta}</li>`
    }
    case "eventRef":
      return `<li class="ev"><span class="k">event</span> <code>${esc(e.eventKind)}</code> <span class="mut">${esc(e.sourceId)} · ${ago(e.at)}</span></li>`
    case "deployment":
      return `<li class="ev"><span class="k">deploy</span> <code>${esc(e.sha.slice(0, 8))}</code> ${esc(e.workflow)} <span class="mut">${esc(e.conclusion)} · ${ago(e.at)}</span></li>`
    case "codeChange":
      return `<li class="ev"><span class="k">code</span> ${esc(e.repo)}#${e.pr} <span class="mut">${e.paths.length} path(s), ${esc(e.sha.slice(0, 8))}</span></li>`
    case "correlation":
      return `<li class="ev"><span class="k">link</span> ${esc(e.relation)} <span class="mut">lag ${Math.round(e.lagMs / 1000)}s</span></li>`
    case "assessment":
      return reviewEvidence(e)
  }
}

const VERDICTS = ["useful", "not_useful", "investigating", "expected", "false_positive", "fixed"]

function renderFinding(f: FindingListItem): string {
  const latest = f.feedback[0]
  return `
<article class="f ${esc(f.severity)}">
  <header>
    <span class="sev">${f.kind === "observation" ? "review observation" : esc(f.severity)}</span>
    <span class="cat">${esc(f.category)}</span>
    ${f.count > 1 ? `<span class="count">seen ${num(f.count)}×</span>` : ""}
    <span class="when">first ${ago(f.detectedAt)} · last ${ago(f.lastSeenAt)}</span>
    <span class="status s-${esc(f.status)}">${esc(f.status)}</span>
  </header>
  <h2>${esc(f.title)}</h2>
  ${f.summary ? `<p class="sum">${esc(f.summary)}</p>` : ""}
  <ul class="evs">${f.evidence.map(renderEvidence).join("")}</ul>
  <footer>
    ${VERDICTS.map((v) => `<button data-id="${esc(f.id)}" data-v="${v}">${v.replace(/_/g, " ")}</button>`).join("")}
    ${latest ? `<span class="mut">last: ${esc(latest.verdict)} by ${esc(latest.actorLabel ?? latest.actor)}</span>` : ""}
  </footer>
</article>`
}

export function renderFindingsPage(findings: FindingListItem[]): string {
  const open = findings.filter((f) => f.status === "new" || f.status === "investigating")
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Intelligence</title>
${stylesheetLinks("findings", "feedback")}</head><body><div class="wrap">
<h1>INTYGA — Intelligence</h1>
<p class="lede">${
    findings.length === 0
      ? "Nothing to look at."
      : `${num(open.length)} open of ${num(findings.length)}. Most severe first.`
  }</p>
${
  findings.length === 0
    ? `<div class="empty">No findings yet.<br><span style="font-size:13px">Detectors run on each tick. An empty list means nothing crossed a threshold — which is the normal state.</span></div>`
    : findings.map(renderFinding).join("")
}
</div>
${FEEDBACK_HTML}
<script>
${FEEDBACK_JS}
// Feedback posts and disables the row's buttons. Deliberately tiny: this page is a list, not an app.
document.addEventListener("click", async (e) => {
  const b = e.target.closest("button[data-v]"); if (!b) return;
  const row = b.closest("footer"); [...row.querySelectorAll("button")].forEach(x => x.disabled = true);
  window.intelligenceToast("Saving feedback…", "pending");
  try {
    const r = await fetch("/api/findings/" + b.dataset.id + "/feedback", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ verdict: b.dataset.v }),
    });
    if (!r.ok) throw new Error();
    window.intelligenceToast("Feedback saved.", "success", {persist:true});
    location.reload();
  } catch { window.intelligenceToast("Could not save feedback. Please try again.", "error"); [...row.querySelectorAll("button")].forEach(x => x.disabled = false); }
});
</script></body></html>`
}
