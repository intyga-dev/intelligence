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
    case "assessment": {
      const p = e.probability !== undefined ? `${(e.probability * 100).toFixed(0)}%` : String(e.answer)
      const c =
        e.confidence !== undefined
          ? ` <span class="mut">confidence ${(e.confidence * 100).toFixed(0)}%</span>`
          : ""
      return `<li class="ev model"><span class="k model">assessment</span> ${esc(e.question)} — <b>${esc(p)}</b>${c} <span class="mut">${esc(e.model)}</span></li>`
    }
  }
}

const VERDICTS = ["useful", "not_useful", "investigating", "expected", "false_positive", "fixed"]

function renderFinding(f: FindingListItem): string {
  const latest = f.feedback[0]
  return `
<article class="f ${esc(f.severity)}">
  <header>
    <span class="sev">${esc(f.severity)}</span>
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
    ${latest ? `<span class="mut">last: ${esc(latest.verdict)} by ${esc(latest.actor)}</span>` : ""}
  </footer>
</article>`
}

export function renderFindingsPage(findings: FindingListItem[]): string {
  const open = findings.filter((f) => f.status === "new" || f.status === "investigating")
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Intelligence</title>
<style>
  :root{--bg:#0d0f12;--fg:#e8eaed;--mut:#8b929c;--line:#222730;--card:#14171c;
        --crit:#ff5c5c;--high:#ff9f43;--med:#f7d154;--low:#6bcf8e;--info:#6aa8ff;--model:#b68cff}
  @media (prefers-color-scheme:light){:root{--bg:#fbfbfc;--fg:#14171c;--mut:#5f6673;--line:#e3e6ea;--card:#fff}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,-apple-system,system-ui,sans-serif}
  .wrap{max-width:860px;margin:0 auto;padding:32px 16px 80px}
  h1{font-size:15px;letter-spacing:.14em;text-transform:uppercase;color:var(--mut);font-weight:600;margin:0 0 4px}
  .lede{color:var(--mut);margin:0 0 28px;font-size:14px}
  .f{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--line);
     border-radius:8px;padding:16px 18px;margin:0 0 14px}
  .f.critical{border-left-color:var(--crit)} .f.high{border-left-color:var(--high)}
  .f.medium{border-left-color:var(--med)} .f.low{border-left-color:var(--low)} .f.info{border-left-color:var(--info)}
  header{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:11px;margin-bottom:8px}
  .sev{text-transform:uppercase;letter-spacing:.1em;font-weight:700}
  .critical .sev{color:var(--crit)} .high .sev{color:var(--high)} .medium .sev{color:var(--med)}
  .low .sev{color:var(--low)} .info .sev{color:var(--info)}
  .cat,.count,.when,.status{color:var(--mut)}
  .status{margin-left:auto;text-transform:uppercase;letter-spacing:.08em}
  .s-resolved,.s-dismissed{opacity:.55}
  h2{font-size:16px;font-weight:600;margin:0 0 6px;line-height:1.35}
  .sum{color:var(--mut);margin:0 0 12px;font-size:14px}
  .evs{list-style:none;margin:0 0 12px;padding:10px 12px;background:rgba(127,127,127,.06);
       border-radius:6px;font-size:13px;display:grid;gap:5px}
  .ev .k{display:inline-block;min-width:82px;color:var(--mut);font-size:10px;text-transform:uppercase;letter-spacing:.09em}
  /* Model output is visually apart from measured fact. A reader must never have to guess. */
  .ev.model{color:var(--model)} .ev .k.model{color:var(--model);font-weight:700}
  .mut{color:var(--mut)} code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
  footer{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
  button{background:transparent;border:1px solid var(--line);color:var(--mut);border-radius:5px;
         padding:4px 9px;font-size:11px;cursor:pointer;font-family:inherit}
  button:hover{color:var(--fg);border-color:var(--mut)}
  button[disabled]{opacity:.5;cursor:default}
  .empty{border:1px dashed var(--line);border-radius:8px;padding:40px 20px;text-align:center;color:var(--mut)}
</style></head><body><div class="wrap">
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
<script>
// Feedback posts and disables the row's buttons. Deliberately tiny: this page is a list, not an app.
document.addEventListener("click", async (e) => {
  const b = e.target.closest("button[data-v]"); if (!b) return;
  const row = b.closest("footer"); [...row.querySelectorAll("button")].forEach(x => x.disabled = true);
  try {
    const r = await fetch("/api/findings/" + b.dataset.id + "/feedback", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ verdict: b.dataset.v }),
    });
    if (r.ok) location.reload(); else throw new Error();
  } catch { [...row.querySelectorAll("button")].forEach(x => x.disabled = false); }
});
</script></body></html>`
}
