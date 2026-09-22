// Inline SVG charts. No library, no build step, no client framework.
//
// COLOUR DECISION, recorded because it was measured rather than chosen by taste:
// running Intyga's brand values through a categorical-palette validator FAILS the lightness band —
// --brand, --green, --amber and --red all sit at 0.71–0.79 lightness because the brand book
// deliberately equalises them to ~9.5:1 against the canvas. That is a conflict between two valid
// systems, not a defect in the brand.
//
// The resolution is to avoid multi-series categorical charts entirely: every chart here is SINGLE
// HUE (--brand), so no adjacent-pair separation is required and no legend is needed (the title
// names the series). Where state must be shown it uses the reserved status colours WITH a text
// label, never colour alone — which is what those tokens are for.
//
// Two measures never share an axis. Two things worth comparing get two charts.

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")
}

export interface Point {
  /** Bucket start. */
  at: Date
  value: number
}

export interface AreaChartOpts {
  id: string
  points: Point[]
  /** Names the series — so no legend is needed for a single series. */
  label: string
  height?: number
  /** Formats the hover readout. */
  unit?: string
}

/**
 * Time series as a thin line over a faint fill.
 *
 * Hover is a crosshair with a readout rather than a per-point label: a number on every point is
 * unreadable past a handful of buckets, and the shape is what the chart is for.
 */
export function areaChart(o: AreaChartOpts): string {
  const h = o.height ?? 132
  const w = 1000 // viewBox units; the SVG scales to its container
  const pad = { t: 10, r: 8, b: 20, l: 8 }
  const pts = o.points
  if (pts.length === 0) return `<div class="empty">No data in this window.</div>`

  const max = Math.max(1, ...pts.map((p) => p.value))
  const innerW = w - pad.l - pad.r
  const innerH = h - pad.t - pad.b
  const x = (i: number) => pad.l + (pts.length === 1 ? innerW / 2 : (i / (pts.length - 1)) * innerW)
  const y = (v: number) => pad.t + innerH - (v / max) * innerH

  const line = pts.map((p, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(p.value).toFixed(1)}`).join("")
  const area = `${line}L${x(pts.length - 1).toFixed(1)},${pad.t + innerH}L${x(0).toFixed(1)},${pad.t + innerH}Z`

  // Three recessive gridlines. More would compete with the data; none would make magnitude unreadable.
  const grid = [0, 0.5, 1]
    .map((f) => {
      const gy = pad.t + innerH - f * innerH
      return `<line x1="${pad.l}" x2="${w - pad.r}" y1="${gy}" y2="${gy}" stroke="var(--border)" stroke-width="1"/>`
    })
    .join("")

  const hotspots = pts
    .map(
      (p, i) =>
        `<rect x="${(x(i) - innerW / Math.max(pts.length, 1) / 2).toFixed(1)}" y="${pad.t}" ` +
        `width="${(innerW / Math.max(pts.length, 1)).toFixed(1)}" height="${innerH}" fill="transparent" ` +
        `data-x="${x(i).toFixed(1)}" data-y="${y(p.value).toFixed(1)}" ` +
        `data-v="${p.value}" data-t="${esc(p.at.toISOString())}"/>`,
    )
    .join("")

  return `
<figure class="chart" id="${esc(o.id)}" data-unit="${esc(o.unit ?? "")}">
  <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img"
       aria-label="${esc(o.label)}: ${pts.length} buckets, peak ${max}">
    ${grid}
    <path d="${area}" fill="var(--brand)" fill-opacity="0.13"/>
    <path d="${line}" fill="none" stroke="var(--brand)" stroke-width="2"
          stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
    <g class="cross" style="display:none">
      <line y1="${pad.t}" y2="${pad.t + innerH}" stroke="var(--border-interactive)" stroke-width="1" vector-effect="non-scaling-stroke"/>
      <circle r="4" fill="var(--brand)" stroke="var(--panel)" stroke-width="2"/>
    </g>
    <g class="hot">${hotspots}</g>
  </svg>
  <figcaption class="mut">${esc(o.label)} · peak ${max}</figcaption>
  <div class="tip" hidden></div>
</figure>`
}

export interface BarRow {
  label: string
  value: number
  /** Optional status word rendered beside the bar. Never colour alone. */
  note?: string
}

/** Horizontal bars — the right form for magnitude compared across named things. */
export function hBars(rows: BarRow[], opts: { max?: number } = {}): string {
  if (rows.length === 0) return `<div class="empty">Nothing to rank yet.</div>`
  const max = Math.max(1, opts.max ?? Math.max(...rows.map((r) => r.value)))
  return `<div class="bars">${rows
    .map(
      (r) => `
    <div class="bar" title="${esc(r.label)}: ${r.value}">
      <span class="bl" title="${esc(r.label)}">${esc(r.label)}</span>
      <span class="bt"><span class="bf" style="width:${((r.value / max) * 100).toFixed(1)}%"></span></span>
      <span class="bv">${r.value}${r.note ? ` <span class="mut">${esc(r.note)}</span>` : ""}</span>
    </div>`,
    )
    .join("")}</div>`
}

/** Vertical histogram for a distribution — buckets are ordered, so the x axis means something. */
export function histogram(buckets: { label: string; count: number }[]): string {
  if (buckets.every((b) => b.count === 0)) return `<div class="empty">No completed approvals yet.</div>`
  const max = Math.max(1, ...buckets.map((b) => b.count))
  return `<div class="hist">${buckets
    .map(
      (b) => `
    <div class="hb" title="${esc(b.label)}: ${b.count}">
      <span class="hv">${b.count || ""}</span>
      <span class="hc"><span class="hf" style="height:${Math.max(2, (b.count / max) * 100).toFixed(1)}%"></span></span>
      <span class="hl">${esc(b.label)}</span>
    </div>`,
    )
    .join("")}</div>`
}

/** Styles and the hover behaviour, injected once per page. */
export const CHART_CSS = `
.chart{margin:0;position:relative}
.chart svg{width:100%;height:132px;display:block;overflow:visible}
.chart figcaption{font-size:11px;margin-top:6px}
.chart .tip{position:absolute;pointer-events:none;background:var(--panel-2);border:1px solid var(--border-interactive);
  border-radius:7px;padding:5px 9px;font-size:12px;white-space:nowrap;transform:translate(-50%,-140%);z-index:5}
.chart .hot rect{cursor:crosshair}

/* 4px rounded data-end, anchored to the baseline; 2px gap between adjacent fills. */
.bars{display:grid;gap:7px}
.bar{display:grid;grid-template-columns:minmax(90px,168px) 1fr auto;gap:10px;align-items:center;font-size:12px}
.bl{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:rtl;text-align:left}
.bt{background:var(--panel-2);border-radius:4px;height:16px;overflow:hidden}
.bf{display:block;height:100%;background:var(--brand);border-radius:0 4px 4px 0;min-width:2px}
.bv{font-variant-numeric:tabular-nums;font-weight:600;font-size:12px}

.hist{display:flex;gap:2px;align-items:flex-end;height:128px}
.hb{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;height:100%}
.hv{font-size:11px;color:var(--muted);font-variant-numeric:tabular-nums;height:13px}
.hc{flex:1;width:100%;display:flex;align-items:flex-end;background:var(--panel-2);border-radius:4px;overflow:hidden}
.hf{width:100%;background:var(--brand);border-radius:4px 4px 0 0}
.hl{font-size:10px;color:var(--muted);white-space:nowrap}
`

export const CHART_JS = `
// Crosshair + readout. One delegated listener per chart; no per-point DOM churn.
for (const fig of document.querySelectorAll(".chart")) {
  const svg = fig.querySelector("svg"), cross = fig.querySelector(".cross"), tip = fig.querySelector(".tip");
  const unit = fig.dataset.unit || "";
  fig.addEventListener("mousemove", (e) => {
    const r = e.target.closest("[data-v]"); if (!r) return;
    const bx = svg.getBoundingClientRect(), fr = fig.getBoundingClientRect();
    const vb = svg.viewBox.baseVal;
    const px = bx.left + (parseFloat(r.dataset.x) / vb.width) * bx.width - fr.left;
    const py = bx.top + (parseFloat(r.dataset.y) / vb.height) * bx.height - fr.top;
    cross.style.display = ""; 
    cross.querySelector("line").setAttribute("x1", r.dataset.x);
    cross.querySelector("line").setAttribute("x2", r.dataset.x);
    cross.querySelector("circle").setAttribute("cx", r.dataset.x);
    cross.querySelector("circle").setAttribute("cy", r.dataset.y);
    const d = new Date(r.dataset.t);
    tip.hidden = false; tip.style.left = px + "px"; tip.style.top = py + "px";
    tip.textContent = r.dataset.v + (unit ? " " + unit : "") + " · " +
      d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  });
  fig.addEventListener("mouseleave", () => { cross.style.display = "none"; tip.hidden = true; });
}
`
