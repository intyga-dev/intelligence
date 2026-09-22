import { CHART_CSS, CHART_JS } from "./charts.ts"
import { THEME_CSS } from "./theme.ts"

// The admin shell.
//
// Intelligence is an ADD-ON you sign up for with an Intyga account: there is no local password and
// no separate identity. So the shell has two states — onboarded, where the nav is live, and not yet
// connected, where every page funnels to binding an Intyga workspace. Rendering a half-usable admin
// panel to someone who has not connected anything is how a product feels broken on first run.

export function esc(s: unknown): string {
  if (s == null) return ""
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")
}

export function num(n: number): string {
  return n.toLocaleString("en-US")
}

export function ago(d: Date | string, now = new Date()): string {
  const s = Math.max(0, Math.round((now.getTime() - new Date(d).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.round(s / 60)}m ago`
  if (s < 86400) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}

export interface NavCounts {
  findings?: number
  alerts?: number
  connectors?: number
}

const NAV: { section: string; items: { href: string; label: string; key?: keyof NavCounts }[] }[] = [
  {
    section: "Watch",
    items: [
      { href: "/", label: "Overview" },
      { href: "/findings", label: "Findings", key: "findings" },
      { href: "/activity", label: "Activity" },
    ],
  },
  {
    section: "Configure",
    items: [
      { href: "/connectors", label: "Connectors", key: "connectors" },
      { href: "/detectors", label: "Detectors" },
      { href: "/alerts", label: "Alerts", key: "alerts" },
      { href: "/judgment", label: "Judgment" },
    ],
  },
  {
    section: "Account",
    items: [
      { href: "/members", label: "Members" },
      { href: "/settings", label: "Settings" },
    ],
  },
]

export interface AuthPageOpts {
  title: string
  /** One line under the title. Kept short — a sign-in screen is not the place to explain the product. */
  lede?: string
  /** Wider for signup, which is a real form rather than one field. */
  width?: "narrow" | "wide"
  error?: string
  body: string
  /** Rendered under the card in muted text. */
  footnote?: string
}

/**
 * The shell for sign-in, enrolment and signup.
 *
 * Deliberately NOT the admin shell with its nav suppressed. That left a dead 212px sidebar column
 * with a logo floating in it and the form pinned to the left of a 1120px empty expanse — the page
 * looked broken rather than focused. An unauthenticated screen has no navigation to show, so it
 * should not be built from a layout whose whole premise is navigation.
 *
 * Centred, one column, no chrome: the only thing on screen is the thing to do.
 */
export function authPage(o: AuthPageOpts): string {
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(o.title)} · INTYGA Intelligence</title>
<style>${THEME_CSS}${AUTH_CSS}</style>
</head><body class="auth">
<main class="authWrap">
  <div class="authCol ${o.width === "wide" ? "wide" : ""}">
    <div class="authBrand">
      <span class="wordmark">INTYGA</span>
      <small>INTELLIGENCE</small>
    </div>

    <div class="authCard">
      <h1>${esc(o.title)}</h1>
      ${o.lede ? `<p class="authLede">${esc(o.lede)}</p>` : ""}
      ${o.error ? `<div class="authError">${esc(o.error)}</div>` : ""}
      ${o.body}
    </div>

    ${o.footnote ? `<p class="authFoot">${o.footnote}</p>` : ""}
  </div>
</main>
</body></html>`
}

const AUTH_CSS = `
body.auth{min-height:100vh}
/* Explicit resets rather than relying on the admin main rule not applying: this element is a
   <main>, and a future change to that selector must not silently un-centre sign-in. */
.authWrap{min-height:100vh;width:100%;max-width:none;margin:0;padding:40px 16px;
  display:flex;align-items:center;justify-content:center}
.authCol{width:100%;max-width:394px}
.authCol.wide{max-width:660px}

/* The mark sits above the card rather than inside it: it identifies the page without competing
   with the one thing there is to do. Same wordmark spec as the console sidebar. */
.authBrand{text-align:center;margin:0 0 24px}
.authBrand .wordmark{display:block;font-weight:800;font-size:21px;letter-spacing:.2em;
  margin-right:-.2em;line-height:1;white-space:nowrap}
.authBrand small{display:block;color:var(--muted);font-weight:500;font-size:10.5px;margin-top:6px}

.authCard{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:26px 26px 24px;
  /* A hairline of brand at the top edge — enough to be ownable, not enough to shout. */
  box-shadow:inset 0 1px 0 0 color-mix(in srgb,var(--brand-mark) 45%,transparent)}
.authCard h1{font-size:19px;font-weight:650;margin:0 0 6px;letter-spacing:-.015em}
.authLede{color:var(--muted);font-size:13px;margin:0 0 20px;line-height:1.5}
.authCard .field{margin:0 0 16px}
.authCard .field:last-of-type{margin-bottom:18px}
.authCard input,.authCard textarea{font-size:14px;padding:9px 11px}
.authCard button{width:100%;min-height:38px;font-size:13px}
.authCard .row{gap:10px}

.authError{background:color-mix(in srgb,var(--red) 11%,transparent);
  border:1px solid color-mix(in srgb,var(--red) 38%,transparent);color:var(--red);
  border-radius:9px;padding:10px 12px;font-size:12.5px;margin:0 0 18px;line-height:1.45}

.authMsg{display:block;min-height:17px;margin-top:11px;font-size:12px;color:var(--muted);text-align:center}
.authFoot{color:var(--muted);font-size:12.5px;text-align:center;margin:18px 0 0;line-height:1.5}
.authFoot a{color:var(--link)}

/* Signup is a real form, so it gets section rules the single-field screens do not need. */
.authSection{border-top:1px solid var(--border);margin:22px 0 0;padding:20px 0 0}
.authSection:first-of-type{border-top:0;margin-top:0;padding-top:0}
.authSection h2{font-size:12px;font-weight:650;letter-spacing:.07em;text-transform:uppercase;
  color:var(--muted);margin:0 0 4px}
.authSection p{color:var(--muted);font-size:12.5px;margin:0 0 14px;line-height:1.5}
`

export interface PageOpts {
  title: string
  lede?: string
  path: string
  counts?: NavCounts
  /** Rendered instead of the nav when no workspace is connected, or nobody is signed in. */
  onboarding?: boolean
  /** Who is signed in. Absent on the sign-in and signup shells. */
  actor?: { label: string; externalId: string }
  body: string
}

export function page(o: PageOpts): string {
  const nav = NAV.map(
    (g) =>
      `<div class="sec">${esc(g.section)}</div>${g.items
        .map((i) => {
          const on = i.href === "/" ? o.path === "/" : o.path.startsWith(i.href)
          const c = i.key ? o.counts?.[i.key] : undefined
          return `<a href="${i.href}"${on ? ' class="on"' : ""}>${esc(i.label)}${
            c ? `<span class="pill">${num(c)}</span>` : ""
          }</a>`
        })
        .join("")}`,
  ).join("")

  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(o.title)} · INTYGA Intelligence</title>
<style>${THEME_CSS}${CHART_CSS}</style>
</head><body>
<div class="shell">
  <aside class="side">
    <div class="brand"><span class="wordmark">INTYGA</span><small>INTELLIGENCE</small></div>
    ${o.onboarding ? "" : `<nav>${nav}</nav>`}
    ${
      o.actor
        ? `<div class="who">
             <div class="whoName">${esc(o.actor.label)}</div>
             <div class="whoId"><code>${esc(o.actor.externalId)}</code></div>
             <a class="signout" href="/logout">Sign out</a>
           </div>`
        : ""
    }
  </aside>
  <main>
    <h1>${esc(o.title)}</h1>
    ${o.lede ? `<p class="lede">${esc(o.lede)}</p>` : ""}
    ${o.body}
  </main>
</div>

<dialog id="approve">
  <form method="dialog">
    <div class="head"><h3>Approve with your passkey</h3></div>
    <div class="body">
      <p class="mut" style="margin:0 0 12px">
        This action changes how Intelligence behaves, so it is signed the same way any protected
        operation is — a human, a passkey, a receipt.
      </p>
      <div id="approve-summary" class="impact-low"></div>
      <p id="approve-error" class="mut" style="color:var(--red);margin:12px 0 0"></p>
    </div>
    <div class="foot">
      <button value="cancel" class="ghost">Cancel</button>
      <button value="ok" id="approve-go" class="primary">Approve</button>
    </div>
  </form>
</dialog>

<script>
${CHART_JS}

// ─── the gated-action ceremony ────────────────────────────────────────────
// Open a challenge, get an assertion from the admin's passkey on THIS origin, then complete. The
// parameters are frozen server-side at step one; nothing the browser sends at step two can change
// what executes.
const dlg = document.getElementById("approve");
const sumEl = document.getElementById("approve-summary");
const errEl = document.getElementById("approve-error");
const goEl = document.getElementById("approve-go");

function b64urlToBuf(s) {
  if (typeof s !== "string") return new Uint8Array();
  const p = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  return Uint8Array.from(atob(p), (c) => c.charCodeAt(0));
}
function bufToB64url(b) {
  return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
}
function unwrapOptions(obj) {
  let cur = obj;
  while (cur && (cur.publicKey || cur.options)) {
    cur = cur.publicKey || cur.options;
  }
  return cur || {};
}

document.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-action]");
  if (!btn) return;
  e.preventDefault();

  const action = btn.dataset.action;
  const params = JSON.parse(btn.dataset.params || "{}");
  errEl.textContent = "";
  sumEl.textContent = "Preparing…";
  sumEl.className = "impact-low";
  goEl.disabled = true;
  dlg.showModal();

  let opened;
  try {
    const r = await fetch("/api/actions/open", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ action, params }),
    });
    opened = await r.json();
    if (!r.ok) throw new Error(opened.error || "could not open the approval");
  } catch (err) {
    sumEl.textContent = "";
    errEl.textContent = err.message;
    return;
  }

  sumEl.textContent = opened.summary;
  sumEl.className = "impact-" + opened.impact;
  goEl.disabled = false;

  goEl.onclick = async (ev) => {
    ev.preventDefault();
    goEl.disabled = true;
    errEl.textContent = "Waiting for your passkey…";
    try {
      const o = unwrapOptions(opened.options);
      const assertion = await navigator.credentials.get({
        publicKey: {
          ...o,
          challenge: b64urlToBuf(o.challenge),
          allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBuf(c.id) })),
        },
      });
      const res = await fetch("/api/actions/complete", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({
          nonce: opened.nonce,
          assertion: {
            id: assertion.id, rawId: bufToB64url(assertion.rawId), type: assertion.type,
            response: {
              clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
              authenticatorData: bufToB64url(assertion.response.authenticatorData),
              signature: bufToB64url(assertion.response.signature),
              userHandle: assertion.response.userHandle ? bufToB64url(assertion.response.userHandle) : null,
            },
          },
        }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error || "the approval was refused");
      dlg.close();
      location.reload();
    } catch (err) {
      errEl.textContent = err.message || String(err);
      goEl.disabled = false;
    }
  };
});
</script>
</body></html>`
}
