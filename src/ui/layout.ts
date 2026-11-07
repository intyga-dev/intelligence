import { EMBEDDED_BROWSER_JS } from "../embedded/browser.ts"
import { CHART_JS } from "./charts.ts"
import { stylesheetLinks } from "./styles.ts"
import { APPROVAL_HTML, APPROVAL_JS } from "./approval.ts"
import { FEEDBACK_HTML, FEEDBACK_JS } from "./feedback.ts"

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
      { href: "/services", label: "Services" },
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
${stylesheetLinks("theme", "auth", "approval", "feedback")}
</head><body class="auth">
${FEEDBACK_HTML}<script>${FEEDBACK_JS}</script>
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
${stylesheetLinks("theme", "charts", "approval", "feedback")}
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
             <a class="signout" href="/profile">Edit your name</a>
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

${APPROVAL_HTML}${FEEDBACK_HTML}
<script>
${CHART_JS}
${EMBEDDED_BROWSER_JS}
${FEEDBACK_JS}
${APPROVAL_JS}
</script>
</body></html>`
}
