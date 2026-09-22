// Intyga Graphite — the design tokens, copied from packages/components/src/tokens.css.
//
// Copied rather than imported: Intelligence is a separate deployable with no build step and no
// dependency on the Intyga monorepo. The values are the contract; if the brand book moves, this
// moves with it. Keeping the comments that explain WHY each value is what it is, because a bare hex
// list is exactly how the two apps previously drifted onto different systems.

export const THEME_CSS = `
:root{
  --bg:#0d0d0f;            /* canvas */
  --panel:#141417;         /* cards */
  --panel-2:#1a1a1e;       /* sunk surfaces */
  --border:#2a2a30;        /* decorative only — panel edges, table rules */
  --border-interactive:#68686e; /* form/control boundaries — clears 3:1 on every surface above */
  --text:#f4f4f5;
  --muted:#9a9aa4;
  --accent:#fafafa;        /* contrast, not hue — primary action CTA */
  --accent-ink:#0d0d0f;
  --brand:#9696ee;         /* identity & interaction — focus, active nav, links */
  --brand-mark:#5151cd;    /* the one ownable value: 3:1 on dark AND white */
  --link:#9696ee;
  --green:#2acd91;         /* Verified / intact ONLY */
  --amber:#eda805;         /* Pending / action required */
  --red:#fd99a6;           /* Failed */
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--bg);color:var(--text);
  font:14px/1.55 ui-sans-serif,-apple-system,system-ui,"Segoe UI",sans-serif;
  -webkit-font-smoothing:antialiased;
}
a{color:var(--link);text-decoration:none}
a:hover{text-decoration:underline}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;overflow-wrap:break-word}

/* ─── shell ─────────────────────────────────────────────────────────────── */
.shell{display:grid;grid-template-columns:212px 1fr;min-height:100vh}
.side{border-right:1px solid var(--border);background:var(--panel);padding:20px 0;position:sticky;top:0;height:100vh;overflow-y:auto}
/* The wordmark, matching packages/components/src/Logo.tsx exactly: caps, weight 800, 0.2em
   tracking, and a negative right margin pulling back the trailing space that caps-plus-tracking
   adds after the final glyph — so the optical right edge lines up with the box. */
.brand{padding:0 18px 18px}
.wordmark{display:block;font-weight:800;font-size:20px;letter-spacing:.2em;margin-right:-.2em;
  line-height:1;white-space:nowrap}
.brand small{display:block;color:var(--muted);font-weight:500;font-size:11px;margin-top:5px}
nav{display:grid;gap:1px;padding:0 10px}
nav a{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:7px 9px;border-radius:7px;color:var(--muted);font-size:13px}
nav a:hover{background:var(--panel-2);color:var(--text);text-decoration:none}
nav a.on{background:var(--panel-2);color:var(--text);box-shadow:inset 2px 0 0 var(--brand)}
nav .pill{background:var(--panel);border:1px solid var(--border);border-radius:999px;padding:1px 7px;font-size:10px;color:var(--muted)}
nav a.on .pill{border-color:var(--border-interactive);color:var(--text)}
nav .sec{color:var(--muted);font-size:10px;letter-spacing:.11em;text-transform:uppercase;padding:16px 9px 5px}
/* Scoped to the admin shell on purpose. As a bare element selector this leaked onto the auth
   pages — whose wrapper is also a <main> — capping them at 1120px with no auto margin, so the
   "centred" card sat inside a left-aligned box and drifted left as the viewport grew. */
.shell main{padding:26px 30px 90px;max-width:1120px}
.shell .side{display:flex;flex-direction:column}
.who{margin-top:auto;padding:14px 18px 0;border-top:1px solid var(--border)}
.whoName{font-size:12.5px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.whoId{font-size:11px;color:var(--muted);margin:2px 0 8px;overflow:hidden;text-overflow:ellipsis}
.signout{font-size:11.5px;color:var(--muted)}
.signout:hover{color:var(--text)}
h1{font-size:20px;font-weight:650;margin:0 0 4px;letter-spacing:-.01em}
.lede{color:var(--muted);margin:0 0 22px;font-size:13px;max-width:70ch}
h2{font-size:14px;font-weight:650;margin:0 0 3px}

/* ─── surfaces ──────────────────────────────────────────────────────────── */
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px 18px;margin:0 0 14px}
.grid{display:grid;gap:14px}
.g2{grid-template-columns:repeat(auto-fit,minmax(310px,1fr))}
.g4{grid-template-columns:repeat(auto-fit,minmax(168px,1fr))}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
.stat .v{font-size:25px;font-weight:650;letter-spacing:-.02em;line-height:1.15;font-variant-numeric:tabular-nums}
.stat .l{color:var(--muted);font-size:11px;letter-spacing:.06em;text-transform:uppercase;margin-top:3px}
.stat .sub{color:var(--muted);font-size:12px;margin-top:5px}

table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--muted);font-weight:600;padding:8px 10px;border-bottom:1px solid var(--border);font-size:11px;letter-spacing:.05em;text-transform:uppercase}
td{padding:9px 10px;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:0}

/* ─── controls ──────────────────────────────────────────────────────────── */
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;min-height:32px;padding:6px 12px;
  border:1px solid var(--border-interactive);border-radius:8px;background:var(--panel-2);color:var(--text);
  font:600 12px/1 inherit;cursor:pointer;transition:background .15s,border-color .15s,transform .05s}
button:hover,.btn:hover{border-color:var(--accent);background:var(--panel);text-decoration:none}
button:active,.btn:active{transform:translateY(1px)}
button[disabled]{opacity:.45;cursor:not-allowed;transform:none}
button.primary,.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--accent-ink)}
button.danger{border-color:var(--red);color:var(--red)}
button.ghost{border-color:var(--border);color:var(--muted);font-weight:500}
input,select,textarea{background:var(--panel-2);border:1px solid var(--border-interactive);color:var(--text);
  border-radius:8px;padding:7px 10px;font:13px/1.4 inherit;width:100%}
input:focus,select:focus,textarea:focus{outline:2px solid var(--brand);outline-offset:1px;border-color:var(--brand)}
label{display:block;font-size:11px;color:var(--muted);letter-spacing:.05em;text-transform:uppercase;margin:0 0 5px}
.field{margin:0 0 12px}
.row{display:flex;gap:9px;align-items:center;flex-wrap:wrap}

/* ─── badges: colour is never the only signal (tokens.css note) ─────────── */
.badge{display:inline-flex;align-items:center;gap:5px;border-radius:999px;padding:2px 9px;font-size:11px;font-weight:600;
  border:1px solid var(--border);color:var(--muted);background:var(--panel-2);white-space:nowrap}
.badge::before{content:"";width:6px;height:6px;border-radius:999px;background:currentColor;flex:none}
.badge.critical{color:var(--red);border-color:color-mix(in srgb,var(--red) 40%,transparent)}
.badge.high{color:var(--amber);border-color:color-mix(in srgb,var(--amber) 40%,transparent)}
.badge.medium{color:var(--brand);border-color:color-mix(in srgb,var(--brand) 40%,transparent)}
.badge.low,.badge.info{color:var(--muted)}
.badge.on{color:var(--green);border-color:color-mix(in srgb,var(--green) 40%,transparent)}
.badge.off{color:var(--muted)}
.mut{color:var(--muted)}
.right{margin-left:auto}
.empty{border:1px dashed var(--border);border-radius:12px;padding:38px 22px;text-align:center;color:var(--muted)}

/* ─── dialog ────────────────────────────────────────────────────────────── */
dialog{border:1px solid var(--border);background:var(--panel);color:var(--text);border-radius:14px;padding:0;max-width:520px;width:calc(100% - 32px)}
dialog::backdrop{background:rgba(0,0,0,.66)}
dialog .head{padding:18px 20px 0}
dialog .body{padding:12px 20px}
dialog .foot{padding:14px 20px 18px;display:flex;gap:9px;justify-content:flex-end}
dialog h3{margin:0 0 6px;font-size:15px}
.impact-high{border-left:3px solid var(--red);padding-left:11px}
.impact-medium{border-left:3px solid var(--amber);padding-left:11px}
.impact-low{border-left:3px solid var(--border-interactive);padding-left:11px}
`
