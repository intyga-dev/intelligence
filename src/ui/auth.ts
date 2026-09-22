import { authPage, esc } from "./layout.ts"

// Sign-in and passkey enrolment.
//
// Rendered on the onboarding shell (no navigation): showing a nav to someone who is not signed in
// advertises the shape of the console and invites them to try each route.

/** Shared base64url helpers — WebAuthn speaks ArrayBuffers, JSON does not. */
const B64 = `
function b64urlToBuf(s) {
  if (typeof s !== "string") return new Uint8Array();
  const p = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  return Uint8Array.from(atob(p), (c) => c.charCodeAt(0));
}
function bufToB64url(b) {
  return btoa(String.fromCharCode(...new Uint8Array(b)))
    .replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
}
function unwrapOptions(obj) {
  let cur = obj;
  while (cur && (cur.publicKey || cur.options)) {
    cur = cur.publicKey || cur.options;
  }
  return cur || {};
}
`

export function loginPage(o: { error?: string; prefill?: string } = {}): string {
  return authPage({
    title: "Sign in",
    lede: "No password — the passkey you approve production actions with.",
    ...(o.error ? { error: o.error } : {}),
    footnote: "No passkey yet? An administrator adds you first, then sends you an enrolment link.",
    body: `
<form id="login-form">
  <div class="field">
    <label>INTYGA subject id</label>
    <input name="externalId" id="externalId" required autocomplete="username webauthn"
           autofocus placeholder="ada" value="${esc(o.prefill ?? "")}">
  </div>
  <button class="primary" type="submit" id="go">Sign in with passkey</button>
  <span id="msg" class="authMsg"></span>
</form>

<script>
${B64}
const form = document.getElementById("login-form");
const msg = document.getElementById("msg");
const go = document.getElementById("go");

function fail(text) {
  msg.textContent = text;
  msg.style.color = "var(--red)";
  go.disabled = false;
  go.textContent = "Sign in with passkey";
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  go.disabled = true;
  go.textContent = "Starting…";
  msg.textContent = "";
  msg.style.color = "";
  const externalId = document.getElementById("externalId").value.trim();
  try {
    const begin = await fetch("/login/begin", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ externalId }),
    });
    const b = await begin.json();
    if (!begin.ok) throw new Error(b.error || "could not start sign-in");

    go.textContent = "Waiting for your passkey…";
    const o = unwrapOptions(b.options);
    const assertion = await navigator.credentials.get({
      publicKey: {
        ...o,
        challenge: b64urlToBuf(o.challenge),
        allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBuf(c.id) })),
      },
    });

    const done = await fetch("/login/complete", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        nonce: b.nonce,
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
    const d = await done.json();
    if (!done.ok) throw new Error(d.error || "sign-in refused");
    go.textContent = "Signed in";
    location.href = "/";
  } catch (err) {
    // A cancelled or timed-out passkey prompt throws NotAllowedError, which reads as a scary
    // browser string. Say what actually happened.
    fail(err && err.name === "NotAllowedError" ? "Passkey prompt dismissed." : (err.message || String(err)));
  }
});
</script>`,
  })
}

export function enrolPage(o: { externalId: string; error?: string }): string {
  return authPage({
    title: "Enrol a passkey",
    lede: "One passkey on this domain. It signs you in here and approves changes.",
    ...(o.error ? { error: o.error } : {}),
    footnote:
      "This credential is registered against Intelligence's own Relying Party — it cannot approve anything in INTYGA itself.",
    body: `
<div class="field">
  <label>Subject</label>
  <div style="background:var(--panel-2);border:1px solid var(--border);border-radius:8px;padding:9px 11px">
    <code>${esc(o.externalId)}</code>
  </div>
</div>
<button class="primary" id="go">Enrol passkey</button>
<span id="msg" class="authMsg"></span>

<script>
${B64}
const go = document.getElementById("go");
const msg = document.getElementById("msg");
const externalId = ${JSON.stringify(o.externalId)};

function fail(text) {
  msg.textContent = text;
  msg.style.color = "var(--red)";
  go.disabled = false;
  go.textContent = "Enrol passkey";
}

go.addEventListener("click", async () => {
  go.disabled = true;
  go.textContent = "Starting…";
  msg.textContent = "";
  msg.style.color = "";
  try {
    const begin = await fetch("/members/enrol/begin", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ externalId }),
    });
    const b = await begin.json();
    if (!begin.ok) throw new Error(b.error || "could not start enrolment");

    go.textContent = "Follow your device's prompt…";
    const o = unwrapOptions(b.options);
    const cred = await navigator.credentials.create({
      publicKey: {
        ...o,
        challenge: b64urlToBuf(o.challenge),
        user: { ...(o.user || {}), id: b64urlToBuf(o.user && o.user.id) },
        excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: b64urlToBuf(c.id) })),
      },
    });

    const done = await fetch("/members/enrol/complete", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        externalId,
        response: {
          id: cred.id, rawId: bufToB64url(cred.rawId), type: cred.type,
          response: {
            clientDataJSON: bufToB64url(cred.response.clientDataJSON),
            attestationObject: bufToB64url(cred.response.attestationObject),
          },
        },
      }),
    });
    const d = await done.json();
    if (!done.ok) throw new Error(d.error || "enrolment refused");
    go.textContent = "Enrolled";
    msg.textContent = "Taking you to sign in…";
    msg.style.color = "var(--green)";
    setTimeout(() => (location.href = "/login?id=" + encodeURIComponent(externalId)), 900);
  } catch (err) {
    fail(err && err.name === "NotAllowedError" ? "Passkey prompt dismissed." : (err.message || String(err)));
  }
});
</script>`,
  })
}
