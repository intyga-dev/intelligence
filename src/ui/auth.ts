import { authPage, esc } from "./layout.ts"

// Sign-in.
//
// Rendered on the onboarding shell (no navigation): showing a nav to someone who is not signed in
// advertises the shape of the console and invites them to try each route.
//
// There is nothing to type but an address. INTYGA is the identity provider (core ADR 030): the form
// posts the address, the server starts an OpenID Connect sign-in and sends the browser to INTYGA,
// where the person approves it with the passkey they use for the console. The browser comes back to
// /auth/callback with a code only this server can redeem.

export function loginPage(o: { error?: string; prefill?: string; consoleUrl?: string } = {}): string {
  return authPage({
    title: "Sign in with INTYGA",
    lede: "No password — the passkey you use for your INTYGA workspace.",
    ...(o.error ? { error: o.error } : {}),
    footnote:
      "Anyone who is a member of this instance's INTYGA workspace can sign in; workspace administrators " +
      "administer Intelligence. No account here? Ask a workspace administrator to add you in INTYGA.",
    body: `
<form method="post" action="/login/begin">
  <div class="field">
    <label>Your INTYGA email</label>
    <input name="email" id="email" type="email" required autocomplete="email" autofocus
           placeholder="ada@example.com" value="${esc(o.prefill ?? "")}">
  </div>
  <button class="primary" type="submit" id="go">Continue to INTYGA</button>
</form>${
      o.consoleUrl
        ? `<p class="mut" style="margin-top:14px;font-size:12.5px">You will approve the sign-in at <code>${esc(
            o.consoleUrl,
          )}</code> and come straight back.</p>`
        : ""
    }`,
  })
}
