import { EMBEDDED_BROWSER_JS } from "../embedded/browser.ts"
import { authPage, esc } from "./layout.ts"

export function loginPage(
  o: {
    error?: string
    prefill?: string
    consoleUrl?: string
    oidcEnabled?: boolean
    embeddedEnabled?: boolean
    setupPending?: boolean
  } = {},
): string {
  if (o.embeddedEnabled) return embeddedLoginPage(o)
  return authPage({
    title: "Sign in to Intelligence",
    lede: "Request access, then approve it with INTYGA.",
    ...(o.error ? { error: o.error } : {}),
    footnote:
      "Approval sign-in grants this browser administrator access for 12 hours under your workspace's approval rules. Every privileged change still needs its own approval.",
    body: `
<button class="primary" type="button" id="approval-login">Request sign-in approval</button>
<p id="approval-status" class="mut" role="status" aria-live="polite"></p>
<p id="approval-details" hidden>Check that the approval names this Intelligence instance and browser code
  <strong id="browser-code"></strong>. <a id="approval-link" target="_blank" rel="noopener noreferrer">Open approval ↗</a></p>
${
  o.oidcEnabled
    ? `
<hr style="margin:24px 0">
<p>Or sign in with your workspace identity and role:</p>
<form method="post" action="/login/begin">
  <div class="field">
    <label for="email">Your INTYGA email</label>
    <input name="email" id="email" type="email" required autocomplete="email"
           placeholder="ada@example.com" value="${esc(o.prefill ?? "")}">
  </div>
  <button type="submit">Sign in with INTYGA (OIDC)</button>
</form>`
    : ""
}
<script>
const button = document.getElementById("approval-login");
const status = document.getElementById("approval-status");
let timer;
button.addEventListener("click", async () => {
  button.disabled = true;
  clearTimeout(timer);
  document.getElementById("approval-details").hidden = true;
  window.intelligenceSignStatus(status,"Preparing sign-in · Requesting INTYGA approval…");
  // Open during the click gesture, then isolate the popup before navigating to the console.
  const popup = window.open("about:blank", "_blank", "popup,width=520,height=760");
  if (popup) popup.opener = null;
  try {
    const response = await fetch("/login/approval/begin", {
      method: "POST", headers: { "x-intelligence-login": "1" }
    });
    const opened = await response.json();
    if (!response.ok) throw new Error(opened.error || "Could not request approval.");
    document.getElementById("browser-code").textContent = opened.browserCode;
    document.getElementById("approval-link").href = opened.approveUrl;
    document.getElementById("approval-details").hidden = false;
    if (popup) popup.location = opened.approveUrl;
    window.intelligenceSignStatus(status,"Awaiting approval · Sign in the INTYGA window, then return here. Keep this page open.");
    const deadline = Date.now() + 10 * 60 * 1000;
    const poll = async () => {
      try {
        if (Date.now() >= deadline) throw new Error("The sign-in expired. Start again.");
        const response = await fetch("/login/approval/status", { cache: "no-store" });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "Sign-in was refused.");
        if (result.status === "approved") {
          if (popup && !popup.closed) popup.close();
          window.intelligenceSignStatus(status,"Approved · Signing you in…","success");
          window.intelligenceToast("Signed in successfully.","success",{persist:true});
          window.location.assign("/");
          return;
        }
        timer = setTimeout(poll, 1500);
      } catch (error) {
        window.intelligenceSignStatus(status,error.message || "Could not check approval. Start again.","error");
        button.disabled = false;
      }
    };
    timer = setTimeout(poll, 1500);
  } catch (error) {
    if (popup && !popup.closed) popup.close();
    window.intelligenceSignStatus(status,error.message || "Could not request approval.","error");
    button.disabled = false;
  }
});
</script>`,
  })
}

function embeddedLoginPage(o: { error?: string; setupPending?: boolean }) {
  return authPage({
    title: o.setupPending ? "Set up your Intelligence passkey" : "Sign in to Intelligence",
    lede: o.setupPending
      ? "Your application is configured. Verify its ownership in INTYGA, then link your membership here."
      : "Use your application passkey, linked to your INTYGA workspace membership.",
    ...(o.error ? { error: o.error } : {}),
    footnote:
      "Your workspace role controls access. Protected changes still require approval under your workspace’s rules.",
    body: `
<button class="primary" id="embedded-login" ${o.setupPending ? "disabled hidden" : ""}>Sign in with passkey</button>
<p id="embedded-status" role="status" aria-live="polite"></p>
<p id="share-approval" hidden>Need another approver? Share this application approval link: <input id="share-approval-url" readonly aria-label="Approval link"></p>
<p>First time on this application? Link your membership once, then create an application passkey.</p>
<button id="embedded-link" ${o.setupPending ? 'class="primary"' : ""}>Link my INTYGA membership</button>
${o.setupPending ? "<p>After creating your passkey, export the application trust anchor from INTYGA Member applications and install it on this server to enable sign-in.</p>" : ""}
<script>
${EMBEDDED_BROWSER_JS}
const statusEl=document.getElementById('embedded-status');
const login=document.getElementById('embedded-login');
login.onclick=async()=>{
 login.disabled=true;
 try {
  window.intelligenceSignStatus(statusEl,'Preparing sign-in · Opening a secure request…');
  const opened=await embeddedPost('/login/approval/begin',{});
  if(opened.embeddedApprovalUrl){document.getElementById('share-approval-url').value=opened.embeddedApprovalUrl;document.getElementById('share-approval').hidden=false;}
  window.intelligenceSignStatus(statusEl,'Waiting for your passkey · Complete the prompt on this device.');
  await signEmbedded('/login/approval/embedded/options','/login/approval/embedded/verify',{});
  window.intelligenceSignStatus(statusEl,'Passkey accepted · Waiting for the required workspace approvals…');
  const end=Date.now()+10*60*1000;
  const poll=async()=>{try{if(Date.now()>=end)throw new Error('Sign-in expired. Start again.');const res=await fetch('/login/approval/status',{cache:'no-store'});const body=await res.json();if(!res.ok)throw new Error(body.error||'Sign-in refused.');if(body.status==='approved'){window.intelligenceSignStatus(statusEl,'Approved · Signing you in…','success');window.intelligenceToast('Signed in successfully.','success',{persist:true});location.assign('/');return;}setTimeout(poll,1500);}catch(e){window.intelligenceSignStatus(statusEl,e.message,'error');login.disabled=false;}};
  await poll();
 }catch(e){window.intelligenceSignStatus(statusEl,e.message||'Passkey sign-in cancelled. Try again.','error');login.disabled=false;}
};
document.getElementById('embedded-link').onclick=async()=>{try{const result=await embeddedPost('/embedded/link/start',{});location.assign(result.url);}catch(e){window.intelligenceSignStatus(statusEl,e.message,'error');}};
</script>`,
  })
}

export function embeddedLinkPage() {
  return authPage({
    title: "Create your Intelligence passkey",
    lede: "Your INTYGA membership is linked. Create a passkey for this application.",
    footnote:
      "The application passkey cannot sign in to the INTYGA console. An administrator must export a fresh application trust anchor before its first use.",
    body: `
<button class="primary" id="create-passkey">Create application passkey</button><p id="link-status" role="status"></p><a href="/login">Return to sign-in</a>
<script>
${EMBEDDED_BROWSER_JS}
const grant=new URLSearchParams(location.hash.slice(1));
history.replaceState(null,'',location.pathname);
const body={token:grant.get('token'),state:grant.get('state')};
const button=document.getElementById('create-passkey');
const statusEl=document.getElementById('link-status');
button.onclick=async()=>{button.disabled=true;window.intelligenceSignStatus(statusEl,'Create your passkey · Follow the prompt on this device.');try{const opened=await embeddedPost('/embedded/link/options',body);const response=await embeddedPasskey(opened.options,true);await embeddedPost('/embedded/link/verify',{...body,response});window.intelligenceSignStatus(statusEl,'Passkey created · Ask your administrator to mount a fresh application trust anchor, then sign in.','success');window.intelligenceToast('Application passkey created.','success');}catch(e){window.intelligenceSignStatus(statusEl,e.message||'Registration cancelled. Try again.','error');button.disabled=false;}};
</script>`,
  })
}

export function embeddedApprovalPage() {
  return authPage({
    title: "Review an Intelligence approval",
    lede: "Read the exact request before using your application passkey.",
    body: `
<pre id="request-details"></pre><p id="request-status" role="status"></p><button id="approve-request" class="primary" disabled>Approve with passkey</button>
<script>
${EMBEDDED_BROWSER_JS}
const ticket=new URLSearchParams(location.hash.slice(1)).get('ticket');
history.replaceState(null,'',location.pathname);
const statusEl=document.getElementById('request-status');
const button=document.getElementById('approve-request');
let options;
(async()=>{window.intelligenceSignStatus(statusEl,'Loading request · Preparing the exact change for review…');try{const opened=await embeddedPost('/embedded/approve/options',{ticket});document.getElementById('request-details').textContent=opened.description+'\n'+opened.actionType+'\n'+JSON.stringify(opened.params,null,2)+'\nRequired approvals: '+opened.requiredApprovals;options=opened.options;button.disabled=false;window.intelligenceSignStatus(statusEl,'Awaiting your approval · Review the request above, then use your passkey.');}catch(e){window.intelligenceSignStatus(statusEl,e.message,'error');}})();
button.onclick=async()=>{button.disabled=true;window.intelligenceSignStatus(statusEl,'Waiting for your passkey · Complete the prompt on this device.');try{const response=await embeddedPasskey(options,false);await embeddedPost('/embedded/approve/verify',{ticket,response});window.intelligenceSignStatus(statusEl,'Approval recorded · The requesting browser will apply the change when all required approvals are complete.','success');window.intelligenceToast('Your approval was recorded.','success');}catch(e){window.intelligenceSignStatus(statusEl,e.message||'Approval cancelled. Try again.','error');button.disabled=false;}};
</script>`,
    footnote:
      "This link lets you review one request. Approval still requires an eligible active workspace member’s application passkey.",
  })
}
