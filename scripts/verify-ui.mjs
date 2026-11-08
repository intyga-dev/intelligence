import { connectorsPage } from "../src/ui/pages.ts"
import { allConnectors, isPush } from "../src/connectors/index.ts"
import { catalogueDetails } from "../src/connectors/catalogue.ts"
// Run: node --experimental-strip-types scripts/verify-ui.mjs
// Requires local Chromium. All action/API calls are fixtures; no provider or live database is used.
import { createServer } from "node:http"
import { readFile, writeFile } from "node:fs/promises"
import { spawn } from "node:child_process"
import { page, authPage } from "../src/ui/layout.ts"
import { profilePage } from "../src/ui/profile.ts"
import { STYLESHEETS } from "../src/ui/styles.ts"
const assertions = `
(async()=>{
 const checks=[];const check=(ok,label)=>{if(!ok)throw new Error(label);checks.push(label)};
 const wait=ms=>new Promise(r=>setTimeout(r,ms));
 const $=id=>document.getElementById(id);
 const result=(error)=>{const pre=document.createElement('pre');pre.id='browser-result';pre.textContent=JSON.stringify({checks,error});document.body.append(pre)};
 try{
  if(sessionStorage.getItem('test.done')){
   checks.push(...JSON.parse(sessionStorage.getItem('test.done')));sessionStorage.removeItem('test.done');
   check(document.querySelector('.toastMessage')?.textContent==='Change approved and applied.','success toast survives Done and reload');
   check(!sessionStorage.getItem('intelligence.flash'),'flash consumed once');result(null);return;
  }
  check(document.styleSheets.length===4,'external styles loaded');
  window.intelligenceToast('<img src=x onerror=alert(1)>','error');
  check(document.querySelector('.toastMessage').textContent.startsWith('<img'),'toast renders text safely');
  check(!document.querySelector('.toast img'),'toast cannot inject HTML');
  check(document.querySelector('.toast').getAttribute('role')==='alert','errors announce to assistive technology');
  document.querySelector('.toast button').click();check(!document.querySelector('.toast'),'toast dismisses');
  let mode='pending',network=false,openError=false,resolveSignature;
  window.fetch=async(url)=>{
   if(url==='/api/actions/open')return {ok:!openError,json:async()=>openError?{error:'Session expired'}:{nonce:'fixture',summary:'Turn on AWS alerts for production',impact:'low',approveUrl:'https://example.test/approve',embedded:true,embeddedApprovalUrl:'https://example.test/share',expiresAt:new Date(Date.now()+600000).toISOString()}};
   if(network)throw new Error('Offline');
   return {ok:true,json:async()=>({status:mode,reason:mode==='refused'?'Approval expired':undefined})};
  };
  window.signEmbedded=()=>new Promise(resolve=>{resolveSignature=resolve});
  openError=true;$('test-action').click();await wait(30);
  check($('approve-state').dataset.state==='error','opening failure is explicit');$('approve-close').click();await wait(30);
  openError=false;$('test-action').click();await wait(30);
  check($('approve-state-label').textContent==='Awaiting approval','awaiting approval visible');
  check($('approve-summary').textContent.includes('AWS'),'exact change visible');
  check(document.querySelector('dialog[open] #toast-region'),'toast stays in dialog top layer');
  check(getComputedStyle($('approve')).borderRadius==='18px','approval stylesheet applied');
  network=true;$('approve-retry').click();await wait(30);
  check($('approve-state-label').textContent==='Connection interrupted','network failure remains unconfirmed');
  check(!$('approve-retry').hidden,'retry offered');network=false;$('approve-retry').click();await wait(30);
  check($('approve-state-label').textContent==='Awaiting approval','retry recovers waiting state');
  mode='surprise';$('approve-retry').click();await wait(30);
  check($('approve-state').dataset.state!=='applied','unknown status never treated as applied');
  mode='refused';$('approve-retry').click();await wait(30);
  check($('approve-state-label').textContent==='Approval expired','expired approval visibly refused');
  check($('approve-embedded').hidden,'refused request cannot be signed');$('approve-close').click();await wait(30);
  mode='pending';$('test-action').click();await wait(30);$('approve-embedded').click();await wait(30);
  check($('approve-state-label').textContent==='Waiting for your passkey','passkey prompt has own state');
  resolveSignature();await wait(30);
  check($('approve-state-label').textContent==='Passkey accepted','accepted signature still awaits quorum');
  check($('approve').open,'signature alone does not dismiss approval');
  mode='applied';$('approve-retry').click();await wait(30);
  check($('approve-state-label').textContent==='Approved and applied','applied state requires server confirmation');
  check($('approve').open&&$('approve-close').textContent==='Done','success remains visible until Done');
  check([...document.querySelectorAll('[data-step]')].every(n=>n.dataset.done==='true'),'all progress steps complete');
  sessionStorage.setItem('test.done',JSON.stringify(checks));$('approve-close').click();
 }catch(e){result(e.stack||String(e))}
})();`
const profileChecks = `
(async()=>{const checks=[];const check=(x,s)=>{if(!x)throw Error(s);checks.push(s)};const wait=()=>new Promise(r=>setTimeout(r,50));try{let ok=false;window.fetch=async()=>({ok,json:async()=>ok?{name:'New name'}:{error:'Try again'}});const form=document.getElementById('profile-form');form.requestSubmit();await wait();check(document.querySelector('.toast[data-tone=error]'),'profile error toast');check(!form.querySelector('button').disabled,'profile retry enabled');ok=true;form.requestSubmit();await wait();check(document.querySelector('.whoName').textContent==='New name','profile visible name updated');check(document.querySelector('.toast[data-tone=success]'),'profile success toast');document.body.insertAdjacentHTML('beforeend','<pre id="browser-result"></pre>');document.getElementById('browser-result').textContent=JSON.stringify({checks,error:null});}catch(e){document.body.insertAdjacentHTML('beforeend','<pre id="browser-result"></pre>');document.getElementById('browser-result').textContent=JSON.stringify({checks,error:e.message});}})();`
const authChecks = `
(()=>{const checks=[];try{const status=document.getElementById('embedded-status');window.intelligenceSignStatus(status,'Waiting for your passkey');const before=getComputedStyle(status).borderColor;window.intelligenceSignStatus(status,'Approval failed','error');if(before===getComputedStyle(status).borderColor)throw Error('error border unchanged');checks.push('auth failure visibly distinct');window.intelligenceSignStatus(status,'Approved','success');if(getComputedStyle(status).borderColor===before)throw Error('success border unchanged');checks.push('auth success visibly distinct');if(getComputedStyle(status).fontSize!=='14px')throw Error('status too small');checks.push('status text enlarged');document.body.insertAdjacentHTML('beforeend','<pre id="browser-result"></pre>');document.getElementById('browser-result').textContent=JSON.stringify({checks,error:null});}catch(e){document.body.insertAdjacentHTML('beforeend','<pre id="browser-result"></pre>');document.getElementById('browser-result').textContent=JSON.stringify({checks,error:e.message});}})();`
const inject = (html, script) => html.replace("</body>", `<script>${script}</script></body>`)
const html = inject(
  page({
    title: "Approval fixture",
    path: "/",
    body: '<button id="test-action" data-action="intelligence.detector.enable" data-params="{}">Enable alerts</button>',
  }),
  assertions,
)
const profile = inject(profilePage({ label: "Admin", externalId: "fixture" }), profileChecks)
const auth = inject(
  authPage({ title: "Sign in", body: '<p id="embedded-status" role="status"></p>' }),
  authChecks,
)
const catalogueChecks = `
(()=>{const checks=[];const check=(ok,label)=>{if(!ok)throw Error(label);checks.push(label)};let error=null;
try{const cards=[...document.querySelectorAll('[data-catalogue-search]')];check(cards.length===20,'all 20 addable connectors displayed, plus built-in INTYGA');
const search=document.getElementById('connector-search'),category=document.getElementById('connector-category');
const visible=()=>cards.filter(c=>getComputedStyle(c).display!=='none');search.value='AWS EventBridge';search.dispatchEvent(new Event('input'));check(visible().length===1,'search narrows to AWS');visible()[0].querySelector('button').click();check(document.getElementById('add-aws-eventbridge').open,'native AWS setup dialog opens');document.getElementById('add-aws-eventbridge').close();
search.value='missing-service-xyz';search.dispatchEvent(new Event('input'));check(!document.getElementById('connector-no-match').hidden,'empty search explains next step');
search.value='';category.value='Cloud';search.dispatchEvent(new Event('input'));check(visible().length>0&&visible().every(c=>c.dataset.catalogueCategory==='Cloud'),'category filter matches cloud sources');
check(document.querySelector('#add-google-workspace input[type=password]'),'Workspace credential field is masked');check(document.querySelector('#add-stripe input[type=password]'),'Stripe signing secret field is masked');
}catch(e){error=e.message}const output=document.createElement('pre');output.id='browser-result';output.textContent=JSON.stringify({checks,error});document.body.append(output)})();`
const catalogue = inject(
  connectorsPage({
    rows: [],
    counts: { findings: 0, alerts: 0, connectors: 0 },
    available: allConnectors()
      .filter((d) => !d.builtIn)
      .map((d) => ({
        ...d,
        ...catalogueDetails(d),
        generatesSecret: isPush(d) && d.generatesSecret,
        installed: false,
        builtIn: false,
      })),
  }),
  catalogueChecks,
)
const server = createServer(async (req, res) => {
  const name = /^\/assets\/ui\/([a-z-]+)\.module\.css$/.exec(req.url)?.[1]
  if (name && STYLESHEETS.includes(name)) {
    res.setHeader("content-type", "text/css")
    res.end(await readFile(new URL(`../src/ui/${name}.module.css`, import.meta.url), "utf8"))
    return
  }
  res.setHeader("content-type", "text/html")
  res.end(
    req.url === "/catalogue"
      ? catalogue
      : req.url === "/profile"
        ? profile
        : req.url === "/auth"
          ? auth
          : req.url === "/preview"
            ? html.replace(`<script>${assertions}</script>`, "")
            : html,
  )
})
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve))
let child
try {
  child = spawn("chromium", [
    "--headless",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-background-networking",
    "--disable-component-update",
    "--no-first-run",
    "--remote-debugging-port=0",
    `--user-data-dir=/tmp/intelligence-ui-cdp-${process.pid}`,
    "about:blank",
  ])
  const endpoint = await new Promise((resolve, reject) => {
    let output = ""
    const timer = setTimeout(() => reject(Error("Chromium did not start")), 15000)
    child.stderr.on("data", (chunk) => {
      output += chunk
      const match = /DevTools listening on (ws:\/\/[^\s]+)/.exec(output)
      if (match) {
        clearTimeout(timer)
        resolve(new URL(match[1]).origin.replace("ws:", "http:"))
      }
    })
    child.on("error", reject)
  })
  const targets = await (await fetch(`${endpoint}/json/list`)).json()
  const target = targets.find((t) => t.type === "page")
  const socket = new WebSocket(target.webSocketDebuggerUrl)
  await new Promise((resolve) => socket.addEventListener("open", resolve, { once: true }))
  let sequence = 0
  const pending = new Map()
  socket.addEventListener("message", (e) => {
    const m = JSON.parse(e.data)
    if (m.id) {
      const pair = pending.get(m.id)
      if (pair) {
        pending.delete(m.id)
        m.error ? pair.reject(Error(m.error.message)) : pair.resolve(m.result)
      }
    }
  })
  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const id = ++sequence
      pending.set(id, { resolve, reject })
      socket.send(JSON.stringify({ id, method, params }))
    })
  await send("Page.enable")
  await send("Emulation.setDeviceMetricsOverride", {
    width: 1280,
    height: 900,
    deviceScaleFactor: 1,
    mobile: false,
  })
  for (const path of ["/", "/profile", "/auth", "/catalogue"]) {
    await send("Page.navigate", { url: `http://127.0.0.1:${server.address().port}${path}` })
    let result
    for (let i = 0; i < 150; i++) {
      await new Promise((r) => setTimeout(r, 100))
      const out = await send("Runtime.evaluate", {
        expression: "document.getElementById('browser-result')?.textContent",
        returnByValue: true,
      })
      if (out.result?.value) {
        result = JSON.parse(out.result.value)
        break
      }
    }
    console.log(path, JSON.stringify(result))
    if (!result || result.error) process.exitCode = 1
  }
  await send("Page.navigate", { url: `http://127.0.0.1:${server.address().port}/preview` })
  await new Promise((r) => setTimeout(r, 300))
  await send("Runtime.evaluate", {
    expression: `window.fetch=async()=>({ok:true,json:async()=>({nonce:'fixture',summary:'Turn on AWS EventBridge for Production. New provider alerts will appear in Findings.',embedded:true,embeddedApprovalUrl:'https://intelligence.example/approve',expiresAt:new Date(Date.now()+600000).toISOString()})});document.getElementById('test-action').click();`,
  })
  await new Promise((r) => setTimeout(r, 300))
  await writeFile(
    "/tmp/intelligence-signing.png",
    Buffer.from((await send("Page.captureScreenshot", { format: "png" })).data, "base64"),
  )
  await send("Emulation.setDeviceMetricsOverride", {
    width: 390,
    height: 844,
    deviceScaleFactor: 1,
    mobile: true,
  })
  await new Promise((r) => setTimeout(r, 150))
  const mobile = await send("Runtime.evaluate", {
    expression:
      "document.getElementById('approve').getBoundingClientRect().width <= innerWidth && document.getElementById('approve').scrollWidth <= document.getElementById('approve').clientWidth",
    returnByValue: true,
  })
  console.log("mobile modal fits", mobile.result?.value)
  if (!mobile.result?.value) process.exitCode = 1
  await writeFile(
    "/tmp/intelligence-signing-mobile.png",
    Buffer.from((await send("Page.captureScreenshot", { format: "png" })).data, "base64"),
  )
  socket.close()
} finally {
  child?.kill()
  server.closeAllConnections()
  server.close()
}
