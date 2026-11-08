export const APPROVAL_HTML = `
<dialog id="approve" aria-labelledby="approve-title" aria-describedby="approve-status">
 <div class="head"><span class="approvalBrand">INTYGA · PROTECTED ACTION</span><h3 id="approve-title">Review and approve</h3></div>
 <div class="body">
  <p class="approvalIntro">Review the change below. INTYGA checks your passkey and workspace approval rules before Intelligence applies it.</p>
  <ol class="approvalSteps" aria-label="Approval progress"><li data-step="0">1 · Review request</li><li data-step="1">2 · Approve</li><li data-step="2">3 · Applied</li></ol>
  <div id="approve-state" class="approvalState" data-state="preparing" role="status" aria-live="polite" aria-atomic="true"><strong id="approve-state-label">Preparing request</strong><p id="approve-status">Opening a secure approval…</p></div>
  <div class="approvalReview"><span>Requested change</span><div id="approve-summary"></div></div>
  <p id="approve-expiry"></p>
  <p id="approve-error" role="alert"></p>
  <div id="approve-share" hidden><label for="approve-share-url">Need another approver? Share this approval link.</label><input id="approve-share-url" readonly><button id="approve-copy" type="button">Copy link</button></div>
 </div>
 <div class="foot"><button id="approve-close" type="button" class="ghost">Close</button><button id="approve-retry" type="button" hidden>Check again</button><button type="button" id="approve-embedded" class="primary" hidden>Approve with passkey</button><a id="approve-go" class="primary" href="#" target="_blank" rel="noopener noreferrer" hidden>Open INTYGA approval ↗</a></div>
</dialog>`
export const APPROVAL_JS = `
(()=>{
 const dlg=document.getElementById('approve');if(!dlg)return;
 const $=id=>document.getElementById(id),summary=$('approve-summary'),status=$('approve-status'),error=$('approve-error'),go=$('approve-go'),embedded=$('approve-embedded'),close=$('approve-close'),retry=$('approve-retry');
 let generation=0,timer=null,wasApplied=false;
 const toast=(message,tone='info')=>window.intelligenceToast(message,tone,{id:'approval'});
 function state(name,label,detail,step){$('approve-state').dataset.state=name;$('approve-state-label').textContent=label;status.textContent=detail;dlg.querySelectorAll('[data-step]').forEach(el=>{const n=Number(el.dataset.step);el.dataset.active=String(n===step&&name!=='applied');el.dataset.done=String(n<step||name==='applied');if(n===step)el.setAttribute('aria-current','step');else el.removeAttribute('aria-current')})}
 close.onclick=()=>dlg.close();
 dlg.addEventListener('close',()=>{if(dlg.open)return;generation++;clearTimeout(timer);timer=null;if(wasApplied){window.intelligenceToast('Change approved and applied.','success',{id:'approval',persist:true});location.reload()}else{window.intelligenceToastClear('approval')}});
 $('approve-copy').onclick=async()=>{try{await navigator.clipboard.writeText($('approve-share-url').value);window.intelligenceToast('Approval link copied.','success',{id:'copy'})}catch{window.intelligenceToast('Could not copy automatically. Select the approval link and copy it.','error',{id:'copy'});$('approve-share-url').select()}};
 document.addEventListener('click',async event=>{
  const button=event.target.closest('[data-action]');if(!button)return;event.preventDefault();
  const current=++generation;clearTimeout(timer);wasApplied=false;let terminal=false,inFlight=false,opened,params;
  close.textContent='Close';error.textContent='';summary.textContent='Preparing the exact change for review…';go.hidden=true;embedded.hidden=true;retry.hidden=true;$('approve-share').hidden=true;$('approve-expiry').textContent='';
  if(!dlg.open)dlg.showModal();state('preparing','Preparing request','Opening a secure INTYGA approval…',0);toast('Preparing approval…','pending');
  try{
   params=JSON.parse(button.dataset.params||'{}');
   const res=await fetch('/api/actions/open',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:button.dataset.action,params})});opened=await res.json();
   if(!res.ok)throw new Error(opened.error||'Could not open approval.');
   if(current!==generation||!dlg.open)return;
  }catch(err){if(current!==generation)return;state('error','Could not start approval','The change has not been applied.',0);error.textContent=err.message||'Please try again.';toast(error.textContent,'error');return}
  summary.textContent=opened.summary;go.href=opened.approveUrl;go.hidden=Boolean(opened.embedded);embedded.hidden=!opened.embedded;embedded.disabled=false;
  if(opened.embeddedApprovalUrl){$('approve-share').hidden=false;$('approve-share-url').value=opened.embeddedApprovalUrl}
  const expires=new Date(opened.expiresAt);if(Number.isFinite(expires.getTime()))$('approve-expiry').textContent='Approval expires at '+expires.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
  const waiting=()=>state('waiting','Awaiting approval',opened.embedded?'Use your passkey below. Your workspace may require additional approvers.':'Open the INTYGA approval to review and sign. Keep this window open while approval is pending.',1);
  waiting();toast('Approval is ready. Review the change and sign with INTYGA.','info');
  async function poll(){
   if(current!==generation||!dlg.open||terminal||inFlight)return;inFlight=true;clearTimeout(timer);
   try{
    const res=await fetch('/api/actions/'+encodeURIComponent(opened.nonce),{headers:{accept:'application/json'}});const body=await res.json();
    if(current!==generation||!dlg.open){if(res.ok&&body.status==='applied')window.intelligenceToast('The previous action was applied. Refresh to see the change.','success');return}
    if(!res.ok)throw new Error(body.error||'Could not check approval.');
    error.textContent='';retry.hidden=true;
    if(body.status==='pending'){if($('approve-state').dataset.state==='error'){waiting();toast('Connection restored. Awaiting approval.','info');}timer=setTimeout(poll,2500);return}
    if(body.status==='refused'){terminal=true;const expired=/expir/i.test(body.reason||'');state('refused',expired?'Approval expired':'Action not approved','Intelligence has not confirmed this change as applied.',1);error.textContent=body.reason||'Approval was refused.';go.hidden=true;embedded.hidden=true;toast(error.textContent,'error');return}
    if(body.status!=='applied')throw new Error('Unexpected approval status. The change is not confirmed.');
    terminal=true;wasApplied=true;state('applied','Approved and applied',body.note||'The signed change has been applied successfully. Select Done to refresh this page.',2);go.hidden=true;embedded.hidden=true;$('approve-share').hidden=true;close.textContent='Done';toast('Change approved and applied.','success');close.focus();
   }catch(err){if(current!==generation||!dlg.open)return;state('error','Connection interrupted','Approval status is unknown. We will check again automatically; keep this window open while we check again.',1);error.textContent=err.message||'Could not check approval.';retry.hidden=false;toast('Could not check approval. Retrying…','error');timer=setTimeout(poll,5000)}
   finally{inFlight=false}
  }
  retry.onclick=()=>poll();
  embedded.onclick=async()=>{
   if(terminal)return;embedded.disabled=true;error.textContent='';state('signing','Waiting for your passkey','Complete the passkey prompt on this device. Nothing is applied until INTYGA confirms approval.',1);toast('Complete the passkey prompt.','pending');
   try{const base='/api/actions/'+encodeURIComponent(opened.nonce)+'/embedded/';await signEmbedded(base+'options',base+'verify',{});if(current!==generation||!dlg.open||terminal)return;state('verifying','Passkey accepted','Checking workspace approvals and applying the change when all requirements are met…',1);toast('Passkey accepted. Waiting for workspace approval.','pending');await poll()}
   catch(err){if(current!==generation||!dlg.open||terminal)return;state('waiting','Approval still pending','The passkey step did not finish. You can try again or share the approval link.',1);error.textContent=err.message||'Passkey request cancelled.';embedded.disabled=false;toast(error.textContent,'error')}
  };
  timer=setTimeout(poll,2500);
 });
})();
`
