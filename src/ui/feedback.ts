export const FEEDBACK_HTML = '<div id="toast-region" class="toastRegion" aria-label="Notifications"></div>'
export const FEEDBACK_JS = `
(()=>{
 const host=document.getElementById('toast-region');if(!host)return;
 const timers=new WeakMap();
 window.intelligenceSignStatus=(element,message,state="pending")=>{element.dataset.signState=state;element.textContent=message;};
 function remove(node){clearTimeout(timers.get(node));node.remove()}
 window.intelligenceToast=(message,tone='info',options={})=>{
   if(!['info','pending','success','error'].includes(tone))tone='info';
   const id=options.id||'general';
   if(options.persist){try{sessionStorage.setItem('intelligence.flash',JSON.stringify({message:String(message),tone,at:Date.now()}))}catch{}}
   let item=Array.from(host.children).find(n=>n.dataset.id===id);
   if(item)remove(item);
   item=document.createElement('div');item.className='toast';item.dataset.tone=tone;item.dataset.id=id;item.setAttribute('role',tone==='error'?'alert':'status');
   const icon=document.createElement('span');icon.className='toastIcon';icon.setAttribute('aria-hidden','true');icon.textContent=({success:'✓',error:'!',pending:'…',info:'i'})[tone];
   const text=document.createElement('span');text.className='toastMessage';text.textContent=String(message);
   const close=document.createElement('button');close.type='button';close.setAttribute('aria-label','Dismiss notification');close.textContent='×';close.onclick=()=>remove(item);
   item.append(icon,text,close);host.append(item);while(host.children.length>4)remove(host.firstElementChild);
   (document.querySelector('dialog[open]')||document.body).append(host);
   if(tone==='success'||tone==='info'){
     const pause=()=>clearTimeout(timers.get(item));
     const schedule=()=>{pause();if(!item.matches(':hover, :focus-within'))timers.set(item,setTimeout(()=>remove(item),7000))};
     item.addEventListener('mouseenter',pause);item.addEventListener('mouseleave',schedule);
     item.addEventListener('focusin',pause);item.addEventListener('focusout',schedule);schedule();
   }
 };
 window.intelligenceToastClear=id=>{for(const node of Array.from(host.children))if(node.dataset.id===id)remove(node)};
 document.addEventListener('close',()=>{if(!document.querySelector('dialog[open]'))document.body.append(host)},true);
 try{const raw=sessionStorage.getItem('intelligence.flash');sessionStorage.removeItem('intelligence.flash');if(raw){const f=JSON.parse(raw);if(Date.now()-f.at<60000)window.intelligenceToast(f.message,f.tone)}}catch{}
 const marker=document.querySelector('[data-flash-message]');if(marker)window.intelligenceToast(marker.dataset.flashMessage,'success');
})();
`
