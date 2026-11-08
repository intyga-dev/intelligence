// Native WebAuthn on Intelligence's origin. No frame and no cross-origin credential ceremony.
export const EMBEDDED_BROWSER_JS = String.raw`
function decode64(value) { return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)); }
function encode64(value) { return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
async function embeddedPost(path, body) {
  const res = await fetch(path, {method:'POST', headers:{'content-type':'application/json','x-intelligence-login':'1'}, body:JSON.stringify(body)});
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Embedded ceremony refused.');
  return data;
}
async function embeddedPasskey(options, create) {
  options.challenge = decode64(options.challenge);
  if (options.user) options.user.id = decode64(options.user.id);
  for (const item of (options.allowCredentials || options.excludeCredentials || [])) item.id = decode64(item.id);
  const credential = create ? await navigator.credentials.create({publicKey:options}) : await navigator.credentials.get({publicKey:options});
  if (!credential) throw new Error('No passkey response.');
  const r = credential.response;
  const response = {clientDataJSON:encode64(r.clientDataJSON)};
  if (create) {response.attestationObject=encode64(r.attestationObject);response.transports=r.getTransports ? r.getTransports() : [];}
  else {response.authenticatorData=encode64(r.authenticatorData);response.signature=encode64(r.signature);if(r.userHandle && r.userHandle.byteLength) response.userHandle=encode64(r.userHandle);}
  return {id:credential.id,rawId:encode64(credential.rawId),type:credential.type,clientExtensionResults:credential.getClientExtensionResults(),response,...(credential.authenticatorAttachment ? {authenticatorAttachment:credential.authenticatorAttachment} : {})};
}
async function signEmbedded(optionsPath, verifyPath, body) {
  const opened = await embeddedPost(optionsPath,body);
  const response = await embeddedPasskey(opened.options,false);
  await embeddedPost(verifyPath,{...body,response});
}
`
