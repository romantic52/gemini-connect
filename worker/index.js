const GOOGLE={issuer:'https://accounts.google.com',auth:'https://accounts.google.com/o/oauth2/v2/auth',token:'https://oauth2.googleapis.com/token',userinfo:'https://openidconnect.googleapis.com/v1/userinfo',revoke:'https://oauth2.googleapis.com/revoke',jwks:'https://www.googleapis.com/oauth2/v3/certs'};
const enc=new TextEncoder(),dec=new TextDecoder();
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
const un64=s=>Uint8Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
const random=()=>b64(crypto.getRandomValues(new Uint8Array(32)));
export const hash=async s=>b64(await crypto.subtle.digest('SHA-256',enc.encode(s)));
const headers={'content-type':'application/json','cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff'};
const json=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers});
class AuthError extends Error {constructor(code){super(code);this.code=code;}}
export async function seal(value,key,aad){const iv=crypto.getRandomValues(new Uint8Array(12));const k=await crypto.subtle.importKey('raw',un64(key),'AES-GCM',false,['encrypt']);return b64(iv)+'.'+b64(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode(aad)},k,enc.encode(JSON.stringify(value))));}
export async function unseal(value,key,aad){const [iv,data]=value.split('.');const k=await crypto.subtle.importKey('raw',un64(key),'AES-GCM',false,['decrypt']);return JSON.parse(dec.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:un64(iv),additionalData:enc.encode(aad)},k,un64(data))));}
const providerFetch=(url,options)=>fetch(url,options);
const epoch=()=>Math.floor(Date.now()/1000);
export class Store{
 constructor(env){this.db=env.DB;this.key=env.TOKEN_ENCRYPTION_KEY;}
 async get(k){const r=await this.db.prepare('SELECT payload FROM oauth_records WHERE key = ? AND (expires_at IS NULL OR expires_at > ?)').bind(k,epoch()).first();return r?unseal(r.payload,this.key,k):null;}
 async put(k,v,expires=null){await this.db.prepare('INSERT INTO oauth_records(key,payload,expires_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET payload=excluded.payload, expires_at=excluded.expires_at').bind(k,await seal(v,this.key,k),expires).run();}
 async del(k){await this.db.prepare('DELETE FROM oauth_records WHERE key = ?').bind(k).run();}
 async consume(k){const r=await this.db.prepare('DELETE FROM oauth_records WHERE key = ? AND expires_at > ? RETURNING payload').bind(k,epoch()).first();return r?unseal(r.payload,this.key,k):null;}
 async generation(u){await this.db.prepare('INSERT OR IGNORE INTO oauth_generations(user_id,generation) VALUES(?,0)').bind(u).run();return (await this.db.prepare('SELECT generation FROM oauth_generations WHERE user_id=?').bind(u).first()).generation;}
 async invalidate(u){await this.db.batch([this.db.prepare('INSERT INTO oauth_generations(user_id,generation) VALUES(?,1) ON CONFLICT(user_id) DO UPDATE SET generation=generation+1').bind(u),this.db.prepare('DELETE FROM oauth_records WHERE key IN (?,?)').bind('connection:'+u,'error:'+u)]);}
 async saveConnection(u,g,value){const key='connection:'+u;const r=await this.db.prepare('INSERT INTO oauth_records(key,payload,expires_at) SELECT ?,?,NULL WHERE EXISTS(SELECT 1 FROM oauth_generations WHERE user_id=? AND generation=?) ON CONFLICT(key) DO UPDATE SET payload=excluded.payload WHERE EXISTS(SELECT 1 FROM oauth_generations WHERE user_id=? AND generation=?)').bind(key,await seal(value,this.key,key),u,g,u,g).run();return r.meta.changes>0;}
 async cleanup(){await this.db.prepare('DELETE FROM oauth_records WHERE expires_at IS NOT NULL AND expires_at <= ?').bind(epoch()).run();}
}
async function remote(url,options={},net=providerFetch){const r=await net(url,{...options,redirect:'manual',signal:AbortSignal.timeout(15000)});if(!r.ok)throw new AuthError(r.status===400||r.status===401?'provider_authorization_rejected':'provider_request_failed');return r;}
async function form(url,data,net){return (await remote(url,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(data).toString()},net)).json();}
export async function verifyID(token,config,nonce,net=providerFetch){
 if(typeof token!=='string'||token.length>20000)throw new AuthError('invalid_id_token');
 const parts=token.split('.');if(parts.length!==3)throw new AuthError('invalid_id_token');
 const h=JSON.parse(dec.decode(un64(parts[0]))),p=JSON.parse(dec.decode(un64(parts[1])));
 if(h.alg!=='RS256'||typeof h.kid!=='string')throw new AuthError('invalid_id_token');
 const jwks=await (await remote(GOOGLE.jwks,{},net)).json();const jwk=jwks.keys?.find(k=>k.kid===h.kid&&k.kty==='RSA'&&(!k.alg||k.alg==='RS256'));
 if(!jwk)throw new AuthError('unknown_signing_key');
 const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,un64(parts[2]),enc.encode(parts[0]+'.'+parts[1])))throw new AuthError('invalid_id_token');
 const audiences=Array.isArray(p.aud)?p.aud:[p.aud];
 if(!['https://accounts.google.com','accounts.google.com'].includes(p.iss)||!audiences.includes(config.clientId)||(audiences.length>1&&p.azp!==config.clientId)||(p.azp&&p.azp!==config.clientId)||typeof p.exp!=='number'||p.exp<=epoch()||typeof p.iat!=='number'||p.iat>epoch()+60||p.nonce!==nonce||typeof p.sub!=='string'||!p.sub)throw new AuthError('invalid_id_claims');
 return p;
}
const scopes=['openid','email','profile'];
export async function begin(store,u,config){
 const state=random(),verifier=random(),nonce=random(),generation=await store.generation(u);
 await store.cleanup();await store.put('attempt:'+u+':'+await hash(state),{state,verifier,nonce,generation,redirectUri:config.redirectUri,clientId:config.clientId},epoch()+300);
 const url=new URL(GOOGLE.auth);url.search=new URLSearchParams({client_id:config.clientId,redirect_uri:config.redirectUri,response_type:'code',scope:scopes.join(' '),state,nonce,code_challenge:await hash(verifier),code_challenge_method:'S256',access_type:'offline',prompt:'consent select_account'});
 return {url:url.href,state};
}
export async function complete(store,u,config,url,cookieState,net=providerFetch){
 const state=url.searchParams.get('state');if(!state||state.length>200||cookieState!==await hash(state))throw new AuthError('invalid_state');
 const a=await store.consume('attempt:'+u+':'+await hash(state));
 if(!a||a.state!==state||a.redirectUri!==config.redirectUri||a.clientId!==config.clientId)throw new AuthError('expired_or_replayed_state');
 if(url.searchParams.get('error'))throw new AuthError('authorization_declined');
 if(url.searchParams.has('iss')&&url.searchParams.get('iss')!==GOOGLE.issuer)throw new AuthError('invalid_issuer');
 const code=url.searchParams.get('code');if(!code||code.length>4096)throw new AuthError('missing_authorization_code');
 const t=await form(GOOGLE.token,{grant_type:'authorization_code',code,redirect_uri:config.redirectUri,client_id:config.clientId,client_secret:config.clientSecret,code_verifier:a.verifier},net);
 if(typeof t.access_token!=='string'||String(t.token_type).toLowerCase()!=='bearer'||!Number.isFinite(t.expires_in)||t.expires_in<=0)throw new AuthError('invalid_token_response');
 const claims=await verifyID(t.id_token,config,a.nonce,net);
 const profile=await (await remote(GOOGLE.userinfo,{headers:{authorization:'Bearer '+t.access_token}},net)).json();
 if(profile.sub!==claims.sub)throw new AuthError('account_mismatch');
 const connection={account:{sub:profile.sub,email:profile.email??null,name:profile.name??null,emailVerified:profile.email_verified===true},accessToken:t.access_token,refreshToken:t.refresh_token??null,expiresAt:epoch()+t.expires_in,scope:t.scope??scopes.join(' '),generation:a.generation};
 if(!await store.saveConnection(u,a.generation,connection)){try{await form(GOOGLE.revoke,{token:t.refresh_token||t.access_token},net);}catch{}throw new AuthError('connection_cancelled');}
 await store.del('error:'+u);return connection;
}
async function fresh(store,u,c,config,net=providerFetch){
 if(c.expiresAt>epoch()+60)return c;
 if(!c.refreshToken)throw new AuthError('authorization_required');
 let t;try{t=await form(GOOGLE.token,{grant_type:'refresh_token',refresh_token:c.refreshToken,client_id:config.clientId,client_secret:config.clientSecret},net);}catch(e){if(e.code==='provider_authorization_rejected'){await store.invalidate(u);throw new AuthError('authorization_required');}throw e;}
 if(typeof t.access_token!=='string'||!Number.isFinite(t.expires_in)||t.expires_in<=0)throw new AuthError('invalid_token_response');
 const updated={...c,accessToken:t.access_token,refreshToken:t.refresh_token||c.refreshToken,expiresAt:epoch()+t.expires_in};
 if(!await store.saveConnection(u,c.generation,updated))throw new AuthError('connection_cancelled');return updated;
}
export async function disconnect(store,u,net=providerFetch){const c=await store.get('connection:'+u);await store.invalidate(u);let revoked=false;if(c){try{await form(GOOGLE.revoke,{token:c.refreshToken||c.accessToken},net);revoked=true;}catch{}}
 return {accountStatus:'Not connected',localTokensDeleted:!!c,providerRevocation:{performed:revoked,status:c?(revoked?'Revoked':'Error: local tokens removed; revoke access manually in your Google Account'):'Not needed'}};}
export async function status(store,u,config,{check=false,net=providerFetch}={}){
 let c=store?await store.get('connection:'+u):null;let issue=null;
 if(c&&check){try{c=await fresh(store,u,c,config,net);const p=await (await remote(GOOGLE.userinfo,{headers:{authorization:'Bearer '+c.accessToken}},net)).json();if(p.sub!==c.account.sub)throw new AuthError('account_mismatch');}catch(e){if(['authorization_required','provider_authorization_rejected'].includes(e.code)){await store.invalidate(u);c=null;issue='authorization_required';}else issue=e.code||'provider_check_failed';}}
 const e=store?await store.get('error:'+u):null;
 return {provider:'Google',accountStatus:issue==='authorization_required'?'Authorization required':issue?'Error':c?'Limited':config?'Not connected':'Unavailable',connectedAccount:c?.account??null,authenticationMethod:c?'Google OAuth 2.0 / OpenID Connect':null,providerAuthorizationCompleted:!!c,lastAuthorizationError:e?.code??null,availableCapabilities:c?['Google account identity','Token refresh when refresh token is available','Disconnect and token revocation']:[],usageLimits:{available:false,value:null},modelTest:{status:'Not run',passed:null},geminiAccess:{available:false,reason:'Google identity scopes do not grant access to Gemini Apps or paid subscription allowances'},subscriptionAccess:{status:'Unverified',paidApiEnabled:false},redirectUri:config?.redirectUri??null,blocker:issue??(!config?'Register a Web application OAuth client in Google Auth Platform, add this redirect URI and enter its client ID/secret on the protected settings page.':!c?'Connect Google to authorize.':'Google identity connected; Gemini model access is not configured.'),missingConfiguration:config?[]:['Google OAuth Web client ID','Google OAuth Web client secret'],tokenStorage:store?'AES-256-GCM encrypted D1 records; key stored in runtime secret':'Unavailable'};
}
const titles={connect:'Connect Antigravity',list_models:'List Antigravity Models',generate_text:'Generate Text with Antigravity',account_status:'Account Status',connected_account:'Connected Account',authentication_method:'Authentication Method',available_capabilities:'Available Capabilities',usage_limits:'Usage Limits',test_request:'Test Model Access',disconnect:'Disconnect',redo_with_pro:'Gemini Apps: Redo with Pro'};
function cookie(req,key){return req.headers.get('cookie')?.split(';').map(s=>s.trim()).find(s=>s.startsWith(key+'='))?.slice(key.length+1);}
const clear='__Host-google-oauth=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0';
function page(title,body,code=200){return new Response(`<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${title}</title><style>body{font:17px system-ui;max-width:760px;margin:40px auto;padding:24px;background:#111827;color:#e5e7eb}a{color:#93c5fd}button,input,textarea{box-sizing:border-box;padding:12px;margin:8px 0;border-radius:8px;width:100%}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>${title}</h1>${body}</html>`,{status:code,headers:{'content-type':'text/html;charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff','content-security-policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"}});}
export default {async fetch(request,env={}){
 try{
 const origin=env.SITE_ORIGIN;
 if(typeof origin!=='string'||!/^https:\/\/[^/]+$/.test(origin)||new URL(origin).origin!==origin)return json({error:'SITE_ORIGIN must be a canonical HTTPS origin'},503);
 const url=new URL(request.url);if(url.origin!==origin)return json({error:'Invalid origin'},400);
 const callback=origin+'/oauth/callback';
 const email=request.headers.get('oai-authenticated-user-email'),id=request.headers.get('oai-authenticated-user-id');
 if(!email&&!id)return json({error:'Authenticated Sites identity required'},401);
 // Verified platform email links browser and MCP identities on this owner-private deployment.
 const u=await hash(email?'email:'+email.toLowerCase():'id:'+id);
 const store=env.DB&&env.TOKEN_ENCRYPTION_KEY?new Store(env):null;
 const savedConfig=store?await store.get('config:'+u):null;
 const config=savedConfig?{...savedConfig,redirectUri:callback}:null;
 if(url.pathname.startsWith('/antigravity')){const routed=await agRoute(request,url,env,store,u);if(routed)return routed;}
 if(url.pathname==='/settings'&&request.method==='GET')return page('Gemini Connect — OAuth settings',`<p>Создай OAuth client типа Web application в Google Auth Platform. Укажи callback:</p><pre>${callback}</pre><p>Доступ только к имени, email и идентификатору Google. Gemini и подписка не подключаются.</p><p><a href="https://console.cloud.google.com/auth/clients" target="_blank" rel="noopener noreferrer">Google Auth Platform → Clients</a></p><p>Вставь JSON, скачанный для Web client. Секрет уйдёт только на этот защищённый сервер и будет сохранён зашифрованным.</p><textarea id="credentials" rows="9" autocomplete="off" spellcheck="false" placeholder="OAuth client JSON"></textarea><button id="save">Сохранить реквизиты</button><p id="result">${config?'Реквизиты сохранены.':'Реквизиты ещё не заданы.'}</p><a href="/oauth/start">Connect Google</a><script>document.getElementById('save').onclick=async()=>{try{const credentials=JSON.parse(document.getElementById('credentials').value);const r=await fetch('/settings',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(credentials)});document.getElementById('credentials').value='';document.getElementById('result').textContent=r.ok?'Сохранено. Нажми Connect Google.':'Ошибка сохранения: '+(await r.json()).error}catch{document.getElementById('result').textContent='Проверь JSON реквизитов.'}};</script>`);
 if(url.pathname==='/settings'&&request.method==='POST'){
  if(request.headers.get('origin')!==url.origin||!request.headers.get('content-type')?.startsWith('application/json'))return json({error:'Same-origin JSON required'},403);
  if(!store)return json({error:'Secure storage not ready'},503);
  const text=await request.text();if(text.length>16000)return json({error:'Input too large'},413);
  let parsed;try{parsed=JSON.parse(text);}catch{return json({error:'Invalid JSON'},400);}
  const w=parsed.web;
  if(!w||typeof w.client_id!=='string'||!w.client_id.endsWith('.apps.googleusercontent.com')||w.client_id.length>512||typeof w.client_secret!=='string'||w.client_secret.length<8||w.client_secret.length>512||!Array.isArray(w.redirect_uris)||!w.redirect_uris.includes(callback))return json({error:'Web client JSON must contain client_id, client_secret and the exact redirect URI'},400);
  const existing=await store.get('connection:'+u);if(existing)return json({error:'Disconnect the current account before replacing the OAuth client'},409);
  await store.invalidate(u);await store.put('config:'+u,{clientId:w.client_id,clientSecret:w.client_secret});return json({saved:true});
 }
 if(url.pathname==='/oauth/start'){
  if(request.method!=='GET')return json({error:'GET required'},405);
  if(!store||!config)return Response.redirect(origin+'/settings',303);
  const {url:auth,state}=await begin(store,u,config);
  return new Response(null,{status:303,headers:{location:auth,'cache-control':'no-store','referrer-policy':'no-referrer','set-cookie':'__Host-google-oauth='+await hash(state)+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=300'}});
 }
 if(url.pathname==='/oauth/callback'){
  if(request.method!=='GET')return json({error:'GET required'},405);
  if(!store||!config)return json({error:'OAuth client not configured'},503);
  let result;
  try{await complete(store,u,config,url,cookie(request,'__Host-google-oauth'));result=page('Google подключён','<p>Limited: Google-аккаунт подключён. Gemini и лимиты подписки не предоставлены этим входом.</p><a href="/">Account Status</a>');}
  catch(e){const code=e instanceof AuthError?e.code:'authorization_failed';await store.put('error:'+u,{code},epoch()+3600);result=page('Авторизация не завершена','<p>'+code+'</p><a href="/oauth/start">Повторить вход</a>',400);}
  result.headers.set('set-cookie',clear);return result;
 }
 if(url.pathname==='/status')return json(await agStatus(store,u,agConfig(env,url.origin)));
 if(url.pathname==='/mcp'){
  if(request.method!=='POST')return json({error:'POST required'},405);
  let rpc;try{rpc=await request.json();}catch{return json({jsonrpc:'2.0',id:null,error:{code:-32700,message:'Parse error'}},400);}
  if(!rpc||Array.isArray(rpc)||rpc.jsonrpc!=='2.0'||typeof rpc.method!=='string')return json({jsonrpc:'2.0',id:null,error:{code:-32600,message:'Invalid request'}},400);
  if(rpc.id===undefined)return new Response(null,{status:202});let result;
  switch(rpc.method){
   case 'server/discover':result={supportedVersions:['2026-07-28'],capabilities:{tools:{}}};break;
   case 'initialize':result={protocolVersion:'2024-11-05',capabilities:{tools:{}},serverInfo:{name:'gemini-connect',version:'0.4.0'}};break;
   case 'ping':result={};break;
   case 'tools/list':result={tools:Object.entries(titles).map(([name,title])=>({name,description:title+'. Unofficial Antigravity OAuth adapter. Login and model access are verified separately.',inputSchema:name==='generate_text'?{type:'object',properties:{model:{type:'string',description:'Exact ID returned by list_models'},prompt:{type:'string',maxLength:20000},max_output_tokens:{type:'integer',minimum:1,maximum:4096,default:256}},required:['model','prompt'],additionalProperties:false}:{type:'object',properties:{},additionalProperties:false},annotations:{readOnlyHint:!['connect','disconnect','generate_text','test_request'].includes(name),destructiveHint:false,idempotentHint:name!=='connect',openWorldHint:true}}))};break;
   case 'tools/call':{
    const name=rpc.params?.name,args=rpc.params?.arguments??{};
    const allowed=name==='generate_text'?['model','prompt','max_output_tokens']:[];
    if(!Object.hasOwn(titles,name)||!args||typeof args!=='object'||Array.isArray(args)||Object.keys(args).some(k=>!allowed.includes(k))){result={content:[{type:'text',text:'Unknown tool or invalid arguments'}],isError:true};break;}
    const operation=await agTool(name,args,store,u,agConfig(env,url.origin));
    result={content:[{type:'text',text:JSON.stringify(operation.value)}],isError:operation.isError};break;
   }
   default:return json({jsonrpc:'2.0',id:rpc.id,error:{code:-32601,message:'Method not found'}});
  }
  return json({jsonrpc:'2.0',id:rpc.id,result});
 }
 if(url.pathname!=='/')return json({error:'Not found'},404);
 return page('Gemini Connect · Antigravity','<p>Подключение моделей через Antigravity по схеме OpenCode. Неофициальная интеграция.</p><a href="/antigravity">Connect Antigravity</a> · <a href="/settings">Google Identity Settings</a><button id="status">Account Status</button><pre id="result"></pre><script>document.getElementById("status").onclick=async()=>{document.getElementById("result").textContent=JSON.stringify(await(await fetch("/status")).json(),null,2)}</script>');
 }catch{return json({accountStatus:'Error',error:'Secure connection service failed; no secrets are included in this response'},503);}
}};

// Protocol adapter based on NoeFabris/opencode-antigravity-auth (MIT, see THIRD_PARTY_LICENSES.md).
const AG_CALLBACK='http://localhost:51121/oauth-callback';
const AG_API='https://daily-cloudcode-pa.googleapis.com';
const AG_SCOPES=['https://www.googleapis.com/auth/cloud-platform','https://www.googleapis.com/auth/userinfo.email','https://www.googleapis.com/auth/userinfo.profile','https://www.googleapis.com/auth/cclog','https://www.googleapis.com/auth/experimentsandconfigs'];
const AG_USER_AGENT='antigravity/hub/2.24.0 (aidev_client; os_type=darwin; arch=arm64; cl=1000335682)';
const AG_SOURCE='https://github.com/NoeFabris/opencode-antigravity-auth';
const agUser=u=>'ag:'+u;
function agConfig(env,origin){return env.ANTIGRAVITY_CLIENT_ID&&env.ANTIGRAVITY_CLIENT_SECRET?{clientId:env.ANTIGRAVITY_CLIENT_ID,clientSecret:env.ANTIGRAVITY_CLIENT_SECRET,origin}:null;}
async function agPost(action,token,body,net=providerFetch){
 const r=await net(AG_API+'/v1internal:'+action,{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json','User-Agent':AG_USER_AGENT},body:JSON.stringify(body),redirect:'manual',signal:AbortSignal.timeout(60000)});
 if(!r.ok)throw new AuthError(r.status===401?'provider_access_revoked':r.status===403?'provider_permission_denied':r.status===429?'provider_rate_limited':r.status===400?'provider_invalid_request':'provider_request_failed');
 return r.json();
}
export async function agBegin(store,u,config){
 u=agUser(u);const state=random(),verifier=random(),generation=await store.generation(u);
 await store.cleanup();await store.put('attempt:'+u+':'+await hash(state),{state,verifier,generation,clientId:config.clientId,redirectUri:AG_CALLBACK},epoch()+600);
 const url=new URL(GOOGLE.auth);url.search=new URLSearchParams({client_id:config.clientId,redirect_uri:AG_CALLBACK,response_type:'code',scope:AG_SCOPES.join(' '),state,code_challenge:await hash(verifier),code_challenge_method:'S256',access_type:'offline',prompt:'consent'});
 return {url:url.href,state};
}
async function oauthStep(code,operation){
 try{return await operation();}
 catch(error){throw new AuthError(error instanceof AuthError&&error.code==='provider_authorization_rejected'?code+'_rejected':code);}
}
export async function agComplete(store,u,config,callbackText,cookieState,net=providerFetch){
 u=agUser(u);if(typeof callbackText!=='string'||callbackText.length>16000)throw new AuthError('invalid_callback');
 let url;try{url=new URL(callbackText);}catch{throw new AuthError('invalid_callback');}
 const base=new URL(AG_CALLBACK);
 if(url.origin!==base.origin||url.pathname!==base.pathname||url.username||url.password||url.hash)throw new AuthError('invalid_callback_uri');
 const state=url.searchParams.get('state');if(!state||state.length>200||await hash(state)!==cookieState)throw new AuthError('invalid_state');
 let attempt;
 try{attempt=await store.consume('attempt:'+u+':'+await hash(state));}
 catch{throw new AuthError('oauth_attempt_storage_failed');}
 if(!attempt||attempt.state!==state||attempt.clientId!==config.clientId||attempt.redirectUri!==AG_CALLBACK)throw new AuthError('expired_or_replayed_state');
 if(url.searchParams.has('error'))throw new AuthError('authorization_declined');
 if(url.searchParams.has('iss')&&url.searchParams.get('iss')!==GOOGLE.issuer)throw new AuthError('invalid_issuer');
 const code=url.searchParams.get('code');if(!code||code.length>4096)throw new AuthError('missing_authorization_code');
 const t=await oauthStep('google_token_exchange_failed',()=>form(GOOGLE.token,{grant_type:'authorization_code',code,redirect_uri:AG_CALLBACK,client_id:config.clientId,client_secret:config.clientSecret,code_verifier:attempt.verifier},net));
 if(typeof t?.access_token!=='string'||typeof t.refresh_token!=='string'||!Number.isFinite(t.expires_in)||t.expires_in<=0||String(t.token_type).toLowerCase()!=='bearer')throw new AuthError('invalid_token_response');
 const profile=await oauthStep('google_profile_request_failed',async()=> (await remote(GOOGLE.userinfo,{headers:{Authorization:'Bearer '+t.access_token}},net)).json());
 if(typeof profile?.sub!=='string'||!profile.sub)throw new AuthError('invalid_account_response');
 const c={account:{sub:profile.sub,email:profile.email??null,name:profile.name??null,emailVerified:profile.email_verified===true},accessToken:t.access_token,refreshToken:t.refresh_token,expiresAt:epoch()+t.expires_in,scope:t.scope??null,generation:attempt.generation,projectId:null,protocol:'Antigravity (unofficial)'};
 const saved=await oauthStep('oauth_connection_storage_failed',()=>store.saveConnection(u,attempt.generation,c));
 if(!saved){try{await form(GOOGLE.revoke,{token:t.refresh_token},net);}catch{}throw new AuthError('connection_cancelled');}
 await Promise.all(['error:','models:','test:'].map(prefix=>store.del(prefix+u)));
 return {authorized:true};
}
export async function agConnection(store,u,config,net=providerFetch){
 const key=agUser(u);let c=await store.get('connection:'+key);if(!c)throw new AuthError('authorization_required');
 try{c=await fresh(store,key,c,config,net);}catch(e){if(e.code==='authorization_required')await store.put('error:'+key,{code:'authorization_required'},epoch()+3600);throw e;}
 return c;
}
export async function agDiscover(store,u,config,{net=providerFetch}={}){
 const key=agUser(u);let c=await agConnection(store,u,config,net);
 if(!c.projectId){const load=await agPost('loadCodeAssist',c.accessToken,{metadata:{ideType:'ANTIGRAVITY'}},net);const p=load.cloudaicompanionProject;c={...c,projectId:typeof p==='string'?p:p?.id??null};
  if(!c.projectId)throw new AuthError('antigravity_project_unavailable');
  if(!await store.saveConnection(key,c.generation,c))throw new AuthError('connection_cancelled');
 }
 const data=await agPost('fetchAvailableModels',c.accessToken,{project:c.projectId},net);
 if(!data.models||typeof data.models!=='object'||Array.isArray(data.models))throw new AuthError('invalid_models_response');
 const visible=(data.agentModelSorts??[]).flatMap(s=>(s.groups??[]).flatMap(g=>g.modelIds??[]));
 const allowed=new Set([...visible,...Object.values(data.tieredModelIds??{}).flat()]);
 const models=Object.entries(data.models).filter(([id,m])=>m&&typeof m==='object'&&/^(gemini-|claude-|gpt-oss-)/.test(id)&&!m.disabled&&!/image|imagen|-(disabled|tiered)$/.test(id)&&(!allowed.size||allowed.has(id))).map(([id,m])=>({id,displayName:typeof m.displayName==='string'?m.displayName:id,maxTokens:Number.isFinite(m.maxTokens)?m.maxTokens:null,maxOutputTokens:Number.isFinite(m.maxOutputTokens)?m.maxOutputTokens:null,supportsImages:typeof m.supportsImages==='boolean'?m.supportsImages:null,supportsThinking:typeof m.supportsThinking==='boolean'?m.supportsThinking:null,remainingFraction:typeof m.quotaInfo?.remainingFraction==='number'&&Number.isFinite(m.quotaInfo.remainingFraction)?Math.max(0,Math.min(1,m.quotaInfo.remainingFraction)):null,resetTime:typeof m.quotaInfo?.resetTime==='string'?m.quotaInfo.resetTime:null}));
 const result={models,checkedAt:new Date().toISOString()};
 await store.put('models:'+key,result,epoch()+300);await store.del('error:'+key);return result;
}
export async function agGenerate(store,u,config,args,{net=providerFetch,test=false}={}){
 const {model,prompt}=args;const max=args.max_output_tokens??256;
 if(typeof model!=='string'||model.length>200||typeof prompt!=='string'||!prompt.trim()||prompt.length>20000||!Number.isInteger(max)||max<1||max>4096)throw new AuthError('invalid_generation_arguments');
 const catalog=await agDiscover(store,u,config,{net});if(!catalog.models.some(m=>m.id===model))throw new AuthError('model_not_available');
 const c=await agConnection(store,u,config,net);
 try{
  const data=await agPost('generateContent',c.accessToken,{project:c.projectId,model,requestType:'agent',userAgent:'antigravity',requestId:'agent-'+crypto.randomUUID(),request:{contents:[{role:'user',parts:[{text:prompt}]}],generationConfig:{maxOutputTokens:max},sessionId:crypto.randomUUID()}},net);
  const payload=data.response??data;
  const text=(payload.candidates??[]).flatMap(c=>(c.content?.parts??[]).filter(p=>typeof p.text==='string'&&!p.thought).map(p=>p.text)).join('\n');
  if(!text)throw new AuthError('no_text_response');
  if(text.length>150000)throw new AuthError('response_too_large');
  const checkedAt=new Date().toISOString();
  if(test)await store.put('test:'+agUser(u),{status:'Passed',passed:true,model,checkedAt});
  return {model,text,usage:payload.usageMetadata?{promptTokenCount:payload.usageMetadata.promptTokenCount??null,candidatesTokenCount:payload.usageMetadata.candidatesTokenCount??null,totalTokenCount:payload.usageMetadata.totalTokenCount??null}:null,checkedAt};
 }catch(e){if(test)await store.put('test:'+agUser(u),{status:'Failed',passed:false,model,error:e.code||'provider_request_failed',checkedAt:new Date().toISOString()});throw e;}
}
export async function agStatus(store,u,config,{net=providerFetch,check=false}={}){
 const key=agUser(u);let error=null;
 if(check&&store&&config){const c=await store.get('connection:'+key);if(c){try{await agDiscover(store,u,config,{net});}catch(e){error=e.code||'provider_request_failed';if(error==='provider_access_revoked'){await store.invalidate(key);error='authorization_required';}await store.put('error:'+key,{code:error},epoch()+3600);}}}
 const c=store?await store.get('connection:'+key):null,models=c&&store?await store.get('models:'+key):null,lastError=store?await store.get('error:'+key):null,test=store?await store.get('test:'+key):null;
 error=error??lastError?.code??null;
 return {provider:'Antigravity',integration:'Unofficial adapter based on OpenCode; not Gemini Apps',accountStatus:!config||!store?'Unavailable':!c?(error==='authorization_required'?'Authorization required':'Not connected'):error||!models?.models.length?'Limited':'Connected',connectedAccount:c?.account??null,authenticationMethod:c?'Google OAuth 2.0 Authorization Code + PKCE S256 (Antigravity)':null,providerAuthorizationCompleted:!!c,availableCapabilities:c?['Antigravity model discovery','Reported quota inspection','Token refresh','Disconnect and revoke',...(models?.models.length?['Text model requests']:[])]:[],modelCount:models?.models.length??null,modelsCheckedAt:models?.checkedAt??null,usageLimits:{available:!!models,value:models?.models.map(m=>({model:m.id,remainingFraction:m.remainingFraction,resetTime:m.resetTime}))??null},modelTest:test??{status:'Not run',passed:null},lastError:error,authorizationUrl:config?.origin&&store?config.origin+'/antigravity':null,redirectUri:AG_CALLBACK,callbackMode:'Manual loopback callback completion in protected form; never paste codes in chat',paidApiEnabled:false,geminiAppsAvailable:false,source:AG_SOURCE};
}
async function agTool(name,args,store,u,config){
 if(!store||!config)return {value:{...await agStatus(store,u,config),blocker:'Antigravity OAuth runtime configuration/storage is unavailable'},isError:['connect','list_models','usage_limits','test_request','generate_text'].includes(name)};
 try{
  if(name==='connect')return {value:{...await agStatus(store,u,config),accountStatus:'Authorization required',userAction:'Open authorizationUrl, complete Google consent, and submit the localhost return address only in the protected completion form.'},isError:false};
  if(name==='disconnect'){const key=agUser(u);const value=await disconnect(store,key);await store.del('models:'+key);await store.del('test:'+key);await store.del('error:'+key);return {value,isError:false};}
  if(name==='list_models'||name==='usage_limits')return {value:await agDiscover(store,u,config),isError:false};
  if(name==='generate_text')return {value:await agGenerate(store,u,config,args),isError:false};
  if(name==='test_request'){
   const catalog=await agDiscover(store,u,config);const m=catalog.models.find(m=>m.id.startsWith('gemini-')&&m.id.includes('flash'))??catalog.models.find(m=>m.id.startsWith('gemini-'))??catalog.models[0];
   if(!m)throw new AuthError('no_available_models');
   return {value:await agGenerate(store,u,config,{model:m.id,prompt:'Reply with OK.',max_output_tokens:64},{test:true}),isError:false};
  }
  if(name==='redo_with_pro')return {value:{accountStatus:'Unavailable',blocker:'Redo with Pro belongs to Gemini Apps. Antigravity does not expose that browser workflow.'},isError:true};
  return {value:await agStatus(store,u,config,{check:name==='account_status'}),isError:false};
 }catch(e){let code=e instanceof AuthError?e.code:'provider_operation_failed';if(code==='provider_access_revoked'){await store.invalidate(agUser(u));code='authorization_required';}await store.put('error:'+agUser(u),{code},epoch()+3600);return {value:{...await agStatus(store,u,config),error:code},isError:true};}
}
async function agRoute(request,url,env,store,u){
 const config=agConfig(env,url.origin);
 if(url.pathname==='/antigravity')return page('Antigravity Connect',`<p>Вход через Google для Antigravity. Это неофициальная интеграция, как в OpenCode. API Key не нужен.</p><p><a href="/antigravity/start" target="_blank" rel="noopener noreferrer">1. Connect Antigravity</a></p><p>После подтверждения Google браузер перейдёт на <code>localhost:51121/oauth-callback</code>. Если страница не открылась — это ожидаемо для облачного плагина. Скопируй полный адрес из адресной строки и вставь ниже. Код не отправляй в чат.</p><textarea id="callback" rows="5" autocomplete="off" spellcheck="false" placeholder="Полный адрес возврата localhost"></textarea><button id="finish">2. Завершить вход</button><button id="check">Account Status</button><button id="disconnect">Disconnect Antigravity</button><pre id="result">${config&&store?'Not connected — статус можно проверить кнопкой Account Status.':'Unavailable — конфигурация сервера ещё не готова.'}</pre><script>const out=document.getElementById('result');document.getElementById('finish').onclick=async()=>{const field=document.getElementById('callback');try{const r=await fetch('/antigravity/finish',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({callbackUrl:field.value})});field.value='';out.textContent=JSON.stringify(await r.json(),null,2)}catch{field.value='';out.textContent='Ошибка соединения'}};document.getElementById('check').onclick=async()=>{out.textContent=JSON.stringify(await(await fetch('/antigravity/status')).json(),null,2)};document.getElementById('disconnect').onclick=async()=>{out.textContent=JSON.stringify(await(await fetch('/antigravity/disconnect',{method:'POST',headers:{'content-type':'application/json'},body:'{}'})).json(),null,2)};</script>`);
 if(url.pathname==='/antigravity/start'){
  if(request.method!=='GET')return json({error:'GET required'},405);
  if(!store||!config)return json({accountStatus:'Unavailable'},503);
  const started=await agBegin(store,u,config);return new Response(null,{status:303,headers:{location:started.url,'cache-control':'no-store','referrer-policy':'no-referrer','set-cookie':'__Host-antigravity='+await hash(started.state)+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600'}});
 }
 if(url.pathname==='/antigravity/status')return json(await agStatus(store,u,config,{check:true}));
 if(url.pathname==='/antigravity/finish'||url.pathname==='/antigravity/disconnect'){
  if(request.method!=='POST'||request.headers.get('origin')!==url.origin||!request.headers.get('content-type')?.startsWith('application/json'))return json({error:'Same-origin JSON POST required'},403);
  if(!store||!config)return json({accountStatus:'Unavailable'},503);
  if(url.pathname.endsWith('/disconnect'))return json((await agTool('disconnect',{},store,u,config)).value);
  const body=await request.text();if(body.length>20000)return json({error:'Input too large'},413);
  try{let data;try{data=JSON.parse(body);}catch{throw new AuthError('invalid_request_json');}await agComplete(store,u,config,data?.callbackUrl,cookie(request,'__Host-antigravity'));return json(await agStatus(store,u,config));}
  catch(e){const code=e instanceof AuthError?e.code:'authorization_failed';await store.put('error:'+agUser(u),{code},epoch()+3600);return json({accountStatus:'Error',error:code},code.endsWith('_storage_failed')?503:400);}
 }
 return null;
}
