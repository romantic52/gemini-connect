import assert from 'node:assert/strict';
import worker,{hash,seal,unseal,begin,complete,status,disconnect} from './worker/index.js';
const ORIGIN='https://gemini.example.invalid';
const env={SITE_ORIGIN:ORIGIN};
const config={redirectUri:ORIGIN+'/oauth/callback',clientId:'test.apps.googleusercontent.com',clientSecret:'TEST_ONLY_SECRET'};
class Memory{
 constructor(){this.values=new Map();this.g=0;}
 async get(k){return this.values.get(k)??null;}
 async put(k,v){this.values.set(k,v);}
 async del(k){this.values.delete(k);}
 async consume(k){const v=this.values.get(k);this.values.delete(k);return v;}
 async generation(){return this.g;}
 async invalidate(u){this.g++;this.values.delete('connection:'+u);}
 async saveConnection(u,g,v){if(g!==this.g)return false;this.values.set('connection:'+u,v);return true;}
 async cleanup(){}
}
const b64=b=>Buffer.from(b).toString('base64url');
const pair=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
const pub={...await crypto.subtle.exportKey('jwk',pair.publicKey),kid:'unit-key',alg:'RS256'};
async function jwt(claims){const body=b64(JSON.stringify({alg:'RS256',kid:'unit-key'}))+'.'+b64(JSON.stringify(claims));return body+'.'+b64(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,new TextEncoder().encode(body)));}
let calls=[];
async function flow(store,alter={}){
 const start=await begin(store,'u',config);const auth=new URL(start.url);
 assert.equal(auth.searchParams.get('code_challenge_method'),'S256');
 assert.equal(auth.searchParams.get('scope'),'openid email profile');
 const nonce=auth.searchParams.get('nonce');
 const claims={iss:'https://accounts.google.com',aud:config.clientId,sub:'google-test-sub',exp:Math.floor(Date.now()/1000)+3600,iat:Math.floor(Date.now()/1000),nonce,...alter};
 const idToken=await jwt(claims);
 const net=async(url,opts)=>{
  calls.push(url);
  if(url.endsWith('/token')){
   const data=new URLSearchParams(opts.body);assert.equal(await hash(data.get('code_verifier')),auth.searchParams.get('code_challenge'));
   return Response.json({access_token:'TEST_ONLY_ACCESS',refresh_token:'TEST_ONLY_REFRESH',token_type:'Bearer',expires_in:3600,id_token:idToken});
  }
  if(url.endsWith('/certs'))return Response.json({keys:[pub]});
  if(url.endsWith('/userinfo'))return Response.json({sub:'google-test-sub',email:'test@example.invalid',email_verified:true});
  if(url.endsWith('/revoke'))return Response.json({});
  throw new Error('Unexpected URL');
 };
 const callback=new URL(ORIGIN+'/oauth/callback?state='+start.state+'&code=TEST_ONLY_CODE');
 return {callback,net,state:start.state};
}
const key=b64(crypto.getRandomValues(new Uint8Array(32)));
const sealed=await seal({token:'TEST_ONLY_ACCESS'},key,'user-a');
assert.ok(!sealed.includes('TEST_ONLY_ACCESS'));
assert.deepEqual(await unseal(sealed,key,'user-a'),{token:'TEST_ONLY_ACCESS'});
await assert.rejects(()=>unseal(sealed,key,'user-b'));
await assert.rejects(()=>unseal(sealed,key,'user-a-changed'));
let s=new Memory(),f=await flow(s);
await assert.rejects(()=>complete(s,'u',config,f.callback,'wrong-cookie',f.net));
assert.equal(calls.length,0);
const cookie=await hash(f.state);
await assert.rejects(()=>complete(s,'wrong-user',config,f.callback,cookie,f.net));
const connected=await complete(s,'u',config,f.callback,cookie,f.net);
assert.equal(connected.account.sub,'google-test-sub');
await assert.rejects(()=>complete(s,'u',config,f.callback,cookie,f.net));
const st=await status(s,'u',config);
assert.equal(st.accountStatus,'Limited');
assert.equal(st.geminiAccess.available,false);
assert.ok(!JSON.stringify(st).includes('TEST_ONLY_ACCESS'));
const gone=await disconnect(s,'u',f.net);
assert.equal(gone.providerRevocation.performed,true);
assert.equal((await status(s,'u',config)).accountStatus,'Not connected');
for(const altered of [{aud:'attacker-client'},{nonce:'wrong-nonce'},{exp:1},{iss:'https://attacker.invalid'}]){
 s=new Memory();f=await flow(s,altered);const c=await hash(f.state);
 await assert.rejects(()=>complete(s,'u',config,f.callback,c,f.net));
 assert.equal(await s.get('connection:u'),null);
}
s=new Memory();f=await flow(s);const cancelledCookie=await hash(f.state);await s.invalidate('u');
await assert.rejects(()=>complete(s,'u',config,f.callback,cancelledCookie,f.net));
assert.equal(await s.get('connection:u'),null);
s=new Memory();f=await flow(s);const deniedCookie=await hash(f.state);f.callback.searchParams.set('error','access_denied');
await assert.rejects(()=>complete(s,'u',config,f.callback,deniedCookie,f.net));
assert.equal(await s.get('connection:u'),null);
const request=(path,method='GET',body,extra={})=>new Request(ORIGIN+path,{method,headers:{'oai-authenticated-user-email':'test@example.invalid',...extra},...(body?{body}: {})});
assert.equal((await worker.fetch(request('/settings'))).status,503);
assert.equal((await worker.fetch(request('/settings'),{SITE_ORIGIN:'https://other.example.invalid'})).status,400);
assert.equal((await worker.fetch(new Request(ORIGIN+'/mcp',{method:'POST',body:'{}'}),env)).status,401);
assert.equal((await worker.fetch(request('/settings','POST','{}',{'content-type':'application/json','origin':'https://attacker.invalid'}),env)).status,403);
assert.equal((await worker.fetch(request('/oauth/callback'),env)).status,503);
const page=await worker.fetch(request('/settings'),env);assert.equal(page.status,200);assert.ok((await page.text()).includes(ORIGIN+'/oauth/callback'));
const rpc=async(method,params)=>{const r=await worker.fetch(request('/mcp','POST',JSON.stringify({jsonrpc:'2.0',id:1,method,params})),env);return r.json();};
assert.deepEqual((await rpc('server/discover')).result.supportedVersions,['2026-07-28']);
assert.equal((await rpc('tools/list')).result.tools.length,11);
assert.equal((await rpc('tools/call',{name:'connect',arguments:{}})).result.isError,true);
assert.equal((await rpc('tools/call',{name:'account_status',arguments:{}})).result.isError,false);
assert.equal((await rpc('tools/call',{name:'test_request',arguments:{}})).result.isError,true);
assert.equal((await rpc('tools/call',{name:'disconnect',arguments:{}})).result.isError,false);
console.log('PASS: encrypted storage/AAD isolation; mocked signed Google OIDC callback; state cookie/user binding and replay; issuer/audience/nonce/expiry rejection; disconnect cancellation; provider denial; revoke; Limited identity vs Gemini; secret-free status; CSRF; MCP. No live Google account was authorized.');
s=new Memory();await s.put('connection:u',{account:{sub:'google-test-sub'},accessToken:'EXPIRED_TEST',refreshToken:'TEST_REFRESH',expiresAt:1,generation:0});
let refreshed=false;
const refreshNet=async(url,opts)=>{
 if(url.endsWith('/token')){assert.equal(new URLSearchParams(opts.body).get('grant_type'),'refresh_token');refreshed=true;return Response.json({access_token:'REFRESHED_TEST',expires_in:3600});}
 if(url.endsWith('/userinfo')){assert.equal(opts.headers.authorization,'Bearer REFRESHED_TEST');return Response.json({sub:'google-test-sub'});}
 throw new Error('Unexpected URL');
};
assert.equal((await status(s,'u',config,{check:true,net:refreshNet})).accountStatus,'Limited');assert.equal(refreshed,true);
await s.put('connection:u',{account:{sub:'google-test-sub'},accessToken:'EXPIRED_TEST',refreshToken:'INVALID_TEST',expiresAt:1,generation:0});
const rejected=await status(s,'u',config,{check:true,net:async()=>Response.json({error:'invalid_grant'},{status:400})});
assert.equal(rejected.accountStatus,'Authorization required');assert.equal(await s.get('connection:u'),null);
console.log('PASS: expired access token refresh and invalid_grant clears connection.');
