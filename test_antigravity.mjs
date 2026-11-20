import assert from 'node:assert/strict';
import worker,{hash,agBegin,agComplete,agStatus,agDiscover,agGenerate,disconnect} from './worker/index.js';
const config={clientId:'TEST_NATIVE_CLIENT',clientSecret:'TEST_NATIVE_SECRET'};
class Memory{
 constructor(){this.values=new Map();this.g=new Map();}
 async get(k){return this.values.get(k)??null;}
 async put(k,v){this.values.set(k,v);}
 async del(k){this.values.delete(k);}
 async consume(k){const v=this.values.get(k);this.values.delete(k);return v;}
 async generation(u){if(!this.g.has(u))this.g.set(u,0);return this.g.get(u);}
 async invalidate(u){this.g.set(u,(this.g.get(u)??0)+1);this.values.delete('connection:'+u);}
 async saveConnection(u,g,v){if(g!==(this.g.get(u)??0))return false;this.values.set('connection:'+u,v);return true;}
 async cleanup(){}
}
const s=new Memory();const started=await agBegin(s,'user',config);const auth=new URL(started.url);
assert.equal(auth.searchParams.get('redirect_uri'),'http://localhost:51121/oauth-callback');
assert.equal(auth.searchParams.get('code_challenge_method'),'S256');
assert.equal(auth.searchParams.get('client_id'),config.clientId);
assert.ok(auth.searchParams.get('scope').includes('/auth/cloud-platform'));
assert.ok(!auth.searchParams.get('state').includes('verifier'));
const cookie=await hash(started.state),callback='http://localhost:51121/oauth-callback?state='+started.state+'&code=TEST_CODE';
let modelRequests=0;
const net=async(url,opts)=>{
 assert.equal(opts.redirect,'manual');
 if(url.endsWith('/token')){assert.equal(typeof opts.body,'string');const body=new URLSearchParams(opts.body);if(body.get('grant_type')==='authorization_code'){assert.equal(await hash(body.get('code_verifier')),auth.searchParams.get('code_challenge'));assert.equal(body.get('redirect_uri'),'http://localhost:51121/oauth-callback');}return Response.json({access_token:'TEST_ACCESS',refresh_token:'TEST_REFRESH',expires_in:3600,token_type:'Bearer'});}
 if(url.endsWith('/userinfo'))return Response.json({sub:'TEST_SUB',email:'test@example.invalid'});
 if(url.endsWith(':loadCodeAssist'))return Response.json({cloudaicompanionProject:'TEST_PROJECT'});
 if(url.endsWith(':fetchAvailableModels'))return Response.json({models:{'gemini-test-flash':{displayName:'Test Flash',quotaInfo:{remainingFraction:0.5,resetTime:'2026-11-01T00:00:00Z'}},'claude-test':{displayName:'Test Claude'},'gemini-image':{},'secret-internal':{experimentPrompt:'DO_NOT_EXPOSE'}},agentModelSorts:[{groups:[{modelIds:['gemini-test-flash','claude-test']}]}]});
 if(url.endsWith(':generateContent')){modelRequests++;const body=JSON.parse(opts.body);assert.equal(body.project,'TEST_PROJECT');assert.equal(body.requestType,'agent');assert.equal(body.model,'gemini-test-flash');return Response.json({response:{candidates:[{content:{parts:[{text:'private thinking',thought:true},{text:'OK'}]}}],usageMetadata:{totalTokenCount:7}}});}
 if(url.endsWith('/revoke'))return Response.json({});throw Error('Unexpected endpoint');
};
await assert.rejects(()=>agComplete(s,'other',config,callback,cookie,net));
await assert.rejects(()=>agComplete(s,'user',config,callback,'wrong-cookie',net));
await assert.rejects(()=>agComplete(s,'user',config,callback.replace('localhost:51121','attacker.invalid'),cookie,net));
await agComplete(s,'user',config,callback,cookie,net);
await assert.rejects(()=>agComplete(s,'user',config,callback,cookie,net));
let st=await agStatus(s,'user',config);assert.equal(st.providerAuthorizationCompleted,true);assert.equal(st.modelTest.passed,null);assert.equal(st.modelCount,null);
assert.ok(!JSON.stringify(st).includes('TEST_ACCESS'));assert.ok(!JSON.stringify(st).includes('TEST_REFRESH'));
const catalog=await agDiscover(s,'user',config,{net});assert.equal(catalog.models.length,2);assert.equal(catalog.models[0].remainingFraction,0.5);assert.equal(catalog.models[1].remainingFraction,null);assert.ok(!JSON.stringify(catalog).includes('DO_NOT_EXPOSE'));
const generated=await agGenerate(s,'user',config,{model:'gemini-test-flash',prompt:'Test',max_output_tokens:64},{net,test:true});assert.equal(generated.text,'OK');assert.equal(modelRequests,1);assert.equal((await agStatus(s,'user',config)).modelTest.passed,true);
await assert.rejects(()=>agGenerate(s,'user',config,{model:'not-listed',prompt:'Test'},{net}));
assert.equal(modelRequests,1);
assert.equal((await agStatus(s,'other',config)).accountStatus,'Not connected');
await disconnect(s,'ag:user',net);st=await agStatus(s,'user',config);assert.equal(st.accountStatus,'Not connected');assert.equal(st.modelCount,null);assert.equal(st.usageLimits.available,false);
const s2=new Memory();const a2=await agBegin(s2,'u',config);await s2.invalidate('ag:u');const c2='http://localhost:51121/oauth-callback?state='+a2.state+'&code=TEST';
const cookie2=await hash(a2.state);
await assert.rejects(()=>agComplete(s2,'u',config,c2,cookie2,net));
const base='https://gemini.example.invalid';
const env={SITE_ORIGIN:base};
let res=await worker.fetch(new Request(base+'/antigravity/finish',{method:'POST',headers:{'oai-authenticated-user-email':'test@example.invalid','origin':'https://attacker.invalid','content-type':'application/json'},body:'{}'}),env);assert.equal(res.status,403);
res=await worker.fetch(new Request(base+'/antigravity'),env);assert.equal(res.status,401);
res=await worker.fetch(new Request(base+'/antigravity',{headers:{'oai-authenticated-user-email':'test@example.invalid'}}),env);assert.equal(res.status,200);assert.ok((await res.text()).includes('localhost:51121'));
console.log('PASS: Antigravity PKCE/state/user/cookie binding, exact loopback URI, one-time callback, connection isolation, real catalog shaping, missing quota stays null, text generation and thinking exclusion, model allowlist, test status, disconnect generation, CSRF. Provider responses are mocks, no live authorization claimed.');
const s3=new Memory();await s3.generation('ag:u');await s3.put('connection:ag:u',{account:{sub:'TEST'},accessToken:'TEST_ACCESS',refreshToken:'TEST_REFRESH',expiresAt:Math.floor(Date.now()/1000)+3600,generation:0,projectId:'TEST_PROJECT'});
const revoked=await agStatus(s3,'u',config,{check:true,net:async()=>Response.json({error:'DO_NOT_EXPOSE'},{status:401})});assert.equal(revoked.accountStatus,'Authorization required');assert.equal(revoked.providerAuthorizationCompleted,false);assert.ok(!JSON.stringify(revoked).includes('DO_NOT_EXPOSE'));
console.log('PASS: provider 401 invalidates Antigravity authorization without leaking provider payloads.');

const failedAttempt=await agBegin(s,'user',config);
const failedCallback=new URL('http://localhost:51121/oauth-callback');
failedCallback.search=new URLSearchParams({state:failedAttempt.state,code:'TEST'});
const failedCookie=await hash(failedAttempt.state);
await assert.rejects(
 ()=>agComplete(s,'user',config,failedCallback.href,failedCookie,async()=>{throw new Error('Private network details');}),
 {message:'google_token_exchange_failed'}
);

const redirectAttempt=await agBegin(s,'user',config);
const redirectCallback=new URL(failedCallback);
redirectCallback.searchParams.set('state',redirectAttempt.state);
const redirectCookie=await hash(redirectAttempt.state);
let redirectRequests=0;
await assert.rejects(
 ()=>agComplete(s,'user',config,redirectCallback.href,redirectCookie,async(url,opts)=>{
  redirectRequests++;
  assert.equal(url,'https://oauth2.googleapis.com/token');
  assert.equal(opts.redirect,'manual');
  return Response.redirect('https://example.invalid');
 }),
 {message:'google_token_exchange_failed'}
);
assert.equal(redirectRequests,1);
