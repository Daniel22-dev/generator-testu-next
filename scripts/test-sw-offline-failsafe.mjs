#!/usr/bin/env node
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync('public/sw.js','utf8');
const base = 'https://school.example/apps/generator/';
const handlers = new Map();
let networkOnline = true;
let networkGeneration = 'v1';
const stores = new Map();

const absUrl = value => new URL(typeof value === 'string' ? value : value.url, base).href;
class MockCache {
  constructor(name){ this.name=name; if(!stores.has(name)) stores.set(name,new Map()); this.map=stores.get(name); }
  async addAll(items){
    for(const item of items){
      const req = new Request(absUrl(item));
      const res = await mockFetch(req);
      if(!res.ok) throw new Error('precache HTTP '+res.status);
      this.map.set(req.url, res.clone());
    }
  }
  async match(request,{ignoreSearch=false}={}){
    const url=absUrl(request);
    if(this.map.has(url)) return this.map.get(url).clone();
    if(ignoreSearch){
      const target=new URL(url); target.search='';
      for(const [k,v] of this.map){ const u=new URL(k); u.search=''; if(u.href===target.href) return v.clone(); }
    }
    return undefined;
  }
  async put(request,response){ this.map.set(absUrl(request), response.clone()); }
}
const caches = {
  async open(name){ return new MockCache(name); },
  async keys(){ return [...stores.keys()]; },
  async delete(name){ return stores.delete(name); },
  async match(request,opts){ for(const name of stores.keys()){ const hit=await new MockCache(name).match(request,opts); if(hit) return hit; } }
};
async function mockFetch(request, opts={}){
  if(!networkOnline) throw new Error('OFFLINE');
  const url=absUrl(request);
  return new Response(`NETWORK:${networkGeneration}:${new URL(url).pathname}`, {status:200, headers:{'content-type':'text/plain'}});
}
const selfObj = {
  location:{ href: base+'sw.js', origin:'https://school.example' },
  clients:{ async claim(){} },
  skipWaiting(){},
  addEventListener(type,fn){ handlers.set(type,fn); }
};
const context=vm.createContext({self:selfObj,caches,fetch:mockFetch,URL,Request,Response,console,Promise,Error,setTimeout,clearTimeout});
vm.runInContext(source,context,{filename:'public/sw.js'});

async function fireInstall(){
  const waits=[]; handlers.get('install')?.({waitUntil:p=>waits.push(Promise.resolve(p))}); await Promise.all(waits);
}
async function swFetch(path,{mode='cors',cache='default'}={}){
  let responsePromise=null;
  const req=new Request(base+path,{method:'GET',cache});
  // Request.mode is readonly; the SW only needs navigate vs non-navigate. Default cors is enough here.
  const event={request:req,respondWith:p=>{responsePromise=Promise.resolve(p);}};
  handlers.get('fetch')?.(event);
  if(!responsePromise) throw new Error('SW did not handle '+path);
  return responsePromise;
}
function ok(name,cond,detail=''){ if(!cond){ console.error(`FAIL ${name}${detail?': '+detail:''}`); process.exit(1); } console.log(`PASS ${name}`); }

await fireInstall();
const cacheName=[...stores.keys()].find(k=>k.startsWith('ghrab-generator-v'));
ok('install-created-cache',!!cacheName);
const installCache=stores.get(cacheName);
ok('cleanup-precached',[...installCache.keys()].some(k=>k.endsWith('/access/suite-session-cleanup.js')));
ok('platform-precached',[...installCache.keys()].some(k=>k.endsWith('/ghrab/ghrab-platform.js')));

// Online freshness: both support layers must use the network and refresh cache.
networkGeneration='v2'; networkOnline=true;
let r=await swFetch('access/suite-session-cleanup.js');
ok('cleanup-online-network-first',(await r.text()).includes('NETWORK:v2:'));
r=await swFetch('ghrab/ghrab-platform.js');
ok('platform-online-network-first',(await r.text()).includes('NETWORK:v2:'));

// Offline fail-safe: both must return the last-known cached v2 copy.
networkOnline=false;
r=await swFetch('access/suite-session-cleanup.js');
ok('cleanup-offline-cache-fallback',(await r.text()).includes('NETWORK:v2:'));
r=await swFetch('ghrab/ghrab-platform.js');
ok('platform-offline-cache-fallback',(await r.text()).includes('NETWORK:v2:'));

// Network-only controls must NOT use cache even if a poisoned/stale copy exists there.
installCache.set(base+'access/revoked-access.json',new Response('STALE-REVOCATION-CACHE',{status:200}));
let rejected=false;
try { await swFetch('access/revoked-access.json'); } catch { rejected=true; }
ok('revocation-remains-network-only-no-cache-fallback',rejected);
installCache.set(base+'security/release-integrity.json',new Response('STALE-INTEGRITY-CACHE',{status:200}));
rejected=false;
try { await swFetch('security/release-integrity.json'); } catch { rejected=true; }
ok('integrity-remains-network-only-no-cache-fallback',rejected);

console.log(JSON.stringify({status:'PASS',checks:9,cacheName,policy:'network-first support layers + network-only authorization/revocation/integrity'},null,2));
