#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const [outArg='security/sbom/generator-testu.cdx.json', mode=''] = process.argv.slice(2);
const root = process.cwd();
const lock = JSON.parse(fs.readFileSync(path.join(root,'package-lock.json'),'utf8'));
const pkg = JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));

const norm = s => String(s || '').replace(/\\/g,'/');
const encName = name => name.startsWith('@') ? name.split('/').map(encodeURIComponent).join('/') : encodeURIComponent(name);
const purl = (name,version) => `pkg:npm/${encName(name)}@${encodeURIComponent(version)}`;
function inferName(lockPath, row){
  if(row?.name) return row.name;
  const p=norm(lockPath);
  const marker='node_modules/';
  const i=p.lastIndexOf(marker);
  const tail=i>=0?p.slice(i+marker.length):p;
  const seg=tail.split('/').filter(Boolean);
  return seg[0]?.startsWith('@') ? seg.slice(0,2).join('/') : seg[0];
}
function integrityHashes(integrity){
  const out=[];
  for(const token of String(integrity||'').trim().split(/\s+/).filter(Boolean)){
    const m=token.match(/^(sha256|sha384|sha512)-([A-Za-z0-9+/=]+)$/i);
    if(!m) continue;
    let hexValue='';
    try { hexValue=Buffer.from(m[2],'base64').toString('hex'); } catch { continue; }
    if(hexValue) out.push({alg:m[1].toUpperCase().replace('SHA','SHA-'),content:hexValue});
  }
  return out;
}
function componentRef(name,version,lockPath){
  return `${purl(name,version)}?path=${encodeURIComponent(norm(lockPath))}`;
}
const entries=[];
for(const [lockPath,row] of Object.entries(lock.packages||{})){
  if(!lockPath || !row?.version || !lockPath.includes('node_modules/')) continue;
  const name=inferName(lockPath,row);
  if(!name) continue;
  const ref=componentRef(name,row.version,lockPath);
  const c={type:'library',name,version:String(row.version),purl:purl(name,row.version),'bom-ref':ref,properties:[{name:'ghrab:lockfilePath',value:norm(lockPath)}]};
  const hashes=integrityHashes(row.integrity);
  if(hashes.length) c.hashes=hashes;
  if(row.license) c.licenses=[{license:{id:String(row.license)}}];
  entries.push({lockPath:norm(lockPath),row,name,ref,component:c});
}
entries.sort((a,b)=>Buffer.compare(Buffer.from(a.lockPath),Buffer.from(b.lockPath)));
const byPath=new Map(entries.map(e=>[e.lockPath,e]));
function parentPackageRoot(lockPath){
  const marker='/node_modules/';
  const idx=lockPath.lastIndexOf(marker);
  if(idx>=0) return lockPath.slice(0,idx);
  if(lockPath.startsWith('node_modules/')) return '';
  return '';
}
function resolveDependency(fromPath,dep){
  let parent=parentPackageRoot(fromPath);
  while(true){
    const candidate=parent ? `${parent}/node_modules/${dep}` : `node_modules/${dep}`;
    if(byPath.has(candidate)) return byPath.get(candidate);
    if(!parent) break;
    parent=parentPackageRoot(parent);
  }
  return null;
}
const rootRef=`${purl(pkg.name,pkg.version)}?root=true`;
const rootDeps=[];
for(const dep of Object.keys({...pkg.dependencies,...pkg.devDependencies,...pkg.optionalDependencies})){
  const e=byPath.get(`node_modules/${dep}`);
  if(e) rootDeps.push(e.ref);
}
const dependencies=[{'ref':rootRef,dependsOn:[...new Set(rootDeps)].sort()}];
for(const e of entries){
  const deps=[];
  for(const dep of Object.keys({...e.row.dependencies,...e.row.optionalDependencies})){
    const r=resolveDependency(e.lockPath,dep); if(r) deps.push(r.ref);
  }
  dependencies.push({ref:e.ref,dependsOn:[...new Set(deps)].sort()});
}

function validateQuality(components){
  const errors=[];
  const purls=new Set();
  for(const c of components){
    if(!c.name || c.name==='node_modules') errors.push(`invalid-name:${c['bom-ref']||c.version}`);
    if(!c.purl || purls.has(c.purl)) errors.push(`duplicate-or-missing-purl:${c.purl||c['bom-ref']}`);
    if(c.purl) purls.add(c.purl);
    if(!Array.isArray(c.hashes)||!c.hashes.length) errors.push(`missing-lockfile-hash:${c.name}@${c.version}`);
  }
  if(errors.length){
    console.error(JSON.stringify({status:'FAIL',reason:'sbom-quality',errors:errors.slice(0,50),count:errors.length},null,2));
    process.exit(1);
  }
}

const components=entries.map(e=>e.component);
validateQuality(components);
const bom={
  '$schema':'https://cyclonedx.org/schema/bom-1.7.schema.json',
  bomFormat:'CycloneDX',
  specVersion:'1.7',
  version:1,
  metadata:{component:{type:'application',name:pkg.name,version:pkg.version,purl:purl(pkg.name,pkg.version),'bom-ref':rootRef}},
  components,
  dependencies
};
const text=JSON.stringify(bom,null,2)+'\n';
const out=path.resolve(root,outArg);
if(mode==='--check'){
  if(!fs.existsSync(out)){console.error(`❌ SBOM snapshot chybí: ${out}`);process.exit(1);}
  const current=fs.readFileSync(out,'utf8');
  if(current!==text){console.error('❌ CycloneDX SBOM neodpovídá package-lock.json/package.json. Spusť npm run garp25:sbom.');process.exit(1);}
  console.log(`✅ CycloneDX 1.7 SBOM odpovídá lockfile: ${entries.length} komponent.`);
}else{
  fs.mkdirSync(path.dirname(out),{recursive:true});
  fs.writeFileSync(out,text,'utf8');
  console.log(`✅ CycloneDX 1.7 SBOM vytvořen: ${out} (${entries.length} komponent).`);
}
