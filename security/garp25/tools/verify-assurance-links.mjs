#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const argv=process.argv.slice(2);
const opt=k=>{const i=argv.indexOf(`--${k}`);return i>=0?argv[i+1]:null;};
const profile=opt('profile')||'prep';
const manifestPath=opt('manifest');
if(!manifestPath){console.error(JSON.stringify({status:'FAIL',errors:['manifest-required']},null,2));process.exit(2);}
const manifest=JSON.parse(await readFile(manifestPath,'utf8'));
if(manifest.schema!=='ghrab-release-integrity-v2'){console.error(JSON.stringify({status:'FAIL',errors:['manifest-schema']},null,2));process.exit(2);}
const links=[
  ['buildProvenanceSha256','provenance'],
  ['sbomSha256','sbom'],
  ['evidenceManifestSha256','evidence-manifest'],
  ['deploymentPackageSha256','deployment-package']
];
const rows=[]; const errors=[];
for(const [field,arg] of links){
  const declared=manifest[field]; const file=opt(arg);
  if(!file){
    rows.push({field,arg,status:declared?'FAIL':'SKIPPED',reason:declared?'declared-without-input':'not-declared'});
    if(declared) errors.push(`${field}:declared-without-input`);
    continue;
  }
  let bytes;
  try{bytes=await readFile(file);}catch{errors.push(`${field}:unreadable:${file}`);rows.push({field,arg,status:'FAIL',file});continue;}
  const actual=createHash('sha256').update(bytes).digest('hex');
  const ok=/^[a-f0-9]{64}$/i.test(String(declared||''))&&actual===String(declared).toLowerCase();
  rows.push({field,arg,status:ok?'PASS':'FAIL',file:path.resolve(file),actual,declared:declared||null});
  if(!ok) errors.push(`${field}:hash-mismatch-or-missing`);
}
const requiredAll=profile==='school'||argv.includes('--require-all');
if(requiredAll){
  for(const row of rows) if(row.status==='SKIPPED') errors.push(`${row.field}:required-link-missing`);
}
const skipped=rows.filter(r=>r.status==='SKIPPED');
const status=errors.length?'FAIL':(skipped.length?'AMBER':'PASS');
console[status==='PASS'?'log':'error'](JSON.stringify({status,profile,links:rows,errors},null,2));
process.exit(status==='PASS'?0:1);
