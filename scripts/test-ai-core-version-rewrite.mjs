#!/usr/bin/env node
import { rewriteAiCoreVersionFile } from './ai-core-version-rewrite.mjs';
const cfg={oldVersion:'1.0.0',newVersion:'1.1.0',oldBuildId:'core-old',newBuildId:'core-new',oldContract:'1',newContract:'2'};
const manifest={aiCore:{coreVersion:'1.0.0',buildId:'core-old',contractVersion:'1'},brandVersion:'1.0.0',nested:{brandVersion:'1.0.0'}};
const out=JSON.parse(rewriteAiCoreVersionFile('studio/app-manifest.template.json',JSON.stringify(manifest),cfg));
if(out.aiCore.coreVersion!=='1.1.0'||out.aiCore.buildId!=='core-new'||out.aiCore.contractVersion!=='2') throw new Error('AI Core keys were not updated');
if(out.brandVersion!=='1.0.0'||out.nested.brandVersion!=='1.0.0') throw new Error('Non-AI-Core version key was modified');
const build="const APP_ID='generator',CORE_VERSION='1.0.0',X='1.0.0';\n";
const buildOut=rewriteAiCoreVersionFile('scripts/build.mjs',build,cfg);
if(!buildOut.includes("CORE_VERSION='1.1.0'")||!buildOut.includes("X='1.0.0'")) throw new Error('Build rewrite changed unrelated version');
console.log(JSON.stringify({status:'PASS',checks:['targeted-json-keys-only','brandVersion-preserved','build-CORE_VERSION-only']},null,2));
