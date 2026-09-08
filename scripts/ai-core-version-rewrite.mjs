export function rewriteAiCoreVersionFile(relative,text,{oldVersion,newVersion,oldBuildId,newBuildId,oldContract,newContract}){
  if(relative.endsWith('.json')){
    const value=JSON.parse(text);
    const allowed=new Set(['coreVersion','buildId','contractVersion']);
    function visit(node){
      if(Array.isArray(node)){for(const x of node) visit(x);return;}
      if(!node||typeof node!=='object') return;
      for(const [key,val] of Object.entries(node)){
        if(key==='coreVersion'&&String(val)===String(oldVersion)) node[key]=newVersion;
        else if(key==='buildId'&&String(val)===String(oldBuildId)) node[key]=newBuildId;
        else if(key==='contractVersion'&&String(val)===String(oldContract)) node[key]=String(newContract);
        else if(!allowed.has(key)) visit(val);
      }
    }
    visit(value);
    return JSON.stringify(value,null,2)+'\n';
  }
  if(relative==='scripts/build.mjs'){
    const esc=String(oldVersion).replace(/[.*+?^${}()|[\\]\\]/g,'\\$&');
    const rx=new RegExp(`(\\bCORE_VERSION\\s*=\\s*['"])${esc}(['"])`);
    if(!rx.test(text)) throw new Error(`Configured CORE_VERSION not found in ${relative}`);
    return text.replace(rx,`$1${newVersion}$2`);
  }
  throw new Error(`Unsupported version file format: ${relative}`);
}
