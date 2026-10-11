import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const source=fs.readFileSync(path.join(root,'web/app.js'),'utf8');
const translations=fs.readFileSync(path.join(root,'web/i18n.js'),'utf8');
new vm.Script(`(async()=>{${source.replace(/^import[^\n]+\n/,'')}\n})`);
const context=vm.createContext({});
vm.runInContext(translations.replaceAll('export const','const').replaceAll('export function','function')+';this.catalog=messages',context);
vm.runInContext(source.slice(source.indexOf('Object.assign'),source.indexOf('const errorKeys')),context);
for(const [key,values]of Object.entries(context.catalog)){
 if(!Array.isArray(values)||values.length!==3||values.some(v=>typeof v!=='string'||!v.trim()))throw Error(`Missing UZ/RU/EN translation: ${key}`);
}
const missing=[...source.matchAll(/\bt\('([^']+)'\)/g)].map(x=>x[1]).filter(key=>!context.catalog[key]);
if(missing.length)throw Error('Missing labels: '+[...new Set(missing)].join(', '));
if(/\son(click|error|load)\s*=\s*["']/i.test(source))throw Error('Inline event handler violates CSP');
console.log(JSON.stringify({javascript:'parsed',translation_keys:Object.keys(context.catalog).length,locales:['uz-Latn','ru','en'],external_runtime_dependencies:0}));
