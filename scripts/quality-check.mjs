import {readFileSync} from 'node:fs';

const html=readFileSync(new URL('../index.html',import.meta.url),'utf8');
const app=readFileSync(new URL('../app.js',import.meta.url),'utf8');

const fail=[];
const ok=(condition,message)=>{if(!condition)fail.push(message);};

try{new Function(app);ok(true,'');}catch(e){fail.push('app.js syntax error: '+e.message);}

const inlineScripts=[...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)]
  .filter(m=>!(m[0].match(/\bsrc\s*=/i)));
ok(inlineScripts.length===0,'inline executable script remains in index.html');

const appTag=/\<script\s+src="\.\/app\.js\?v=[^"]+"\><\/script\>/.test(html);
ok(appTag,'same-origin app.js script tag is missing');

const csp=(html.match(/Content-Security-Policy"\s+content="([^"]+)"/i)?.[1]||'');
ok(csp.includes("script-src 'self'"),'CSP does not include self script policy');
ok(!/script-src[^;]*'unsafe-inline'/.test(csp),'script-src still allows unsafe-inline');

const acts=[...new Set([...html.matchAll(/data-act="([^"]+)"/g)].map(m=>m[1]))];
const handled=[...new Set([...app.matchAll(/act==='([^']+)'/g)].map(m=>m[1]))];
for(const act of acts)ok(handled.includes(act),`data-act has no handler: ${act}`);

ok(!/\beval\s*\(/.test(app),'eval() detected');
ok(!/\bnew\s+Function\s*\(/.test(app),'dynamic Function constructor detected');
ok(!/touch-fallback\.js/.test(html+app),'obsolete touch fallback is still referenced');
ok(app.includes('blocked-cross-origin-redirect'),'cross-origin redirect validation missing');
ok(app.includes('isConfiguredOllama'),'configured Ollama method guard missing');
ok(!/https:\'&&isSafeOllamaUrl\(u\.href\)/.test(app),'generic HTTPS is still treated as Ollama');
ok(app.includes(".rich-motion .view.active{animation:none!important}"),'stable view animation override missing');
ok(app.includes("classList.remove('view-slide-forward','view-slide-backward')"),'view transition cleanup missing');
ok(app.includes("navigator.wakeLock"),'screen wake-lock feature missing');
ok(app.includes("classList.add('loading-bar-live')"),'loading feedback missing');
ok(app.includes("hydrateSavedKeys"),'cached-book hydration missing');
ok(app.includes("dateKeyOf"),'local date helper missing');

if(fail.length){
  console.error('QUALITY CHECK FAILED');
  for(const f of fail)console.error(' - '+f);
  process.exit(1);
}
console.log('QUALITY CHECK PASSED');
console.log(`actions=${acts.length} handled=${handled.length} appBytes=${Buffer.byteLength(app)} htmlBytes=${Buffer.byteLength(html)}`);
