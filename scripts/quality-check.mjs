import {readFileSync} from 'node:fs';

const html=readFileSync(new URL('../index.html',import.meta.url),'utf8');
const app=readFileSync(new URL('../app.js',import.meta.url),'utf8');
const notice=readFileSync(new URL('../NOTICE.md',import.meta.url),'utf8');
const license=readFileSync(new URL('../LICENSE.md',import.meta.url),'utf8');
const readme=readFileSync(new URL('../README.md',import.meta.url),'utf8');
const smoke=readFileSync(new URL('./browser-smoke.html',import.meta.url),'utf8');
const workflow=readFileSync(new URL('../.github/workflows/quality.yml',import.meta.url),'utf8');
const rightsManifest=readFileSync(new URL('../rights-allowlist.json',import.meta.url),'utf8');

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
const changeHandled=new Set(['sel-speed-change']);
for(const act of acts)ok(handled.includes(act)||changeHandled.has(act),`data-act has no handler: ${act}`);

const phoneActs=[...new Set([...app.matchAll(/data-phone-action="([^"]+)"/g)].map(m=>m[1]))];
for(const act of phoneActs)ok(handled.includes(act)||act==='sheet-close',`data-phone-action has no handler: ${act}`);
const ids=[...html.matchAll(/id="([^"]+)"/g)].map(m=>m[1]);
const idCounts=new Map();
for(const id of ids)idCounts.set(id,(idCounts.get(id)||0)+1);
for(const [id,count] of idCounts)ok(count===1,`duplicate id: ${id}`);
for(const id of ['phone-app','phone-content','phone-detail','phone-reader','phone-reader-body','phone-reader-progress','phone-sheet','phone-sheet-body','phone-sheet-scrim'])ok(new RegExp(`id=["']${id}["']`).test(html),`smartphone shell id missing: ${id}`);
ok(inlineScripts.length===0,'inline script remains and may be blocked by CSP');
ok(html.includes('touch-action:pan-y!important'),'smartphone reader body does not allow vertical touch scrolling');
ok(/<script\s+src="\.\/app\.js\?v=[^"]+"><\/script>/.test(html),'app.js cache-bust script tag is missing');
ok(app.includes("reader.classList.add('phone-open')"),'smartphone reader open class lifecycle missing');
ok(html.includes('.phone-reader.phone-open{display:flex!important}'),'smartphone reader display rule missing');
ok(app.includes('__aozoraPhoneOpenSheet=openPhoneSheet'),'global sheet bridge missing');
ok(app.includes('__aozoraPhoneOpenReader=openReader'),'global reader bridge missing');
ok(app.includes('__aozoraPhoneOpenDetail=openDetail'),'global detail bridge missing');
ok(app.includes('__aozoraPhoneShowScreen=showScreen'),'global navigation bridge missing');
ok(app.includes("if(document.documentElement.dataset.device==='smartphone')return;"),'desktop popstate handler can interfere with smartphone history');
ok(app.includes("state.sheetOpen&&layer!=='phone-sheet'"),'smartphone sheet back handling missing');
ok(app.includes("state.reader&&layer!=='phone-reader'"),'smartphone reader back handling missing');
ok(app.includes("openReader(w,fromDetail=false)"),'smartphone reader origin default is unstable');
ok(app.includes("cur==='auto'?'sepia':cur==='sepia'?'dark':'auto'"),'smartphone theme cycle contains invalid theme value');
ok(app.includes("const isAnyReaderOpen=()=>"),'PC/smartphone shared reader tracking missing');
ok(app.includes("state.work=w;curWork=w"),'smartphone AI context is not synchronized');
ok(!/activeBook=w;\s*activeBook=w/.test(app),'duplicate activeBook assignment remains');
for(const fn of ['animateReaderPage','execInBookSearch','jumpToInBookMatch']){
  const count=(app.match(new RegExp(`(?:^|\\n)function ${fn}\\(`, 'g'))||[]).length;
  ok(count===1,`duplicate global reader function: ${fn}`);
}

ok(!/\beval\s*\(/.test(app),'eval() detected');
ok(!/\bnew\s+Function\s*\(/.test(app),'dynamic Function constructor detected');
ok(!/touch-fallback\.js/.test(html+app),'obsolete touch fallback is still referenced');
ok(app.includes('blocked-cross-origin-redirect'),'cross-origin redirect validation missing');
ok(app.includes('isConfiguredOllama'),'configured Ollama method guard missing');
ok(!/https:\'&&isSafeOllamaUrl\(u\.href\)/.test(app),'generic HTTPS is still treated as Ollama');
ok(html.includes(".rich-motion .view.active{animation:none!important}"),'stable view animation override missing');
ok(app.includes("classList.remove('view-slide-forward','view-slide-backward')"),'view transition cleanup missing');
ok(app.includes("navigator.wakeLock"),'screen wake-lock feature missing');
ok(app.includes("classList.add('loading-bar-live')"),'loading feedback missing');
ok(app.includes("hydrateSavedKeys"),'cached-book hydration missing');
ok(app.includes("dateKeyOf"),'local date helper missing');
ok(app.includes('out.goalMin=Number.isFinite(Number(d.goalMin))'),'daily reading goal is not persisted safely');
ok(app.includes('const isAnyReaderOpen=()=>'),'shared PC/smartphone reader activity detection missing');
ok(app.includes("const url=baseUrl+'#work='+encodeURIComponent(String(w.id))"),'smartphone share deep link missing');
ok(app.includes("rawHash.match(/^#work=(.+)$/)"),'smartphone shared-work deep link reader missing');
ok(app.includes('BROWSER_SMOKE'),'browser smoke isolation mode is missing');
ok(app.includes('const catalogDeadline=Date.now()+45000'),'catalog fetch has no total wait deadline');
ok(app.includes('const bodyDeadline=Date.now()+30000'),'book fetch has no total wait deadline');
ok(smoke.includes('function readerScrollable'),'browser smoke does not verify actual reader scrollability');
ok(smoke.includes("readerRendered(d,'#phone-reader-body')"),'smartphone smoke does not verify visible reader geometry');
ok(smoke.includes("readerRendered(d,'#body')"),'desktop smoke does not verify visible reader geometry');
ok(workflow.includes('timeout 120s'),'browser process timeout is missing');
ok(!workflow.includes('--virtual-time-budget='),'browser smoke still relies on virtual-time-budget');
ok(app.includes("currentView==='v-search'"),'desktop search does not recover after catalog initialization');
ok(app.includes('retryPhoneCatalog'),'smartphone catalog boot retry is missing');
ok(notice.includes('CC BY 4.0'),'NOTICE.md is missing CC BY 4.0 attribution');
ok(notice.includes('aozora.gr.jp'),'NOTICE.md is missing Aozora source');
ok(notice.includes('公式アプリケーションではありません'),'NOTICE.md is missing unofficial-app disclaimer');
ok(license.includes('MIT License'),'LICENSE.md is missing MIT License');
ok(license.includes('catalog.json'),'LICENSE.md does not separate catalog.json licensing');
ok(readme.includes('CC BY 4.0'),'README.md is missing CC BY 4.0 information');
ok(html.includes('青空文庫リーダー（非公式）'),'index.html title is missing unofficial designation');
ok(app.includes('rightsAllowlist.has(rawId.padStart(6,\'0\'))'),'catalog sanitizer does not enforce persisted rights allowlist');
ok(app.includes('rightsReady&&rightsAllowlist.has')||app.includes('rightsReady && rightsAllowlist.has'),'reader public-work guard does not require copyright allowlist verification');
ok(app.includes("if(!background&&cBar)cBar.style.width='70%'"),'background catalog parsing safety guard is missing');
ok(app.includes("await idb.set('k',CATALOG_CACHE_KEY,allWorks)"),'catalog import is not persisted to canonical cache key');
ok(app.includes("c=await idb.get('k','cat')"),'legacy cat cache migration is missing');
ok(app.includes('scheduleCatalogRefresh'),'scheduled catalog refresh is missing');
let rightsIds=[];try{rightsIds=JSON.parse(rightsManifest)}catch{}
ok(Array.isArray(rightsIds)&&rightsIds.length>1000&&rightsIds.length<30000,'rights allowlist size is invalid');
ok(Array.isArray(rightsIds)&&rightsIds.every(id=>/^\d{6}$/.test(String(id))),'rights allowlist contains invalid IDs');
ok(!Array.isArray(rightsIds)||!rightsIds.includes('061517'),'known excluded work is present in rights allowlist');
ok(app.includes("const CATALOG_CACHE_KEY='cat-rights-v5'"),'persistent catalog cache key is missing');
ok(app.includes('refreshCatalogInBackground'),'background catalog refresh helper is missing');
ok(app.includes('scheduleCatalogRefresh'),'scheduled catalog refresh is missing');
ok(app.includes("await idb.set('k',CATALOG_CACHE_KEY,allWorks)"),'catalog import does not persist to the canonical cache key');
ok(app.includes("c=await idb.get('k','cat')"),'legacy manual catalog cache migration is missing');
ok(app.includes("if(!background&&cBar)cBar.style.width='70%'"),'background catalog parsing still touches missing progress UI');

ok(app.includes('scheduleCatalogRefresh'),'scheduled catalog refresh is missing');
ok(!html.includes('data-act="chip-toggle" data-k="c"'),'copyright filter chip is still exposed');
ok(!html.includes('>著作権切れ</button>'),'copyright filter label is still exposed');
ok(!app.includes('searchState.filter.c'),'copyright search filter logic remains');
ok(!app.includes('searchState.filter.k'),'writing-system search filter logic remains');
ok(app.includes("const RIGHTS_CACHE_KEY='rights-allowlist-v1'"),'persistent rights cache key is missing');
ok(app.includes('requestPersistentStorage'),'persistent storage request is missing');
ok(app.includes('loadCachedCatalog'),'persistent catalog restore helper is missing');
ok(app.includes('LEGACY_CATALOG_CACHE_KEY'),'legacy verified catalog migration is missing');
ok(app.includes("const authorRightsFlag = cols[26]"),'CSV import does not inspect person copyright flag');

ok(app.includes('m.delete(id); blocked.add(id); continue;'),'CSV import does not permanently exclude a work after any protected author row');
ok(app.includes("if(!w||!isPublicWork(w))throw new Error('protected-work')"),'fetchBody public-work guard missing');
ok(app.includes("if(!w||!isPublicWork(w))return 'この作品はアプリの公開対象外です。';"),'fetchHead public-work guard missing');
ok(app.includes('青空文庫 作品情報'),'Aozora source metadata rendering is missing');
ok(!/const b=t\.search\(\/\\n底本：\//.test(app),'Aozora source metadata is still being discarded');
ok(app.includes("if(!curWork||!isPublicWork(curWork))"),'AI public-work guard missing');
ok(app.includes('phone-license'),'smartphone UI is missing its copyright/license section');
ok(app.includes('クリエイティブ・コモンズ 表示 4.0 国際（CC BY 4.0）'),'smartphone license section is missing CC BY 4.0 attribution');
ok(app.includes('青空文庫の公式アプリケーションではありません'),'smartphone unofficial-app disclaimer missing');
ok(app.includes("sheet.removeAttribute('inert')"),'phone sheet does not clear inert state when reopening');
ok(app.includes("scrim.removeAttribute('inert')"),'phone scrim does not clear inert state when reopening');
ok(app.includes('専用に即時処理し、Android WebView等でclick合成が遅れても確実に閉じる'),'phone sheet close fallback is missing');

if(fail.length){
  console.error('QUALITY CHECK FAILED');
  for(const f of fail)console.error(' - '+f);
  process.exit(1);
}
console.log('QUALITY CHECK PASSED');
console.log(`actions=${acts.length} handled=${handled.length} appBytes=${Buffer.byteLength(app)} htmlBytes=${Buffer.byteLength(html)}`);
