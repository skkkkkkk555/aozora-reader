import {readFileSync} from 'node:fs';

const html=readFileSync(new URL('../index.html',import.meta.url),'utf8');
const latestEntry=readFileSync(new URL('../reader-latest.html',import.meta.url),'utf8');
const v24Entry=readFileSync(new URL('../reader-v24.html',import.meta.url),'utf8');
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
ok(latestEntry.includes('./redirect.js?v=20261005-26')&&!latestEntry.includes('phone-app'),'reader-latest.html must be a thin single-entry redirect');
ok(v24Entry.includes('./redirect.js?v=20261005-26')&&!v24Entry.includes('phone-app'),'reader-v24.html must be a thin single-entry redirect');
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
ok(/\/Android\|iPhone\|iPad\|iPod/.test(app),'handheld detection does not include Android tablets/iPad');
ok(app.includes("const handheld=document.documentElement.dataset.device==='smartphone'"),'handheld fetch path missing');
ok(app.includes("headers:{'Accept':'text/plain,*/*'}"),'handheld plain GET fallback missing');
ok(app.includes('readerVertical:false'),'smartphone vertical reader state missing');
ok(app.includes('data-phone-action="reader-vertical"'),'smartphone vertical reader menu action missing');
ok(app.includes('function applyPhoneReaderDirection'),'smartphone reader direction helper missing');
ok(app.includes('function togglePhoneReaderDirection'),'smartphone reader direction toggle missing');
ok(app.includes('if(state.readerVertical)'),'smartphone vertical progress axis handling missing');
ok(app.includes("showScreen(state.screen||'home','back');"),'smartphone back navigation does not return to the previous main screen');
ok(app.includes("phoneLayer:'phone-main'"),'smartphone main screen history is missing');
ok(app.includes("history.state?.phoneScreen"),'smartphone history does not store/restore tabs');
ok(app.includes("showScreen(next,'back',true)"),'smartphone popstate does not restore previous tab');
ok(app.includes("globalBack.style.setProperty('display',showBack?'flex':'none','important')"),'smartphone global back control is not independently synchronized');
ok(html.includes('aozora-final-device-ui-hardening'),'final cross-device UI hardening block is missing');
ok(html.includes('phone-reader-body.phone-reader-vertical'),'smartphone vertical reader CSS is missing');
ok(html.includes('reader-flow.reader-vertical-flow'),'vertical reader flow wrapper CSS is missing');
ok(app.includes("flow.className='reader-flow'+(body.classList.contains('v')?' reader-vertical-flow':'')"),'desktop reader flow wrapper is missing');
ok(app.includes("flow.className='reader-flow'+(state.readerVertical?' reader-vertical-flow':'')"),'handheld reader flow wrapper is missing');
ok(html.includes('--phone-sub:#d0d6de!important'),'dark smartphone contrast palette is missing');
ok(html.includes('html[data-device="desktop"] #reader.open.mode-focus .r-bar'),'desktop mode-focus UI lockdown is missing');
ok(app.includes('function getVerticalScrollMetrics'),'desktop vertical scroll metric helper missing');
ok(app.includes('function scrollDesktopVerticalBy'),'desktop vertical scroll helper missing');
ok(app.includes('function bindDesktopVerticalWheel'),'desktop vertical wheel binding missing');
ok(app.includes("b.style.setProperty('touch-action',state.readerVertical?'pan-x':'pan-y','important')"),'handheld vertical touch-axis fix missing');
ok(app.includes("if(handheld||buffer.byteLength<=4*1024*1024)"),'handheld parser still depends on Reader Worker');
ok(app.includes('b.scrollLeft=Math.max(0,m.max-p*m.max);'),'handheld vertical fraction uses stable LTR coordinates');
ok(app.includes('function decodeAozoraText(buffer)'),'robust Aozora decoder is missing');
ok(app.includes("new TextDecoder(enc,{fatal:false})"),'Aozora decoder does not try multiple encodings');
ok(html.includes('aozora-mobile-final-stability'),'mobile final stability CSS is missing');
ok(html.includes('max-width:300px!important'),'mobile toast is not compact');
ok(html.includes('width:min(320px,calc(100vw - 28px))!important'),'mobile banner is not compact');
ok(app.includes('const handlePhoneBack='),'direct mobile back handler is missing');
ok(app.includes("const left=b.classList.contains('v')?Math.max(0,m.max-target):target"),'desktop vertical page position does not use stable LTR coordinates');
ok(app.includes("b.scrollLeft=Math.max(0,Math.min(m.max,b.scrollLeft-d))"),'desktop vertical wheel direction is unstable');
ok(app.includes("body.classList.remove('paper-turning-next','paper-turning-prev')"),'page turn still transforms article body');
ok(html.includes('app.js?v=reader-mobile-zero-bug-v20261005-38'),'mobile zero-bug cache bust missing');
ok(html.includes('id="phone-global-back"'),'smartphone global back control missing');
ok(html.includes('aozora-actual-device-fix'),'actual-device control hardening missing');
ok(html.includes('.phone-icon-button .phone-svg'),'smartphone icon size hardening missing');


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
ok(/new Worker\('\.\/reader-worker\.js\?v='/.test(app),'reader parser worker missing');
ok(html.includes("worker-src 'self'"),'CSP does not permit the reader parser worker');

ok(app.includes("function getReaderAxis"),'reader paging axis helper missing');
ok(html.includes("columns:auto!important"),'reader column layout was not disabled');

ok(app.includes("classList.add('loading-bar-live')"),'loading feedback missing');
ok(app.includes("hydrateSavedKeys"),'cached-book hydration missing');
ok(app.includes("dateKeyOf"),'local date helper missing');
ok(app.includes('out.goalMin=Number.isFinite(Number(d.goalMin))'),'daily reading goal is not persisted safely');
ok(app.includes('const isAnyReaderOpen=()=>'),'shared PC/smartphone reader activity detection missing');
ok(app.includes("const url=baseUrl+'#work='+encodeURIComponent(String(w.id))"),'smartphone share deep link missing');
ok(app.includes("rawHash.match(/^#work=(.+)$/)"),'smartphone shared-work deep link reader missing');
ok(app.includes('BROWSER_SMOKE'),'browser smoke isolation mode is missing');
ok(/const catalogDeadline=Date\.now\(\)\+\d+/.test(app),'catalog fetch has no total wait deadline');
ok(/const bodyDeadline=Date\.now\(\)\+\d+/.test(app),'book fetch has no total wait deadline');
ok(smoke.includes('function readerScrollable'),'browser smoke does not verify actual reader scrollability');
ok(smoke.includes("readerRendered(d,'#phone-reader-body')"),'smartphone smoke does not verify visible reader geometry');
ok(smoke.includes("globalBack"),'smartphone smoke does not exercise global back control');
ok(smoke.includes("rect.width>0&&rect.height>0"),'reader smoke lacks usable geometry checks');
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
ok(/const CATALOG_CACHE_KEY='cat-rights-v\d+'/.test(app),'persistent catalog cache key is missing');
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

ok(html.includes('id="reader-loading-layer"'),'desktop reader loading layer missing');
ok(html.includes('id="phone-reader-loading-layer"'),'smartphone reader loading layer missing');
ok(app.includes('function renderReaderBody'),'reader body renderer missing');
ok(app.includes('function splitReaderHtml'),'reader chunk splitter missing');
ok(app.includes('readerRenderYield'),'reader cooperative rendering yield missing');
ok(app.includes("root?.closest?.('#body,#phone-reader-body')"),'reader DOM mutation observer still scans article content');
ok(app.includes("history.replaceState(baseState,'',location.href)"),'reader opening from sheet does not normalize overlay history');
ok(app.includes('cancelReaderRender();'),'reader render cancellation missing');
ok(app.includes('cancelReaderParser();'),'reader parser cancellation missing');
ok(html.includes('#reader.open { display: flex; animation: none!important;'),'reader still fades the full overlay over the previous UI');
ok(html.includes('background:var(--bg)!important;'),'reader loading layer is not opaque');

ok(app.includes("body.classList.add('reader-building')"),'reader build isolation missing');
ok(app.includes('function enforceDesktopVerticalReaderLayout'),'desktop vertical reader layout guard missing');
ok(app.includes("st.v!==false)enforceDesktopVerticalReaderLayout()"),'vertical toggle does not reassert desktop reader layout');
ok(html.includes('id="aozora-pc-ui-absolute-final"'),'desktop reader absolute UI rule missing');
ok(smoke.includes("desktop reader chrome after vertical toggle"),'browser smoke does not verify desktop vertical reader UI');
ok(app.includes('readerTok++;'),'reader close does not invalidate pending work');
ok(!app.includes("body.innerHTML=readerLoaderMarkup()"),'reader loader must not be injected into article body');
ok(app.includes("body.scrollTop=0;")&&app.includes("body.scrollLeft=0;"),'reader opening does not reset both scroll axes');
ok(app.includes("d.scrollTop=0;"),'smartphone detail does not reset its scroll position');
ok(html.includes('id="aozora-splash"'),'book-theater splash is missing');
ok(html.includes('splash.js?v=20261005-01'),'splash startup script is not CSP-safe external JS');

ok(/app\.js\?v=[^"]+/.test(html),'reader stability cache-bust version missing');
ok(smoke.includes('loader did not hide after render'),'browser smoke does not verify loader lifecycle');
ok(app.includes('const count=2200'),'browser smoke is not exercising long reader content');

if(fail.length){
  console.error('QUALITY CHECK FAILED');
  for(const f of fail)console.error(' - '+f);
  process.exit(1);
}
console.log('QUALITY CHECK PASSED');
console.log(`actions=${acts.length} handled=${handled.length} appBytes=${Buffer.byteLength(app)} htmlBytes=${Buffer.byteLength(html)}`);
