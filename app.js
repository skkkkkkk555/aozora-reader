/* touch/click reliability */
(function(){
let start=null,suppressEl=null,suppressUntil=0,synthetic=false;
const actionOf=t=>t?.closest?.('[data-act]')||null;
document.addEventListener('pointerdown',e=>{
  if(e.pointerType!=='touch')return;
  const el=actionOf(e.target); if(!el)return;
  start={x:e.clientX,y:e.clientY,el,moved:false};
},{passive:true});
document.addEventListener('pointermove',e=>{
  if(e.pointerType!=='touch'||!start)return;
  const dx=e.clientX-start.x,dy=e.clientY-start.y;
  if(dx*dx+dy*dy>324)start.moved=true;
},{passive:true});
document.addEventListener('pointerup',e=>{
  if(e.pointerType!=='touch'||!start)return;
  const el=actionOf(e.target),dx=e.clientX-start.x,dy=e.clientY-start.y;
  const isTap=el===start.el&&!start.moved&&dx*dx+dy*dy<=324;
  if(isTap){
    suppressEl=el;suppressUntil=Date.now()+900;synthetic=true;
    try{el.click()}finally{synthetic=false}
  }else if(start.moved&&start.el){
    // スワイプ終了時に後から発火するclickで誤作動しないようにする。
    suppressEl=start.el;suppressUntil=Date.now()+450;
  }
  start=null;
},{passive:true});
document.addEventListener('pointercancel',e=>{if(e.pointerType==='touch')start=null;},{passive:true});
document.addEventListener('click',e=>{
  if(synthetic)return;
  if(suppressEl&&Date.now()<suppressUntil&&actionOf(e.target)===suppressEl){
    e.preventDefault();e.stopImmediatePropagation();
  }
  suppressEl=null;suppressUntil=0;
},true);
})();
/* ==================== 1. 状態 & ユーティリティ ==================== */
const $=i=>document.getElementById(i);
/* スマホUIはメインアプリの初期化失敗でも空シェルだけ残らないよう、早期にエラーを捕捉する。 */
(function(){
  const recoverPhone=()=>{
    if(document.documentElement.dataset.device!=='smartphone')return;
    const app=document.getElementById('phone-app');
    const reader=document.getElementById('phone-reader');
    const detail=document.getElementById('phone-detail');
    const content=document.getElementById('phone-content');
    const tabs=document.querySelector('.phone-tabbar');
    const readerActive=!!reader?.classList.contains('phone-open');
    const detailActive=!!detail&&!detail.hidden&&detail.style.display!=='none';
    if(!app||readerActive||detailActive)return;
    app.style.display='flex';app.setAttribute('aria-hidden','false');
    if(reader){reader.hidden=true;reader.classList.remove('phone-open');reader.style.display='none';}
    if(detail){detail.hidden=true;detail.classList.remove('phone-open');detail.style.display='none';}
    if(content){content.hidden=false;content.style.display='block';}
    if(tabs){tabs.hidden=false;tabs.style.display='flex';}
    if(content&&!content.textContent.trim()){
      content.innerHTML='<section class="phone-screen"><div class="phone-empty"><b>青空文庫を準備しています…</b><br><span style="font-size:12px">アプリの初期化中です。</span></div></section>';
    }
  };
  window.addEventListener('error',()=>{try{recoverPhone()}catch{}});
  window.addEventListener('unhandledrejection',()=>{try{recoverPhone()}catch{}});
})();
/* ================= Smartphone UI auto-detection ================= */
const refreshSmartphoneUI = ()=>{
  const ua = String(navigator.userAgent || '');
  const mobileUA = navigator.userAgentData?.mobile === true ||
    /Android.*Mobile|iPhone|iPod|Windows Phone|IEMobile|BlackBerry|Opera Mini|Mobile Safari/i.test(ua);
  const shortestSide = Math.min(window.innerWidth || 0, window.innerHeight || 0);
  // タッチ対応判定はAndroid WebView等で0になることがあるため、端末判定には使用しない。
  const isSmartphone = !!mobileUA && shortestSide <= 899;
  document.documentElement.classList.toggle('smartphone-ui', isSmartphone);
  document.documentElement.dataset.device = isSmartphone ? 'smartphone' : 'desktop';
  return isSmartphone;
};
refreshSmartphoneUI();
window.addEventListener('resize', refreshSmartphoneUI, {passive:true});

const esc=s=>(s||'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]||c));
const escAttr=esc;

/* ==================== SECURITY HARDENING ==================== */
const SEC={maxCatalogBytes:30*1024*1024,maxCatalogText:32*1024*1024,maxLocalFileBytes:30*1024*1024,maxBookBytes:32*1024*1024,maxResponseHeadBytes:4096,maxStateChars:4*1024*1024};
const NETWORK_HOSTS=new Set(['www.aozora.gr.jp','aozorahack.org','raw.githubusercontent.com','corsproxy.io','corsproxy.org','api.allorigins.win']);
const secureUrl=input=>{
  try{
    const u=new URL(typeof input==='string'?input:input.url,location.href);
    if(!['http:','https:'].includes(u.protocol))return null;
    if(u.origin===location.origin)return u;
    if(NETWORK_HOSTS.has(u.hostname))return u;
    if(typeof st!=='undefined'&&isSafeOllamaUrl(st.oUrl)){
      const configured=new URL(normalizeOllamaUrl(st.oUrl));
      if(u.origin===configured.origin)return u;
    }
  }catch{}
  return null;
};
const secureFetch=async(input,init={})=>{
  const u=secureUrl(input);
  if(!u)throw new Error('blocked-network-destination');
  const method=String(init.method||'GET').toUpperCase();
  let isConfiguredOllama=false;
  try{
    if(typeof st!=='undefined'&&isSafeOllamaUrl(st.oUrl)){
      isConfiguredOllama=u.origin===new URL(normalizeOllamaUrl(st.oUrl)).origin;
    }
  }catch{}
  if(!isConfiguredOllama&&!['GET','HEAD'].includes(method))throw new Error('blocked-network-method');
  const response=await window.fetch(u.href,{...init,referrerPolicy:'no-referrer',cache:init.cache||'no-store',redirect:'follow'});
  const finalUrl=secureUrl(response.url);
  if(!finalUrl||finalUrl.origin!==u.origin)throw new Error('blocked-cross-origin-redirect');
  return response;
};
async function readResponseBytes(res,maxBytes){
  if(!res||!res.ok)return null;
  const len=Number(res.headers.get('content-length')||0);
  if(len&&len>maxBytes)throw new Error('response-too-large');
  if(res.body&&typeof res.body.getReader==='function'){
    const reader=res.body.getReader(),chunks=[];let total=0;
    try{
      while(true){
        const p=await reader.read();
        if(p.done)break;
        total+=p.value.byteLength;
        if(total>maxBytes){try{await reader.cancel();}catch{};throw new Error('response-too-large');}
        chunks.push(p.value);
      }
    }finally{try{reader.releaseLock();}catch{}}
    const out=new Uint8Array(total);let off=0;
    for(const chunk of chunks){out.set(chunk,off);off+=chunk.byteLength;}
    return out.buffer;
  }
  const buf=await res.arrayBuffer();
  if(buf.byteLength>maxBytes)throw new Error('response-too-large');
  return buf;
}
function sanitizeCatalogRecords(v){
  if(!Array.isArray(v))return [];
  const out=[];const seen=new Set();
  for(const raw of v){
    if(out.length>=20000||!raw||typeof raw!=='object')break;
    const rawId=String(raw.id||'').slice(0,80);
    // c:1 に加えて、永続化した著作権確認済みIDを必須とする。
    // catalog.jsonにはrフラグが無い場合があるため、許可リスト照合後にr:1へ正規化する。
    if(Number(raw.c)!==1||!rightsReady||!rightsAllowlist.has(rawId.padStart(6,'0')))continue;
    const id=rawId,t=String(raw.t||'').slice(0,300),a=String(raw.a||'').slice(0,300),x=String(raw.x||'').slice(0,500);
    if(!safeStateKey(id)||seen.has(id)||!t||!x||x.length>500||x.includes('..')||x.includes('\\')||x.startsWith('http')||x.startsWith('//')||!/^[A-Za-z0-9._\/-]+$/.test(x))continue;
    seen.add(id);
    out.push({id,t,a,tk:String(raw.tk||'').slice(0,300),ak:String(raw.ak||'').slice(0,300),d:String(raw.d||'').slice(0,80),k:Number(raw.k)===1?1:0,c:1,r:1,ndc:String(raw.ndc||'').slice(0,80),norm:String(raw.norm||'').slice(0,700),x});
  }
  return out;
}
const SEC_STATE={maxItems:5000,maxAuthors:2000,maxHistory:200,maxNotesPerBook:50,maxText:2000,maxMapKeys:5000};
const safeStateKey=k=>typeof k==='string'&&/^[A-Za-z0-9._:-]{1,80}$/.test(k);
const safeStateText=(v,max=SEC_STATE.maxText)=>typeof v==='string'?v.slice(0,max):'';
const safeStateArray=(v,max=SEC_STATE.maxItems)=>Array.isArray(v)?v.filter(x=>typeof x==='string'&&x.length<=160).slice(0,max):[];
function sanitizeStateMap(v,mapper,max=SEC_STATE.maxMapKeys){
  const out={};if(!v||typeof v!=='object'||Array.isArray(v))return out;
  let n=0;
  for(const [k,val] of Object.entries(v)){
    if(n>=max||!safeStateKey(k))continue;
    const mapped=mapper(val);
    if(mapped!==undefined){Object.defineProperty(out,k,{value:mapped,writable:true,enumerable:true,configurable:true});n++;}
  }
  return out;
}
function sanitizePersistedState(d){
  if(!d||typeof d!=='object'||Array.isArray(d))return null;
  let size=0;try{size=JSON.stringify(d).length;}catch{return null;}
  if(size>SEC.maxStateChars)return null;
  const out={};
  out.goalMin=Number.isFinite(Number(d.goalMin))?Math.max(10,Math.min(180,Math.round(Number(d.goalMin)))):30;
  out.fav=safeStateArray(d.fav);out.want=safeStateArray(d.want);out.done=safeStateArray(d.done);
  out.favAuthors=safeStateArray(d.favAuthors,SEC_STATE.maxAuthors);
  out.dead=safeStateArray(d.dead,SEC_STATE.maxItems);
  out.searchHistory=safeStateArray(d.searchHistory,100);
  out.hist=Array.isArray(d.hist)?d.hist.filter(x=>x&&safeStateKey(String(x.id))&&Number.isFinite(Number(x.t))).slice(0,SEC_STATE.maxHistory).map(x=>({id:String(x.id).slice(0,80),t:Math.max(0,Math.min(Number(x.t),Date.now()+86400000))})):[];
  out.calData=sanitizeStateMap(d.calData,v=>Number.isFinite(Number(v))?Math.max(0,Math.min(1440,Math.round(Number(v)))):undefined);
  out.pos=sanitizeStateMap(d.pos,v=>v&&typeof v==='object'?{f:Math.max(0,Math.min(1,Number(v.f)||0)),t:Math.max(0,Math.min(Number(v.t)||0,Date.now()+86400000))}:undefined);
  out.bm=sanitizeStateMap(d.bm,v=>Array.isArray(v)?v.slice(0,SEC_STATE.maxNotesPerBook).filter(x=>x&&typeof x==='object').map(x=>({f:Math.max(0,Math.min(1,Number(x.f)||0)),s:safeStateText(x.s,500),t:Math.max(0,Math.min(Number(x.t)||0,Date.now()+86400000))})):[],SEC_STATE.maxMapKeys);
  out.notes=sanitizeStateMap(d.notes,v=>Array.isArray(v)?v.slice(0,SEC_STATE.maxNotesPerBook).filter(x=>x&&typeof x==='object').map(x=>({s:safeStateText(x.s,500),m:safeStateText(x.m,2000),t:Math.max(0,Math.min(Number(x.t)||0,Date.now()+86400000)),f:Math.max(0,Math.min(1,Number(x.f)||0))})):[],SEC_STATE.maxMapKeys);
  out.hls=sanitizeStateMap(d.hls,v=>Array.isArray(v)?v.slice(0,SEC_STATE.maxNotesPerBook).filter(x=>x&&typeof x==='object').map(x=>({t:safeStateText(x.t,500),c:safeStateText(x.c,40),d:Math.max(0,Math.min(Number(x.d)||0,Date.now()+86400000))})):[],SEC_STATE.maxMapKeys);
  if(d.st&&typeof d.st==='object'&&!Array.isArray(d.st)){
    out.st={
      fs:Math.max(14,Math.min(32,Number(d.st.fs)||18)),
      lh:Math.max(1.6,Math.min(2.6,Number(d.st.lh)||2.1)),
      theme:['auto','sepia','dark'].includes(d.st.theme)?d.st.theme:'auto',
      font:['mincho','gothic'].includes(d.st.font)?d.st.font:'mincho',
      warm:!!d.st.warm,kp:!!d.st.kp,offline:!!d.st.offline,lowSpec:!!d.st.lowSpec,ollamaEnabled:!!d.st.ollamaEnabled,
      oUrl:safeStateText(d.st.oUrl,500),
      oMod:safeStateText(d.st.oMod,120),v:d.st.v!==false,
      rMode:['normal','focus','night'].includes(d.st.rMode)?d.st.rMode:'normal',
      readSpeed:[350,500,750].includes(Number(d.st.readSpeed))?Number(d.st.readSpeed):500,
      todayBook:d.st.todayBook&&safeStateKey(String(d.st.todayBook.id))?{id:String(d.st.todayBook.id).slice(0,80),date:safeStateText(d.st.todayBook.date,20)}:null
    };
  }
  return out;
}

const isPrivateHost=host=>{
  const h=String(host||'').toLowerCase().replace(/^\[|\]$/g,'');
  if(h==='localhost'||h.endsWith('.localhost')||h.endsWith('.local')||h==='::1')return true;
  const p=h.split('.').map(Number);
  if(p.length===4&&p.every(Number.isInteger)){
    if(p[0]===10||p[0]===127||p[0]===0)return true;
    if(p[0]===172&&p[1]>=16&&p[1]<=31)return true;
    if(p[0]===192&&p[1]===168)return true;
    if(p[0]===169&&p[1]===254)return true;
  }
  return false;
};
const isSafeOllamaUrl=value=>{
  const raw=String(value||'').trim().replace(/[\u0000-\u001f\u007f]/g,'');
  const candidate=/^https?:\/\//i.test(raw)?raw:'http://'+raw;
  try{
    const u=new URL(candidate);
    if(!['http:','https:'].includes(u.protocol)||u.username||u.password||u.search||u.hash)return false;
    if(!u.hostname||u.hostname.length>253)return false;
    if(NETWORK_HOSTS.has(u.hostname))return false;
    return u.protocol==='https:'||isPrivateHost(u.hostname);
  }catch{return false}
};
const sanitizeReaderHtml=html=>{
  const doc=new DOMParser().parseFromString(String(html||''),'text/html');
  const allowed=new Set(['BR','RUBY','RT','EM','U','B','SPAN','H2','H3','HR','SECTION','PRE']);
  [...doc.body.querySelectorAll('*')].forEach(el=>{
    const tag=el.tagName;
    if(!allowed.has(tag)){el.replaceWith(doc.createTextNode(el.textContent||''));return;}
    [...el.attributes].forEach(a=>{
      const allowClass=(tag==='SPAN'||tag==='EM')&&a.name==='class';
      const allowHeadClass=(tag==='H2'||tag==='H3')&&a.name==='class';
      const allowSourceClass=(tag==='SECTION'||tag==='PRE')&&a.name==='class';
      const allowHid=(tag==='H2'||tag==='H3')&&a.name==='data-hid';
      const ok=allowHid||allowHeadClass||allowClass||allowSourceClass;
      if(!ok)el.removeAttribute(a.name);
    });
    if((tag==='SPAN'||tag==='EM'||tag==='H2'||tag==='H3'||tag==='SECTION'||tag==='PRE')&&el.hasAttribute('class')){
      const allowedClass=['em','tcy','serif','aozora-page-break','aozora-source-info','aozora-source-title'];
      el.setAttribute('class',el.getAttribute('class').split(/\s+/).filter(c=>allowedClass.includes(c)).join(' '));
      if(!el.getAttribute('class'))el.removeAttribute('class');
    }
    if((tag==='H2'||tag==='H3')&&el.hasAttribute('data-hid')&&!/^h-[0-9]{1,9}$/.test(el.getAttribute('data-hid')))el.removeAttribute('data-hid');
  });
  doc.body.querySelectorAll('H2,H3').forEach(el=>el.removeAttribute('style'));
  return doc.body.innerHTML;
};

const PAL=['#23445d','#2e5b70','#3b5249','#5c3d46','#6e4a2e','#4a4e69','#3d5a80','#583131'];
const colorOf=s=>{let h=0;for(let i=0;i<s.length;i++){h=(h<<5)-h+s.charCodeAt(i);h|=0}return PAL[Math.abs(h)%PAL.length]};
const sig=(ms)=>{const c=new AbortController();setTimeout(()=>c.abort(new DOMException('Timeout','TimeoutError')),ms);return c.signal};

function decodeHtmlEntities(str){
  const txt = document.createElement('textarea');
  txt.innerHTML = str;
  return txt.value;
}

const idb={
  d:new Promise(r=>{try{const o=indexedDB.open('aozora_terminal_v17',1);o.onupgradeneeded=()=>{const db=o.result;if(!db.objectStoreNames.contains('k'))db.createObjectStore('k');if(!db.objectStoreNames.contains('docs'))db.createObjectStore('docs');};o.onsuccess=()=>r(o.result);o.onerror=()=>r(null);o.onblocked=()=>r(null)}catch{r(null)}}),
  async get(s,k){try{const db=await this.d;return new Promise(r=>{const q=db.transaction(s,'readonly').objectStore(s).get(k);q.onsuccess=()=>r(q.result);q.onerror=()=>r(null)})}catch{return null}},
  async set(s,k,v){try{const db=await this.d;db.transaction(s,'readwrite').objectStore(s).put(v,k)}catch{}},
  async del(s,k){try{const db=await this.d;db.transaction(s,'readwrite').objectStore(s).delete(k)}catch{}},
  async keys(s){try{const db=await this.d;return await new Promise(resolve=>{const q=db.transaction(s,'readonly').objectStore(s).getAllKeys();q.onsuccess=()=>resolve(q.result||[]);q.onerror=()=>resolve([])})}catch{return[]}}
};

let allWorks=[], works=[], byId=new Map(), dead=new Set();
let rightsAllowlist=new Set(), rightsReady=false;
let fav=new Set(), want=new Set(), done=new Set(), favAuthors=new Set();
let pos={}, bm={}, notes={}, hls={}, hist=[], savedKeys=new Set(), searchHistory=[];
let calData={}, goalMin=30;
let st={ fs:18, lh:2.1, theme:'auto', font:'mincho', warm:true, kp:true, offline:false, lowSpec:false, ollamaEnabled:false, oUrl:'http://127.0.0.1:11434', oMod:'', v:true, rMode:'normal', readSpeed:500, todayBook:null };
let aiConn={ ok:false, models:[], err:'' };
let activeBook=null;
const isPublicWork = w => !!w && Number(w.c) === 1 && rightsReady && rightsAllowlist.has(String(w.id).padStart(6,'0'));
const dateKeyOf=(d=new Date())=>`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
const localDateKey=()=>dateKeyOf(new Date());
const normalizeOllamaUrl=(value='')=>{
  const raw=String(value||'').trim().replace(/[\u0000-\u001f\u007f]/g,'');
  if(!raw)return 'http://127.0.0.1:11434';
  const candidate=/^https?:\/\//i.test(raw)?raw:'http://'+raw;
  try{
    const u=new URL(candidate);
    if(!['http:','https:'].includes(u.protocol)||u.username||u.password||u.search||u.hash)return '';
    if(!u.hostname||u.hostname.length>253)return '';
    u.pathname=u.pathname.replace(/\/{2,}/g,'/').replace(/\/$/,'');
    return u.origin+(u.pathname||'');
  }catch{return ''}
};
const canUseOllama=()=>st.ollamaEnabled&&!st.offline&&isSafeOllamaUrl(st.oUrl);
const BROWSER_SMOKE=/(?:[?&])browser-smoke(?:=|&|$)/.test(location.search);
const safeEl = id => document.getElementById(id) || null;
async function hydrateSavedKeys(){
  const keys=await idb.keys('docs');
  savedKeys=new Set(keys.map(String).filter(safeStateKey));
}

const safeText = (id, value) => { const el = safeEl(id); if (el) el.textContent = String(value ?? ''); };
const safeDisplay = (id, show) => { const el = safeEl(id); if (el) el.style.display = show ? '' : 'none'; };
const closeOneLineMode = () => {};
const escRe = s => (s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

let searchState={
  query: '',
  scope: null,
  filter: { saved: false, time: null },
  sort: 'new'
};

const save=()=>{
  const d={fav:[...fav],want:[...want],done:[...done],favAuthors:[...favAuthors],pos,bm,notes,hls,hist,calData,goalMin,st,searchHistory,dead:[...dead]};
  try{
    const packed=JSON.stringify(d);
    localStorage.setItem('aozora_terminal_v17',packed);
    localStorage.setItem('aozora_terminal_settings_v1',JSON.stringify(st));
  }catch(err){
    console.warn('localStorage save failed',err);
  }
  // localStorageが満杯でもIndexedDBには保存できるよう、別系統で必ず試す。
  idb.set('k','state',d);
};
const load=async()=>{
  try {
    const raw = localStorage.getItem('aozora_terminal_v17') || localStorage.getItem('aozora_terminal_v16') || 'null';
    if(raw.length>SEC.maxStateChars) throw new Error('state-too-large');
    const localState=raw!=='null'?JSON.parse(raw):null;
    let d=sanitizePersistedState(localState);
    if(!d)d=sanitizePersistedState(await idb.get('k','state'));
    const savedSettingsRaw=localStorage.getItem('aozora_terminal_settings_v1');
    if(!d&&savedSettingsRaw){
      try{d=sanitizePersistedState({st:JSON.parse(savedSettingsRaw)});}catch{}
    }
    if(d){
      fav=new Set(safeStateArray(d.fav)); want=new Set(safeStateArray(d.want)); done=new Set(safeStateArray(d.done));
      favAuthors=new Set(safeStateArray(d.favAuthors,SEC_STATE.maxAuthors));
      dead=new Set(safeStateArray(d.dead)); pos=d.pos||{}; bm=d.bm||{}; notes=d.notes||{}; hls=d.hls||{};
      hist=Array.isArray(d.hist)?d.hist:[]; calData=d.calData||{}; goalMin=Math.max(10,Math.min(180,Number(d.goalMin)||30)); searchHistory=safeStateArray(d.searchHistory,100);
      st=Object.assign(st,d.st||{});
      if(d.st?.off!==undefined) st.offline=!!d.st.off;
      if(d.st?.ollamaEnabled!==undefined) st.ollamaEnabled=!!d.st.ollamaEnabled;
      if(savedSettingsRaw){
        try{
          const sd=sanitizePersistedState({st:JSON.parse(savedSettingsRaw)});
          if(sd?.st)st=Object.assign(st,sd.st);
        }catch{}
      }
    }
  } catch (err) {
    console.warn('load failed; resetting state', err);
    fav=new Set(); want=new Set(); done=new Set(); favAuthors=new Set(); dead=new Set(); pos={}; bm={}; notes={}; hls={}; hist=[]; calData={}; goalMin=30; searchHistory=[];
  }
};

function renderInsightBar(){
  const todayKey = localDateKey();
  const todayMin = Number(calData[todayKey] || 0);
  const totalBooks = new Set(hist.map(item => item.id)).size;
  const progress = Math.min(100, Math.round((todayMin / Math.max(1, goalMin)) * 100));
  const shelfCount = works.filter(w => pos[w.id] || fav.has(w.id) || want.has(w.id) || done.has(w.id)).length;

  safeText('insight-read-time', `${todayMin}分`);
  safeText('insight-read-sub', todayMin >= goalMin ? '目標達成' : `残り ${Math.max(0, goalMin - todayMin)}分`);
  safeText('insight-progress', `${progress}%`);
  safeText('insight-progress-sub', progress >= 100 ? '目標達成' : '継続中');
  safeText('insight-shelf', `${Math.max(0, shelfCount)}冊`);
  safeText('insight-shelf-sub', totalBooks ? `${totalBooks}冊を記録` : 'まだ始めていません');
}

window.addEventListener('error',(event)=>{
  console.warn('Captured app error:',event.message);
});
window.addEventListener('unhandledrejection',()=>{
  showBanner('一部の機能でエラーが発生しました。ページを再読み込みすると改善する場合があります。');
});

/* ==================== 2. レンダリング共通 ==================== */
const rows=(arr,fn)=>arr.map((item,i)=>fn(item,i)).join('');
const tileHtml=(w,i=0)=>`
  <div class="tile book-cover-card" style="--book-color:${colorOf(w.t)}; --book-delay:${Math.min(i,20)*52}ms; --book-shine-delay:${1200+Math.min(i,8)*70}ms" data-act="open-book" data-id="${escAttr(w.id)}">
    <div class="book-cover-inner">
      <div class="book-cover-top">
        ${savedKeys.has(w.id)?'<span class="book-badge">保存済</span>':'<span></span>'}
        <span class="book-markers">
          ${favAuthors.has(w.a)?'<span class="book-badge">推し作家</span>':''}
          ${fav.has(w.id)?'<span class="book-star">★</span>':''}
        </span>
      </div>
      <div class="book-cover-title serif">${esc(w.t)}</div>
      <div class="book-cover-author">${esc(w.a)}</div>
    </div>
  </div>`;


let bookRevealObserver=null;
let bookPhysicsBound=new WeakSet();
function bindBookPhysics(root){
  if(!window.matchMedia || !matchMedia('(hover:hover)').matches) return;
  const list=(root||document).querySelectorAll?.('.book-cover-card');
  if(!list) return;
  list.forEach(card=>{
    if(bookPhysicsBound.has(card)) return;
    bookPhysicsBound.add(card);
    let raf=0;
    card.addEventListener('pointermove',e=>{
      if(document.body.classList.contains('low-power')) return;
      const inner=card.querySelector('.book-cover-inner');
      if(!inner) return;
      if(raf) cancelAnimationFrame(raf);
      raf=requestAnimationFrame(()=>{
        const r=inner.getBoundingClientRect();
        const px=((e.clientX-r.left)/r.width-.5)*2;
        const py=((e.clientY-r.top)/r.height-.5)*2;
        inner.style.setProperty('--tilt-x',(py*-3.2).toFixed(2)+'deg');
        inner.style.setProperty('--tilt-y',(px*4.2).toFixed(2)+'deg');
        inner.style.setProperty('--lift',Math.max(0,1-Math.abs(px)*.35-Math.abs(py)*.35).toFixed(2));
      });
    });
    const reset=()=>{
      if(raf) cancelAnimationFrame(raf);
      raf=0;
      const inner=card.querySelector('.book-cover-inner');
      if(inner){
        inner.style.setProperty('--tilt-x','0deg');
        inner.style.setProperty('--tilt-y','0deg');
        inner.style.setProperty('--lift','0');
      }
      card.classList.remove('physics-pressed');
    };
    card.addEventListener('pointerleave',reset);
    card.addEventListener('pointerdown',()=>{
      if(document.body.classList.contains('low-power')) return;
      card.classList.add('physics-pressed');
    });
    card.addEventListener('pointerup',()=>card.classList.remove('physics-pressed'));
    card.addEventListener('pointercancel',reset);
  });
}

function enhanceActionables(root=document){
  if(root?.id==='body'||root?.id==='phone-reader-body'||root?.closest?.('#body,#phone-reader-body'))return;
  const list=root.querySelectorAll?.('[data-act]:not(button):not(input):not(select):not(textarea):not(label):not(a)')||[];
  list.forEach(el=>{
    if(!el.hasAttribute('role'))el.setAttribute('role','button');
    if(!el.hasAttribute('tabindex'))el.setAttribute('tabindex','0');
    if(el.dataset.keyActionBound)return;
    el.dataset.keyActionBound='1';
    el.addEventListener('keydown',e=>{
      if(e.key==='Enter'||e.key===' '){
        e.preventDefault();
        el.click();
      }
    });
  });
}

function bindPressPhysics(){
  const selector='button,.block[data-act],.tile[data-act]';
  document.addEventListener('pointerdown',e=>{
    if(document.body.classList.contains('low-power')) return;
    const el=e.target.closest(selector);
    if(!el) return;
    el.classList.add('physics-pressed');
  },{passive:true});
  const clear=e=>{
    const el=e.target.closest?.(selector);
    if(el) el.classList.remove('physics-pressed');
  };
  document.addEventListener('pointerup',clear,{passive:true});
  document.addEventListener('pointercancel',clear,{passive:true});
}

function watchBookCovers(root){
  const list=(root||document).querySelectorAll?.('.book-cover-card:not(.is-visible)');
  if(!list) return;
  if(!bookRevealObserver){
    bookRevealObserver=new IntersectionObserver(entries=>{
      const entering=entries.filter(entry=>entry.isIntersecting && !entry.target.classList.contains('is-visible'));
      entering.sort((a,b)=>{
        const ar=a.boundingClientRect, br=b.boundingClientRect;
        return (ar.top-br.top)||(ar.left-br.left);
      });
      entering.forEach((entry,i)=>{
        entry.target.style.setProperty('--book-delay',(Math.min(i,12)*68)+'ms');
        entry.target.classList.add('is-visible');
        bookRevealObserver.unobserve(entry.target);
      });
    },{root:null,rootMargin:'0px 0px 6% 0px',threshold:0.08});
  }
  list.forEach(el=>bookRevealObserver.observe(el));
  bindBookPhysics(root);
}

function sheet(title, html){
  if(document.documentElement.dataset.device==='smartphone'&&typeof window.__aozoraPhoneOpenSheet==='function'){
    window.__aozoraPhoneOpenSheet(title,html);
    return;
  }
  restoreFocusEl=document.activeElement instanceof HTMLElement?document.activeElement:null;
  $('sheet-t').textContent=title;
  $('sheet-b').innerHTML=html;
  $('sheet').classList.add('open');
  $('sheet').setAttribute('aria-hidden','false');
  $('scrim').classList.add('open');
  pushLayer('sheet');
  requestAnimationFrame(()=>{
    $('sheet').querySelector('[data-act="close-sheet"]')?.focus({preventScroll:true});
  });
}
function closeSheet(fromPop=false){
  if(document.documentElement.dataset.device==='smartphone'&&typeof window.__aozoraPhoneCloseSheet==='function'){
    window.__aozoraPhoneCloseSheet(fromPop);
    return;
  }
  $('sheet').classList.remove('open');
  $('sheet').setAttribute('aria-hidden','true');
  $('scrim').classList.remove('open');
  popLayer('sheet');
  if(!fromPop && history.state?.layer==='sheet') history.back();
  requestAnimationFrame(()=>{
    if(restoreFocusEl&&document.contains(restoreFocusEl)){
      try{restoreFocusEl.focus({preventScroll:true});}catch{}
    }
    restoreFocusEl=null;
  });
}

document.addEventListener('click',e=>{
  if(e.target.id==='scrim'){
    e.preventDefault();
    e.stopPropagation();
    closeSheet(false);
  }
},{capture:true});
let toastTimer=null, undoFn=null, restoreFocusEl=null;
function toast(m, undo){
  $('toast-m').textContent=m; undoFn=undo;
  $('toast-u').style.display=undo?'block':'none';
  const t=$('toast'); t.classList.add('open');
  clearTimeout(toastTimer);
  toastTimer=setTimeout(()=>t.classList.remove('open'), undo?5000:2600);
}

/* ==================== 3. 画面層 & 戻る管理 ==================== */
const layers=[];
let handlingPopstate=false;
let closingLayer=false;
function pushLayer(n){
  if(layers[layers.length-1]!==n){
    layers.push(n);
    history.pushState({layer:n},'',location.href);
  }
}
function popLayer(n){
  const idx=layers.lastIndexOf(n);
  if(idx>=0) layers.splice(idx,1);
}
function closeLayerByUser(n,fn){
  if(closingLayer)return;
  closingLayer=true;
  popLayer(n);
  fn?.();
  if(history.state?.layer===n) history.back();
  else {
    // 既存の状態が残っている場合も1段だけ戻す。
    history.back();
  }
  setTimeout(()=>{closingLayer=false},120);
}
window.addEventListener('popstate',()=>{
  if(document.documentElement.dataset.device==='smartphone')return;
  if(closingLayer){closingLayer=false;return;}
  const target=history.state?.layer||null;

  // reader上に重なったシートを「戻る」で一段だけ閉じる。
  if(target==='reader'){
    if(!$('reader').classList.contains('open')) return;
    if($('sheet').classList.contains('open')){
      closeSheet(true);
      return;
    }
    if(layers[layers.length-1]==='reader') return;
    return;
  }

  // ルートへ戻った場合は、最上位のUIから順に閉じる。
  if(target===null){
    if($('sheet').classList.contains('open')){ closeSheet(true); return; }
    if($('reader').classList.contains('open')){ closeReader(true); return; }
    $('pop').classList.remove('open');
    layers.length=0;
    switchView('v-home');
  }
});
window.addEventListener('keydown',e=>{
  if(e.key==='Escape'){
    if(layers.length){
      const l=layers[layers.length-1];
      if(l==='sheet'){
        closeSheet(false);
        return;
      }
      if(l==='reader'){
        closeReader(false);
        return;
      }
      if(l==='pop'){
        $('pop').classList.remove('open');
        popLayer('pop');
        if(history.state?.layer==='pop')history.back();
        return;
      }
    }
  }
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){ e.preventDefault(); openSearchPage(); }
});

const CATALOG_CACHE_KEY='cat-rights-v5';
const LEGACY_CATALOG_CACHE_KEY='cat-rights-v4';
const RIGHTS_CACHE_KEY='rights-allowlist-v1';
const RIGHTS_MANIFEST='./rights-allowlist.json';
const CATALOG_TARGET='https://www.aozora.gr.jp/index_pages/list_person_all_extended_utf8.zip';
const URLS=[
  CATALOG_TARGET,
  'https://raw.githubusercontent.com/aozorabunko/aozorabunko/master/index_pages/list_person_all_extended_utf8.zip',
  'https://raw.githubusercontent.com/code4fukui/koten-reader/main/list_person_all_extended_utf8.csv',
  'https://corsproxy.org/?'+encodeURIComponent(CATALOG_TARGET),
  'https://api.allorigins.win/raw?url='+encodeURIComponent(CATALOG_TARGET)
];

function validRightsAllowlist(data){
  if(!Array.isArray(data)||data.length<1000||data.length>30000)return null;
  const set=new Set();
  for(const id of data){const v=String(id||'');if(/^\d{6}$/.test(v))set.add(v);}
  return set.size>=1000?set:null;
}

async function saveRightsAllowlist(set){
  try{await idb.set('k',RIGHTS_CACHE_KEY,[...set]);}catch{}
}

async function refreshRightsAllowlist(){
  // 起動直後の一時的な通信遅延でカタログ全体を停止させない。
  // 同一オリジンの静的ファイルを最大3回・合計約30秒まで再試行する。
  let lastErr=null;
  for(let attempt=0;attempt<3;attempt++){
    try{
      const res=await secureFetch(RIGHTS_MANIFEST+'?v='+Date.now(),{
        signal:sig(10000),
        cache:'no-store'
      });
      if(!res.ok)throw new Error('rights-manifest-http-'+res.status);
      const data=await res.json();
      const set=validRightsAllowlist(data);
      if(!set)throw new Error('rights-manifest-invalid');
      rightsAllowlist=set;
      rightsReady=true;
      await saveRightsAllowlist(set);
      if(allWorks.length){filterWorks();renderHome();}
      return true;
    }catch(err){
      lastErr=err;
      if(attempt<2)await new Promise(resolve=>setTimeout(resolve,350*(attempt+1)));
    }
  }
  console.warn('rights manifest refresh failed; using persisted verification when available',lastErr);
  return false;
}

async function loadRightsAllowlist(){
  if(BROWSER_SMOKE){rightsAllowlist=new Set(['000789']);rightsReady=true;return true;}
  // 再読み込み時はネットワークを待たず、端末に保存済みの確認済みIDを先に復元する。
  try{
    const cached=validRightsAllowlist(await idb.get('k',RIGHTS_CACHE_KEY));
    if(cached){
      rightsAllowlist=cached;
      rightsReady=true;
      // バックグラウンドで最新状態へ更新。更新失敗でも保存済みデータを消さない。
      void refreshRightsAllowlist();
      return true;
    }
  }catch(err){console.debug('persisted rights allowlist unavailable',err);}
  return await refreshRightsAllowlist();
}

async function requestPersistentStorage(){
  try{
    if(!navigator.storage?.persist)return false;
    if(await navigator.storage.persisted())return true;
    return await navigator.storage.persist();
  }catch{return false;}
}

async function loadCachedCatalog(){
  let c=await idb.get('k',CATALOG_CACHE_KEY);
  let safeCatalog=sanitizeCatalogRecords(c);
  if(safeCatalog.length){
    if(safeCatalog.length!==c.length)await idb.set('k',CATALOG_CACHE_KEY,safeCatalog);
    return safeCatalog;
  }
  // v4の既存利用者を壊さず、新しい永続キーへ一度だけ移行。
  c=await idb.get('k',LEGACY_CATALOG_CACHE_KEY);
  safeCatalog=sanitizeCatalogRecords(c);
  if(safeCatalog.length){
    await idb.set('k',CATALOG_CACHE_KEY,safeCatalog);
    return safeCatalog;
  }
  // さらに旧自動/手動取り込みキーも安全に移行する。
  c=await idb.get('k','cat');
  safeCatalog=sanitizeCatalogRecords(c);
  if(safeCatalog.length){
    await idb.set('k',CATALOG_CACHE_KEY,safeCatalog);
    return safeCatalog;
  }
  return [];
}

async function refreshCatalogInBackground(){
  if(catalogBusy)return false;
  try{
    const res=await secureFetch('./catalog.json?'+Date.now(),{signal:sig(30000),cache:'no-store'});
    if(res.ok){
      const data=await res.json();
      const parsed=sanitizeCatalogRecords(data);
      if(parsed.length>=100){
        allWorks=parsed;
        await idb.set('k',CATALOG_CACHE_KEY,parsed);
        filterWorks();renderHome();
        return true;
      }
    }
  }catch(err){console.debug('background same-origin catalog refresh failed',err);}
  return fetchCatalog({background:true,notifyOnFail:false});
}

let catalogRefreshTimer=null;
function scheduleCatalogRefresh(){
  clearTimeout(catalogRefreshTimer);
  const delay=6*60*60*1000;
  catalogRefreshTimer=setTimeout(async()=>{
    try{
      if(!document.hidden&&navigator.onLine!==false)await refreshCatalogInBackground();
    }catch(err){console.debug('scheduled catalog refresh failed',err);}
    scheduleCatalogRefresh();
  },delay);
}
async function checkCatalog(){
  const rightsOk=await loadRightsAllowlist();
  if(!rightsOk){
    allWorks=[];filterWorks();renderHome();
    showBanner('著作権確認データを取得できないため、作品を表示できません。時間を置いて再試行してください。');
    return;
  }
  if(BROWSER_SMOKE){
    allWorks=[{"id":"000789","t":"吾輩は猫である","a":"夏目 漱石","tk":"わがはいはねこである","ak":"なつめ","d":"1999-09-21","k":1,"c":1,"r":1,"ndc":"NDC 913","norm":"吾輩は猫であるわがはいはねこである夏目漱石なつめ","x":"cards/000148/files/789_ruby_5639/789_ruby_5639.txt"}];
    filterWorks();renderHome();return;
  }

  const safeCatalog=await loadCachedCatalog();
  if(safeCatalog.length){
    allWorks=safeCatalog;
    filterWorks();
    renderHome();
    void refreshCatalogInBackground();
    return;
  }

  // 初回はリポジトリに同梱した catalog.json を最優先で読む。
  // GitHub Pages上では外部配信元よりこちらが安定するため、短いタイムアウトで
  // 一度失敗しただけで「手動読み込み」に落とさない。
  for(let attempt=0;attempt<3;attempt++){
    try{
      const res=await secureFetch('./catalog.json',{signal:sig(15000),cache:attempt===0?'default':'no-store'});
      if(!res.ok)throw new Error('catalog-http-'+res.status);
      const data=await res.json();
      const parsed=sanitizeCatalogRecords(data);
      if(parsed.length>=100){
        allWorks=parsed;
        await idb.set('k',CATALOG_CACHE_KEY,parsed);
        filterWorks();renderHome();
        return;
      }
      throw new Error('catalog-invalid-or-empty');
    }catch(err){
      console.debug('same-origin catalog attempt failed',attempt+1,err);
      if(attempt<2)await new Promise(resolve=>setTimeout(resolve,400*(attempt+1)));
    }
  }

  // 同梱カタログが一時的に取得できない場合だけ、外部配信元を順番に試す。
  // ここでも45秒ではなく最大2分確保し、スマホ回線等の遅延で誤って失敗扱いしない。
  filterWorks();renderHome();
  void fetchCatalog({background:true,notifyOnFail:true});
}
function filterWorks(){
  works = allWorks.filter(w => !dead.has(w.id) && isPublicWork(w));
  byId = new Map(works.map(w => [w.id, w]));
  try{window.dispatchEvent(new Event('aozora-phone-data-ready'));}catch{}
  try{window.__aozoraPhoneRefresh?.();}catch{}
  // カタログ到着前にPC版で検索を開始していても、到着後に同じ条件を自動再実行する。
  try{
    if(document.documentElement.dataset.device!=='smartphone'&&typeof currentView!=='undefined'&&currentView==='v-search'&&(searchState.query||searchState.scope||searchState.filter?.time)){
      applySearch(true);
    }
  }catch{}
}
function openCatalogIntro(){
  const html=`
    <div style="text-align:center; padding:16px 0">
      <h2 style="font-size:var(--fs-h); margin-bottom:8px">作品カタログの導入</h2>
      <p style="color:var(--sub); margin-bottom:20px; font-size:var(--fs-b)">約1.6万作品の目録を端末に保存します (最初の一度だけ必要です)。</p>
      <div style="height:6px; background:var(--card-sub); border-radius:3px; overflow:hidden; margin-bottom:16px"><div id="c-bar" style="width:0; height:100%; background:var(--ac); transition:width .2s"></div></div>
      <div id="c-log" style="font-size:var(--fs-s); color:var(--sub); margin-bottom:24px">準備完了</div>
      <button class="primary" data-act="cat-auto" style="width:100%; height:56px; margin-bottom:12px">自動で読み込む</button>
      <label class="secondary" style="width:100%; height:56px; border-radius:var(--radius-sm); cursor:pointer; display:inline-flex; align-items:center; justify-content:center">ファイルから選択 (.zip/.csv)<input type="file" id="c-file" accept=".zip,.csv" hidden></label>
    </div>`;
  sheet('初期設定', html);
  $('c-file').onchange=e=>parseFile(e.target.files[0]);
}

async function fetchCatalog({background=false,notifyOnFail=false}={}){
  if(catalogBusy)return false;
  catalogBusy=true;
  const trigger=document.querySelector('[data-act="cat-auto"]');
  if(!background)trigger?.setAttribute('disabled','true');
  const bar=$('c-bar'),log=$('c-log');
  if(!background)bar?.classList.add('loading-bar-live');
  if(!background&&log)log.textContent='配信元へ接続中…';
  if(!background&&bar)bar.style.width='20%';
  try{
    let buf=null,csvText=null;
    const catalogDeadline=Date.now()+120000;
    for(let i=0;i<URLS.length&&Date.now()<catalogDeadline;i++){
      if(!background&&log)log.textContent='配信元へ接続中… ('+(i+1)+'/'+URLS.length+')';
      try{
        const remain=Math.max(1000,Math.min(30000,catalogDeadline-Date.now()));
        const res=await secureFetch(URLS[i],{signal:sig(remain)});
        if(!res.ok)continue;
        const b=await readResponseBytes(res,SEC.maxCatalogBytes);
        if(!b||!b.byteLength)continue;
        const u8=new Uint8Array(b);
        if(u8.length>=4&&u8[0]===0x50&&u8[1]===0x4b&&[0x03,0x05,0x07].includes(u8[2])){buf=b;break;}
        const textBody=new TextDecoder('utf-8').decode(b).replace(/^\\uFEFF/,'');
        if(textBody.includes('作品ID')&&textBody.includes('作品名')&&textBody.includes('テキストファイルURL')){csvText=textBody;break;}
      }catch(err){console.debug('catalog source failed',URLS[i],err);}
    }
    if(!buf&&!csvText){
      if(!background&&log)log.textContent='自動取得に失敗しました。ファイルを選択してください。';
      if(notifyOnFail)showCatalogManualNotice();
      else if(!background)toast('自動取得元に接続できませんでした。別の配信元を試しました。');
      return false;
    }
    if(csvText){
      if(!background&&bar)bar.style.width='70%';
      if(!background&&log)log.textContent='CSVを解析中…';
      await parseCsv(csvText,{background});
      return true;
    }
    if(!background&&bar)bar.style.width='50%';
    if(!background&&log)log.textContent='解凍中…';
    const z=await JSZip.loadAsync(buf,{checkCRC32:true});
    const names=Object.keys(z.files);
    const totalUncompressed=names.reduce((sum,n)=>sum+Number(z.files[n]?._data?.uncompressedSize||0),0);
    if(totalUncompressed>SEC.maxCatalogText*2)throw new Error('catalog-uncompressed-too-large');
    if(names.length>60000)throw new Error('catalog-entries-too-many');
    const cf=names.find(n=>n.toLowerCase().endsWith('.csv'));
    if(!cf||!z.files[cf]||z.files[cf].dir)throw new Error('catalog-csv-missing');
    csvText=await z.files[cf].async('string');
    if(csvText.length>SEC.maxCatalogText)throw new Error('catalog-text-too-large');
    await parseCsv(csvText,{background});
    return true;
  }catch(e){
    console.warn('catalog fetch rejected:',e);
    if(!background&&log)log.textContent='カタログの読み込みに失敗しました。';
    if(notifyOnFail)showCatalogManualNotice();
    else if(!background)toast('カタログを読み込めませんでした。時間を置いて再試行してください');
    return false;
  }finally{
    if(!background)bar?.classList.remove('loading-bar-live');
    catalogBusy=false;
    if(!background)trigger?.removeAttribute('disabled');
  }
}
function parseFile(file){
  if(!file) return;
  const r=new FileReader();
  if(file.size>SEC.maxLocalFileBytes){toast('ファイルが大きすぎます（最大30MB）');return;}
  r.onload=async()=>{
    try{
      if(file.name.toLowerCase().endsWith('.zip')){
        const z=await JSZip.loadAsync(r.result,{checkCRC32:true});
        const names=Object.keys(z.files);
        if(names.length>60000)throw new Error('catalog-entries-too-many');
        const totalUncompressed=names.reduce((sum,n)=>sum+Number(z.files[n]?._data?.uncompressedSize||0),0);
        if(totalUncompressed>SEC.maxCatalogText*2)throw new Error('catalog-uncompressed-too-large');
        const cf=names.find(n=>n.toLowerCase().endsWith('.csv'));
        if(!cf||!z.files[cf]||z.files[cf].dir)throw new Error('catalog-csv-missing');
        const txt=await z.files[cf].async('string');
        if(txt.length>SEC.maxCatalogText)throw new Error('catalog-text-too-large');
        await parseCsv(txt,{background:false});
      }else{
        if(typeof r.result!=='string'||r.result.length>SEC.maxCatalogText)throw new Error('catalog-text-too-large');
        await parseCsv(r.result,{background:false});
      }
    }catch(e){
      console.warn('catalog file rejected:',e);
      toast('カタログを安全に読み込めませんでした');
    }
  };
  if(file.name.toLowerCase().endsWith('.zip')) r.readAsArrayBuffer(file); else r.readAsText(file);
}

async function parseCsv(csv,{background=false}={}){
  if(typeof csv!=='string'||csv.length>SEC.maxCatalogText)throw new Error('catalog-text-too-large');
  const cBar=$('c-bar'),cLog=$('c-log');
  if(!background&&cBar)cBar.style.width='70%';
  if(!background&&cLog)cLog.textContent='解析中…';
  const lines=csv.split('\n');
  if(lines.length>20000)throw new Error('catalog-rows-too-many');
  if(!lines.length||lines[0].length>200000)throw new Error('catalog-header-invalid');
  const h=lines[0].split(',').map(s=>s.replace(/^["\uFEFF]|["\r]/g,'').trim()).slice(0,100);
  const col={ id:h.indexOf('作品ID'), t:h.indexOf('作品名'), a:h.indexOf('姓'), am:h.indexOf('名'), tk:h.indexOf('作品名読み'), ak:h.indexOf('姓読み'), x:h.indexOf('テキストファイルURL'), d:h.indexOf('公開日'), k:h.indexOf('文字遣い種別'), c:h.indexOf('作品著作権フラグ'), ndc:h.indexOf('分類番号') };
  const m=new Map();
  const blocked=new Set();

  for(let i=1;i<lines.length;i++){
    const l=lines[i]; if(!l) continue;
    const cols=[]; let c='', q=false;
    for(let j=0;j<l.length;j++){
      const ch=l[j];
      if(q){ if(ch==='"'){ if(l[j+1]==='"'){c+='"';j++;}else q=false; }else c+=ch; }
      else if(ch==='"') q=true;
      else if(ch===','){ cols.push(c); c=''; } else c+=ch;
    }
    cols.push(c);
    const rawId=String(cols[col.id]||'').trim();
    if(blocked.has(rawId))continue;
    const rawUrl=String(cols[col.x]||'').trim();
    let parsedUrl=null;try{parsedUrl=new URL(rawUrl);}catch{}
    if(!rawId||!parsedUrl||parsedUrl.protocol!=='https:'||parsedUrl.hostname!=='www.aozora.gr.jp'||!rawUrl.toLowerCase().endsWith('.zip'))continue;
    if(!safeStateKey(rawId))continue;
    const id=rawId;
    const rightsFlag = cols[col.c];
    const isPublic = rightsFlag === 'なし' || rightsFlag === '1' || rightsFlag === 1 || rightsFlag === '1.0';
    // 作品側・人物側の権利が1行でも保護中なら、その作品ID全体を除外。
    // CSVは1作品に著者・訳者など複数行があり得るため、後続行で保護状態が出ても復活させない。
    const authorRightsFlag = cols[26];
    const authorIsPublic = authorRightsFlag === 'なし' || authorRightsFlag === '1' || authorRightsFlag === 1 || authorRightsFlag === '1.0';
    if(!isPublic || !authorIsPublic){ m.delete(id); blocked.add(id); continue; }
    const author=((cols[col.a]||'')+' '+(cols[col.am]||'')).trim();
    if(m.has(id)){
      const ex=m.get(id);
      if(author&&!ex.a.includes(author)) ex.a+='・'+author;
      continue;
    }
    const t=cols[col.t]||'', tk=(cols[col.tk]||'').toLowerCase(), ak=(cols[col.ak]||'').toLowerCase();
    m.set(id,{
      id, t, a:author, tk, ak, d:cols[col.d]||'',
      k:cols[col.k]?.includes('新字新仮名')?1:0, c:1, r:1,
      ndc:cols[col.ndc]||'',
      norm:(t+' '+tk+' '+author+' '+ak).replace(/[\s　]/g,'').toLowerCase(),
      x:cols[col.x].replace('https://www.aozora.gr.jp/','').replace(/\.zip$/,'').replace(/\/([^\/]+)$/,'/$1/$1.txt').replace(/^\/+|\.\.+/g,'')
    });
    if(i%2500===0){
      if(!background&&cBar)cBar.style.width=(70+Math.round(i/lines.length*28))+'%';
      await new Promise(r=>setTimeout(r,0));
    }
  }
  allWorks=sanitizeCatalogRecords([...m.values()]);
  filterWorks();
  await idb.set('k',CATALOG_CACHE_KEY,allWorks);
  if(cBar)cBar.classList.remove('loading-bar-live');
  if(cBar)cBar.style.width='100%';
  if(cLog)cLog.textContent='完了しました！';
  if(background){renderHome();}else setTimeout(()=>{ closeSheet(); renderHome(); toast('作品カタログを取り込みました'); },400);
}

// 欠落検査 (4並列・自動除外)
let auditIdx=0, auditTimer=null;
function startAudit(){
  if(st.offline||!works.length||document.body.classList.contains('low-power')) return;
  clearInterval(auditTimer);
  auditTimer=setInterval(async()=>{
    if(document.hidden||$('reader').classList.contains('open')) return;
    const w=works[auditIdx++%works.length];
    try {
      const res=await secureFetch(`https://raw.githubusercontent.com/aozorahack/aozorabunko_text/master/${w.x}`,{method:'HEAD',signal:sig(4000)});
      if(res.status===404){
        const r2=await secureFetch(`https://aozorahack.org/aozorabunko_text/${w.x}`,{method:'HEAD',signal:sig(4000)}).catch(()=>null);
        if(!r2||r2.status===404){ dead.add(w.id); filterWorks(); }
      }
    }catch{}
  },120000);
}

/* ==================== 6. ホーム・おすすめ・新機能 ==================== */
let featIdx=0, featTimer=null, featProg=0, featList=[], featQuotes=new Map();
const FAMOUS=['夏目漱石','芥川龍之介','太宰治','宮沢賢治','中島敦','森鴎外','樋口一葉','梶井基次郎','坂口安吾','江戸川乱歩','夢野久作','新美南吉'];

function bookmarkEntriesForHome(){
  const groups=[];
  Object.entries(bm).forEach(([id,arr])=>{
    const w=byId.get(id);
    if(!w||!Array.isArray(arr)||!arr.length)return;
    const clean=arr.filter(x=>x&&Number.isFinite(Number(x.f))).map(x=>({...x,f:Math.max(0,Math.min(1,Number(x.f)))})).sort((a,b)=>(b.t||0)-(a.t||0));
    if(clean.length) groups.push({w,items:clean});
  });
  groups.sort((a,b)=>(b.items[0]?.t||0)-(a.items[0]?.t||0));
  return groups;
}
function renderHomeBookmarks(){
  const box=$('home-bookmarks'),section=$('home-bookmarks-section');
  if(!box||!section)return;
  const groups=bookmarkEntriesForHome();
  section.style.display=groups.length?'block':'none';
  box.style.display=groups.length?'flex':'none';
  if(!groups.length){box.innerHTML='';return;}
  box.innerHTML=groups.slice(0,8).map(g=>{
    const latest=g.items[0],pct=Math.round(latest.f*100);
    return `<button class="home-bookmark-card" data-act="open-bookmark" data-id="${escAttr(g.w.id)}" data-f="${latest.f}">
      <span class="home-bookmark-icon">🔖</span>
      <span class="home-bookmark-text"><strong>${esc(g.w.t)}</strong><small>${esc(g.w.a)} · ${pct}% · ${g.items.length}個</small></span>
      <span class="home-bookmark-arrow" aria-hidden="true">›</span>
    </button>`;
  }).join('');
}

function renderHome(){
  $('home-clock').textContent=new Date().toLocaleTimeString('ja-JP',{hour:'2-digit',minute:'2-digit'});

  if(!allWorks.length) showBanner('作品カタログが未登録です');
  else if(st.ollamaEnabled && !st.offline && !aiConn.ok && canUseOllama()) showBanner('Ollamaが未接続です');
  else $('banner').style.display='none';

  // オンボーディング
  const ob=[];
  if(!allWorks.length) ob.push('① 作品カタログを自動準備中…');
  if(st.ollamaEnabled && !st.offline && !aiConn.ok && canUseOllama()) ob.push('② AI設定 (任意)');
  if(!done.size) ob.push('③ はじめての1冊を読む');
  if(ob.length){ $('blk-onboard').style.display='flex'; $('onboard-items').innerHTML=ob.map(s=>`<div>○ ${s}</div>`).join(''); }
  else $('blk-onboard').style.display='none';

  // 続きを読む
  const rId=hist[0]?.id;
  const rw=rId&&byId.get(rId);
  if(rw&&(pos[rw.id]?.f||0)<0.97){
    const f=pos[rw.id]?.f||0, pct=Math.round(f*100);
    $('res-t').textContent=rw.t; $('res-a').textContent=rw.a;
    $('res-ring').textContent=pct+'%';
    $('res-rem').textContent=`読了まで約${Math.max(1,Math.ceil(((rw.plain?.length||8000)*(1-f))/st.readSpeed))}分`;
    $('blk-resume').dataset.wid=rw.id;
  } else {
    $('res-t').textContent='はじめての一冊'; $('res-a').textContent='おすすめから選ぶ';
    $('res-ring').textContent='0%'; $('res-rem').textContent='読了まで約--分';
    $('blk-resume').dataset.wid='';
  }

  renderHomeBookmarks();

  // 最近読んだ本 (最大5冊)
  const recentWorks=hist.slice(0,5).map(h=>byId.get(h.id)).filter(Boolean);
  if(recentWorks.length>0){
    $('blk-recent').style.display='block';
    $('recent-scroll').innerHTML=recentWorks.map(w=>`
      <div class="recent-book" data-act="open-book" data-id="${escAttr(w.id)}" style="--book-color:${colorOf(w.t)}">
        <div class="recent-book-cover">
          <div class="recent-book-title serif">${esc(w.t)}</div>
        </div>
        <div class="recent-book-meta">
          <div>${esc(w.t)}</div>
          <span>${esc(w.a)}</span>
        </div>
      </div>
    `).join('');
  } else {
    $('blk-recent').style.display='none';
  }

  // 読書チャレンジ計算
  const todayKey=localDateKey();
  const todayMin=calData[todayKey]||0;
  const chalPct=Math.min(100, Math.round((todayMin / goalMin)*100));
  $('chal-pct-txt').textContent=chalPct+'%';
  $('chal-pbar').style.width=chalPct+'%';
  $('chal-goal-title').textContent=`今日は${goalMin}分読もう`;
  $('chal-rem-txt').textContent=todayMin>=goalMin?'今日の目標を達成しました！':`あと ${goalMin - todayMin}分 で達成`;
  $('home-today-info').textContent=`今日の読書: ${todayMin}分 · 目標達成率 ${chalPct}%`;

  // 読書統計
  const uniqueBooks=new Set(hist.map(h=>h.id)).size;
  $('st-total-books').textContent=uniqueBooks;
  $('st-done-books').textContent=done.size;
  let totalMin=0; Object.values(calData).forEach(m=>totalMin+=m);
  $('st-total-time').textContent=totalMin+'分';
  renderInsightBar();
  
  // 連続日数
  const dates=Object.keys(calData).filter(k=>calData[k]>0).sort();
  let streak=0;
  if(dates.length){
    let curD=new Date();
    let curKey=dateKeyOf(curD);
    if(!calData[curKey]){
      curD.setDate(curD.getDate()-1);
      curKey=dateKeyOf(curD);
    }
    while(calData[curKey]>0){
      streak++;
      curD.setDate(curD.getDate()-1);
      curKey=dateKeyOf(curD);
    }
  }
  $('st-streak').textContent=streak+'日';

  // スマートおすすめ
  initSmartRec();

  // 今日の一冊固定 または 12選巡回
  const todayStr=localDateKey();
  if(st.todayBook && st.todayBook.date === todayStr && byId.has(st.todayBook.id)){
    const w = byId.get(st.todayBook.id);
    featList = [w];
    featIdx = 0;
    $('feat-badge-lbl').textContent = '本日固定の一冊';
    $('btn-feat-pin').textContent = '固定を解除';
    renderFeatItem();
  } else {
    $('feat-badge-lbl').textContent = '今日のおすすめ';
    $('btn-feat-pin').textContent = '今日の一冊に固定';
    if(!featList.length && works.length){
      const d=new Date(), seed=d.getFullYear()*10000+(d.getMonth()+1)*100+d.getDate();
      const pop=works.filter(w=>w.k&&w.c&&FAMOUS.some(a=>w.a.includes(a)));
      const rem=works.filter(w=>w.k&&w.c&&!pop.includes(w));
      featList=[];
      for(let i=0;i<8&&pop.length;i++) featList.push(pop.splice(Math.abs(seed*(i+1)*17)%pop.length,1)[0]);
      for(let i=0;i<4&&rem.length;i++) featList.push(rem.splice(Math.abs(seed*(i+1)*97)%rem.length,1)[0]);
      renderFeatItem();
    }
  }

  $('blk-fav-cnt').textContent=`${fav.size} 件`;
  $('blk-fav-authors-cnt').textContent=`${favAuthors.size} 名`;
  $('blk-want-cnt').textContent=`${want.size} 件`;
  let nCnt=0; Object.values(notes).forEach(arr=>nCnt+=arr.length); Object.values(hls).forEach(arr=>nCnt+=arr.length);
  $('blk-note-cnt').textContent=`${nCnt} 件`;
  
  const aiAvailable = st.ollamaEnabled && aiConn.ok && canUseOllama();
  if(!st.ollamaEnabled){
    $('set-dot').style.display='none';
    $('set-st-txt').textContent='OFF';
  } else {
    $('set-dot').style.display='block';
    $('set-dot').style.background=aiAvailable ? '#28a745' : '#d9534f';
    $('set-st-txt').textContent=aiAvailable ? '接続中' : '未接続';
  }
  
  // AIボタン・関連UIの自動表示制御
  document.querySelectorAll('.ai-feature').forEach(el=>{
    el.style.display = aiAvailable ? '' : 'none';
  });
}

function initSmartRec(){
  if(!works.length) return;
  const authorCounts={};
  hist.forEach(h=>{
    const w=byId.get(h.id);
    if(w) authorCounts[w.a]=(authorCounts[w.a]||0)+1;
  });
  favAuthors.forEach(a=>{ authorCounts[a] = (authorCounts[a]||0) + 3; });

  const topAuthor=Object.entries(authorCounts).sort((a,b)=>b[1]-a[1])[0]?.[0];
  let candidate=null;
  let reason='人気の名作から選出';

  if(topAuthor){
    const authorWorks=works.filter(w=>w.a===topAuthor && !hist.some(h=>h.id===w.id));
    if(authorWorks.length){
      candidate=authorWorks[0];
      reason=`お気に入り・愛読作家「${topAuthor}」の作品`;
    }
  }
  if(!candidate){
    const shortWorks=works.filter(w=>((w.plain?.length||8000)/st.readSpeed)<=15 && !hist.some(h=>h.id===w.id));
    if(shortWorks.length){
      const seed=Number(localDateKey().replace(/-/g,''))||1;
      candidate=shortWorks[seed%shortWorks.length];
      reason='サクッと読める短編作品';
    } else {
      candidate=works[0];
    }
  }

  $('smart-t').textContent=candidate.t;
  $('smart-reason').textContent=reason;
  $('blk-smart-rec').dataset.id=candidate.id;
}

function renderFeatItem(){
  if(!featList.length)return;
  const w=featList[featIdx], body=$('feat-body');
  if(body&&!document.body.classList.contains('low-power')){
    body.classList.remove('content-swap'); void body.offsetWidth; body.classList.add('content-swap');
  }
  $('feat-dots').innerHTML=featList.map((_,i)=>`<div style="width:8px; height:8px; border-radius:50%; background:${i===featIdx?'var(--ac)':'var(--card-sub)'}"></div>`).join('');
  $('feat-t').textContent=w.t; $('feat-a').textContent=w.a;
  $('feat-genre').textContent=w.ndc?`NDC ${w.ndc.match(/\d{3}/)?.[0]||''}`:'名作';
  $('feat-time').textContent=`約${Math.max(1,Math.ceil((w.plain?.length||8000)/st.readSpeed))}分`;
  
  if(featQuotes.has(w.id)) $('feat-q').textContent=featQuotes.get(w.id);
  else {
    $('feat-q').textContent='冒頭を取得中…';
    fetchHead(w).then(q=>{ featQuotes.set(w.id,q); if(featList[featIdx]?.id===w.id) $('feat-q').textContent=q; });
  }
}

function startFeatTimer(){
  clearInterval(featTimer);
  featTimer=null;
  featProg=0;
  if(document.body.classList.contains('low-power')) return;
  featTimer=setInterval(()=>{
    if(layers.length||document.hidden||!featList.length||featList.length===1) return;
    featProg+=100/15;
    const el=$('feat-timer'); if(el) el.style.width=featProg+'%';
    if(featProg>=100){
      featProg=0;
      featIdx=(featIdx+1)%featList.length;
      renderFeatItem();
    }
  },2000);
}

function showBanner(msg){
  const banner=$('banner');
  const text=$('ban-txt');
  const btn=banner?.querySelector('[data-act="ban-btn"]');
  if(text)text.textContent=msg;
  if(banner){
    banner.dataset.reason='';
    banner.style.display='flex';
  }
  if(btn)btn.textContent='確認';
}
function showCatalogManualNotice(){
  const banner=$('banner');
  const text=$('ban-txt');
  const btn=banner?.querySelector('[data-act="ban-btn"]');
  if(text)text.textContent='カタログの自動読み込みに失敗しました。設定からファイルを手動で読み込めます。';
  if(banner){banner.dataset.reason='catalog-manual';banner.style.display='flex';}
  if(btn)btn.textContent='手動で読み込む';
}

/* ==================== 7. 探す (分離・完全検索パイプライン) ==================== */
let searchPool=[], searchCursor=0;
const GENRES=[{n:'小説',c:'913'},{n:'童話',c:'童話'},{n:'詩歌',c:'911'},{n:'随筆',c:'914'},{n:'評論',c:'910'},{n:'戯曲',c:'912'}];
const KANA=['あ','か','さ','た','な','は','ま','や','ら','わ'];

function openSearchPage(){
  if(document.documentElement.dataset.device==='smartphone'&&typeof window.__aozoraPhoneShowScreen==='function'){
    window.__aozoraPhoneShowScreen('search');
    return;
  }
  switchView('v-search');
  renderSearchInit();
  $('q-input').focus();
}

function renderSearchInit(){
  $('genre-grid').innerHTML=GENRES.map(g=>`<div class="block" data-act="g-pick" data-c="${g.c}" style="min-height:72px; padding:16px"><div style="font-size:var(--fs-t); font-weight:700">${g.n}</div></div>`).join('');
  $('kana-chips').innerHTML=KANA.map(k=>`<button data-act="k-pick" data-k="${k}" class="secondary sm-btn">${k}行</button>`).join('');

  if(searchHistory.length>0){
    $('search-hist-section').style.display='block';
    $('search-hist-chips').innerHTML=searchHistory.map(term=>`
      <button class="secondary sm-btn" data-act="search-hist-pick" data-val="${esc(term)}">${esc(term)}</button>
    `).join('');
  } else {
    $('search-hist-section').style.display='none';
  }
}

function applySearch(reset=true){
  const summary=$('search-result-summary');
  if(reset){
    searchCursor=0;
    $('search-tiles').innerHTML='';
    if(summary){summary.classList.remove('show');summary.textContent='';}
  }

  const q=searchState.query.trim().toLowerCase().replace(/[\s　]/g,'');
  $('q-clear').style.display=q?'block':'none';

  const hasScope=!!searchState.scope;
  const hasQuery=!!q;
  const hasTimeFilter=!!searchState.filter.time;

  if(!hasScope && !hasQuery && !hasTimeFilter && !searchState.filter.saved){
    $('search-init-box').style.display='block';
    $('search-results-area').style.display='none';
    $('search-scope-bar').style.display='none';
    return;
  }

  $('search-init-box').style.display='none';
  $('search-results-area').style.display='block';

  if(hasScope){
    $('search-scope-bar').style.display='flex';
    $('search-scope-text').textContent=`${searchState.scope.label}`;
  } else {
    $('search-scope-bar').style.display='none';
  }

  let list=[...works];

  if(searchState.scope){
    const s=searchState.scope;
    if(s.type==='genre'){
      if(s.value==='童話'){
        list=list.filter(w=>w.t.includes('童話')||w.t.includes('昔話')||/宮沢賢治|新美南吉|小川未明|アンデルセン|グリム/.test(w.a)||/K913|K933/.test(w.ndc));
      } else {
        list=list.filter(w=>w.ndc&&w.ndc.includes(s.value));
      }
    } else if(s.type==='kana'){
      const KANA_MAP={
        'あ':'^[あ-おア-オアイウエオぁ-ぉァ-ォ]',
        'か':'^[か-こカ-コが-ごガ-ゴ]',
        'さ':'^[さ-そサ-ソざ-ぞザ-ゾ]',
        'た':'^[た-とタ-トだ-どダ-ドっッ]',
        'な':'^[な-のナ-ノ]',
        'は':'^[は-ほハ-ホば-ぼバ-ボぱ-ぽパ-ポ]',
        'ま':'^[ま-もマ-モ]',
        'や':'^[や-よヤ-ヨゃ-ょャ-ョ]',
        'ら':'^[ら-ろラ-ロ]',
        'わ':'^[わ-んワ-ン]'
      };
      const pat=KANA_MAP[s.value]||`^[${escRe(s.value)}]`;
      const reg=new RegExp(pat,'i');
      list=list.filter(w=>reg.test(w.ak));
    } else if(s.type==='author'){
      list=list.filter(w=>w.a.includes(s.value));
    } else if(s.type==='favAuthors'){
      list=list.filter(w=>favAuthors.has(w.a));
    } else if(s.type==='new'){
      list.sort((a,b)=>(b.d||'').localeCompare(a.d||''));
    }
  }

  if(hasQuery){
    list=list.filter(w=>w.norm.includes(q));
    if(reset && !searchHistory.includes(searchState.query.trim())){
      searchHistory.unshift(searchState.query.trim());
      if(searchHistory.length>5) searchHistory.pop();
      save();
    }
  }

  if(searchState.filter.saved) list=list.filter(w=>savedKeys.has(w.id));

  if(searchState.filter.time){
    const tf=searchState.filter.time;
    list=list.filter(w=>{
      const m=Math.max(1,Math.ceil((w.plain?.length||8000)/st.readSpeed));
      if(tf==='t10') return m<=10;
      if(tf==='t30') return m<=30;
      if(tf==='tOver') return m>30;
      return true;
    });
  }

  const sm=searchState.sort;
  if(sm==='new') list.sort((a,b)=>(b.d||'').localeCompare(a.d||''));
  else if(sm==='old') list.sort((a,b)=>(a.d||'').localeCompare(b.d||''));
  else if(sm==='t') list.sort((a,b)=>(a.tk||a.t).localeCompare(b.tk||b.t,'ja'));
  else if(sm==='a') list.sort((a,b)=>(a.ak||a.a).localeCompare(b.ak||b.a,'ja'));

  searchPool=list;

  if(hasScope) $('search-scope-text').textContent=`${searchState.scope.label} (${searchPool.length}件)`;
  if(summary){
    const descriptor=hasQuery?`「${searchState.query.trim()}」`:hasScope?(searchState.scope?.label||'絞り込み'):'条件';
    summary.textContent=`${descriptor} · ${searchPool.length.toLocaleString('ja-JP')}件`;
    summary.classList.add('show');
  }

  const chunk=searchPool.slice(searchCursor,searchCursor+40);
  searchCursor+=40;

  if(!searchPool.length){
    $('search-tiles').innerHTML='';
    $('search-empty-msg').style.display='block';
  } else {
    $('search-empty-msg').style.display='none';
    $('search-tiles').insertAdjacentHTML('beforeend',rows(chunk,w=>tileHtml(w)));
      watchBookCovers($('search-tiles'));
  }
}

// 本棚タブ & 読書タイムライン
let curShelf='reading';
function renderShelf(){
  $('shelf-timeline-area').style.display='none';
  $('shelf-tiles').style.display='grid';

  let l=[];
  if(curShelf==='reading') l=works.filter(w=>(pos[w.id]?.f||0)>0&&(pos[w.id]?.f||0)<0.97);
  else if(curShelf==='want') l=works.filter(w=>want.has(w.id));
  else if(curShelf==='done') l=works.filter(w=>done.has(w.id));
  else if(curShelf==='fav') l=works.filter(w=>fav.has(w.id));
  else if(curShelf==='notes') { renderNotesShelf(); return; }
  else if(curShelf==='timeline') { renderTimelineShelf(); return; }

  $('shelf-empty').style.display=l.length?'none':'block';
  $('shelf-tiles').innerHTML=rows(l,w=>tileHtml(w));
  if(!document.body.classList.contains('low-power')){
    const shelfGrid=$('shelf-tiles');
    shelfGrid.classList.remove('shelf-reflow');
    void shelfGrid.offsetWidth;
    shelfGrid.classList.add('shelf-reflow');
  }
  watchBookCovers($('shelf-tiles'));
}

function renderTimelineShelf(){
  $('shelf-tiles').style.display='none';
  const ta=$('shelf-timeline-area');
  ta.style.display='flex';
  ta.innerHTML='';

  const events=[];
  hist.forEach(h=>{
    const w=byId.get(h.id);
    if(w) events.push({ date:h.t, type:(pos[w.id]?.f||0)>=0.97?'読了':'読書', title:w.t, desc:`${w.a} · 進捗 ${Math.round((pos[w.id]?.f||0)*100)}%`, id:w.id, frac:pos[w.id]?.f||0 });
  });
  Object.entries(bm).forEach(([id,arr])=>{
    const w=byId.get(id);
    if(w) arr.forEach(b=>events.push({ date:b.t, type:'栞', title:w.t, desc:`「${b.s}」`, id:w.id, frac:b.f }));
  });
  Object.entries(notes).forEach(([id,arr])=>{
    const w=byId.get(id);
    if(w) arr.forEach(n=>events.push({ date:n.t, type:'メモ', title:w.t, desc:`${n.m} (「${n.s}」)`, id:w.id }));
  });

  events.sort((a,b)=>b.date-a.date);

  if(!events.length){
    ta.innerHTML='<div style="text-align:center; padding:40px; color:var(--sub)">記録はまだありません</div>';
    return;
  }

  ta.innerHTML=events.slice(0,40).map(ev=>`
    <div class="timeline-item" data-act="open-book" data-id="${escAttr(ev.id)}">
      <div class="timeline-dot"></div>
      <div style="flex:1">
        <div style="display:flex; justify-content:space-between">
          <span class="badge" style="background:var(--ac); color:#fff">${ev.type}</span>
          <span style="font-size:var(--fs-s); color:var(--sub)">${new Date(ev.date).toLocaleDateString()}</span>
        </div>
        <div style="font-weight:700; font-size:var(--fs-b); margin-top:4px">${esc(ev.title)}</div>
        <div style="font-size:var(--fs-s); color:var(--sub)">${esc(ev.desc)}</div>
      </div>
    </div>
  `).join('');
}

function renderNotesShelf(){
  const all=[];
  Object.entries(bm).forEach(([id,arr])=>arr.forEach((it,i)=>all.push({id,t:'栞',kind:'bookmark',i,txt:it.s||'この位置',f:it.f,d:Number(it.t)||0})));
  Object.entries(notes).forEach(([id,arr])=>arr.forEach((it,i)=>all.push({id,t:'メモ',kind:'memo',i,txt:it.m||'',d:Number(it.t)||0})));
  Object.entries(hls).forEach(([id,arr])=>arr.forEach((it,i)=>all.push({id,t:'蛍光ペン',kind:'highlight',i,txt:it.t||'',c:it.c,d:Number(it.d)||0})));
  all.sort((a,b)=>b.d-a.d);

  $('shelf-empty').style.display=all.length?'none':'block';
  $('shelf-tiles').innerHTML=all.map(n=>{
    const w=byId.get(n.id); if(!w) return '';
    const color=n.kind==='highlight'?(n.c||'var(--ac)'):'var(--ac)';
    return `
      <div class="block record-tile" data-act="open-book" data-id="${escAttr(w.id)}" style="min-height:100px; padding:16px">
        <div style="display:flex; justify-content:space-between; align-items:center; gap:8px">
          <span class="badge" style="background:${escAttr(color)}; color:#fff">${n.t}</span>
          <div style="display:flex; align-items:center; gap:6px">
            <span style="font-size:var(--fs-s); color:var(--sub); overflow:hidden; text-overflow:ellipsis; white-space:nowrap">${esc(w.t)}</span>
            <button class="secondary sm-btn record-delete" data-act="delete-record" data-id="${escAttr(w.id)}" data-kind="${n.kind}" data-index="${n.i}" aria-label="${n.t}を削除" title="${n.t}を削除">削除</button>
          </div>
        </div>
        <div style="font-size:var(--fs-b); font-weight:700; margin-top:8px">${esc(n.txt)}</div>
      </div>`;
  }).join('');
}

function removeStoredRecord(kind,id,index){
  const stores={bookmark:bm,memo:notes,highlight:hls};
  const store=stores[kind], arr=store?.[id];
  if(!Array.isArray(arr)||!Number.isInteger(index)||index<0||index>=arr.length)return false;
  arr.splice(index,1);
  if(!arr.length) delete store[id];
  return true;
}

// 本の詳細シート
function openBookDetail(w){
  if(document.documentElement.dataset.device==='smartphone'&&typeof window.__aozoraPhoneOpenDetail==='function'){
    window.__aozoraPhoneOpenDetail(w);
    return;
  }
  activeBook=w;
  const isF=fav.has(w.id), isW=want.has(w.id), isS=savedKeys.has(w.id), isFA=favAuthors.has(w.a);
  const isDone=(pos[w.id]?.f||0)>=0.97;
  const estM=Math.max(1,Math.ceil((w.plain?.length||8000)/st.readSpeed));

  let nextRecHtml='';
  if(isDone){
    const nextCandidates=works.filter(x=>x.id!==w.id&&(x.a===w.a||(w.ndc&&x.ndc===w.ndc)));
    const nextWork=nextCandidates[Math.floor(Math.random()*nextCandidates.length)];
    if(nextWork){
      nextRecHtml=`
        <div style="padding:16px; background:var(--c-blue); border-radius:var(--radius-sm); margin-top:8px">
          <div style="font-size:var(--fs-s); font-weight:700; color:var(--ac); margin-bottom:4px">読了！ 次におすすめの一冊</div>
          <div style="font-weight:700; font-size:var(--fs-b); cursor:pointer" data-act="open-book" data-id="${escAttr(nextWork.id)}">${esc(nextWork.t)} (${esc(nextWork.a)}) ›</div>
        </div>`;
    }
  }

  const html=`
    <div style="display:flex; flex-direction:column; gap:16px">
      <div>
        <h2 class="serif" style="font-size:var(--fs-xl); line-height:1.2; margin-bottom:6px">${esc(w.t)}</h2>
        <div style="display:flex; align-items:center; gap:8px">
          <span style="font-size:var(--fs-t); color:var(--ac); font-weight:700; cursor:pointer" data-act="open-author-page" data-author="${esc(w.a)}">${esc(w.a)} ›</span>
          <button class="secondary sm-btn" data-act="toggle-fav-author" data-author="${esc(w.a)}" style="height:32px; padding:0 8px; font-size:12px">${isFA?'★ 推し作家':'☆ 作家フォロー'}</button>
        </div>
        <div style="display:flex; gap:6px; margin-top:8px">
          <span class="badge">${esc(w.d||'公開日不明')}</span>
          <span class="badge">目安 ${estM}分</span>
          ${isS?'<span class="badge" style="background:var(--ac); color:#fff">保存済み</span>':''}
          ${isDone?'<span class="badge" style="background:#28a745; color:#fff">読了</span>':''}
        </div>
      </div>
      <div style="display:flex; gap:8px">
        <button class="primary" data-act="read-now" style="flex:2">読む</button>
        <button class="secondary" data-act="toggle-want" style="flex:1">${isW?'読みたい済':'＋読みたい'}</button>
        <button class="secondary" data-act="toggle-fav" style="flex:1">${isF?'★':'☆'}</button>
      </div>
      ${nextRecHtml}
      <div id="b-quote" style="padding:16px; background:var(--card-sub); border-radius:var(--radius-sm); font-size:var(--fs-b); line-height:1.6; color:var(--sub)">冒頭を読み込んでいます…</div>
    </div>`;
  sheet(w.t, html);
  fetchHead(w).then(q=>{
    const el=$('b-quote');
    if(el){el.textContent=q;el.classList.remove('book-quote-loading');el.setAttribute('aria-busy','false');}
  });
}

/* ==================== 8. 本文取得 & パース ==================== */
async function fetchHead(w){
  if(!w||!isPublicWork(w))return 'この作品はアプリの公開対象外です。';
  if(typeof w.id!=='string'||!safeStateKey(w.id)||typeof w.x!=='string'||w.x.length>500||w.x.includes('..')||w.x.includes('\\')||w.x.startsWith('http'))return '本文の取得をお試しください。';
  const c=await idb.get('docs',w.id);
  if(c&&typeof c==='object'&&typeof c.plain==='string'&&c.plain.length<=SEC.maxBookBytes/2)return c.plain.slice(0,90);
  const urls=buildBodyUrlCandidates(w);
  for(const u of urls){
    try{
      const res=await secureFetch(u,{headers:{'Range':'bytes=0-3500'},signal:sig(5000)});
      if(!res.ok)continue;
      const b=await readResponseBytes(res,SEC.maxResponseHeadBytes);
      if(!b)continue;
      const t=new TextDecoder('shift_jis').decode(b);
      const q=parseAozora(t,true).plain.slice(0,90);
      if(q.trim())return q;
    }catch{}
  }
  return '本文の取得をお試しください。';
}

let readerTok=0;
let readerLoadingWorkId='';
/* 本文が正常に描画された読書セッションだけ進捗を保存する。
   取得失敗時のエラー画面を「100%読了」として保存しない。 */
let desktopReaderContentReady=false;
let phoneReaderContentReady=false;
function buildBodyUrlCandidates(w){
  if(!w||typeof w.x!=='string')return [];
  const path=String(w.x).replace(/^\/+|\s+$/g,'');
  if(!path||path.length>500||path.includes('..')||path.includes('\\')||path.startsWith('http'))return [];
  const official=`https://www.aozora.gr.jp/${path}`;
  const raw=`https://raw.githubusercontent.com/aozorahack/aozorabunko_text/master/${path}`;
  const mirror=`https://aozorahack.org/aozorabunko_text/${path}`;
  const proxy1=`https://corsproxy.io/?url=${encodeURIComponent(official)}`;
  const proxy2=`https://corsproxy.org/?url=${encodeURIComponent(official)}`;
  const proxy3=`https://api.allorigins.win/raw?url=${encodeURIComponent(official)}`;
  // raw/mirrorを先に試し、公式→CORSプロキシへ段階的にフォールバック。
  return [...new Set([raw,mirror,official,proxy1,proxy2,proxy3])];
}

async function fetchBody(w){
  if(!w||!isPublicWork(w))throw new Error('protected-work');
  if(BROWSER_SMOKE){
    const plain='これは長文スモークテスト用の本文です。ローダー隔離、段階的描画、ページ化、スクロール、戻る操作を検証します。';
    const count=2200;
    const paragraphs=Array.from({length:count},(_,i)=>'<p>'+plain+' テスト段落'+(i+1)+'です。長い青空文庫作品を想定した十分な本文量で、メインスレッドを占有し続けない描画を検証します。</p>').join('');
    const text=Array.from({length:count},(_,i)=>plain+' テスト段落'+(i+1)+'です。長い青空文庫作品を想定した十分な本文量で、メインスレッドを占有し続けない描画を検証します。').join('\n');
    return {html:'<h2 data-hid="h-1">スモークテスト本文</h2>'+paragraphs,plain:text};
  }
  if(typeof w.id!=='string'||!safeStateKey(w.id)||typeof w.x!=='string'||w.x.length>500||w.x.includes('..')||w.x.includes('\\')||w.x.startsWith('http'))throw new Error('invalid-book-path');
  const c=await idb.get('docs',w.id);
  if(c&&typeof c==='object'&&typeof c.html==='string'&&c.html.length<=4*1024*1024){
    if(c.safe===2&&typeof c.plain==='string'&&c.plain.length<=SEC.maxBookBytes&&c.plain.trim().length>=20)return c;
    try{await idb.del('docs',w.id);}catch{}
  }
  if(st.offline) throw new Error('オフラインです');
  const urls=buildBodyUrlCandidates(w);
  let buf=null, notFoundCount=0, attempted=0;
  // 本文取得は「同じ作品を複数経路」で確認する。1経路のCORS/一時障害で作品を死蔵しない。
  const bodyDeadline=Date.now()+45000;
  for(const u of urls){
    if(Date.now()>=bodyDeadline)break;
    attempted++;
    try{
      const remain=Math.max(1500,Math.min(9000,bodyDeadline-Date.now()));
      const res=await secureFetch(u,{signal:sig(remain)});
      if(res.status===404){notFoundCount++;continue;}
      if(!res.ok)continue;
      const b=await readResponseBytes(res,SEC.maxBookBytes);
      if(b&&b.byteLength>=200){buf=b;break;}
    }catch(err){
      console.debug('book source failed',u,err);
    }
  }
  if(!buf){
    // すべての経路で404だった場合だけ「存在しない作品」と判断する。
    // CORS/タイムアウト等の通信失敗では作品をcatalogから除外しない。
    if(attempted>0 && notFoundCount===attempted){
      dead.add(w.id); filterWorks(); save(); throw {dead:true};
    }
    throw new Error('通信エラーが発生しました。本文の配信元を切り替えて再試行してください。');
  }
  const parsed=await parseAozoraAsync(buf.buffer.slice(buf.byteOffset,buf.byteOffset+buf.byteLength));
  const html=parsed.html,plain=parsed.plain;
  const doc={html,plain,safe:2};
  await idb.set('docs',w.id,doc);
  savedKeys.add(w.id);
  return doc;
}

let readerParseSeq=0;
let activeReaderParserWorker=null;
function cancelReaderParser(){
  if(!activeReaderParserWorker)return;
  try{activeReaderParserWorker.terminate();}catch{}
  activeReaderParserWorker=null;
}
function parseAozoraAsync(buffer){
  return new Promise((resolve,reject)=>{
    cancelReaderParser();
    const id=++readerParseSeq;
    let settled=false,worker=null;
    const finish=(fn,val)=>{if(settled)return;settled=true;try{worker?.terminate()}catch{}if(activeReaderParserWorker===worker)activeReaderParserWorker=null;fn(val)};
    try{
      worker=new Worker('./reader-worker.js');
      activeReaderParserWorker=worker;
      worker.onmessage=e=>{
        const d=e.data||{};if(d.id!==id)return;
        if(d.ok&&typeof d.html==='string'&&typeof d.plain==='string')finish(resolve,{html:d.html,plain:d.plain,safe:2});
        else finish(reject,new Error(d.error||'本文解析に失敗しました'));
      };
      worker.onerror=e=>finish(reject,new Error(e.message||'本文解析ワーカーを起動できませんでした'));
      worker.postMessage({id,buffer},[buffer]);
    }catch(e){finish(reject,e)}
  });
}

let midashiSeq=0;
function parseAozora(raw,withPlain=false){
  midashiSeq=0;
  let t=String(raw||'').replace(/\r\n?/g,'\n');
  const ls=t.split('\n'),d=[];
  ls.forEach((l,i)=>{if(/^-{20,}$/.test(l)&&i<60)d.push(i);});
  t=d.length>=2?ls.slice(d[1]+1).join('\n'):ls.slice(2).join('\n');

  let sourceInfo='';
  const sourceIndex=t.search(/\n底本：/);
  if(sourceIndex>0){sourceInfo=t.slice(sourceIndex).trim();t=t.slice(0,sourceIndex);}

  let plain='';
  if(withPlain){
    plain=t
      .replace(/[０-９]/g,s=>String.fromCharCode(s.charCodeAt(0)-0xFEE0))
      .replace(/｜([^《\n]+)《([^》\n]+)》/g,'$1')
      .replace(/([\u4E00-\u9FFF々〆ヶ〇]+)《([^》\n]+)》/g,'$1')
      .replace(/［＃[^］]*］/g,'')
      .replace(/[ \t]+\n/g,'\n')
      .trim();
  }

  t=t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
   .replace(/[０-９]/g,s=>String.fromCharCode(s.charCodeAt(0)-0xFEE0))
   .replace(/｜([^《\n]+)《([^》\n]+)》/g,'<ruby>$1<rt>$2</rt></ruby>')
   .replace(/([\u4E00-\u9FFF々〆ヶ〇]+)《([^》\n]+)》/g,'<ruby>$1<rt>$2</rt></ruby>')
   .replace(/［＃「([^」]+)」に傍点］/g,'<em class="em">$1</em>')
   .replace(/［＃傍点］(.*?)［＃傍点終わり］/g,'<em class="em">$1</em>')
   .replace(/［＃「([^」]+)」に傍線］/g,'<u>$1</u>')
   .replace(/［＃太字］(.*?)［＃太字終わり］/g,'<b>$1</b>')
   .replace(/［＃大見出し］([^\n]+)/g,(_,line)=>`<h2 class="serif" data-hid="h-${midashiSeq++}">${line}</h2>`)
   .replace(/［＃中見出し］([^\n]+)/g,(_,line)=>`<h3 class="serif" data-hid="h-${midashiSeq++}">${line}</h3>`)
   .replace(/［＃(改ページ|改丁)］/g,'<hr class="aozora-page-break">')
   .replace(/［＃[^］]*］/g,'');

  // 改行は<BR>要素に展開せず、そのまま保持してCSSのpre-wrapで表示する。
  let html=t;
  if(sourceInfo){
    html+=`<section class="aozora-source-info" aria-label="青空文庫 作品情報"><div class="aozora-source-title">青空文庫 作品情報</div><pre>${esc(sourceInfo)}</pre></section>`;
  }
  return withPlain?{html,plain}:html;
}

function toPlain(h){ const d=document.createElement('div'); d.innerHTML=h.replace(/<br>/g,'\n'); d.querySelectorAll('rt').forEach(x=>x.remove()); return d.textContent||''; }

/* ==================== 9. 読書画面 & 表示 ==================== */
let curDoc=null, curWork=null;
let wakeLock=null, wakeLockWanted=false, catalogBusy=false, ollamaPingController=null, readingMinuteTimer=null;

function setBootStage(percent,text){
  const p=Math.max(0,Math.min(100,percent));
  const fill=$('boot-fill'), stage=$('boot-stage'), pct=$('boot-percent');
  if(fill)fill.style.width=p+'%';
  if(pct)pct.textContent=Math.round(p)+'%';
  if(stage)stage.textContent=text;
}
function bindMobileUx(){
  const body=$('body');
  const reader=$('reader');
  const page=$('body');
  if(!body||!reader||!page||page.dataset.uxBound)return;
  page.dataset.uxBound='1';
  let raf=0;
  page.addEventListener('scroll',()=>{
    if(raf)return;
    raf=requestAnimationFrame(()=>{
      raf=0;
      const max=page.scrollHeight-page.clientHeight;
      const p=max>0?page.scrollTop/max:0;
      reader.style.setProperty('--read-scroll-progress',String(Math.max(0,Math.min(1,p))));
      const bar=$('r-scroll-progress');
      if(bar)bar.style.transform=`scaleX(${p})`;
    });
  },{passive:true});
  let lastY=0, ticking=false;
  page.addEventListener('touchstart',e=>{lastY=e.touches[0]?.clientY||0},{passive:true});
  page.addEventListener('touchmove',e=>{
    const y=e.touches[0]?.clientY||lastY,dy=y-lastY;lastY=y;
    if(Math.abs(dy)<4||ticking)return;
    ticking=true;
    requestAnimationFrame(()=>{
      ticking=false;
      if(page.scrollTop>28){
        if(dy<0)reader.classList.add('reader-scrolled');
        else if(dy>0)reader.classList.remove('reader-scrolled');
      }else reader.classList.remove('reader-scrolled');
    });
  },{passive:true});
}

function finishBoot(){
  setBootStage(100,'準備完了');
  const boot=$('app-boot');
  if(boot){
    boot.classList.add('done');
    window.setTimeout(()=>boot.remove(),420);
  }
}
async function requestScreenWakeLock(){
  const desktopReaderOpen=!!$('reader')?.classList.contains('open');
  const phoneReaderOpen=document.documentElement.dataset.device==='smartphone'&&!!$('phone-reader')?.classList.contains('phone-open');
  if(!wakeLockWanted||(!desktopReaderOpen&&!phoneReaderOpen))return;
  if(!('wakeLock' in navigator)){toast('この端末では画面維持に対応していません');return;}
  try{
    if(wakeLock)return;
    wakeLock=await navigator.wakeLock.request('screen');
    wakeLock.addEventListener('release',()=>{
      wakeLock=null;
      updateWakeButton();
    },{once:true});
    updateWakeButton();
  }catch(e){
    wakeLock=null;
    updateWakeButton();
    if(e?.name!=='AbortError')toast('画面維持を開始できませんでした');
  }
}
async function releaseScreenWakeLock(){
  wakeLockWanted=false;
  if(wakeLock){
    try{await wakeLock.release();}catch{}
    wakeLock=null;
  }
  updateWakeButton();
}
function updateWakeButton(){
  const b=$('btn-r-wake');
  if(!b)return;
  b.classList.toggle('is-on',!!wakeLock);
  b.setAttribute('aria-pressed',wakeLock?'true':'false');
  b.setAttribute('aria-label',wakeLock?'画面維持中':'画面維持');
  if(b.lastChild&&b.lastChild.nodeType===3)b.lastChild.nodeValue=wakeLock?'画面維持中':'画面維持';
}

function setReaderChromeVisible(show){
  const reader=$('reader'),top=$('r-top'),dock=$('r-dock'),bottom=$('r-bottom-info');
  if(!reader||!top||!dock||!bottom)return;
  if(reader.classList.contains('mode-focus')){
    [top,dock,bottom].forEach(el=>el.classList.toggle('show-temp',!!show));
    reader.classList.toggle('chrome-hidden',!show);
    return;
  }
  [top,dock,bottom].forEach(el=>el.classList.toggle('hide',!show));
  reader.classList.toggle('chrome-hidden',!show);
}
function toggleReaderChrome(){
  const reader=$('reader');
  if(!reader)return;
  const hidden=reader.classList.contains('chrome-hidden');
  setReaderChromeVisible(hidden);
}

let lastUserActivityTime=Date.now();
let inBookSearchResults=[], inBookSearchIdx=0;

async function openReader(w, fromDetail=false, bookmarkF=null){
  if(!w||typeof w.id!=='string')return;
  const readerEl=$('reader');
  const currentId=readerLoadingWorkId;
  if(currentId===w.id && readerEl?.classList.contains('open') && $('body')?.getAttribute('aria-busy')==='true')return;
  readerLoadingWorkId=w.id;
  if(document.documentElement.dataset.device==='smartphone'&&typeof window.__aozoraPhoneOpenReader==='function'){
    const phoneTask=window.__aozoraPhoneOpenReader(w,fromDetail,bookmarkF);
    if(phoneTask&&typeof phoneTask.finally==='function')phoneTask.finally(()=>{if(readerLoadingWorkId===w.id)readerLoadingWorkId=''});
    else if(readerLoadingWorkId===w.id)readerLoadingWorkId='';
    return;
  }
  if($('sheet')?.classList.contains('open')){
    const sheetEl=$('sheet'),scrimEl=$('scrim');
    sheetEl.style.transition='none';
    scrimEl.style.transition='none';
    sheetEl.classList.remove('open');
    scrimEl.classList.remove('open');
    sheetEl.setAttribute('aria-hidden','true');
    scrimEl.setAttribute('aria-hidden','true');
    sheetEl.style.pointerEvents='none';
    scrimEl.style.pointerEvents='none';
    popLayer('sheet');
    const baseState={...(history.state||{})};
    delete baseState.layer;
    history.replaceState(baseState,'',location.href);
    requestAnimationFrame(()=>{
      sheetEl.style.removeProperty('transition');
      scrimEl.style.removeProperty('transition');
      sheetEl.style.removeProperty('pointer-events');
      scrimEl.style.removeProperty('pointer-events');
      restoreFocusEl=null;
    });
  }else{
    closeSheet();
  }
  closeOneLineMode();
  curWork=w;
  lastUserActivityTime=Date.now();
  lastProgressPct=-1;
  lastProgressSave=0;
  if(progressRaf!==null){cancelAnimationFrame(progressRaf);progressRaf=null;}
  const tId=++readerTok;
  desktopReaderContentReady=false;
  $('r-title').textContent=w.t;
  setReaderLoading(true);
  $('reader').classList.add('open','paper-reader');
  $('reader').classList.remove('chrome-hidden');
  setReaderChromeVisible(true);
  $('reader').classList.add('paper-first-open');
  pushLayer('reader');

  try {
    const doc=await fetchBody(w);
    if(tId!==readerTok||!$('reader')?.classList.contains('open'))return;
    curDoc=doc;
    const rendered=await renderReaderBody(()=>tId===readerTok&&curWork?.id===w.id&&$('reader')?.classList.contains('open'));
    if(!rendered)return;
    if(tId!==readerTok||!$('reader')?.classList.contains('open'))return;
    desktopReaderContentReady=true;
    setReaderLoading(false);
    applyReaderConfig(null);

    const restoreInitialPage=()=>{
      if(tId!==readerTok||curWork?.id!==w.id||!$('reader')?.classList.contains('open'))return;
      const f=(bookmarkF!==null&&Number.isFinite(Number(bookmarkF)))?Math.max(0,Math.min(1,Number(bookmarkF))):(pos[w.id]?.f||0);
      if(f<=0){
        const b=$('body');
        if(b)b.scrollLeft=0;
        safeText('r-prog','0%');
        const slider=$('r-slider');
        if(slider)slider.value='0';
        safeText('r-page-lbl','0% · 読書準備完了');
      }else{
        const page=getReaderPageCount();
        const idx=Math.max(0,Math.min(page-1,Math.round(f*Math.max(0,page-1))));
        setReaderPage(idx,false);
        updateProgress(true);
      }
      window.setTimeout(()=>$('reader').classList.remove('paper-first-open'),900);
    };
    requestAnimationFrame(()=>{
      if(typeof window.requestIdleCallback==='function')window.requestIdleCallback(restoreInitialPage,{timeout:700});
      else window.setTimeout(restoreInitialPage,120);
    });

    if(readerLoadingWorkId===w.id)readerLoadingWorkId='';

    if(false && st.kp && !document.body.classList.contains('low-power') && doc.plain.length<=120000){
      const schedule=fn=>{
        if(typeof window.requestIdleCallback==='function') window.requestIdleCallback(fn,{timeout:1200});
        else window.setTimeout(fn,2500);
      };
      schedule(()=>{
        if(tId!==readerTok||curWork?.id!==w.id||!$('reader')?.classList.contains('open'))return;
        try{extractKeyphrases(doc.plain)}catch(err){console.debug('reader keyphrase enhancement skipped',err);}
      });
    }
  } catch(e){
    desktopReaderContentReady=false;
    setReaderLoading(false);
    if(readerLoadingWorkId===w.id)readerLoadingWorkId='';
    if(e.dead)toast('取得できない作品のため除外しました');
    else{
      $('body').innerHTML='<div class="reader-error-state"><div class="reader-error-icon">!</div><div class="reader-error-title">本文を読み込めませんでした</div><div class="reader-error-text">通信状態を確認して、もう一度お試しください。</div><button class="primary" data-act="r-retry" style="margin-top:16px">再試行</button></div>';
      $('body').setAttribute('aria-busy','false');
    }
  }
}


function readerLoaderMarkup(){
  return '<div class="reader-loading aozora-loader" role="status" aria-live="polite">'+
    '<div class="abl-rig">'+
      '<div class="abl-base l"></div><div class="abl-base r"></div><div class="abl-spine-crease"></div>'+
      '<div class="abl-leaf"><div class="abl-typeset-front">私はその人を常に先生と呼んでいた。だからここでもただ先生と書くだけで本名は打ち明けない。</div><div class="abl-typeset-back">私はその人を常に先生と呼んでいた。だからここでもただ先生と書くだけで本名は打ち明けない。</div></div>'+
      '<div class="abl-leaf"><div class="abl-typeset-front">これは世間を憚かる遠慮というよりも、その方が私にとって自然だからである。</div><div class="abl-typeset-back">これは世間を憚かる遠慮というよりも、その方が私にとって自然だからである。</div></div>'+
      '<div class="abl-leaf"><div class="abl-typeset-front">私はその人の記憶を呼び起すごとに、すぐ「先生」といいたくなる。</div><div class="abl-typeset-back">私はその人の記憶を呼び起すごとに、すぐ「先生」といいたくなる。</div></div>'+
      '<div class="abl-leaf"><div class="abl-typeset-front">筆を執っても心持は同じ事である。余所余所しい頭文字などはとても使う気にならない。</div><div class="abl-typeset-back">筆を執っても心持は同じ事である。余所余所しい頭文字などはとても使う気にならない。</div></div>'+
      '<div class="abl-leaf"><div class="abl-typeset-front">私が先生と知り合いになったのは鎌倉である。その時私はまだ若々しい書生であった。</div><div class="abl-typeset-back">私が先生と知り合いになったのは鎌倉である。その時私はまだ若々しい書生であった。</div></div>'+
      '<div class="abl-leaf"><div class="abl-typeset-front">暑中休暇を利用して海へ泳ぎに行った友達からぜひ来いという端書を受け取ったので、</div><div class="abl-typeset-back">暑中休暇を利用して海へ泳ぎに行った友達からぜひ来いという端書を受け取ったので、</div></div>'+
      '<div class="abl-leaf"><div class="abl-typeset-front">私は多少の金を工面して出掛ける事にした。私は金の工面に二三日を費やした。</div><div class="abl-typeset-back">私は多少の金を工面して出掛ける事にした。私は金の工面に二三日を費やした。</div></div>'+
    '</div>'+
    '<div class="reader-loading-title">本文を読み込んでいます</div>'+
    '<div class="reader-loading-sub">本文を画面に準備しています…</div>'+
  '</div>';
}
function setLayerLoading(layer,show){
  if(!layer)return;
  if(show){
    if(!layer.firstElementChild)layer.innerHTML=readerLoaderMarkup();
    layer.hidden=false;
    layer.setAttribute('aria-hidden','false');
  }else{
    layer.hidden=true;
    layer.setAttribute('aria-hidden','true');
  }
}
function resetDesktopReaderBody(){
  const body=$('body');
  if(!body)return;
  body.setAttribute('aria-busy','true');
  body.classList.remove('paper-paged','v','reader-building','reader-page-next','reader-page-prev','paper-turning-next','paper-turning-prev');
  body.style.removeProperty('--reader-page-width');
  body.style.removeProperty('--reader-v-column-width');
  body.innerHTML='';
}
function setReaderLoading(show){
  const body=$('body'),reader=$('reader'),layer=$('reader-loading-layer');
  if(body)body.setAttribute('aria-busy',show?'true':'false');
  if(show){
    cancelReaderRender();
    resetDesktopReaderBody();
    if(reader)reader.classList.add('reader-is-loading');
    setLayerLoading(layer,true);
  }else{
    if(reader)reader.classList.remove('reader-is-loading');
    setLayerLoading(layer,false);
  }
}
function setPhoneReaderLoading(show){
  const body=$p('#phone-reader-body'),reader=$p('#phone-reader'),layer=$p('#phone-reader-loading-layer');
  if(body)body.setAttribute('aria-busy',show?'true':'false');
  if(show){
    cancelReaderRender();
    if(body){
      body.innerHTML='';
      body.classList.remove('reader-building');
    }
    reader?.classList.add('reader-is-loading');
    setLayerLoading(layer,true);
  }else{
    reader?.classList.remove('reader-is-loading');
    setLayerLoading(layer,false);
  }
}
function pulseState(el){
  if(!el||document.body.classList.contains('low-power'))return;
  el.classList.remove('state-bump');
  void el.offsetWidth;
  el.classList.add('state-bump');
  window.setTimeout(()=>el.classList.remove('state-bump'),360);
}

let readerRenderSeq=0;
function cancelReaderRender(){readerRenderSeq++;}

function readerRenderYield(){
  return new Promise(resolve=>{
    const run=()=>resolve();
    if(typeof window.requestIdleCallback==='function')window.requestIdleCallback(run,{timeout:50});
    else window.setTimeout(run,0);
  });
}

function splitReaderHtml(html,maxChars=16000){
  const source=String(html||'');
  if(!source)return [''];
  const sourceInfoIndex=source.indexOf('<section class="aozora-source-info"');
  const main=sourceInfoIndex>=0?source.slice(0,sourceInfoIndex):source;
  const tail=sourceInfoIndex>=0?source.slice(sourceInfoIndex):'';
  const chunks=[];
  let start=0,lastSafe=0;
  const boundary=/<\/p>|<\/h[1-6]>|<\/div>|<hr\b[^>]*>|\n/gi;
  let m;
  while((m=boundary.exec(main))){
    const end=m.index+m[0].length;
    if(end-start>=maxChars){
      const cut=lastSafe>start?lastSafe:end;
      chunks.push(main.slice(start,cut));
      start=cut;
      lastSafe=start;
    }
    lastSafe=end;
  }
  while(main.length-start>maxChars){
    const desired=start+maxChars;
    let cut=main.lastIndexOf('\n',desired);
    if(cut<=start)cut=desired;
    const tagStart=main.lastIndexOf('<',cut),tagEnd=main.lastIndexOf('>',cut);
    if(tagStart>tagEnd&&tagStart>start)cut=tagStart;
    if(cut<=start)cut=desired;
    chunks.push(main.slice(start,cut));
    start=cut;
  }
  if(start<main.length)chunks.push(main.slice(start));
  if(tail)chunks.push(tail);
  return chunks.filter(Boolean);
}

async function renderReaderBody(isCurrent){
  const body=$('body');
  if(!curDoc||!body)return false;
  const seq=++readerRenderSeq;
  body.setAttribute('aria-busy','true');
  body.classList.add('reader-building','paper-paged');
  body.classList.toggle('v',st.v!==false);
  body.innerHTML='';
  const chunks=splitReaderHtml(curDoc.html);
  for(let i=0;i<chunks.length;i++){
    if(seq!==readerRenderSeq||!isCurrent())return false;
    body.insertAdjacentHTML('beforeend',chunks[i]);
    if(i<chunks.length-1)await readerRenderYield();
  }
  if(seq!==readerRenderSeq||!isCurrent())return false;
  await new Promise(requestAnimationFrame);
  if(seq!==readerRenderSeq||!isCurrent())return false;
  body.classList.remove('reader-building');
  return true;
}

async function renderPhoneReaderBody(body,html,isCurrent){
  if(!body)return false;
  const seq=++readerRenderSeq;
  body.setAttribute('aria-busy','true');
  body.classList.add('reader-building');
  body.innerHTML='';
  const chunks=splitReaderHtml(html);
  for(let i=0;i<chunks.length;i++){
    if(seq!==readerRenderSeq||!isCurrent())return false;
    body.insertAdjacentHTML('beforeend',chunks[i]);
    if(i<chunks.length-1)await readerRenderYield();
  }
  if(seq!==readerRenderSeq||!isCurrent())return false;
  await new Promise(requestAnimationFrame);
  if(seq!==readerRenderSeq||!isCurrent())return false;
  body.classList.remove('reader-building');
  return true;
}

function getReaderPageMetrics(){
  const b=$('body');
  if(!b)return {width:1,height:1,pt:0,pr:0,pb:0,pl:0};
  const cs=getComputedStyle(b);
  const pl=parseFloat(cs.paddingLeft)||0;
  const pr=parseFloat(cs.paddingRight)||0;
  const pt=parseFloat(cs.paddingTop)||0;
  const pb=parseFloat(cs.paddingBottom)||0;
  return {
    width:Math.max(1,b.clientWidth-pl-pr),
    height:Math.max(1,b.clientHeight-pt-pb),
    pt,pr,pb,pl
  };
}
function getReaderPageSize(){return getReaderPageMetrics().width}
function getReaderAxis(){return $('body')?.classList.contains('v')?'x':'y'}
function getReaderPageCount(){
  const b=$('body');if(!b)return 1;
  const axis=getReaderAxis(),step=axis==='x'?Math.max(1,b.clientWidth):Math.max(1,b.clientHeight);
  const travel=axis==='x'?Math.max(0,b.scrollWidth-b.clientWidth):Math.max(0,b.scrollHeight-b.clientHeight);
  return Math.max(1,Math.ceil((travel+0.5)/step)+1);
}
function getReaderPageIndex(){
  const b=$('body'),count=getReaderPageCount();if(!b||count<=1)return 0;
  const axis=getReaderAxis(),step=axis==='x'?Math.max(1,b.clientWidth):Math.max(1,b.clientHeight);
  const raw=axis==='x'?Math.abs(Number(b.scrollLeft)||0):Math.max(0,Number(b.scrollTop)||0);
  return Math.max(0,Math.min(count-1,Math.round(raw/step)));
}
function syncReaderPagination(preserveFraction=null){
  const b=$('body');
  if(!b||!b.classList.contains('paper-paged'))return;
  const metrics=getReaderPageMetrics();
  const cs=getComputedStyle(b);
  const fontSize=Math.max(1,parseFloat(cs.fontSize)||18);
  const lineHeightPx=Math.max(fontSize,parseFloat(cs.lineHeight)||fontSize*Number(st.lh||2.1));
  b.style.setProperty('--reader-page-width',metrics.width+'px');
  // 縦書きも「1画面＝1ページ」。列幅を行の高さではなく実際の本文ページ幅にする。
  b.style.setProperty('--reader-v-column-width',metrics.width+'px');
  if(preserveFraction===null||!Number.isFinite(Number(preserveFraction))){
    updateProgress(true);
    return;
  }
  requestAnimationFrame(()=>{
    const count=getReaderPageCount();
    const idx=Math.max(0,Math.min(count-1,Math.round(Number(preserveFraction)*Math.max(0,count-1))));
    setReaderPage(idx,false);
    updateProgress(true);
  });
}
function readerPageProgress(index=getReaderPageIndex()){
  const count=getReaderPageCount();
  return count<=1?0:index/(count-1);
}
function turnReaderPage(dir){
  const count=getReaderPageCount();
  if(count<=1)return false;
  const current=getReaderPageIndex();
  const next=Math.max(0,Math.min(count-1,current+(dir==='next'?1:-1)));
  if(next===current){
    try{navigator.vibrate?.(12);}catch{}
    return false;
  }
  setReaderPage(next,true);
  return true;
}
function setReaderPage(index,animate=true){
  const b=$('body');if(!b)return;
  const count=getReaderPageCount(),clamped=Math.max(0,Math.min(count-1,Number(index)||0)),axis=getReaderAxis();
  const step=axis==='x'?Math.max(1,b.clientWidth):Math.max(1,b.clientHeight);
  const maxTravel=axis==='x'?Math.max(0,b.scrollWidth-b.clientWidth):Math.max(0,b.scrollHeight-b.clientHeight);
  const target=Math.min(maxTravel,clamped*step);
  if(animate)playPaperTurn(clamped>getReaderPageIndex()?'next':'prev');
  b.scrollTo(axis==='x'?{left:b.classList.contains('v')?-target:target,top:0,behavior:'auto'}:{left:0,top:target,behavior:'auto'});
  updateProgress(true);
}
function playPaperTurn(direction){
  if(document.body.classList.contains('low-power'))return;
  const overlay=$('r-page-turn'),body=$('body');
  if(!overlay||!body)return;
  overlay.classList.remove('next','prev');
  body.classList.remove('paper-turning-next','paper-turning-prev');
  void overlay.offsetWidth;
  void body.offsetWidth;
  overlay.classList.add(direction==='next'?'next':'prev');
  body.classList.add(direction==='next'?'paper-turning-next':'paper-turning-prev');
  clearTimeout(window.__paperTurnTimer);
  window.__paperTurnTimer=setTimeout(()=>{
    overlay.classList.remove('next','prev');
    body.classList.remove('paper-turning-next','paper-turning-prev');
  },380);
}

async function closeReader(fromPop=false){
  closeOneLineMode();
  cancelReaderRender();
  cancelReaderParser();
  readerTok++;
  readerLoadingWorkId='';
  if(curWork && desktopReaderContentReady){
    try{updateProgress(true);}catch{}
  }
  desktopReaderContentReady=false;
  $('reader').classList.remove('open','paper-reader','paper-first-open','reader-is-loading');
  $('reader').classList.remove('reader-night','mode-focus');
  setLayerLoading($('reader-loading-layer'),false);
  if(window.speechSynthesis)speechSynthesis.cancel();
  popLayer('reader');
  save();
  switchView('v-home');
  renderHome();
  void releaseScreenWakeLock();
  if(!fromPop&&history.state?.layer==='reader')history.back();
  curDoc=null;
  curWork=null;
  return true;
}

let progressRaf=null;
let lastProgressPct=-1;
let lastProgressSave=0;

function updateProgress(force=false){
  if(!curWork || !desktopReaderContentReady) return;
  const b=$('body');
  if(b?.getAttribute('aria-busy')==='true'||b?.classList.contains('reader-building'))return;
  const count=getReaderPageCount();
  const idx=getReaderPageIndex();
  const f=readerPageProgress(idx);
  const pct=Math.round(f*100);
  const now=Date.now();

  pos[curWork.id]={f,t:now};
  if(f>=0.999) done.add(curWork.id);

  if(force || pct!==lastProgressPct){
    lastProgressPct=pct;
    safeText('r-prog',pct+'%');
    const slider=$('r-slider');
    if(slider){
      slider.max=String(Math.max(1,count-1));
      slider.value=String(idx);
    }
    const prog=$('r-prog');
    if(prog&&!document.body.classList.contains('low-power')){
      prog.classList.remove('progress-bump'); void prog.offsetWidth; prog.classList.add('progress-bump');
      window.setTimeout(()=>prog.classList.remove('progress-bump'),280);
    }

    const totalChars=curWork.plain?.length||8000;
    const readChars=Math.floor(totalChars*f);
    const totalP=Math.max(1,count);
    const curP=Math.min(totalP,idx+1);
    const remM=Math.max(1,Math.ceil((totalChars*(1-f))/st.readSpeed));
    safeText('r-page-lbl',`${pct}% · ${curP}/${totalP}ページ · 残り約${f>=.999?0:remM}分 · ${readChars}/${totalChars}字読了`);
  }

  if(force || now-lastProgressSave>=3000){
    lastProgressSave=now;
    hist=hist.filter(h=>h.id!==curWork.id);
    hist.unshift({id:curWork.id,t:now});
    if(hist.length>50) hist.pop();
    if(force) save();
  }
}

/* タッチ端末では合成clickに依存せず、本文タップから読書UIを確実に復帰できるようにする。 */
(function bindReaderTapRestore(){
  const body=$('body');
  if(body&&body.dataset.tapRestoreBound!=='1'){
    body.dataset.tapRestoreBound='1';
    let sx=0,sy=0,down=false;
    body.addEventListener('pointerdown',e=>{
      if(e.pointerType!=='touch')return;
      sx=e.clientX;sy=e.clientY;down=true;
    },{passive:true});
    body.addEventListener('pointerup',e=>{
      if(e.pointerType!=='touch'||!down)return;
      down=false;
      const moved=Math.hypot(e.clientX-sx,e.clientY-sy);
      if(moved>14)return;
      if(e.target.closest?.('button,a,input,select,textarea'))return;
      const reader=$('reader');
      if(!reader?.classList.contains('open'))return;
      const hidden=reader.classList.contains('chrome-hidden');
      if(hidden){
        e.preventDefault();
        setReaderChromeVisible(true);
      }
    },{passive:false});
  }
  const phoneBody=$('phone-reader-body');
  if(phoneBody&&phoneBody.dataset.tapRestoreBound!=='1'){
    phoneBody.dataset.tapRestoreBound='1';
    let sx=0,sy=0,down=false;
    phoneBody.addEventListener('pointerdown',e=>{
      if(e.pointerType!=='touch')return;
      sx=e.clientX;sy=e.clientY;down=true;
    },{passive:true});
    phoneBody.addEventListener('pointerup',e=>{
      if(e.pointerType!=='touch'||!down)return;
      down=false;
      if(Math.hypot(e.clientX-sx,e.clientY-sy)>14)return;
      const reader=$('phone-reader');
      if(!reader?.classList.contains('phone-open'))return;
      if(e.target.closest?.('button,a,input,select,textarea'))return;
      if(reader.classList.contains('reader-chrome-hidden')){
        e.preventDefault();
        reader.classList.remove('reader-chrome-hidden');
      }
    },{passive:false});
  }
})();
$('body').onscroll=()=>{
  lastUserActivityTime=Date.now();
  if(progressRaf===null){
    progressRaf=requestAnimationFrame(()=>{
      progressRaf=null;
      updateProgress();
    });
  }
};
window.addEventListener('pagehide',()=>{
  try{
    if(curWork&&desktopReaderContentReady&&$('reader')?.classList.contains('open')){
      updateProgress(true);
      save();
    }
  }catch(err){console.debug('reader progress pagehide save failed',err)}
});

$('body').onclick=(e)=>{
  lastUserActivityTime=Date.now();
  if(e.target.closest('.keyphrase,u,b,ruby')||getSelection().toString()) return;

  const b=$('body');
  if(!b.classList.contains('paper-paged')) return;
  const w=innerWidth,x=e.clientX;

  if(x>w*0.35 && x<w*0.65 && !$('reader').classList.contains('mode-focus')){
    toggleReaderChrome();
    return;
  }

  const vertical=b.classList.contains('v');
  // 横書き: 左=前 / 右=次
  // 縦書き: 右=前 / 左=次（紙のページ方向）
  const dir=vertical ? (x>=w*0.65?'prev':'next') : (x<=w*0.35?'prev':'next');
  turnReaderPage(dir);
};

function animateReaderPage(direction){
  if(document.body.classList.contains('low-power')) return;
  const b=$('body');
  b.classList.remove('reader-page-next','reader-page-prev');
  void b.offsetWidth;
  b.classList.add(direction==='next'?'reader-page-next':'reader-page-prev');
  clearTimeout(window.__readerPageAnim);
  window.__readerPageAnim=setTimeout(()=>{
    b.classList.remove('reader-page-next','reader-page-prev');
  },360);
}

function execInBookSearch(){
  const q=$('r-search-inp').value.trim();
  if(q.length>500){$('r-search-count').textContent='検索語が長すぎます';return;}
  const body=$('body');
  body.querySelectorAll('.search-hl').forEach(el=>{
    el.replaceWith(document.createTextNode(el.textContent));
  });
  inBookSearchResults=[];
  inBookSearchIdx=0;

  if(!q){
    $('r-search-count').textContent='0件';
    return;
  }

  const walker=document.createTreeWalker(body, NodeFilter.SHOW_TEXT);
  const nodes=[]; let n;
  while((n=walker.nextNode())) nodes.push(n);

  nodes.forEach(node=>{
    if(node.parentElement.closest('rt,rp,ruby,#r-search-bar')) return;
    const txt=node.nodeValue;
    const idx=txt.indexOf(q);
    if(idx!==-1){
      const span=document.createElement('span');
      const safePattern = new RegExp(escRe(q), 'g');
      span.innerHTML=esc(txt).replace(safePattern, m=>`<mark class="search-hl">${m}</mark>`);
      node.parentNode.replaceChild(span, node);
    }
  });

  inBookSearchResults=[...body.querySelectorAll('.search-hl')];
  $('r-search-count').textContent=`${inBookSearchResults.length}件`;
  if(inBookSearchResults.length>0) jumpToInBookMatch(0);
}

function jumpToInBookMatch(idx){
  if(!inBookSearchResults.length) return;
  inBookSearchIdx=(idx+inBookSearchResults.length)%inBookSearchResults.length;
  inBookSearchResults.forEach((el,i)=>el.style.outline=(i===inBookSearchIdx?'3px solid #ff5722':'none'));
  inBookSearchResults[inBookSearchIdx].scrollIntoView({ behavior:'smooth', block:'center' });
  updateProgress(true);
}


// 読書モード切替 (通常・集中・夜間)
function openModeSelectSheet(){
  const m=st.rMode||'normal';
  sheet('読書モードの選択',`
    <div style="display:flex; flex-direction:column; gap:12px">
      <div class="block" data-act="set-read-mode" data-m="normal" style="padding:16px; min-height:auto">
        <div style="font-weight:700">${m==='normal'?'● ':''}通常モード</div>
        <div style="font-size:var(--fs-s); color:var(--sub)">すべての操作バー・ドックを表示します</div>
      </div>
      <div class="block" data-act="set-read-mode" data-m="focus" style="padding:16px; min-height:auto">
        <div style="font-weight:700">${m==='focus'?'● ':''}集中モード</div>
        <div style="font-size:var(--fs-s); color:var(--sub)">UIを最小化し、本文に没入します (右上に解除ボタン常駐)</div>
      </div>
      <div class="block" data-act="set-read-mode" data-m="night" style="padding:16px; min-height:auto">
        <div style="font-weight:700">${m==='night'?'● ':''}夜間モード</div>
        <div style="font-size:var(--fs-s); color:var(--sub)">暗所向け配色と暖色フィルターを読書画面だけに適用</div>
      </div>
    </div>
  `);
}

function applyReaderMode(){
  const m=st.rMode||'normal';
  const readerEl=$('reader');
  readerEl.classList.toggle('mode-focus', m==='focus');
  readerEl.classList.toggle('reader-night', m==='night');
  $('btn-read-mode').textContent=m==='normal'?'通常':m==='focus'?'集中':'夜間';
  
  if(m==='night'){
    $('r-warm').style.display='block';
    $('r-dim').style.backgroundColor='rgba(0,0,0,0.2)';
  } else {
    $('r-dim').style.backgroundColor='rgba(0,0,0,0)';
    checkNightWarm();
  }
}

function applyReaderConfig(preserveOverride=undefined){
  const b=$('body');
  const open=!!$('reader')?.classList.contains('open');
  const preserve=preserveOverride===null
    ? null
    : (preserveOverride!==undefined
      ? Number(preserveOverride)
      : (open&&curDoc&&b?.getAttribute('aria-busy')!=='true'?readerPageProgress():null));

  b.style.setProperty('--r-fs',st.fs+'px');
  b.style.setProperty('--r-lh',st.lh);
  b.style.fontFamily=st.font==='gothic'?'var(--font-sans)':'var(--font-serif)';
  b.classList.toggle('v',st.v!==false);
  b.classList.add('paper-paged');
  applyReaderMode();

  // 初回表示では、本文DOMの直後にscrollWidthを読むと大きな作品でレイアウト計算が固まりやすい。
  // openReader側が描画を1フレーム渡してから初期ページを復元する。
  if(open && preserveOverride===null)return;

  if(open){
    requestAnimationFrame(()=>requestAnimationFrame(()=>syncReaderPagination(preserve)));
  }else{
    syncReaderPagination(null);
  }
}

function checkNightWarm(){
  const h=new Date().getHours();
  $('r-warm').style.display=(st.warm&&(h>=20||h<6))?'block':'none';
}

function extractKeyphrases(txt){
  if(!window.Intl?.Segmenter) return;
  const seg=new Intl.Segmenter('ja',{granularity:'word'});
  const cnt=new Map();
  for(const it of seg.segment(txt.slice(0,5000))){
    if(it.isWordLike&&it.segment.length>=2&&/[\u4E00-\u9FFF]/.test(it.segment)){
      cnt.set(it.segment,(cnt.get(it.segment)||0)+1);
    }
  }
  const top=[...cnt.entries()].sort((a,b)=>b[1]-a[1]).slice(0,7).map(x=>x[0]);
  if(!top.length) return;
  const re=new RegExp(top.map(escRe).join('|'),'gu');
  const w=document.createTreeWalker($('body'),NodeFilter.SHOW_TEXT);
  const nds=[]; let n;
  while((n=w.nextNode())){
    nds.push(n);
    if(nds.length>=3000)break;
  }
  nds.forEach(node=>{
    if(node.parentElement.closest('rt,rp,ruby,.keyphrase,.search-hl')) return;
    re.lastIndex=0;
    const text=node.nodeValue||'';
    re.lastIndex=0;
    if(re.test(text)){
      re.lastIndex=0;
      const frag=document.createDocumentFragment();
      let last=0,match;
      while((match=re.exec(text))){
        if(match.index>last) frag.append(document.createTextNode(text.slice(last,match.index)));
        const mark=document.createElement('span');
        mark.className='keyphrase';
        mark.textContent=match[0];
        frag.append(mark);
        last=re.lastIndex;
      }
      if(last<text.length) frag.append(document.createTextNode(text.slice(last)));
      node.parentNode.replaceChild(frag,node);
    }
  });
}

document.addEventListener('visibilitychange',()=>{
  if(document.visibilityState==='visible'&&wakeLockWanted&&isAnyReaderOpen()) requestScreenWakeLock();
});
document.addEventListener('keydown',e=>{
  if(!$('reader').classList.contains('open'))return;
  if(e.target.closest?.('input,textarea,select,[contenteditable="true"]'))return;
  if(e.key==='ArrowLeft'||e.key==='ArrowRight'||e.key==='PageDown'||e.key==='PageUp'||e.key===' '){
    e.preventDefault();
    let dir=(e.key==='ArrowLeft'||e.key==='PageUp')?'prev':'next';
    if(e.key===' '&&e.shiftKey)dir='prev';
    turnReaderPage(dir);
  }
});
const actionObserver=new MutationObserver(muts=>{
  for(const m of muts){
    for(const n of m.addedNodes){
      if(n.nodeType===1)enhanceActionables(n);
    }
  }
});
document.addEventListener('DOMContentLoaded',()=>actionObserver.observe(document.body,{childList:true,subtree:true}),{once:true});
document.addEventListener('selectionchange',()=>{
  lastUserActivityTime=Date.now();
  const s=getSelection(), t=s?.toString().trim();
  if(!t||!$('reader').contains(s.anchorNode)){ $('pop').classList.remove('open'); return; }
  const r=s.getRangeAt(0).getBoundingClientRect();
  $('pop').style.top=Math.max(10,r.top-56)+'px';
  $('pop').style.left=Math.min(innerWidth-280,Math.max(10,r.left+r.width/2-140))+'px';
  $('pop').classList.add('open');
  pushLayer('pop');
});

/* ==================== 10.  () シート ==================== */
/* ==================== 11. AI機能 (完全日本語化 & 制御) ==================== */
let aiAbort=null;

function openAiChat(initQ=''){
  sheet('AIコンシェルジュ',`
    <div style="display:flex; flex-direction:column; height:60vh">
      <div style="display:flex; gap:8px; overflow-x:auto; padding-bottom:8px">
        <button class="secondary sm-btn" data-act="ai-chip" data-q="この作品のあらすじを三段要約してください。">三段要約</button>
        <button class="secondary sm-btn" data-act="ai-chip" data-q="この作品の特徴や読みどころを教えてください。">読みどころ</button>
        <button class="secondary sm-btn" data-act="ai-chip" data-q="この場面の時代背景や状況を教えてください。">背景解説</button>
        <button class="secondary sm-btn" data-act="ai-chip" data-q="登場人物たちの関係を教えてください。">登場人物</button>
      </div>
      <div class="chat-box" id="ai-chat" style="flex:1; overflow-y:auto; padding:10px 0"></div>
      <div style="display:flex; gap:8px; align-items:flex-end">
        <textarea id="ai-input" rows="1" placeholder="質問を入力 (Enterで送信)" style="flex:1; background:var(--card-sub); border-radius:var(--radius-sm); padding:14px; font-size:var(--fs-b); max-height:100px; resize:none"></textarea>
        <button class="primary" id="ai-btn-send" data-act="ai-send" style="width:72px">送信</button>
      </div>
    </div>`);

  $('ai-input').onkeydown=(e)=>{
    if(e.key==='Enter'&&!e.shiftKey){ e.preventDefault(); $('ai-btn-send').click(); }
  };
  if(initQ){ $('ai-input').value=initQ; $('ai-btn-send').click(); }
}

async function sendAiMessage(q){
  if(!curWork||!isPublicWork(curWork)){
    toast('この作品ではAI機能を利用できません');
    return;
  }
  q=String(q||'').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g,'').trim();
  if(q.length>4000){toast('質問が長すぎます（最大4000文字）');return;}
  if(!/^[A-Za-z0-9._:/-]{1,128}$/.test(String(st.oMod||''))){toast('AIモデル名が不正です');return;}
  if(st.offline){ toast('オフライン設定中です'); return; }
  if(!canUseOllama() || !aiConn.ok || !st.oMod){ toast('Ollama未接続またはモデル未選択です'); return; }

  const box=$('ai-chat');
  box.insertAdjacentHTML('beforeend',`<div class="bubble me">${esc(q)}</div><div class="bubble ai" id="ai-cur"><div class="typing-dots"><span></span><span></span><span></span></div></div>`);
  box.scrollTop=box.scrollHeight;

  const btn=$('ai-btn-send');
  btn.textContent='停止'; btn.dataset.act='ai-stop';

  if(aiAbort) aiAbort.abort();
  aiAbort=new AbortController();
  const aiHardTimeout=setTimeout(()=>{try{aiAbort.abort(new DOMException('AI timeout','TimeoutError'));}catch{aiAbort.abort();}},180000);

  let firstWordTimer=setTimeout(()=>{ const el=$('ai-cur'); if(el) el.innerHTML='モデルを読み込み中… (約150秒お待ちください)'; }, 15000);

  try {
    const ctx=curDoc?curDoc.plain.slice(0,3000):'';
    const sysPrompt=`【重要指示】
必ず自然な日本語のみで回答してください。英語や中国語など他言語は一切含めないでください。
要約では本文にない事実を捏造せず、原文に基づいた客観的な内容にしてください。
参考本文:
${ctx}`;

    const res=await secureFetch(normalizeOllamaUrl(st.oUrl)+'/api/chat',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        model:st.oMod,
        messages:[{role:'system',content:sysPrompt},{role:'user',content:q}],
        stream:true,options:{num_ctx:4096,num_predict:900},keep_alive:'30m',think:false
      }),
      signal:aiAbort.signal
    });

    clearTimeout(firstWordTimer);
    clearTimeout(aiHardTimeout);
    const r=res.body.getReader(), dec=new TextDecoder();
    let full='', buf=''; let responseBytes=0; const maxAiBytes=2*1024*1024;

    while(true){
      const {done,value}=await r.read(); if(done) break;
      responseBytes+=value.byteLength;
      if(responseBytes>maxAiBytes){try{await r.cancel();}catch{};throw new Error('AI応答が大きすぎます');}
      buf+=dec.decode(value,{stream:true});
      const lines=buf.split('\n'); buf=lines.pop();
      for(const l of lines){
        if(!l.trim()) continue;
        const j=JSON.parse(l);
        if(j.message?.content){
          full+=j.message.content;
          const aiCur=$('ai-cur'); if(aiCur) aiCur.textContent=full.replace(/<think>[\s\S]*?<\/think>/g,'').trim();
          box.scrollTop=box.scrollHeight;
        }
      }
    }
  }catch(e){
    clearTimeout(firstWordTimer);clearTimeout(aiHardTimeout);
    $('ai-cur').textContent=(e.name==='AbortError'||e.name==='TimeoutError')?'回答を停止しました。':'接続失敗: '+e.message;
  }finally{
    const aiCur=$('ai-cur'); if(aiCur) aiCur.removeAttribute('id');
    btn.textContent='送信'; btn.dataset.act='ai-send';
  }
}

async function pingOllama(){
  if(ollamaPingController)try{ollamaPingController.abort()}catch{}
  ollamaPingController=new AbortController();
  aiConn.ok=false; aiConn.models=[]; aiConn.err='';
  if(!st.ollamaEnabled||!canUseOllama()){
    renderHome();
    return;
  }
  const controller=ollamaPingController;
  try{
    const url=normalizeOllamaUrl(st.oUrl);
    const timer=setTimeout(()=>controller.abort(),4000);
    const res=await secureFetch(url+'/api/tags',{signal:controller.signal});
    clearTimeout(timer);
    if(res.ok){
      const raw=await readResponseBytes(res,64*1024);
      if(!raw)throw new Error('AI model list unavailable');
      const d=JSON.parse(new TextDecoder().decode(raw));
      const models=Array.isArray(d.models)?d.models.map(m=>String(m?.name||'').trim()).filter(n=>/^[A-Za-z0-9._:/-]{1,128}$/.test(n)).slice(0,200):[];
      aiConn.ok=true; aiConn.models=models;
      if(!st.oMod&&models.length)st.oMod=models[0];
    }else{
      aiConn.err='Ollama が応答しませんでした';
    }
  }catch(e){
    if(e?.name!=='AbortError')aiConn.err=e?.message||'接続失敗';
    aiConn.ok=false;
  }finally{
    if(ollamaPingController===controller)ollamaPingController=null;
  }
  renderHome();
}

/* ==================== 12. カレンダー & 読書記録 ==================== */
function renderCalendar(){
  $('cal-goal-txt').textContent=goalMin+'分';
  $('rng-goal').value=goalMin;
  const hm=$('cal-heatmap');
  hm.innerHTML='';
  const d=new Date();
  d.setDate(d.getDate()-83);
  for(let i=0;i<84;i++){
    const k=dateKeyOf(d);
    const m=calData[k]||0;
    const bg=m===0?'var(--card-sub)':m>=goalMin?'var(--ac)':'color-mix(in srgb, var(--ac) 45%, var(--card-sub))';
    hm.insertAdjacentHTML('beforeend',`<div style="width:18px; height:18px; border-radius:4px; background:${bg}" title="${escAttr(k)}: ${m}分"></div>`);
    d.setDate(d.getDate()+1);
  }
}

// 読書分数タイマー
// PC版とスマホ版で別々のリーダーを使うため、両方を明示的に監視する。
// 「スクロールしないで読む」だけでも読書時間が記録され、スマホ版でもカレンダーに反映される。
const isAnyReaderOpen=()=>{
  const desktopOpen=!!$('reader')?.classList.contains('open');
  const phoneOpen=!!$('phone-reader')?.classList.contains('phone-open');
  return desktopOpen||phoneOpen;
};
readingMinuteTimer=setInterval(()=>{
  if(!isAnyReaderOpen()||document.hidden)return;
  const todayKey=localDateKey();
  calData[todayKey]=Math.max(0,Number(calData[todayKey])||0)+1;
  save();
},60000);

document.addEventListener('visibilitychange',()=>{
  if(document.visibilityState==='visible'&&isAnyReaderOpen()){
    lastUserActivityTime=Date.now();
  }
});

/* ==================== 13. 設定画面レンダリング ==================== */
function renderSettingsPage(){
  const sa=$('settings-area');
  sa.innerHTML=`
    <div class="apple-settings-group block" style="min-height:auto">
      <div class="apple-group-title">表示環境</div>
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px">
        <span>外観テーマ</span>
        <div class="seg" style="width:260px">
          <button data-act="set-th" data-v="auto" class="${st.theme==='auto'?'active':''}">自動</button>
          <button data-act="set-th" data-v="sepia" class="${st.theme==='sepia'?'active':''}">和紙</button>
          <button data-act="set-th" data-v="dark" class="${st.theme==='dark'?'active':''}">夜間</button>
        </div>
      </div>
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px">
        <span>フォント</span>
        <div class="seg" style="width:200px">
          <button data-act="set-ft" data-v="mincho" class="${st.font==='mincho'?'active':''}">明朝</button>
          <button data-act="set-ft" data-v="gothic" class="${st.font==='gothic'?'active':''}">ゴシック</button>
        </div>
      </div>
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; gap:14px">
        <div>
          <div style="font-weight:700">低スペックモード</div>
          <div style="font-size:var(--fs-s); color:var(--sub); margin-top:4px">アニメーション・影・背景効果・不要な監視処理を停止</div>
        </div>
        <div class="seg" style="width:180px; flex:none">
          <button data-act="set-low-spec" data-v="1" class="${st.lowSpec?'active':''}">ON</button>
          <button data-act="set-low-spec" data-v="0" class="${!st.lowSpec?'active':''}">OFF</button>
        </div>
      </div>
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px">
        <span>読書速度 (${st.readSpeed}字/分)</span>
        <select id="sel-read-speed" data-act="sel-speed-change" style="background:var(--card-sub); padding:8px 12px; border-radius:8px">
          <option value="350" ${st.readSpeed===350?'selected':''}>ゆっくり (350字)</option>
          <option value="500" ${st.readSpeed===500?'selected':''}>標準 (500字)</option>
          <option value="750" ${st.readSpeed===750?'selected':''}>速め (750字)</option>
        </select>
      </div>
      <div style="display:flex; justify-content:space-between; align-items:center">
        <span>文字サイズ (${st.fs}px)</span>
        <input type="range" min="14" max="32" value="${st.fs}" data-act="set-fs-range" style="width:160px; height:44px">
      </div>
    </div>

    <div class="apple-settings-group block" style="min-height:auto">
      <div class="apple-group-title">AI</div>
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px">
        <div style="font-weight:700; font-size:var(--fs-t)">Ollama</div>
        <div class="seg" style="width:140px">
          <button data-act="set-ollama-toggle" data-v="1" class="${st.ollamaEnabled?'active':''}">ON</button>
          <button data-act="set-ollama-toggle" data-v="0" class="${!st.ollamaEnabled?'active':''}">OFF</button>
        </div>
      </div>
      ${!st.ollamaEnabled ? `
        <div style="font-size:var(--fs-s); color:var(--sub); padding:4px 0 8px">
          
        </div>
      ` : `
        <div style="margin-bottom:14px">
          <div style="font-size:var(--fs-s); color:var(--sub); margin-bottom:6px">Ollama URL（HTTPS/HTTP を安全に扱う）</div>
          <div style="display:flex; gap:8px">
            <input id="set-ourl" value="${esc(normalizeOllamaUrl(st.oUrl))}" style="flex:1; background:var(--card-sub); padding:12px; border-radius:10px; font-size:var(--fs-b)">
            <button class="primary sm-btn" data-act="set-save-url">保存</button>
          </div>
        </div>
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px">
          <span>AIモデル選択</span>
          <button class="secondary sm-btn" data-act="set-pick-mod">${esc(st.oMod||'未選択')} ›</button>
        </div>
        <button class="secondary" data-act="set-ping" style="width:100%">Ollama 接続を確認</button>
        ${aiConn.err ? `<div style="margin-top:12px; font-size:var(--fs-s); color:var(--sub)">${esc(aiConn.err)}</div>` : ''}
      `}
    </div>

    <div class="apple-settings-group block" style="min-height:auto">
      <div class="apple-group-title">データ</div>
      <button class="secondary" data-act="cat-intro" style="width:100%; margin-bottom:10px">作品カタログを再取得</button>
      <button class="secondary" data-act="cache-clear" style="width:100%; color:#d9534f; margin-bottom:10px">本文キャッシュを消去</button>
      <div style="display:flex; gap:10px">
        <button class="secondary" data-act="data-export" style="flex:1">書き出し</button>
        <label class="secondary" style="flex:1; cursor:pointer; text-align:center; line-height:52px; display:inline-flex; align-items:center; justify-content:center">復元<input type="file" id="file-restore" accept=".json" hidden></label>
      </div>
    </div>`;

  $('file-restore').onchange=e=>{
    const f=e.target.files[0]; if(!f) return;
    const r=new FileReader();
    if(f.size>8*1024*1024){toast('バックアップが大きすぎます（最大8MB）');return;}
    r.onload=async()=>{
      try {
        const d=sanitizePersistedState(JSON.parse(r.result));if(!d)throw new Error('invalid-backup');
        fav=new Set(d.fav||[]); want=new Set(d.want||[]); done=new Set(d.done||[]);
        favAuthors=new Set(d.favAuthors||[]);
        pos=d.pos||{}; bm=d.bm||{}; notes=d.notes||{}; hls=d.hls||{};
        hist=d.hist||[]; calData=d.calData||{}; goalMin=d.goalMin||30; searchHistory=d.searchHistory||[];
        if(d.st){ const safeImportedSt=Object.assign({},d.st,{ollamaEnabled:false,oUrl:'http://127.0.0.1:11434',oMod:''}); st=Object.assign(st,safeImportedSt); }
        save(); toast('データを復元しました'); applySettings(); filterWorks(); renderHome();
      }catch{ toast('不正なファイル形式です'); }
    };
    r.readAsText(f);
  };
}

/* ==================== 14. イベント委譲 (data-act) ==================== */
let currentView='v-home';
const viewOrder=['v-home','v-search','v-shelf','v-cal','v-settings'];

function switchView(vid){
  if(vid===currentView){
    const same=$(vid);
    if(same && same.scrollTop>24 && !document.body.classList.contains('low-power')){
      same.scrollTo({top:0,behavior:'smooth'});
    }
    return;
  }

  const prev=currentView;
  const direction=viewOrder.indexOf(vid)>=viewOrder.indexOf(prev)?'forward':'backward';
  const current=$(prev), next=$(vid);
  if(!next)return;

  // 旧画面と新画面を同時に描画しない。
  // まず全画面をDOM上で完全に非表示にしてから、新画面だけを表示する。
  window.clearTimeout(window.__viewInTimer);
  document.querySelectorAll('.view').forEach(v=>{
    v.classList.remove(
      'active',
      'view-slide-forward',
      'view-slide-backward',
      'view-exit-forward',
      'view-exit-backward'
    );
    v.hidden=true;
    v.style.display='none';
    v.style.visibility='hidden';
    v.setAttribute('aria-hidden','true');
  });

  current?.setAttribute('aria-hidden','true');

  currentView=vid;

  // 表示前に新画面の内容とスクロール位置を確定。
  next.scrollTop=0;
  if(vid==='v-home') renderHome();
  else if(vid==='v-search') renderSearchInit();
  else if(vid==='v-shelf') renderShelf();
  else if(vid==='v-cal') renderCalendar();
  else if(vid==='v-settings') renderSettingsPage();

  // 新画面だけを描画対象にする。
  next.hidden=false;
  next.style.display='block';
  next.style.visibility='visible';
  next.setAttribute('aria-hidden','false');
  next.classList.add('active');

  const reduced=document.body.classList.contains('low-power') ||
    !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

  if(!reduced){
    // 表示状態を一度確定させてから、新画面だけに入場アニメーションを付ける。
    void next.offsetWidth;
    next.classList.add(direction==='forward'?'view-slide-forward':'view-slide-backward');
    window.__viewInTimer=window.setTimeout(()=>{
      next.classList.remove('view-slide-forward','view-slide-backward');
    },480);
  }

  document.querySelectorAll('.nav-btn, .b-nav-btn').forEach(b=>{
    const active=b.dataset.v===vid;
    b.classList.toggle('active',active);
    if(active)b.setAttribute('aria-current','page');
    else b.removeAttribute('aria-current');
  });
}

document.addEventListener('input',e=>{
  const el=e.target.closest?.('[data-act]');if(!el)return;
  if(el.dataset.act==='set-fs-range'){
    st.fs=Math.max(14,Math.min(32,Number(el.value)||18));
    safeText('r-fs-value',st.fs+'px');
    applyReaderConfig();save();
  }
  else if(el.dataset.act==='set-lh-range'){
    st.lh=Math.max(1.6,Math.min(2.8,Number(el.value)||2.1));
    safeText('r-lh-value',Number(st.lh).toFixed(1));
    applyReaderConfig();save();
  }
});
document.addEventListener('change',e=>{
  const b=e.target.closest('[data-act="sel-speed-change"]');
  if(!b) return;
  st.readSpeed=parseInt(b.value,10)||500;
  save();
  renderHome();
  toast('読書速度を設定しました');
});

document.addEventListener('click',async(e)=>{
  const b=e.target.closest('[data-act]'); if(!b) return;
  const act=b.dataset.act;

  // ナビゲーション
  if(act==='nav') switchView(b.dataset.v);
  else if(act==='back-home') switchView('v-home');
  else if(act==='close-sheet'){ e.preventDefault(); e.stopPropagation(); closeSheet(false); }
  else if(act==='ban-btn'){
    const banner=$('banner');
    const manual=banner?.dataset.reason==='catalog-manual';
    if(banner)banner.style.display='none';
    if(manual){
      if(document.documentElement.dataset.device==='smartphone'&&typeof window.__aozoraPhoneOpenCatalogManual==='function'){
        window.__aozoraPhoneOpenCatalogManual();
      }else{
        switchView('v-settings');
        setTimeout(()=>openCatalogIntro(),60);
      }
    }else switchView('v-settings');
  }
  else if(act==='nav-settings') switchView('v-settings');

  // 検索画面
  else if(act==='open-search') openSearchPage();
  else if(act==='q-clear') { $('q-input').value=''; searchState.query=''; applySearch(true); }
  else if(act==='scroll-top') $('v-search').scrollTo({top:0,behavior:'smooth'});
  else if(act==='clear-scope') { searchState.scope=null; searchState.query=''; $('q-input').value=''; applySearch(true); }
  else if(act==='chip-toggle' && b.dataset.k==='saved') {
    searchState.filter.saved=!searchState.filter.saved;
    b.classList.toggle('active',searchState.filter.saved);
    applySearch(true);
  }
  else if(act==='chip-time') {
    const t=b.dataset.t;
    if(searchState.filter.time===t){
      searchState.filter.time=null;
      b.classList.remove('active');
    } else {
      document.querySelectorAll('[data-act="chip-time"]').forEach(el=>el.classList.remove('active'));
      searchState.filter.time=t;
      b.classList.add('active');
    }
    applySearch(true);
  }
  else if(act==='sort-pick') {
    document.querySelectorAll('#sort-seg button').forEach(el=>el.classList.remove('active'));
    b.classList.add('active');
    searchState.sort=b.dataset.s;
    applySearch(true);
  }
  else if(act==='g-pick') {
    const code=b.dataset.c;
    const g=GENRES.find(x=>x.c===code);
    searchState.scope={ type:'genre', value:code, label:`ジャンル: ${g?.n||code}` };
    searchState.query='';
    $('q-input').value='';
    applySearch(true);
  }
  else if(act==='k-pick') {
    const k=b.dataset.k;
    searchState.scope={ type:'kana', value:k, label:`五十音: ${k}行` };
    searchState.query='';
    $('q-input').value='';
    applySearch(true);
  }
  else if(act==='search-hist-pick') {
    const val=b.dataset.val;
    $('q-input').value=val;
    searchState.query=val;
    applySearch(true);
  }
  else if(act==='clear-search-hist') {
    searchHistory=[];
    save();
    renderSearchInit();
  }

  // ホームの各小ブロック
  else if(act==='open-kana') {
    openSearchPage(); searchState.scope=null; $('q-input').value=''; renderSearchInit();
    $('sec-kana-select').scrollIntoView({ behavior:'smooth' });
  }
  else if(act==='open-genre') {
    openSearchPage(); searchState.scope=null; $('q-input').value=''; renderSearchInit();
    $('sec-genre-select').scrollIntoView({ behavior:'smooth' });
  }
  else if(act==='open-new') {
    openSearchPage();
    searchState.scope={ type:'new', value:'', label:'新着作品' };
    searchState.query='';
    $('q-input').value='';
    applySearch(true);
  }
  else if(act==='open-time') {
    openSearchPage();
    searchState.scope=null;
    searchState.filter.time='t10';
    document.querySelectorAll('[data-act="chip-time"]').forEach(el=>el.classList.remove('active'));
    document.querySelector('[data-act="chip-time"][data-t="t10"]')?.classList.add('active');
    applySearch(true);
  }
  else if(act==='open-rand') {
    if(works.length){
      const rnd=works[Math.floor(Math.random()*works.length)];
      openBookDetail(rnd);
    }
  }
  else if(act==='tab-shelf-fav') { switchView('v-shelf'); curShelf='fav'; document.querySelectorAll('#shelf-seg button').forEach(el=>el.classList.toggle('active',el.dataset.t==='fav')); renderShelf(); }
  else if(act==='open-fav-authors') {
    switchView('v-search');
    searchState.scope={ type:'favAuthors', value:'', label:'お気に入り作家の作品' };
    searchPool=works.filter(w=>favAuthors.has(w.a));
    searchCursor=0;
    $('search-init-box').style.display='none';
    $('search-results-area').style.display='block';
    $('search-scope-bar').style.display='flex';
    $('search-scope-text').textContent=`お気に入り作家 (${searchPool.length}件)`;
    $('search-tiles').innerHTML=rows(searchPool.slice(0,40),w=>tileHtml(w));
    watchBookCovers($('search-tiles'));
    searchCursor=40;
  }
  else if(act==='tab-shelf-want') { switchView('v-shelf'); curShelf='want'; document.querySelectorAll('#shelf-seg button').forEach(el=>el.classList.toggle('active',el.dataset.t==='want')); renderShelf(); }
  else if(act==='tab-shelf-notes') { switchView('v-shelf'); curShelf='notes'; document.querySelectorAll('#shelf-seg button').forEach(el=>el.classList.toggle('active',el.dataset.t==='notes')); renderShelf(); }
  else if(act==='open-ai-chat') openAiChat();
  else if(act==='smart-rec-click') {
    const wid=b.dataset.id;
    if(wid&&byId.has(wid)) openBookDetail(byId.get(wid));
  }

  // ホームのしおり
  else if(act==='open-bookmark'){
    e.preventDefault();
    e.stopPropagation();
    const w=byId.get(b.dataset.id);
    const f=Number(b.dataset.f);
    if(w){
      closeSheet();
      openReader(w,false,Number.isFinite(f)?f:null);
    }
  }

  // 栞・メモ・蛍光ペンの個別削除
  else if(act==='delete-record'){
    e.preventDefault();
    e.stopPropagation();
    const kind=b.dataset.kind, id=b.dataset.id, index=Number(b.dataset.index);
    if(removeStoredRecord(kind,id,index)){
      save();
      renderNotesShelf();
      renderHomeBookmarks();
      const labels={bookmark:'栞',memo:'メモ',highlight:'蛍光ペン'};
      toast((labels[kind]||'記録')+'を削除しました');
    }
  }

  // 本の操作
  else if(act==='resume-click'){
    const wid=b.dataset.wid;
    if(wid&&byId.has(wid)){ closeSheet(); openReader(byId.get(wid)); }
    else if(featList.length) openBookDetail(featList[0]);
  }
  else if(act==='feat-click'){
    if(featList[featIdx]) openBookDetail(featList[featIdx]);
  }
  else if(act==='feat-next'){
    e.stopPropagation();
    featIdx=(featIdx+1)%featList.length;
    renderFeatItem();
  }
  else if(act==='feat-pin'){
    e.stopPropagation();
    const w=featList[featIdx];
    if(w){
      const todayStr=localDateKey();
      if(st.todayBook && st.todayBook.id === w.id){
        st.todayBook = null;
        toast('固定を解除しました');
      } else {
        st.todayBook = { id: w.id, date: todayStr };
        toast(`『${w.t}』を今日の一冊に固定しました`);
      }
      save();
      renderHome();
    }
  }
  else if(act==='feat-read'){
    e.stopPropagation();
    const w=featList[featIdx];
    if(w) openReader(w);
  }
  else if(act==='open-book'){
    const w=byId.get(b.dataset.id);
    if(w) openBookDetail(w);
  }
  else if(act==='read-now'){
    e.stopPropagation();
    closeSheet(true);
    history.replaceState(null,'',location.href);
    openReader(activeBook, false);
  }
  else if(act==='toggle-want'){
    want.has(activeBook.id)?want.delete(activeBook.id):want.add(activeBook.id);
    save(); pulseState(b); openBookDetail(activeBook);
  }
  else if(act==='toggle-fav'){
    const isF=fav.has(activeBook.id);
    if(isF){ fav.delete(activeBook.id); toast('お気に入りを解除しました',()=>{fav.add(activeBook.id);save();}); }
    else fav.add(activeBook.id);
    save(); pulseState(b); openBookDetail(activeBook);
  }
  else if(act==='toggle-fav-author'){
    const a=b.dataset.author;
    if(favAuthors.has(a)){ favAuthors.delete(a); toast(`作家「${a}」のフォローを解除しました`); }
    else { favAuthors.add(a); toast(`作家「${a}」をお気に入りに追加しました`); }
    save(); openBookDetail(activeBook);
  }
  else if(act==='open-author-page'){
    const author=b.dataset.author;
    closeSheet();
    openSearchPage();
    searchState.scope={ type:'author', value:author, label:`作家: ${author}` };
    searchState.query='';
    $('q-input').value='';
    applySearch(true);
  }

  // 本棚
  else if(act==='shelf-tab'){
    curShelf=b.dataset.t;
    document.querySelectorAll('#shelf-seg button').forEach(el=>el.classList.toggle('active',el.dataset.t===curShelf));
    renderShelf();
  }

  // 読書画面
  else if(act==='r-back') closeReader();
  else if(act==='r-retry'){ if(curWork) openReader(curWork); }
  else if(act==='r-bm'){
    const f=pos[curWork.id]?.f||0;
    (bm[curWork.id]=bm[curWork.id]||[]).push({f,s:curWork.plain?curWork.plain.slice(f*curWork.plain.length,f*curWork.plain.length+18).replace(/\s+/g,' '):curWork.t,t:Date.now()});
    save(); toast('しおりを挟みました');
  }
  else if(act==='r-vt'){ st.v=st.v===false; applyReaderConfig(); updateProgress(); save(); }
  else if(act==='r-mode-sheet'){ openModeSelectSheet(); }
  else if(act==='r-ui-toggle'){ toggleReaderChrome(); }
  else if(act==='set-read-mode'){
    st.rMode=b.dataset.m;
    applyReaderMode();
    save();
    closeSheet();
    toast(`読書モード: ${st.rMode==='normal'?'通常':st.rMode==='focus'?'集中':'夜間'}`);
  }
  else if(act==='r-exit-focus'){
    st.rMode='normal';
    applyReaderMode();
    save();
    toast('集中モードを解除しました');
  }
  else if(act==='r-search-open'){ $('r-search-bar').style.display='flex'; $('r-search-inp').focus(); }
  else if(act==='r-search-close'){ $('r-search-bar').style.display='none'; }
  else if(act==='r-search-prev'){ jumpToInBookMatch(inBookSearchIdx-1); }
  else if(act==='r-search-next'){ jumpToInBookMatch(inBookSearchIdx+1); }
  else if(act==='r-wake'){
    if(wakeLock){ await releaseScreenWakeLock(); }
    else { wakeLockWanted=true; await requestScreenWakeLock(); }
  }
  else if(act==='r-tts'){
    if(!('speechSynthesis' in window)){ toast('音声合成未対応です'); return; }
    if(speechSynthesis.speaking){ speechSynthesis.cancel(); toast('朗読を停止しました'); }
    else {
      const f=pos[curWork.id]?.f||0;
      const startChar=Math.floor(f*(curWork.plain?.length||0));
      const u=new SpeechSynthesisUtterance(toPlain(curDoc.html).slice(startChar,startChar+2000));
      u.lang='ja-JP'; speechSynthesis.speak(u); toast('朗読を開始しました');
    }
  }
  else if(act==='r-cfg'){
    sheet('表示設定',`
      <div class="reader-config-panel">
        <div class="reader-config-row">
          <div><span class="reader-config-label">文字サイズ</span><output id="r-fs-value">${st.fs}px</output></div>
          <input type="range" min="14" max="32" step="1" value="${st.fs}" data-act="set-fs-range" aria-label="文字サイズ">
        </div>
        <div class="reader-config-row">
          <div><span class="reader-config-label">行間</span><output id="r-lh-value">${Number(st.lh).toFixed(1)}</output></div>
          <input type="range" min="1.6" max="2.8" step="0.1" value="${st.lh}" data-act="set-lh-range" aria-label="行間">
        </div>
      </div>`);
  }
  else if(act==='r-menu'){
    const isAi=aiConn.ok && canUseOllama();
    sheet('目次・栞',`
      <div style="display:flex; flex-direction:column; gap:16px">
        <div style="display:flex; gap:8px">
          ${isAi?`<button class="secondary sm-btn" data-act="r-ai-action" data-m="要約" style="flex:1">AI要約</button>`:''}
        </div>
        <div style="font-weight:700">目次</div>
        <div style="max-height:180px; overflow-y:auto">${[...$('body').querySelectorAll('[data-hid]')].map(h=>`<div style="padding:12px; border-bottom:1px solid var(--line); cursor:pointer" data-act="jmp-h" data-hid="${escAttr(h.dataset.hid)}">${esc(h.textContent)}</div>`).join('')||'<div style="color:var(--sub)">目次情報なし</div>'}</div>
      </div>`);
  }
  else if(act==='jmp-h'){
    const hid=b.dataset.hid;
    const h=$('body').querySelector(`[data-hid="${hid}"]`);
    if(h){ closeSheet(); h.scrollIntoView({behavior:'smooth'}); }
  }
  else if(act==='r-ai-action') openAiChat(b.dataset.m+'してください');

  // ポップオーバー
  else if(act==='hl'){
    const s=getSelection();
    if(s && s.rangeCount){
      try {
        const sp=document.createElement('span'); sp.className=b.dataset.c;
        s.getRangeAt(0).surroundContents(sp);
        (hls[curWork.id]=hls[curWork.id]||[]).push({t:s.toString(),c:b.dataset.c,d:Date.now()});
        save(); toast('蛍光ペンを引きました');
      } catch(err){
        toast('この範囲にはハイライトを付けられません');
      }
    }
    $('pop').classList.remove('open');
  }
  else if(act==='pop-copy'){    const txt=getSelection().toString();
    $('pop').classList.remove('open');
    if(txt){
      const quoteText=`「${txt}」\n\n――『${curWork?.t||''}』\n${curWork?.a||''}`;
      if(navigator.clipboard && navigator.clipboard.writeText){
        navigator.clipboard.writeText(quoteText).then(()=>{ toast('引用をコピーしました'); }).catch(()=>{ toast('コピーできませんでした'); });
      } else {
        toast('お使いの環境ではコピーできません');
      }
    }
  }
  else if(act==='pop-memo'){
    const txt=getSelection().toString(); $('pop').classList.remove('open');
    sheet('メモを追加',`
      <textarea id="memo-inp" rows="3" placeholder="メモを入力…" style="width:100%; background:var(--card-sub); padding:12px; border-radius:8px; margin-bottom:12px; font-size:var(--fs-b)"></textarea>
      <button class="primary" data-act="save-memo" data-s="${esc(txt)}" style="width:100%">保存</button>`);
  }
  else if(act==='save-memo'){
    const memoVal=$('memo-inp').value.trim();
    if(memoVal){
      (notes[curWork.id]=notes[curWork.id]||[]).push({s:b.dataset.s,m:memoVal,t:Date.now()});
      save(); closeSheet(); toast('メモを保存しました');
    } else {
      toast('メモの内容を入力してください');
    }
  }
  else if(act==='pop-ai'){
    const txt=getSelection().toString(); $('pop').classList.remove('open');
    openAiChat(`「${txt}」について教えてください`);
  }
  else if(act==='pop-bm'){
    const f=pos[curWork.id]?.f||0;
    (bm[curWork.id]=bm[curWork.id]||[]).push({f,s:curWork.plain?curWork.plain.slice(f*curWork.plain.length,f*curWork.plain.length+18).replace(/\s+/g,' '):curWork.t,t:Date.now()});
    save(); $('pop').classList.remove('open'); toast('しおりを挟みました');
  }

  // AIチャット
  else if(act==='ai-send') sendAiMessage($('ai-input').value.trim());
  else if(act==='ai-stop'&&aiAbort) aiAbort.abort();
  else if(act==='ai-chip') sendAiMessage(b.dataset.q);

  // 設定
  else if(act==='set-ollama-toggle'){
    st.ollamaEnabled = b.dataset.v === '1';
    save();
    if(st.ollamaEnabled) pingOllama();
    else { aiConn.ok = false; aiConn.err = ''; }
    renderSettingsPage();
    renderHome();
    toast(st.ollamaEnabled ? 'Ollama連携を有効にしました' : 'Ollama連携を無効にしました');
  }
  else if(act==='set-th'){
    st.theme=b.dataset.v;
    applySettings();
    renderSettingsPage();
  }
  else if(act==='set-low-spec'){
    st.lowSpec=b.dataset.v==='1';
    save();
    applyPerformanceMode();
    if(st.lowSpec){clearInterval(featTimer);featTimer=null;clearInterval(auditTimer);auditTimer=null;}
    else {startFeatTimer();startAudit();}
    renderHome();
    renderSettingsPage();
    toast(st.lowSpec?'低スペックモードをONにしました':'低スペックモードをOFFにしました');
  }
  else if(act==='set-ft'){ st.font=b.dataset.v; applyReaderConfig(); save(); renderSettingsPage(); }
  else if(act==='set-save-url'){ st.oUrl = normalizeOllamaUrl($('set-ourl').value.trim()); save(); pingOllama(); toast('URLを保存しました'); }
  else if(act==='set-pick-mod'){
    sheet('モデル選択',aiConn.models.map(m=>`<div class="block" data-act="set-mod-val" data-m="${escAttr(m)}" style="min-height:56px; padding:16px; margin-bottom:8px; font-weight:700">${esc(m)}</div>`).join('')||'<div>利用可能なモデルがありません</div>');
  }
  else if(act==='set-mod-val'){ st.oMod=b.dataset.m; save(); closeSheet(); renderSettingsPage(); }
  else if(act==='set-ping'){ await pingOllama(); toast(aiConn.ok?'接続を確認しました':'接続できませんでした'); renderSettingsPage(); }
  else if(act==='cat-intro') openCatalogIntro();
  else if(act==='cat-auto') fetchCatalog();
  else if(act==='cache-clear'){
    const db=await idb.d; db.transaction('docs','readwrite').objectStore('docs').clear();
    savedKeys.clear(); toast('キャッシュを消去しました');
  }
  else if(act==='data-export'){
    try{
      const blob=new Blob([JSON.stringify({allWorks,fav:[...fav],want:[...want],done:[...done],favAuthors:[...favAuthors],pos,bm,notes,hls,hist,calData,goalMin,st,searchHistory})],{type:'application/json'});
      const url=URL.createObjectURL(blob),a=document.createElement('a');
      a.href=url;a.download='aozora_terminal_backup.json';a.click();
      setTimeout(()=>URL.revokeObjectURL(url),1000);
      toast('バックアップを書き出しました');
    }catch{toast('バックアップを書き出せませんでした');}
  }
  else if(act==='toast-undo'){
    if(undoFn) undoFn();
    $('toast').classList.remove('open');
  }
});

function applySettings(){
  let th=st.theme;
  if(th==='auto') th=matchMedia('(prefers-color-scheme:dark)').matches?'dark':'sepia';
  document.documentElement.dataset.theme=th;
  save();
}

function detectLowPowerMode(){
  if(!('matchMedia' in window)) return false;
  return matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function applyPerformanceMode(){
  const low=!!st.lowSpec || detectLowPowerMode();
  document.body.classList.toggle('low-power',low);
  document.body.classList.toggle('rich-motion',!low);
  if(low){
    clearInterval(featTimer);featTimer=null;
    clearInterval(auditTimer);auditTimer=null;
  }
}

if(window.matchMedia){
  const motionQuery = matchMedia('(prefers-reduced-motion: reduce)');
  const motionListener = ()=> applyPerformanceMode();
  if(motionQuery.addEventListener) motionQuery.addEventListener('change', motionListener);
  else if(motionQuery.addListener) motionQuery.addListener(motionListener);
}

const colorSchemeQuery=matchMedia('(prefers-color-scheme:dark)');
const colorSchemeListener=()=>{ if(st.theme==='auto') applySettings(); };
if(colorSchemeQuery.addEventListener) colorSchemeQuery.addEventListener('change',colorSchemeListener);
else if(colorSchemeQuery.addListener) colorSchemeQuery.addListener(colorSchemeListener);

$('r-slider').oninput=e=>{
  lastUserActivityTime=Date.now();
  setReaderPage(Number(e.target.value)||0,false);
};
let readerLayoutResizeTimer=0;
window.addEventListener('resize',()=>{
  if(!$('reader')?.classList.contains('open'))return;
  clearTimeout(readerLayoutResizeTimer);
  readerLayoutResizeTimer=setTimeout(()=>{
    const preserve=readerPageProgress();
    syncReaderPagination(preserve);
  },80);
},{passive:true});

$('rng-goal').oninput=e=>{ goalMin=parseInt(e.target.value,10); $('cal-goal-txt').textContent=goalMin+'分'; save(); renderCalendar(); renderHome(); };
$('r-search-inp').oninput=()=>execInBookSearch();

function bindUiRipple(){
  document.addEventListener('pointerdown',e=>{
    if(document.body.classList.contains('low-power') || !document.body.classList.contains('rich-motion')) return;
    const el=e.target.closest('button,[data-act="open-book"],[data-act="resume-click"],[data-act="feat-click"]');
    if(!el || !el.getBoundingClientRect().width) return;
    if(getComputedStyle(el).position==='static') el.style.position='relative';
    const r=el.getBoundingClientRect(), ripple=document.createElement('span');
    ripple.className='ui-ripple'; ripple.style.left=(e.clientX-r.left)+'px'; ripple.style.top=(e.clientY-r.top)+'px';
    el.appendChild(ripple); setTimeout(()=>ripple.remove(),460);
  },{passive:true});
}

/* ==================== 15. 初期化 ==================== */
function initHomeHeroMotion(){
  const hero=$('blk-resume');
  if(!hero || !window.matchMedia || !matchMedia('(hover:hover)').matches) return;
  hero.addEventListener('pointermove',e=>{
    if(document.body.classList.contains('low-power') || !document.body.classList.contains('rich-motion')) return;
    const r=hero.getBoundingClientRect();
    const x=((e.clientX-r.left)/r.width-.5)*2;
    const y=((e.clientY-r.top)/r.height-.5)*2;
    hero.style.setProperty('--hero-x',x.toFixed(3));
    hero.style.setProperty('--hero-y',y.toFixed(3));
  });
  hero.addEventListener('pointerleave',()=>{
    hero.style.setProperty('--hero-x','0');
    hero.style.setProperty('--hero-y','0');
  });
}

window.addEventListener('DOMContentLoaded',async()=>{
  const phoneMode=()=>document.documentElement.dataset.device==='smartphone';
  const safeStage=(p,t)=>{try{setBootStage(p,t)}catch{}};
  const safeStep=async(fn,label)=>{
    try{return await fn()}catch(err){console.warn('init step failed:',label,err);return null;}
  };

  safeStage(12,'表示環境を確認中…');
  // IndexedDB上のカタログ・権利確認データをブラウザの永続ストレージとして保持するよう要求。
  // 拒否されてもアプリは通常動作し、保存データ自体はIndexedDBへ残す。
  void safeStep(()=>requestPersistentStorage(),'persistent-storage');

  // スマホは共通アプリの初期化完了を待たず、先に独立UIを操作可能にする。
  if(phoneMode()){
    requestAnimationFrame(()=>{
      try{
        document.getElementById('app-boot')?.classList.add('done');
        document.body.classList.add('phone-init-fast');
      }catch{}
    });
  }

  await safeStep(()=>applyPerformanceMode(),'performance');
  safeStage(30,'保存データを読み込み中…');
  await safeStep(()=>load(),'state');
  await safeStep(()=>{ window.__aozoraPhoneSyncSettings?.(); },'phone-reader-settings');

  await safeStep(()=>applyPerformanceMode(),'performance-after-load');
  safeStage(52,'読書設定を反映中…');
  await safeStep(()=>applySettings(),'settings');
  await safeStep(()=>applyReaderConfig(),'reader-settings');
  await safeStep(()=>initHomeHeroMotion(),'hero-motion');
  await safeStep(()=>enhanceActionables(),'actionables');
  await safeStep(()=>bindPressPhysics(),'press-physics');
  await safeStep(()=>bindUiRipple(),'ui-ripple');

  safeStage(70,'本棚を準備中…');
  await safeStep(()=>checkCatalog(),'catalog');
  scheduleCatalogRefresh();
  await safeStep(()=>hydrateSavedKeys(),'saved-keys');
  await safeStep(()=>renderHome(),'home');

  document.body.classList.add('app-ready');
  safeStage(88,'仕上げています…');

  await safeStep(()=>{
    if(!document.body.classList.contains('low-power')) startFeatTimer();
    if(!document.body.classList.contains('low-power')) startAudit();
  },'background-tasks');

  // Ollama接続確認は起動をブロックしない。
  safeStep(()=>pingOllama(),'ollama');
  finishBoot();

  // 検索入力遅延実行
  const qInput=$('q-input');
  let searchTimer=null;
  if(qInput){
    qInput.oninput=()=>{
      clearTimeout(searchTimer);
      searchTimer=setTimeout(()=>{
        searchState.query=qInput.value;
        applySearch(true);
      },250);
    };
  }

  // 検索無限スクロール
  const sentinel=$('search-sentinel');
  if(sentinel&&'IntersectionObserver' in window){
    new IntersectionObserver(entries=>{
      if(entries[0].isIntersecting && searchCursor<searchPool.length){
        const chunk=searchPool.slice(searchCursor,searchCursor+40);
        searchCursor+=40;
        const target=$('search-tiles');
        if(target)target.insertAdjacentHTML('beforeend',rows(chunk,w=>tileHtml(w)));
      }
    }).observe(sentinel);
  }

  // 共通初期化が途中で止まっても、スマホ側のブートを残さない。
  if(phoneMode()){
    requestAnimationFrame(()=>{
      try{
        document.getElementById('app-boot')?.classList.add('done');
        window.dispatchEvent(new Event('aozora-phone-data-ready'));
      }catch{}
    });
  }
});

/* ================= Mobile UX / Focus Timer v4 ================= */
let mobileFocusTimer=null;
let mobileFocusTimerTick=null;
let focusTimerSheetTick=null;

function focusTimerFormat(ms){
  const sec=Math.max(0,Math.ceil(ms/1000));
  const m=Math.floor(sec/60), s=sec%60;
  return String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');
}
function getResumeWork(){
  const unfinished=hist.map(h=>byId.get(h.id)).filter(w=>w&&((pos[w.id]?.f||0)<0.97));
  return unfinished[0]||null;
}
function getTodayQuickWork(){
  const today=localDateKey();
  if(st.todayBook&&st.todayBook.date===today&&byId.has(st.todayBook.id)) return byId.get(st.todayBook.id);
  return featList[featIdx]||works[Math.floor(Math.random()*Math.max(1,works.length))]||null;
}
function renderFocusTimerPill(){
  const pill=$('focus-timer-pill'), label=$('focus-timer-label');
  if(!pill||!label)return;
  if(!mobileFocusTimer){
    pill.style.display='none';
    return;
  }
  const remaining=mobileFocusTimer.running
    ? Math.max(0,mobileFocusTimer.end-Date.now())
    : mobileFocusTimer.remaining;
  label.textContent=focusTimerFormat(remaining);
  pill.classList.toggle('paused',!mobileFocusTimer.running);
  pill.style.display=window.innerWidth<=899?'inline-flex':'none';
}
function stopFocusTimerTicker(){
  if(mobileFocusTimerTick){clearInterval(mobileFocusTimerTick);mobileFocusTimerTick=null;}
}
function finishFocusTimer(){
  stopFocusTimerTicker();
  if(focusTimerSheetTick){clearInterval(focusTimerSheetTick);focusTimerSheetTick=null;}
  mobileFocusTimer=null;
  renderFocusTimerPill();
  try{navigator.vibrate?.([180,90,180]);}catch{}
  toast('集中読書タイマーが終了しました 📖');
}
function updateFocusTimer(){
  if(!mobileFocusTimer)return;
  if(mobileFocusTimer.running){
    mobileFocusTimer.remaining=Math.max(0,mobileFocusTimer.end-Date.now());
    if(mobileFocusTimer.remaining<=0){finishFocusTimer();return;}
  }
  renderFocusTimerPill();
}
function startFocusTimer(minutes){
  const duration=Math.max(1,Number(minutes)||25)*60*1000;
  mobileFocusTimer={duration,remaining:duration,end:Date.now()+duration,running:true};
  stopFocusTimerTicker();
  mobileFocusTimerTick=setInterval(updateFocusTimer,250);
  renderFocusTimerPill();
  toast(minutes+'分の集中読書を開始しました');
}
function pauseFocusTimer(){
  if(!mobileFocusTimer)return;
  updateFocusTimer();
  mobileFocusTimer.running=false;
  mobileFocusTimer.remaining=Math.max(0,mobileFocusTimer.end-Date.now());
  stopFocusTimerTicker();
  renderFocusTimerPill();
}
function resumeFocusTimer(){
  if(!mobileFocusTimer)return;
  if(mobileFocusTimer.remaining<=0){finishFocusTimer();return;}
  mobileFocusTimer.end=Date.now()+mobileFocusTimer.remaining;
  mobileFocusTimer.running=true;
  stopFocusTimerTicker();
  mobileFocusTimerTick=setInterval(updateFocusTimer,250);
  renderFocusTimerPill();
}
function resetFocusTimer(){
  stopFocusTimerTicker();
  if(focusTimerSheetTick){clearInterval(focusTimerSheetTick);focusTimerSheetTick=null;}
  mobileFocusTimer=null;
  renderFocusTimerPill();
}
function openFocusTimerSheet(){
  if(focusTimerSheetTick){clearInterval(focusTimerSheetTick);focusTimerSheetTick=null;}
  const current=mobileFocusTimer;
  const live=current?(current.running?Math.max(0,current.end-Date.now()):current.remaining):25*60*1000;
  if(current){
    sheet('集中読書タイマー',`
      <div class="focus-timer-hero">
        <div class="focus-timer-clock" id="focus-sheet-clock">${focusTimerFormat(live)}</div>
        <div class="focus-timer-caption">${current.running?'集中して読んでいます':'一時停止中です'}</div>
      </div>
      <div style="display:flex;gap:8px">
        ${current.running
          ? '<button class="primary" data-act="focus-pause" style="flex:2">一時停止</button>'
          : '<button class="primary" data-act="focus-resume" style="flex:2">再開</button>'}
        <button class="secondary" data-act="focus-reset" style="flex:1">リセット</button>
      </div>
      <div style="font-size:13px;color:var(--sub);line-height:1.6">タイマーは画面を閉じても端末の時刻を基準に進みます。終了時は通知とバイブレーションを試みます。</div>
    `);
    const timerSheetRefresh=()=>{
      const el=$('focus-sheet-clock');
      if(!el||!mobileFocusTimer)return;
      const left=mobileFocusTimer.running?Math.max(0,mobileFocusTimer.end-Date.now()):mobileFocusTimer.remaining;
      el.textContent=focusTimerFormat(left);
      if(left<=0) finishFocusTimer();
    };
    focusTimerSheetTick=setInterval(()=>{
      if(!$('sheet').classList.contains('open')){
        clearInterval(focusTimerSheetTick);
        focusTimerSheetTick=null;
        return;
      }
      timerSheetRefresh();
    },250);
    return;
  }
  sheet('集中読書タイマー',`
    <div class="focus-timer-hero">
      <div class="focus-timer-clock" id="focus-sheet-clock">25:00</div>
      <div class="focus-timer-caption">本を開いて、集中する時間を決めよう</div>
    </div>
    <div class="focus-preset-grid">
      <button class="secondary" data-act="focus-preset" data-min="5">5分</button>
      <button class="secondary" data-act="focus-preset" data-min="15">15分</button>
      <button class="secondary" data-act="focus-preset" data-min="25">25分</button>
    </div>
    <div class="focus-preset-grid">
      <button class="secondary" data-act="focus-preset" data-min="45">45分</button>
      <button class="secondary" data-act="focus-preset" data-min="60">60分</button>
      <button class="primary" data-act="focus-start" data-min="25">25分で開始</button>
    </div>
    <div style="font-size:13px;color:var(--sub);line-height:1.6">読書中は残り時間が小さく表示されます。ページを離れてもタイマーは動き続けます。</div>
  `);
}
function openMobileQuickSheet(){
  const resume=getResumeWork();
  const today=getTodayQuickWork();
  const random=works.length?works[Math.floor(Math.random()*works.length)]:null;
  const readLabel=resume?'続きから読む':'おすすめを読む';
  sheet('クイックメニュー',`
    <div class="mobile-quick-grid">
      <button class="block mobile-quick-card blue" data-act="quick-resume">
        <span class="mq-icon">↻</span>
        <span class="mq-title">${readLabel}</span>
        <span class="mq-sub">${resume?esc(resume.t):'まず一冊を開きます'}</span>
      </button>
      <button class="block mobile-quick-card green" data-act="quick-today">
        <span class="mq-icon">✦</span>
        <span class="mq-title">今日の一冊</span>
        <span class="mq-sub">${today?esc(today.t):'おすすめを探します'}</span>
      </button>
      <button class="block mobile-quick-card orange" data-act="quick-random" ${random?'':'disabled'}>
        <span class="mq-icon">⌘</span>
        <span class="mq-title">ランダム</span>
        <span class="mq-sub">思いがけない一冊へ</span>
      </button>
      <button class="block mobile-quick-card purple" data-act="quick-timer">
        <span class="mq-icon">◷</span>
        <span class="mq-title">${mobileFocusTimer?'タイマーを開く':'集中タイマー'}</span>
        <span class="mq-sub">${mobileFocusTimer?focusTimerFormat(mobileFocusTimer.running?mobileFocusTimer.end-Date.now():mobileFocusTimer.remaining):'5〜60分から選択'}</span>
      </button>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:2px">
      <button class="secondary" data-act="quick-search">検索を開く</button>
      <button class="secondary" data-act="quick-shelf">本棚を開く</button>
    </div>
  `);
}

document.addEventListener('click',e=>{
  const b=e.target.closest?.('[data-act]');
  if(!b)return;
  const act=b.dataset.act;
  if(act==='mobile-quick'){openMobileQuickSheet();return;}
  if(act==='focus-timer'){openFocusTimerSheet();return;}
  if(act==='quick-resume'){
    const w=getResumeWork()||featList[featIdx]||works[0];
    closeSheet();
    if(w) openReader(w); else toast('作品カタログを準備してください');
    return;
  }
  if(act==='quick-today'){
    const w=getTodayQuickWork();
    closeSheet();
    if(w) openBookDetail(w); else toast('作品カタログを準備してください');
    return;
  }
  if(act==='quick-random'){
    const w=works.length?works[Math.floor(Math.random()*works.length)]:null;
    closeSheet();
    if(w) openBookDetail(w); else toast('作品カタログを準備してください');
    return;
  }
  if(act==='quick-search'){
    closeSheet();
    switchView('v-search');
    requestAnimationFrame(()=>$('q-input')?.focus());
    return;
  }
  if(act==='quick-shelf'){
    closeSheet();
    switchView('v-shelf');
    return;
  }
  if(act==='quick-timer'){
    openFocusTimerSheet();
    return;
  }
  if(act==='focus-preset'){
    const min=Number(b.dataset.min)||25;
    const preview=$('focus-sheet-clock');
    if(preview)preview.textContent=String(min).padStart(2,'0')+':00';
    document.querySelectorAll('[data-act="focus-preset"]').forEach(x=>x.classList.remove('active'));
    b.classList.add('active');
    const startBtn=document.querySelector('[data-act="focus-start"]');
    if(startBtn)startBtn.dataset.min=String(min);
    if(startBtn)startBtn.textContent=min+'分で開始';
    return;
  }
  if(act==='focus-start'){
    startFocusTimer(Number(b.dataset.min)||25);
    closeSheet();
    return;
  }
  if(act==='focus-pause'){
    pauseFocusTimer();
    openFocusTimerSheet();
    return;
  }
  if(act==='focus-resume'){
    resumeFocusTimer();
    openFocusTimerSheet();
    return;
  }
  if(act==='focus-reset'){
    resetFocusTimer();
    closeSheet();
    toast('集中タイマーをリセットしました');
    return;
  }
});

function bindMobilePageSwipe(){
  const page=$('body');
  if(document.documentElement.dataset.device==='smartphone')return;
  if(!page||page.dataset.swipeUxBound)return;
  page.dataset.swipeUxBound='1';
  let sx=0,sy=0,active=false;
  page.addEventListener('touchstart',e=>{
    if(!page.classList.contains('v')){active=false;return;}
    const t=e.touches[0];if(!t){active=false;return;}
    sx=t.clientX;sy=t.clientY;active=true;
  },{passive:true});
  page.addEventListener('touchend',e=>{
    if(!active||!page.classList.contains('v'))return;
    active=false;
    const t=e.changedTouches[0];if(!t)return;
    const dx=t.clientX-sx,dy=t.clientY-sy;
    if(Math.abs(dx)<55||Math.abs(dx)<Math.abs(dy)*1.35)return;
    const next=dx<0;
    turnReaderPage(next?'next':'prev');
  });
}

window.addEventListener('DOMContentLoaded',()=>{
  bindMobilePageSwipe();
  renderFocusTimerPill();
  window.addEventListener('resize',renderFocusTimerPill,{passive:true});
});



/* ============================================================
   Smartphone iOS-like router v2
   Keeps the desktop engine/data layer, but gives smartphones a
   complete independent navigation + reader experience.
   ============================================================ */
(function(){
  const isPhone=()=>document.documentElement.dataset.device==='smartphone';
  const $p=sel=>document.querySelector(sel);
  const $$p=sel=>Array.from(document.querySelectorAll(sel));
  const state={
    screen:'home',
    work:null,
    reader:false,
    saveTimer:0,
    query:'',
    shelf:'reading',
    record:'all',
    readerFs:Number(st?.fs)||19,
    readerLh:Number(st?.lh)||2.05,
    searchHits:[],
    searchIndex:0,
    readerDoc:null,
    sheetOpen:false,
    headerCompact:false,
    readerFromDetail:false
  };

  const escP=s=>String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));

  // Cache the smartphone catalog and precompute search text to reduce repeated work.
  let phoneWorksCache=[];
  let phoneWorksIndex=[];
  let phoneWorksCacheSize=-1;
  let phoneWorksCacheMap=null;
  const works=()=>{
    const map=byId instanceof Map?byId:null;
    const size=map?map.size:-1;
    if(map!==phoneWorksCacheMap||size!==phoneWorksCacheSize){
      phoneWorksCache=Array.from(map?.values?.()||[]).filter(isPublicWork);
      phoneWorksIndex=phoneWorksCache.map(w=>({w,text:(wt(w)+' '+wa(w)).toLocaleLowerCase('ja')}));
      phoneWorksCacheSize=size;
      phoneWorksCacheMap=map;
    }
    return phoneWorksCache;
  };
  const getWork=id=>byId.get(String(id))||byId.get(id)||null;
  const wt=w=>w?.t||w?.title||'作品';
  const wa=w=>w?.a||w?.author||w?.authors||'';
  const wc=w=>String(w?.c??'');
  const workColor=w=>{try{return colorOf(wt(w))}catch{return '#59636b'}};
  const cover=w=>(w?.cover||w?.img||w?.image||w?.thumbnail||'');
  const progressOf=w=>Math.max(0,Math.min(1,Number(pos?.[w?.id]?.f||0)));
  const dateText=t=>t?new Date(t).toLocaleDateString('ja-JP',{month:'short',day:'numeric'}):'';
  const setPhoneTitle=t=>{const e=$p('#phone-title');if(e)e.textContent=t;};

  function phoneHaptic(ms=7){try{navigator.vibrate?.(ms)}catch{}}

  function phoneSearchSave(){
    const q=String(state.query||'').trim();
    if(!q||q.length>120)return;
    searchHistory=[q,...searchHistory.filter(x=>String(x)!==q)].slice(0,8);
    save();
  }

  function phoneReadingStreak(){
    const days=new Set();
    for(const h of hist||[]){
      const t=Number(h?.t)||0;
      if(t>0)days.add(new Date(t).toLocaleDateString('en-CA',{timeZone:'Asia/Tokyo'}));
    }
    let streak=0,cursor=new Date();
    cursor.setHours(0,0,0,0);
    while(streak<366){
      const key=cursor.toLocaleDateString('en-CA',{timeZone:'Asia/Tokyo'});
      if(!days.has(key))break;
      streak++;cursor.setDate(cursor.getDate()-1);
    }
    return streak;
  }

  async function sharePhoneWork(w=state.work){
    if(!w)return;
    const title=wt(w),author=wa(w);
    const text=author?title+' — '+author:title;
    const baseUrl=location.href.split('#')[0];
    const url=baseUrl+'#work='+encodeURIComponent(String(w.id));
    try{
      if(navigator.share){await navigator.share({title,text,url});return;}
      if(navigator.clipboard?.writeText){
        await navigator.clipboard.writeText(text+'\\n'+url);
        toast('作品情報をコピーしました');
        return;
      }
    }catch(err){if(err?.name==='AbortError')return;}
    toast('共有機能を利用できません');
  }

  function phonePress(el){
    if(!el)return;
    el.classList.add('phone-pressing');
    clearTimeout(el.__phonePressTimer);
    el.__phonePressTimer=setTimeout(()=>el.classList.remove('phone-pressing'),210);
  }

  function bindPhoneHeaderScroll(){
    const content=$p('#phone-content'),header=$p('.phone-header');
    if(!content||!header||content.dataset.headerBound==='1')return;
    content.dataset.headerBound='1';
    let raf=0;
    content.addEventListener('scroll',()=>{
      if(raf)return;
      raf=requestAnimationFrame(()=>{
        raf=0;
        const compact=content.scrollTop>18;
        if(compact!==state.headerCompact){
          state.headerCompact=compact;
          header.classList.toggle('compact',compact);
        }
        const tabbar=$p('.phone-tabbar');
        if(tabbar){
          const now=content.scrollTop;
          const delta=now-(content.__iosLastScroll||0);
          const collapse=now>44&&delta>2;
          const reveal=now<24||delta<-2;
          if(reveal)tabbar.classList.remove('ios-tabbar-collapsed');
          else if(collapse)tabbar.classList.add('ios-tabbar-collapsed');
          content.__iosLastScroll=now;
        }
      });
    },{passive:true});
  }

  function bindReaderChrome(){
    const body=$p('#phone-reader-body'),reader=$p('#phone-reader');
    if(!body||!reader||body.dataset.chromeBound==='1')return;
    body.dataset.chromeBound='1';
    let last=body.scrollTop,raf=0;
    const update=()=>{
      raf=0;
      const now=body.scrollTop;
      const delta=now-last;
      last=now;
      if(now<18 || delta<-3){
        reader.classList.remove('reader-chrome-hidden');
      }else if(delta>4 && now>48){
        reader.classList.add('reader-chrome-hidden');
      }
    };
    body.addEventListener('scroll',()=>{
      if(raf)return;
      raf=requestAnimationFrame(update);
    },{passive:true});
    body.addEventListener('click',e=>{
      if(e.target.closest?.('a,button,input,select,textarea'))return;
      reader.classList.toggle('reader-chrome-hidden');
    },{passive:true});
  }

  function bindPhoneSheetDrag(){
    const sheet=$p('#phone-sheet');
    if(!sheet||sheet.dataset.dragBound==='1')return;
    sheet.dataset.dragBound='1';
    const head=$p('.phone-sheet-head');
    if(!head)return;
    let startY=0,dragging=false,active=false;
    const reset=()=>{
      sheet.style.transform='';
      sheet.style.transition='';
      dragging=false;active=false;
    };
    head.addEventListener('pointerdown',e=>{
      if(e.pointerType==='mouse'||e.target.closest?.('.phone-icon-button'))return;
      startY=e.clientY;dragging=true;active=true;
      sheet.style.transition='none';
    },{passive:true});
    head.addEventListener('pointermove',e=>{
      if(!active)return;
      const dy=Math.max(0,e.clientY-startY);
      if(dy>0)sheet.style.transform='translate3d(0,'+dy+'px,0)';
    },{passive:true});
    head.addEventListener('pointerup',e=>{
      if(!active)return;
      const dy=Math.max(0,e.clientY-startY);
      sheet.style.transition='';
      if(dy>92){
        reset();
        closePhoneSheet();
      }else{
        sheet.style.transform='translate3d(0,0,0)';
        setTimeout(()=>{if(!dragging)sheet.style.transform='';},220);
      }
      dragging=false;active=false;
    },{passive:true});
    head.addEventListener('pointercancel',reset,{passive:true});
  }

  function bookVisual(w,cls='phone-book-cover',detail=false){
    const img=cover(w);
    if(img)return '<img class="'+cls+'" src="'+escP(img)+'" alt="" loading="lazy">';
    const text=wt(w).slice(0,8);
    return '<div class="'+cls+' phone-book-placeholder" style="background:'+escP(workColor(w))+';color:#fff"><span>'+escP(text)+'</span></div>';
  }

  function bookCard(w){
    const p=Math.round(progressOf(w)*100);
    return '<button class="phone-book" data-phone-work="'+escP(w.id)+'">'+
      bookVisual(w)+
      '<div class="phone-book-name">'+escP(wt(w))+'</div>'+
      '<div class="phone-book-meta">'+escP(wa(w))+(p>0?' · '+p+'%':'')+'</div>'+
      (p>0?'<div class="phone-progress-line" style="margin-top:6px;height:3px"><span style="width:'+p+'%"></span></div>':'')+
      '</button>';
  }

  function getResumeWork(){
    return hist.map(h=>getWork(h.id)).filter(Boolean).find(w=>progressOf(w)<.97)||null;
  }
  function getTodayWork(){
    if(st?.todayBook?.id&&getWork(st.todayBook.id))return getWork(st.todayBook.id);
    if(featList?.[featIdx])return featList[featIdx];
    const list=works();
    if(!list.length)return null;
    const day=Math.floor(Date.now()/86400000);
    return list[Math.abs(day)%list.length];
  }

  function renderHome(){
    setPhoneTitle('今読む');
    const c=$p('#phone-content');if(!c)return;
    const resume=getResumeWork(),today=getTodayWork();
    const catalog=works();
    const recent=hist.map(h=>getWork(h.id)).filter(Boolean).slice(0,6);
    const fallback=recent.length?recent:catalog.slice(0,6);
    const reading=catalog.filter(w=>progressOf(w)>0&&progressOf(w)<.97).length;
    const marks=Object.values(bm||{}).reduce((n,a)=>n+(Array.isArray(a)?a.length:0),0);
    const memo=Object.values(notes||{}).reduce((n,a)=>n+(Array.isArray(a)?a.length:0),0);
    const streak=phoneReadingStreak();

    const hero=resume||today;
    const hp=hero?Math.round(progressOf(hero)*100):0;
    c.innerHTML='<section class="phone-section">'+
      (hero?
        '<button class="phone-continue" data-phone-work="'+escP(hero.id)+'">'+
          bookVisual(hero,'phone-continue-cover')+
          '<div class="phone-continue-copy">'+
            '<span class="phone-overline">'+(resume?'続きから読む':'今日の一冊')+'</span>'+
            '<span class="phone-book-title-big">'+escP(wt(hero))+'</span>'+
            '<span class="phone-book-author">'+escP(wa(hero))+'</span>'+
            '<span class="phone-progress-line"><span style="width:'+hp+'%"></span></span>'+
            '<span class="phone-progress-text">'+(hp>0?hp+'%読了':'まず詳細を開く')+'</span>'+
          '</div>'+
        '</button>'
      :'<div class="phone-card phone-empty">作品カタログを準備中です…</div>')+
    '</section>'+
    '<section class="phone-section"><div class="phone-section-head"><h2 class="phone-section-title">クイック</h2></div>'+
      '<div class="phone-quick-grid">'+
        '<button class="phone-quick" data-phone-action="search"><svg class="phone-quick-icon phone-svg" viewBox="0 0 24 24"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 5 5"/></svg><span class="phone-quick-label">作品を探す</span><span class="phone-quick-sub">タイトル・作家名から検索</span></button>'+
        '<button class="phone-quick" data-phone-action="random"><svg class="phone-quick-icon phone-svg" viewBox="0 0 24 24"><path d="M4 6h3c4 0 5 12 10 12h3"/><path d="m17 15 3 3-3 3M17 3l3 3-3 3"/><path d="M4 18h3c1.4 0 2.4-.9 3-2"/></svg><span class="phone-quick-label">ランダム</span><span class="phone-quick-sub">偶然の一冊を開く</span></button>'+
        '<button class="phone-quick" data-phone-action="shelf"><svg class="phone-quick-icon phone-svg" viewBox="0 0 24 24"><path d="M5 4.5A2.5 2.5 0 0 1 7.5 2H19v18H7.5A2.5 2.5 0 0 1 5 17.5z"/><path d="M5 4.5V18a2 2 0 0 0 2 2h.5"/></svg><span class="phone-quick-label">本棚</span><span class="phone-quick-sub">読書中・読みたい・お気に入り</span></button>'+
        '<button class="phone-quick" data-phone-action="today"><svg class="phone-quick-icon phone-svg" viewBox="0 0 24 24"><path d="M6 3v18M18 3v18M6 7h12M6 17h12"/></svg><span class="phone-quick-label">今日の一冊</span><span class="phone-quick-sub">'+(today?escP(wt(today)):'おすすめを選ぶ')+'</span></button>'+
      '</div></section>'+
    '<section class="phone-section"><div class="phone-section-head"><h2 class="phone-section-title">読書状況</h2><button class="phone-section-link" data-phone-action="records">詳しく見る</button></div>'+
      '<div class="phone-stat-row"><div class="phone-stat"><strong>'+reading+'</strong><small>読書中</small></div><div class="phone-stat"><strong>'+streak+'</strong><small>連続日</small></div><div class="phone-stat"><strong>'+marks+'</strong><small>栞</small></div><div class="phone-stat"><strong>'+memo+'</strong><small>メモ</small></div></div>'+
    '</section>'+
    '<section class="phone-section"><div class="phone-section-head"><h2 class="phone-section-title">'+(recent.length?'最近読んだ作品':'おすすめ')+'</h2></div>'+
      '<div class="phone-grid">'+fallback.map(bookCard).join('')+'</div>'+
    '</section>';
  }

  function renderSearch(){
    setPhoneTitle('探す');
    const c=$p('#phone-content');if(!c)return;
    const chips=[['all','すべて'],['new','新着'],['short','10分以内'],['fav','お気に入り作家']];
    const recent=searchHistory.slice(0,5);
    c.innerHTML='<section class="phone-section">'+
      '<div class="phone-search-wrap"><svg class="phone-search-icon phone-svg" viewBox="0 0 24 24"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 5 5"/></svg><input id="phone-search-input" class="phone-search" value="'+escP(state.query)+'" placeholder="作品名・作家名を検索" autocomplete="off" inputmode="search" enterkeyhint="search"></div>'+
      (recent.length?'<div class="phone-search-recent"><span>最近の検索</span>'+recent.map(q=>'<button class="phone-recent-chip" data-phone-action="search-history" data-query="'+escP(q)+'">'+escP(q)+'</button>').join('')+'</div>':'')+
      '<div class="phone-chip-row">'+chips.map(x=>'<button class="phone-chip '+(state.searchFilter===x[0]?'active':'')+'" data-phone-action="search-filter" data-filter="'+x[0]+'">'+x[1]+'</button>').join('')+'</div>'+
      '<div id="phone-result-count" class="phone-result-count"></div><div id="phone-search-results" class="phone-grid"></div>'+
    '</section>';
    const inp=$p('#phone-search-input');
    let drawRaf=0;
    const draw=()=>{
      if(drawRaf)return;
      drawRaf=requestAnimationFrame(()=>{
        drawRaf=0;
        state.query=String(inp?.value||'');
        const q=state.query.trim().toLocaleLowerCase('ja');
        let list=phoneWorksIndex;
        if(state.searchFilter==='new')list=list.slice().sort((a,b)=>(b.w.d||'').localeCompare(a.w.d||''));
        else if(state.searchFilter==='short')list=list.filter(x=>Math.max(1,Math.ceil((x.w.plain?.length||8000)/st.readSpeed))<=10);
        else if(state.searchFilter==='fav')list=list.filter(x=>favAuthors.has(x.w.a));
        if(q)list=list.filter(x=>x.text.includes(q));
        list=list.slice(0,80);
        const count=$p('#phone-result-count');if(count)count.textContent=list.length+'件';
        const result=$p('#phone-search-results');
        if(result)result.innerHTML=list.map(x=>bookCard(x.w)).join('')||'<div class="phone-empty" style="grid-column:1/-1">一致する作品がありません</div>';
      });
    };
    inp?.addEventListener('input',draw);
    inp?.addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();phoneSearchSave();inp.blur();}});
    inp?.addEventListener('blur',phoneSearchSave);
    draw();
  }
  state.searchFilter='all';

  function shelfList(){
    if(state.shelf==='reading')return works().filter(w=>progressOf(w)>0&&progressOf(w)<.97);
    if(state.shelf==='want')return works().filter(w=>want.has(w.id));
    if(state.shelf==='fav')return works().filter(w=>fav.has(w.id));
    if(state.shelf==='done')return works().filter(w=>done.has(w.id));
    const ids=new Set([...Object.keys(bm||{}),...Object.keys(notes||{}),...Object.keys(hls||{})].map(String));
    return works().filter(w=>ids.has(String(w.id)));
  }

  function renderShelf(){
    setPhoneTitle('本棚');
    const c=$p('#phone-content');if(!c)return;
    const chips=[['reading','読書中'],['want','読みたい'],['fav','お気に入り'],['done','読了'],['records','記録']];
    const list=shelfList();
    c.innerHTML='<section class="phone-section">'+
      '<div class="phone-chip-row">'+chips.map(x=>'<button class="phone-chip '+(state.shelf===x[0]?'active':'')+'" data-phone-action="shelf-filter" data-filter="'+x[0]+'">'+x[1]+'</button>').join('')+'</div>'+
      '<div class="phone-result-count">'+list.length+'件</div>'+
      (state.shelf==='records'?'': '<div class="phone-grid">'+list.map(bookCard).join('')+'</div>')+
      (state.shelf==='records'?'<div class="phone-list"><button class="phone-row" data-phone-action="records"><span class="phone-row-icon">≡</span><span class="phone-row-copy"><b class="phone-row-title">栞・メモ・蛍光ペン</b><small class="phone-row-sub">保存した記録をまとめて表示</small></span><span class="phone-chevron">›</span></button></div>':(list.length?'':'<div class="phone-empty">この本棚にはまだ作品がありません</div>'))+
    '</section>';
  }

  function recordRows(){
    const rows=[];
    Object.entries(bm||{}).forEach(([id,a])=>(a||[]).forEach((x,i)=>rows.push({id,kind:'bookmark',index:i,icon:'▱',title:'栞',sub:x.s||'保存した位置',t:x.t||0,f:x.f||0})));
    Object.entries(notes||{}).forEach(([id,a])=>(a||[]).forEach((x,i)=>rows.push({id,kind:'memo',index:i,icon:'✎',title:'メモ',sub:x.m||'',t:x.t||0,f:x.f||0})));
    Object.entries(hls||{}).forEach(([id,a])=>(a||[]).forEach((x,i)=>rows.push({id,kind:'highlight',index:i,icon:'▰',title:'蛍光ペン',sub:x.t||'',t:x.d||0,f:0})));
    return rows.sort((a,b)=>b.t-a.t);
  }

  function renderRecords(){
    setPhoneTitle('記録');
    const c=$p('#phone-content');if(!c)return;
    const filters=[['all','すべて'],['bookmark','栞'],['memo','メモ'],['highlight','蛍光']];
    let rows=recordRows();if(state.record!=='all')rows=rows.filter(x=>x.kind===state.record);
    c.innerHTML='<section class="phone-section"><div class="phone-chip-row">'+filters.map(x=>'<button class="phone-chip '+(state.record===x[0]?'active':'')+'" data-phone-action="record-filter" data-filter="'+x[0]+'">'+x[1]+'</button>').join('')+'</div>'+
      '<div class="phone-result-count">'+rows.length+'件</div><div class="phone-list">'+rows.slice(0,150).map(x=>{
        const w=getWork(x.id);
        return w?'<button class="phone-row" data-phone-work="'+escP(w.id)+'"><span class="phone-row-icon">'+x.icon+'</span><span class="phone-row-copy"><b class="phone-row-title">'+escP(wt(w))+'</b><small class="phone-row-sub">'+escP(x.title)+' · '+escP(x.sub)+' · '+escP(dateText(x.t))+'</small></span><span class="phone-chevron">›</span></button>':'';
      }).join('')+'</div>'+
      (rows.length?'':'<div class="phone-empty">まだ読書記録がありません</div>')+
    '</section>';
  }

  function renderSettings(){
    setPhoneTitle('設定');
    const c=$p('#phone-content');if(!c)return;
    const th=document.documentElement.dataset.theme||'sepia';
    c.innerHTML='<section class="phone-section">'+
      '<div class="phone-section-head"><h2 class="phone-section-title">表示</h2></div>'+
      '<div class="phone-list">'+
        '<button class="phone-row" data-phone-action="theme"><span class="phone-row-icon">◐</span><span class="phone-row-copy"><b class="phone-row-title">テーマ</b><small class="phone-row-sub">現在: '+escP(th==='dark'?'ダーク':th==='light'?'ライト':'自動')+'</small></span><span class="phone-chevron">›</span></button>'+
        '<button class="phone-row" data-phone-action="reader-font"><span class="phone-row-icon">Aa</span><span class="phone-row-copy"><b class="phone-row-title">読書文字サイズ</b><small class="phone-row-sub">'+state.readerFs+'px</small></span><span class="phone-chevron">›</span></button>'+
        '<button class="phone-row" data-phone-action="reader-line"><span class="phone-row-icon">↕</span><span class="phone-row-copy"><b class="phone-row-title">読書の行間</b><small class="phone-row-sub">'+Number(state.readerLh).toFixed(1)+'</small></span><span class="phone-chevron">›</span></button>'+
      '</div>'+
    '</section>'+
    '<section class="phone-section"><div class="phone-section-head"><h2 class="phone-section-title">読書機能</h2></div><div class="phone-list">'+
      '<button class="phone-row" data-phone-action="search"><span class="phone-row-icon">⌕</span><span class="phone-row-copy"><b class="phone-row-title">作品を検索</b><small class="phone-row-sub">青空文庫の登録作品を探す</small></span><span class="phone-chevron">›</span></button>'+
      '<button class="phone-row" data-phone-action="reader-more"><span class="phone-row-icon">⋯</span><span class="phone-row-copy"><b class="phone-row-title">読書機能一覧</b><small class="phone-row-sub">朗読・本文検索・目次・AIなど</small></span><span class="phone-chevron">›</span></button>'+
    '</div></section>'+
    '<section class="phone-section phone-license" aria-label="出典・ライセンス">'+
      '<div class="phone-section-head"><h2 class="phone-section-title">出典・ライセンス</h2></div>'+
      '<div class="phone-license-copy">'+
        '<p>本アプリでは、青空文庫が提供する書誌情報を利用しています。</p>'+
        '<p>書誌情報は <strong>クリエイティブ・コモンズ 表示 4.0 国際（CC BY 4.0）</strong> に基づいて利用しています。</p>'+
        '<p><a href="https://www.aozora.gr.jp/" target="_blank" rel="noopener noreferrer">青空文庫</a> / <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">CC BY 4.0</a></p>'+
        '<p>本アプリは青空文庫の公式アプリケーションではありません。青空文庫による推薦・認可・運営・支持を意味するものではありません。</p>'+
        '<p>作品本文は、青空文庫の公開データから公開対象作品について取得します。作品ごとの利用条件は青空文庫の規準に従います。</p>'+
        '<p>第三者ソフトウェア：JSZip 3.10.1（MIT / GPLv3）</p>'+
      '</div>'+
    '</section>';
  }

  function syncScreens(mode,direction='forward'){
    const content=$p('#phone-content'),tabs=$p('.phone-tabbar'),detail=$p('#phone-detail'),reader=$p('#phone-reader');
    const layers=[content,detail,reader].filter(Boolean);
    const reduce=!!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    layers.forEach(el=>{
      el.classList.remove('phone-screen-push','phone-screen-pop');
      el.hidden=true;
      el.style.display='none';
      el.style.visibility='hidden';
      el.setAttribute('aria-hidden','true');
      el.setAttribute('inert','');
    });
    if(tabs){tabs.hidden=true;tabs.style.display='none';}

    let target=null;
    if(mode==='detail')target=detail;
    else if(mode==='reader')target=reader;
    else target=content;

    if(target){
      target.hidden=false;
      target.style.display=target===reader?'flex':'block';
      target.style.visibility='visible';
      target.removeAttribute('inert');
      target.setAttribute('aria-hidden','false');
      if(target===reader)reader.classList.add('phone-open');
      if(!reduce){
        void target.offsetWidth;
        target.classList.add(direction==='back'?'phone-screen-pop':'phone-screen-push');
        clearTimeout(target.__phoneRouteTimer);
        target.__phoneRouteTimer=setTimeout(()=>{
          target.classList.remove('phone-screen-push','phone-screen-pop');
        },340);
      }
    }

    if(target!==reader)reader?.classList.remove('phone-open');

    if(mode==='main'&&tabs){
      tabs.hidden=false;
      tabs.style.display='flex';
      tabs.removeAttribute('inert');
    }
  }

  function showScreen(name,direction='forward'){
    if(!isPhone())return;
    closePhoneSheet();
    state.work=null;
    state.readerFromDetail=false;
    const baseState={...(history.state||{})};
    delete baseState.phoneLayer;
    delete baseState.phoneParent;
    history.replaceState(baseState,'',location.href);
    const previous=state.screen;
    const tabNames=['home','search','shelf','records','settings'];
    const fromIndex=tabNames.indexOf(previous),toIndex=tabNames.indexOf(name);
    const routeDirection=direction==='back'
      ?'back'
      :(toIndex>=0&&fromIndex>=0&&toIndex<fromIndex?'back':'forward');
    state.screen=name;
    syncScreens('main',routeDirection);
    $$p('.phone-tab').forEach(b=>b.classList.toggle('active',b.dataset.phoneTab===name));
    const fn={
      home:renderHome,
      search:renderSearch,
      shelf:renderShelf,
      records:renderRecords,
      settings:renderSettings
    }[name]||renderHome;
    fn();
    const content=$p('#phone-content');
    if(content){
      content.scrollTop=0;
      state.headerCompact=false;
      $p('.phone-header')?.classList.remove('compact');
      bindPhoneHeaderScroll();
    }
  }

  function openDetail(w,direction='forward',fromHistory=false){
    if(!w)return;
    state.work=w;
    state.readerFromDetail=false;
    if(!fromHistory&&history.state?.phoneLayer!=='phone-detail')history.pushState({...history.state,phoneLayer:'phone-detail'},'',location.href);
    syncScreens('detail',direction);
    const d=$p('#phone-detail');if(!d)return;
    const p=Math.round(progressOf(w)*100), f=progressOf(w);
    d.innerHTML='<div class="phone-detail-nav">'+
      '<button class="phone-icon-button" data-phone-action="detail-back" aria-label="戻る"><svg class="phone-svg" viewBox="0 0 24 24"><path d="m15 5-7 7 7 7"/></svg></button>'+
      '<b style="font-size:14px">作品詳細</b>'+
      '<button class="phone-icon-button" data-phone-action="detail-more" aria-label="その他">•••</button>'+
    '</div>'+
      bookVisual(w,'phone-detail-cover',true)+
      '<div class="phone-detail-title">'+escP(wt(w))+'</div>'+
      '<div class="phone-detail-author">'+escP(wa(w))+'</div>'+
      (p>0?'<div class="phone-detail-progress"><div class="phone-detail-progress-top"><span>読書進捗</span><b>'+p+'%</b></div><div class="phone-progress-line"><span style="width:'+p+'%"></span></div></div>':'')+
      '<div class="phone-detail-actions">'+
        '<button class="'+(fav.has(w.id)?'active':'')+'" data-phone-action="detail-fav">お気に入り</button>'+
        '<button class="'+(want.has(w.id)?'active':'')+'" data-phone-action="detail-want">読みたい</button>'+
        '<button class="'+(done.has(w.id)?'active':'')+'" data-phone-action="detail-done">読了</button>'+
      '</div>'+
      '<div class="phone-detail-description">'+escP(w.desc||w.description||'青空文庫の公開作品です。本文を読みながら、栞・メモ・蛍光ペン・朗読などを利用できます。')+'</div>'+
      '<button class="phone-primary" data-phone-action="detail-read" data-act="read-now">'+(p>0&&p<97?'続きから読む':'この作品を読む')+'</button>'+
      '<button class="phone-secondary" data-phone-action="detail-author">この作家の作品を見る</button>';
  }

  function currentReaderBody(){return $p('#phone-reader-body')}
  function fraction(){
    const b=currentReaderBody();if(!b||b.scrollHeight<=b.clientHeight)return 0;
    return Math.max(0,Math.min(1,b.scrollTop/(b.scrollHeight-b.clientHeight)));
  }
  function snippet(){
    const w=state.work,b=currentReaderBody();if(!w)return '';
    const plain=state.readerDoc?.plain||b?.innerText||'';
    const f=fraction(),i=Math.max(0,Math.floor(plain.length*f));
    return plain.slice(i,i+90).replace(/\s+/g,' ').trim()||wt(w);
  }
  function saveReaderProgress(){
    if(!state.work || !phoneReaderContentReady)return;
    const f=fraction();
    pos[state.work.id]={f,t:Date.now()};
    hist=hist.filter(x=>String(x.id)!==String(state.work.id));
    hist.unshift({id:state.work.id,t:Date.now()});
    hist=hist.slice(0,200);
    clearTimeout(state.saveTimer);
    state.saveTimer=setTimeout(save,220);
    const bar=$p('#phone-reader-progress span');if(bar)bar.style.width=Math.round(f*100)+'%';
  }

  async function openReader(w,fromDetail=false){
    if(!w)return;
    phoneReaderContentReady=false;
    state.work=w;curWork=w;state.reader=true;state.readerDoc=null;state.readerFromDetail=!!fromDetail;
    if(history.state?.phoneLayer!=='phone-reader')history.pushState({...history.state,phoneLayer:'phone-reader'},'',location.href);
    syncScreens('reader','forward');
    const titleEl=$p('#phone-reader-title');if(titleEl)titleEl.textContent=wt(w);
    const body=currentReaderBody();if(!body)return;
    bindReaderChrome();
    const reader=$p('#phone-reader');reader?.classList.remove('reader-chrome-hidden');
    body.style.setProperty('--phone-reader-fs',state.readerFs+'px');
    body.style.setProperty('--phone-reader-lh',state.readerLh);
    setPhoneReaderLoading(true);
    const prog=$p('#phone-reader-progress');if(prog)prog.style.width=Math.round(progressOf(w)*100)+'%';
    try{
      const doc=await fetchBody(w);
      if(!state.reader||String(state.work?.id)!==String(w.id))return;
      state.readerDoc=doc;
      curDoc=doc;
      const rendered=await renderPhoneReaderBody(body,doc.html,()=>state.reader&&String(state.work?.id)===String(w.id)&&$p('#phone-reader')?.classList.contains('phone-open'));
      if(!rendered)return;
      if(!state.reader||String(state.work?.id)!==String(w.id))return;
      phoneReaderContentReady=true;
      setPhoneReaderLoading(false);
      body.scrollTop=0;
      let progressRaf=0;
      body.onscroll=()=>{
        if(progressRaf)return;
        progressRaf=requestAnimationFrame(()=>{
          progressRaf=0;
          saveReaderProgress();
        });
      };
      $p('#phone-reader')?.classList.remove('reader-chrome-hidden');
      requestAnimationFrame(()=>{const f=progressOf(w);body.scrollTop=f*Math.max(0,body.scrollHeight-body.clientHeight);saveReaderProgress();});
      hist=hist.filter(x=>String(x.id)!==String(w.id));hist.unshift({id:w.id,t:Date.now()});hist=hist.slice(0,200);save();
    }catch(err){
      phoneReaderContentReady=false;
      setPhoneReaderLoading(false);
      body.innerHTML='<div class="phone-empty"><b>本文を読み込めませんでした</b><br><span style="font-size:12px">通信状態または作品の公開先を確認してください。</span><button class="phone-primary" data-phone-action="reader-retry" style="margin-top:18px">もう一度読み込む</button></div>';
      body.setAttribute('aria-busy','false');
    }
  }


  function closeReader(fromHistory=false){
    cancelReaderRender();
    cancelReaderParser();
    if(phoneReaderContentReady)saveReaderProgress();
    const b=currentReaderBody();
    if(!fromHistory&&history.state?.phoneLayer==='phone-reader'){
      history.back();
      return;
    }
    if(b)b.onscroll=null;
    setPhoneReaderLoading(false);
    const w=state.work;
    state.reader=false;state.readerDoc=null;
    if(w&&state.readerFromDetail){openDetail(w,'back',true);}
    else{state.work=null;state.readerFromDetail=false;showScreen(state.screen,'back');}
    void releaseScreenWakeLock();
  }

  function addBookmark(){
    if(!state.work)return;
    const f=fraction();
    (bm[state.work.id]=bm[state.work.id]||[]).push({f,s:snippet(),t:Date.now()});
    save();toast('しおりを挟みました');
  }
  function addMemo(){
    if(!state.work)return;
    const selected=getSelection()?.toString?.().trim()||'';
    const memo=window.prompt(selected?'選択した文章へのメモ':'この位置へのメモ');
    if(!memo)return;
    (notes[state.work.id]=notes[state.work.id]||[]).push({s:selected.slice(0,500)||snippet(),m:memo.slice(0,2000),t:Date.now(),f:fraction()});
    save();toast('メモを保存しました');
  }
  function addHighlight(){
    if(!state.work)return;
    const sel=getSelection?.();const text=sel?.toString?.().trim()||'';
    if(!text){toast('本文を選択してから蛍光ペンを押してください');return;}
    let applied=false;
    try{
      const range=sel.getRangeAt(0);
      const mark=document.createElement('span');mark.className='hl-y';range.surroundContents(mark);applied=true;
    }catch{}
    if(!applied){toast('この範囲には蛍光ペンを付けられません');return;}
    (hls[state.work.id]=hls[state.work.id]||[]).push({t:text.slice(0,500),c:'hl-y',d:Date.now(),f:fraction()});
    save();if(sel)sel.removeAllRanges();toast('蛍光ペンを保存しました');
  }
  function speakReader(){
    if(!('speechSynthesis' in window)){toast('この端末では朗読に対応していません');return}
    if(speechSynthesis.speaking){speechSynthesis.cancel();toast('朗読を停止しました');return}
    const text=String(state.readerDoc?.plain||currentReaderBody()?.innerText||'').slice(Math.floor(fraction()*20000));
    if(!text){toast('本文がありません');return}
    const u=new SpeechSynthesisUtterance(text.slice(0,12000));u.lang='ja-JP';u.rate=1;speechSynthesis.speak(u);toast('朗読を開始しました');
  }

  function clearSearchMarks(){
    const b=currentReaderBody();if(!b)return;
    b.querySelectorAll('.phone-search-hit').forEach(mark=>{
      const p=mark.parentNode;if(!p)return;
      p.replaceChild(document.createTextNode(mark.textContent||''),mark);p.normalize();
    });
    state.searchHits=[];state.searchIndex=0;
  }
  function performReaderSearch(){
    clearSearchMarks();
    const inp=$p('#phone-reader-search-input'),q=String(inp?.value||'').trim();
    if(!q)return;
    const b=currentReaderBody();if(!b)return;
    const nodes=[],walker=document.createTreeWalker(b,NodeFilter.SHOW_TEXT);
    let n;while((n=walker.nextNode()))if(n.parentElement&&!n.parentElement.closest('script,style,.phone-search-hit'))nodes.push(n);
    const qq=q.toLocaleLowerCase('ja');
    nodes.forEach(node=>{
      const raw=node.nodeValue||'',low=raw.toLocaleLowerCase('ja'),frag=document.createDocumentFragment();let from=0,idx;
      while((idx=low.indexOf(qq,from))>=0){
        if(idx>from)frag.append(document.createTextNode(raw.slice(from,idx)));
        const m=document.createElement('mark');m.className='phone-search-hit';m.textContent=raw.slice(idx,idx+q.length);frag.append(m);
        state.searchHits.push(m);from=idx+q.length;
      }
      if(state.searchHits.length&&from>0){if(from<raw.length)frag.append(document.createTextNode(raw.slice(from)));node.parentNode.replaceChild(frag,node);}
    });
    if(state.searchHits.length){state.searchIndex=0;state.searchHits[0].scrollIntoView({block:'center'});}
  }

  function openSearchBar(){
    const bar=$p('#phone-reader-search'),inp=$p('#phone-reader-search-input');
    if(bar)bar.hidden=false;
    setTimeout(()=>inp?.focus(),40);
  }
  function closeSearchBar(){
    const bar=$p('#phone-reader-search');if(bar)bar.hidden=true;
    clearSearchMarks();
  }

  function openPhoneSheet(title,html){
    const sheet=$p('#phone-sheet'),scrim=$p('#phone-sheet-scrim'),stitle=$p('#phone-sheet-title'),body=$p('#phone-sheet-body');
    if(!sheet||!scrim||!body)return;
    if(history.state?.phoneLayer!=='phone-sheet')history.pushState({...history.state,phoneLayer:'phone-sheet',phoneParent:history.state?.phoneLayer||null},'',location.href);
    stitle.textContent=title;
    body.innerHTML=html;
    // 閉じた後に残る inert/hidden が次回の操作をブロックしないよう、開く時に必ず解除する。
    sheet.removeAttribute('inert');
    scrim.removeAttribute('inert');
    sheet.hidden=false;
    scrim.hidden=false;
    sheet.setAttribute('aria-hidden','false');
    scrim.setAttribute('aria-hidden','false');
    sheet.classList.add('open');
    scrim.classList.add('open');
    state.sheetOpen=true;
    bindPhoneSheetDrag();
  }
  function closePhoneSheet(fromHistory=false){
    const sheet=$p('#phone-sheet'),scrim=$p('#phone-sheet-scrim');
    if(!sheet||!scrim)return;
    state.sheetOpen=false;
    sheet.classList.remove('open');
    scrim.classList.remove('open');
    sheet.setAttribute('aria-hidden','true');
    scrim.setAttribute('aria-hidden','true');
    sheet.setAttribute('inert','');
    scrim.setAttribute('inert','');
    // CSSアニメーション完了後に完全に非表示。再オープンされた場合は消さない。
    clearTimeout(sheet.__hideTimer);
    sheet.__hideTimer=setTimeout(()=>{
      if(!state.sheetOpen){
        sheet.hidden=true;
        scrim.hidden=true;
      }
    },380);
    if(!fromHistory&&history.state?.phoneLayer==='phone-sheet'){
      const next={...(history.state||{})},parent=next.phoneParent||null;
      delete next.phoneParent;
      if(parent)next.phoneLayer=parent;else delete next.phoneLayer;
      history.replaceState(next,'',location.href);
    }
  }

  function readerMenu(){
    const ai=typeof openAiChat==='function'&&canUseOllama?.();
    openPhoneSheet('読書機能',
      '<button class="phone-sheet-row" data-phone-action="tts"><span>▷</span><b>朗読</b></button>'+
      '<button class="phone-sheet-row" data-phone-action="reader-search"><span>⌕</span><b>本文を検索</b></button>'+
      '<button class="phone-sheet-row" data-phone-action="reader-toc"><span>≡</span><b>目次を開く</b></button>'+
      '<div class="phone-reader-setting"><div><b>文字サイズ</b><strong id="phone-reader-font-value">'+state.readerFs+'px</strong></div><input id="phone-reader-font-range" type="range" min="14" max="32" step="1" value="'+state.readerFs+'" aria-label="文字サイズ"></div>'+
      '<div class="phone-reader-setting"><div><b>行間</b><strong id="phone-reader-line-value">'+Number(state.readerLh).toFixed(1)+'</strong></div><input id="phone-reader-line-range" type="range" min="1.6" max="2.8" step="0.1" value="'+state.readerLh+'" aria-label="行間"></div>'+
      '<button class="phone-sheet-row" data-phone-action="reader-theme"><span>◐</span><b>テーマ</b></button>'+
      '<button class="phone-sheet-row" data-phone-action="reader-share"><span>↗</span><b>作品を共有</b></button>'+
      '<button class="phone-sheet-row" data-phone-action="reader-wake"><span>□</span><b>画面を消さない</b></button>'+
      (ai?'<div class="phone-sheet-divider"></div><button class="phone-sheet-row" data-phone-action="reader-ai"><span>✦</span><b>AIでこの作品を要約</b></button>':'')
    );
  }

  function readerToc(){
    const b=currentReaderBody();if(!b)return;
    const hs=Array.from(b.querySelectorAll('[data-hid],h2,h3')).slice(0,80);
    openPhoneSheet('目次',hs.length?
      hs.map((h,i)=>'<button class="phone-sheet-row" data-phone-action="reader-jump" data-index="'+i+'"><span>'+(i+1)+'</span><b>'+escP(h.textContent)+'</b></button>').join(''):
      '<div class="phone-empty">目次情報がありません</div>');
    const body=$p('#phone-sheet-body');
    if(body)body.dataset.toc='1';
  }

  function cycleTheme(){
    const cur=st.theme||'auto';
    const next=cur==='auto'?'sepia':cur==='sepia'?'dark':'auto';
    st.theme=next;applySettings();save();renderSettings();toast('テーマを変更しました');
  }
  function applyPhoneReaderTypography(kind,value){
    const b=currentReaderBody();
    const oldFraction=fraction();
    if(kind==='font')state.readerFs=Math.max(14,Math.min(32,Number(value)||19));
    else state.readerLh=Math.max(1.6,Math.min(2.8,Number(value)||2.05));
    st.fs=state.readerFs;
    st.lh=state.readerLh;
    if(b){
      b.style.setProperty('--phone-reader-fs',state.readerFs+'px');
      b.style.setProperty('--phone-reader-lh',state.readerLh);
      requestAnimationFrame(()=>{
        b.scrollTop=oldFraction*Math.max(0,b.scrollHeight-b.clientHeight);
      });
    }
    save();
    const fv=$p('#phone-reader-font-value');if(fv)fv.textContent=state.readerFs+'px';
    const lv=$p('#phone-reader-line-value');if(lv)lv.textContent=Number(state.readerLh).toFixed(1);
  }
  function cycleFont(){
    const next=Math.min(32,Number(state.readerFs||19)+1);
    applyPhoneReaderTypography('font',next);
    toast('文字サイズ '+state.readerFs+'px');
  }
  function cycleLine(){
    const next=Math.min(2.8,Number(state.readerLh||2.05)+0.1);
    applyPhoneReaderTypography('line',next);
    toast('行間 '+Number(state.readerLh).toFixed(1));
  }
  document.addEventListener('input',e=>{
    if(!isPhone())return;
    if(e.target?.id==='phone-reader-font-range')applyPhoneReaderTypography('font',e.target.value);
    else if(e.target?.id==='phone-reader-line-range')applyPhoneReaderTypography('line',e.target.value);
  });
  window.__aozoraPhoneSyncSettings=()=>{
    state.readerFs=Math.max(14,Math.min(32,Number(st?.fs)||19));
    state.readerLh=Math.max(1.6,Math.min(2.8,Number(st?.lh)||2.05));
    const b=currentReaderBody();
    if(b){
      b.style.setProperty('--phone-reader-fs',state.readerFs+'px');
      b.style.setProperty('--phone-reader-lh',state.readerLh);
    }
  };
  async function toggleWake(){
    if(typeof wakeLock==='undefined'||typeof requestScreenWakeLock!=='function'){toast('画面維持は利用できません');return}
    if(wakeLock){await releaseScreenWakeLock();toast('画面維持を解除しました');}
    else{wakeLockWanted=true;await requestScreenWakeLock();toast('画面維持を有効にしました');}
  }

  function activatePhone(el){
    if(!el||!isPhone())return;
    if(el.matches('[data-phone-tab]')){showScreen(el.dataset.phoneTab);return}
    const id=el.dataset.phoneWork;
    if(id!=null){const w=getWork(id);if(w)openDetail(w);return}
    const act=el.dataset.phoneAction;if(!act)return;
    if(act==='sheet-close'){closePhoneSheet();return}
    if(state.sheetOpen){
      if(act==='reader-jump'){
        const b=currentReaderBody(),hs=Array.from(b?.querySelectorAll('[data-hid],h2,h3')||[]),h=hs[Number(el.dataset.index)];
        closePhoneSheet();if(h)h.scrollIntoView({block:'center',behavior:'smooth'});return;
      }
      if(act==='reader-ai'){closePhoneSheet();if(typeof openAiChat==='function')openAiChat('この作品のあらすじと読みどころを要約してください。');return}
      if(act==='reader-share'){closePhoneSheet();sharePhoneWork();return}
      if(act==='detail-share'){closePhoneSheet();sharePhoneWork();return}
      if(act==='detail-fav-author'){
        const a=wa(state.work);
        if(a){
          if(favAuthors.has(a))favAuthors.delete(a);else favAuthors.add(a);
          save();
          toast(favAuthors.has(a)?'作家をフォローしました':'作家のフォローを外しました');
        }
        return;
      }
      if(act==='tts'){closePhoneSheet();speakReader();return}
      if(act==='reader-search'){closePhoneSheet();openSearchBar();return}
      if(act==='reader-toc'){readerToc();return}
      if(act==='reader-font'){cycleFont();return}
      if(act==='reader-line'){cycleLine();return}
      if(act==='reader-theme'){closePhoneSheet();cycleTheme();return}
      if(act==='reader-wake'){closePhoneSheet();toggleWake();return}
    }
    if(act==='settings'){showScreen('settings');return}
    if(act==='search'){showScreen('search');requestAnimationFrame(()=>$p('#phone-search-input')?.focus());return}
    if(act==='search-history'){
      state.searchFilter='all';state.query=el.dataset.query||'';
      renderSearch();
      requestAnimationFrame(()=>{$p('#phone-search-input')?.focus()});
      return;
    }
    if(act==='theme'){cycleTheme();return}
    if(act==='shelf'){state.shelf='reading';showScreen('shelf');return}
    if(act==='records'){showScreen('records');return}
    if(act==='random'){const ws=works();if(ws.length)openDetail(ws[Math.floor(Math.random()*ws.length)]);return}
    if(act==='today'){const w=getTodayWork();if(w)openDetail(w);return}
    if(act==='resume'){const w=getResumeWork();if(w)openReader(w);return}
    if(act==='search-filter'){state.searchFilter=el.dataset.filter||'all';renderSearch();return}
    if(act==='shelf-filter'){state.shelf=el.dataset.filter||'reading';if(state.shelf==='records'){showScreen('records')}else renderShelf();return}
    if(act==='record-filter'){state.record=el.dataset.filter||'all';renderRecords();return}
    if(act==='detail-back'){
      if(history.state?.phoneLayer==='phone-detail'){
        const base={...(history.state||{})};
        delete base.phoneLayer;
        delete base.phoneParent;
        history.replaceState(base,'',location.href);
      }
      state.work=null;
      state.readerFromDetail=false;
      syncScreens('main','back');
      $p('.phone-tab').forEach(b=>b.classList.toggle('active',b.dataset.phoneTab===state.screen));
      const fn={home:renderHome,search:renderSearch,shelf:renderShelf,records:renderRecords,settings:renderSettings}[state.screen]||renderHome;
      fn();
      return;
    }
    if(act==='detail-read'){
      const w=state.work;
      if(!w)return;
      openReader(w,true);
      return;
    }
    if(act==='detail-more'){
      const w=state.work;if(!w)return;
      openPhoneSheet('作品の操作',
        '<button class="phone-sheet-row" data-phone-action="detail-author"><span>⌕</span><b>この作家の作品を見る</b></button>'+
        '<button class="phone-sheet-row" data-phone-action="detail-fav-author"><span>★</span><b>'+(favAuthors.has(wa(w))?'作家のフォローを外す':'この作家をフォロー')+'</b></button>'+
        '<button class="phone-sheet-row" data-phone-action="detail-share"><span>↗</span><b>作品を共有</b></button>'+
        '<button class="phone-sheet-row" data-phone-action="detail-reader-settings"><span>Aa</span><b>読書表示を調整</b></button>');
      return;
    }
    if(act==='detail-author'){
      const w=state.work;if(!w)return;
      closePhoneSheet();state.query='';state.searchFilter='all';showScreen('search');
      const inp=$p('#phone-search-input');if(inp){inp.value=wa(w);inp.dispatchEvent(new Event('input',{bubbles:true}))}
      return;
    }
    if(act==='detail-reader-settings'){closePhoneSheet();showScreen('settings');return}
    if(act==='detail-fav'){if(fav.has(state.work.id))fav.delete(state.work.id);else fav.add(state.work.id);save();openDetail(state.work);return}
    if(act==='detail-want'){if(want.has(state.work.id))want.delete(state.work.id);else want.add(state.work.id);save();openDetail(state.work);return}
    if(act==='detail-done'){if(done.has(state.work.id))done.delete(state.work.id);else done.add(state.work.id);save();openDetail(state.work);return}
    if(act==='reader-back'){closeReader();return}
    if(act==='reader-retry'){openReader(state.work,state.readerFromDetail);return}
    if(act==='reader-ui-toggle'){
      const reader=$p('#phone-reader');
      if(reader)reader.classList.remove('reader-chrome-hidden');
      return;
    }
    if(act==='bookmark'){addBookmark();return}
    if(act==='note'){addMemo();return}
    if(act==='highlight'){addHighlight();return}
    if(act==='tts'){speakReader();return}
    if(act==='reader-search'){openSearchBar();return}
    if(act==='reader-search-close'){closeSearchBar();return}
    if(act==='reader-search-next'){
      if(!state.searchHits.length)performReaderSearch();else{state.searchIndex=(state.searchIndex+1)%state.searchHits.length;state.searchHits[state.searchIndex]?.scrollIntoView({block:'center'});}
      return;
    }
    if(act==='reader-search-prev'){
      if(!state.searchHits.length)performReaderSearch();else{state.searchIndex=(state.searchIndex-1+state.searchHits.length)%state.searchHits.length;state.searchHits[state.searchIndex]?.scrollIntoView({block:'center'});}
      return;
    }
    if(act==='reader-more'){readerMenu();return}
    if(act==='reader-font'){cycleFont();return}
    if(act==='reader-line'){cycleLine();return}
    if(act==='reader-theme'){cycleTheme();return}
    if(act==='reader-wake'){toggleWake();return}
  }

  let lastPhoneTabTap=0;
  let lastPhoneTabName='';
  let edgeSwipe=null;

  let phonePointerHandledEl=null;
  let phonePointerHandledUntil=0;

  const phoneActivateElement=(el,fromTouch=false)=>{
    if(!el||!isPhone())return;
    if(el.matches('[data-phone-tab]')){
      const name=el.dataset.phoneTab||'home';
      if(state.screen===name&&!state.reader){
        $p('#phone-content')?.scrollTo({top:0,behavior:'smooth'});
        phoneHaptic(5);
        return;
      }
      lastPhoneTabName=name;
      lastPhoneTabTap=Date.now();
    }
    if(fromTouch)phonePress(el);
    phoneHaptic(6);
    activatePhone(el);
  };

  // タップとエッジスワイプを pointer イベントで一元処理する。
  // Androidブラウザの click 合成状態に依存せず、スマホUIを直接起動する。
  let phoneStartX=0,phoneStartY=0,phoneTouching=false;

  const phonePointerStart=e=>{
    if(!isPhone()||e.pointerType!=='touch')return;
    phoneStartX=e.clientX;
    phoneStartY=e.clientY;
    phoneTouching=true;

    const el=e.target.closest?.('#phone-app button,#phone-app [data-phone-tab],#phone-app [data-phone-work],#phone-app [data-phone-action],#phone-sheet button,#phone-sheet [data-phone-action],#phone-sheet-scrim[data-phone-action="sheet-close"]');
    if(el)phonePress(el);

    const x=e.clientX,y=e.clientY;
    if(state.sheetOpen&&x<32)edgeSwipe=null;
    else if((state.reader||state.work)&&x<28)edgeSwipe={x,y};
    else if(!state.reader&&!state.work&&
      (state.screen==='home'||state.screen==='search'||state.screen==='shelf'||state.screen==='records'||state.screen==='settings')&&x<24)edgeSwipe={x,y};
    else edgeSwipe=null;
  };

  const phonePointerEnd=e=>{
    if(!isPhone()||e.pointerType!=='touch'||!phoneTouching)return;
    phoneTouching=false;

    const dx=e.clientX-phoneStartX,dy=e.clientY-phoneStartY;
    const swiped=!!edgeSwipe&&dx>82&&Math.abs(dx)>Math.abs(dy)*1.35;
    edgeSwipe=null;

    if(swiped){
      e.preventDefault();
      e.stopPropagation();
      phoneHaptic(10);
      if(state.sheetOpen){closePhoneSheet();return;}
      if(state.reader){closeReader();return;}
      else if(state.work&&history.state?.phoneLayer==='phone-detail'){history.back();return;}
      else if(state.work){state.work=null;showScreen(state.screen,'back');}
      else if(state.screen!=='home')showScreen('home','back');
      return;
    }

    if(Math.abs(dx)>18||Math.abs(dy)>18)return;

    const el=e.target.closest?.('#phone-app [data-phone-tab],#phone-app [data-phone-work],#phone-app [data-phone-action],#phone-sheet [data-phone-action],#phone-sheet-scrim[data-phone-action="sheet-close"]');
    if(!el)return;
    if(el.dataset.phoneAction==='detail-read' && state.work){
      e.preventDefault();
      e.stopPropagation();
      phonePointerHandledEl=el;
      phonePointerHandledUntil=Date.now()+650;
      openReader(state.work,true);
      return;
    }
    e.preventDefault();
    e.stopPropagation();
    phonePointerHandledEl=el;
    phonePointerHandledUntil=Date.now()+650;
    phoneActivateElement(el,true);
  };

  document.addEventListener('pointerdown',phonePointerStart,{capture:true,passive:true});
  document.addEventListener('pointerup',phonePointerEnd,{capture:true,passive:false});
  document.addEventListener('pointercancel',()=>{
    phoneTouching=false;
    edgeSwipe=null;
  },{capture:true,passive:true});

  // Pointer Events が利用できない古いWebView向けのフォールバック。
  if(!('PointerEvent' in window)){
    document.addEventListener('touchstart',e=>{
      if(!isPhone())return;
      const t=e.touches[0];if(!t)return;
      phoneStartX=t.clientX;phoneStartY=t.clientY;phoneTouching=true;
      const el=e.target.closest?.('#phone-app button,#phone-app [data-phone-tab],#phone-app [data-phone-work],#phone-app [data-phone-action],#phone-sheet button,#phone-sheet [data-phone-action],#phone-sheet-scrim[data-phone-action="sheet-close"]');
      if(el)phonePress(el);
    },{capture:true,passive:true});
    document.addEventListener('touchend',e=>{
      if(!isPhone()||!phoneTouching)return;
      phoneTouching=false;
      const t=e.changedTouches[0];if(!t)return;
      const dx=t.clientX-phoneStartX,dy=t.clientY-phoneStartY;
      if(Math.abs(dx)>18||Math.abs(dy)>18)return;
      const el=e.target.closest?.('#phone-app [data-phone-tab],#phone-app [data-phone-work],#phone-app [data-phone-action],#phone-sheet [data-phone-action],#phone-sheet-scrim[data-phone-action="sheet-close"]');
      if(!el)return;
      e.preventDefault();
      e.stopPropagation();
      phoneActivateElement(el,true);
    },{capture:true,passive:false});
  }

  // シートの閉じる操作は専用に即時処理し、Android WebView等でclick合成が遅れても確実に閉じる。
  document.addEventListener('pointerup',e=>{
    if(!isPhone()||e.pointerType!=='touch')return;
    const closeEl=e.target.closest?.('#phone-sheet [data-phone-action="sheet-close"],#phone-sheet-scrim[data-phone-action="sheet-close"]');
    if(!closeEl||!state.sheetOpen)return;
    e.preventDefault();
    e.stopImmediatePropagation();
    phonePointerHandledEl=closeEl;
    phonePointerHandledUntil=Date.now()+650;
    closePhoneSheet();
  },{capture:true,passive:false});

  const phoneEvent=e=>{
    if(!isPhone()||e.type!=='click')return;
    const el=e.target.closest?.('#phone-app [data-phone-tab],#phone-app [data-phone-work],#phone-app [data-phone-action],#phone-sheet [data-phone-action],#phone-sheet-scrim[data-phone-action="sheet-close"]');
    if(!el)return;

    // Touch pointerup handled this command already. Keep click for keyboard/mouse accessibility.
    if(phonePointerHandledEl===el&&Date.now()<phonePointerHandledUntil){
      e.preventDefault();
      e.stopImmediatePropagation();
      phonePointerHandledEl=null;
      phonePointerHandledUntil=0;
      return;
    }

    e.preventDefault();
    e.stopImmediatePropagation();
    phoneActivateElement(el,false);
  };
  document.addEventListener('click',phoneEvent,{capture:true});

  const phoneTouchGuard=e=>{
    if(!isPhone())return;
    const el=e.target.closest?.('#phone-app button,#phone-app [data-phone-tab],#phone-app [data-phone-work],#phone-app [data-phone-action],#phone-sheet button,#phone-sheet [data-phone-action],#phone-sheet-scrim[data-phone-action="sheet-close"]');
    if(!el)return;
    if(e.type==='contextmenu'){
      e.preventDefault();e.stopImmediatePropagation();
    }
  };
  document.addEventListener('contextmenu',phoneTouchGuard,{capture:true});


  const searchInputListener=()=>{
    const inp=$p('#phone-reader-search-input');
    if(!inp||inp.dataset.bound==='1')return;
    inp.dataset.bound='1';inp.addEventListener('input',()=>performReaderSearch());
  };
  document.addEventListener('focusin',()=>{searchInputListener()});

  function syncPhoneVisibility(){
    if(!isPhone())return;
    const app=$p('#phone-app');if(app){app.style.display='flex';app.setAttribute('aria-hidden','false')}
    bindPhoneHeaderScroll();
    syncScreens(state.reader?'reader':'main');
  }

  const phoneBootWatchdog=setTimeout(()=>{
    if(!isPhone())return;
    try{
      document.getElementById('app-boot')?.classList.add('done');
      const content=$p('#phone-content');
      if(content&&!content.textContent.trim())showScreen(state.screen||'home');
    }catch(err){console.warn('Phone boot watchdog:',err)}
  },900);

  function initPhone(){
    if(!isPhone())return;
    try{
      syncPhoneVisibility();
      bindPhoneHeaderScroll();
      showScreen(state.screen||'home');
    }catch(err){
      console.error('Phone init failed',err);
      try{
        syncScreens('main');
        $p('#phone-content')?.insertAdjacentHTML('afterbegin','<div class="phone-card phone-empty">青空文庫を準備しています…<br><span style="font-size:12px">データの読み込みを続けています。</span></div>');
      }catch{}
    }
    // スマホUIは先に操作可能にしつつ、起動演出は短時間だけ維持する。
    try{
      window.setTimeout(()=>document.getElementById('app-boot')?.classList.add('done'),900);
    }catch{}
  }

  function openPhoneCatalogManual(){
    openPhoneSheet('カタログを手動で読み込む',
      '<div class="phone-catalog-manual">'+
      '<p>自動読み込みに失敗しました。青空文庫のカタログ（.zip / .csv）を選択してください。</p>'+
      '<label class="phone-sheet-row phone-catalog-file"><span>↑</span><b>ファイルを選択</b><input id="phone-catalog-file" type="file" accept=".zip,.csv" style="position:absolute;opacity:0;inset:0;width:100%;height:100%;cursor:pointer"></label>'+
      '</div>'
    );
    $p('#phone-catalog-file')?.addEventListener('change',e=>{
      const file=e.target.files?.[0];
      if(file){closePhoneSheet();parseFile(file);}
    },{once:true});
  }

  window.__aozoraPhoneOpenSheet=openPhoneSheet;
  window.__aozoraPhoneOpenCatalogManual=openPhoneCatalogManual;
  window.__aozoraPhoneCloseSheet=closePhoneSheet;
  window.__aozoraPhoneOpenReader=openReader;
  window.__aozoraPhoneOpenDetail=openDetail;
  window.__aozoraPhoneShowScreen=showScreen;

  const refreshPhoneFromCatalog=()=>{
    if(!isPhone()||state.reader)return;
    state.readerFs=Number(st?.fs)||19;
    state.readerLh=Number(st?.lh)||2.05;
    const rawHash=String(location.hash||'');
    const match=rawHash.match(/^#work=(.+)$/);
    if(match){
      let id='';
      try{id=decodeURIComponent(match[1]);}catch{}
      const w=id?getWork(id):null;
      if(w){openDetail(w);return;}
    }
    showScreen(state.screen||'home');
  };
  window.__aozoraPhoneRefresh=refreshPhoneFromCatalog;
  window.addEventListener('aozora-phone-data-ready',refreshPhoneFromCatalog);
  // カタログイベントがこのルーター初期化より先に発火していても取りこぼさない。
  if(allWorks.length)queueMicrotask(refreshPhoneFromCatalog);
  // 非同期カタログ復元とスマホルーターの初期化順が前後しても、作品一覧を確実に再描画する。
  let phoneCatalogRetry=0;
  const retryPhoneCatalog=()=>{
    if(!isPhone()||state.reader||phoneCatalogRetry>=12)return;
    phoneCatalogRetry++;
    if(works().length){refreshPhoneFromCatalog();return;}
    setTimeout(retryPhoneCatalog,250);
  };
  setTimeout(retryPhoneCatalog,0);
  window.addEventListener('popstate',()=>{
    if(!isPhone())return;
    const layer=history.state?.phoneLayer||null;
    if(state.sheetOpen&&layer!=='phone-sheet'){
      closePhoneSheet(true);
      return;
    }
    if(state.reader&&layer!=='phone-reader'){
      closeReader(true);
      return;
    }
    if(state.work&&!state.reader&&layer!=='phone-detail'){
      state.work=null;
      state.readerFromDetail=false;
      syncScreens('main','back');
      $p('.phone-tab').forEach(b=>b.classList.toggle('active',b.dataset.phoneTab===state.screen));
      const fn={home:renderHome,search:renderSearch,shelf:renderShelf,records:renderRecords,settings:renderSettings}[state.screen]||renderHome;
      fn();
    }
  });
  window.addEventListener('resize',()=>{if(isPhone()&&!state.reader)syncPhoneVisibility()},{passive:true});
  document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='hidden'&&isPhone()&&state.reader)saveReaderProgress()});

  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',initPhone,{once:true});
  else initPhone();
})();