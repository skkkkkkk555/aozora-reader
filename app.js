/* touch/click reliability */
(function(){
let start=null,suppressEl=null,suppressUntil=0,synthetic=false;
const actionOf=t=>t?.closest?.('[data-act]')||null;
document.addEventListener('pointerdown',e=>{if(e.pointerType!=='touch')return;const el=actionOf(e.target);if(!el)return;start={x:e.clientX,y:e.clientY,el};},{passive:true});
document.addEventListener('pointerup',e=>{if(e.pointerType!=='touch'||!start)return;const el=actionOf(e.target),dx=e.clientX-start.x,dy=e.clientY-start.y;if(el===start.el&&dx*dx+dy*dy<=324){suppressEl=el;suppressUntil=Date.now()+900;synthetic=true;try{el.click()}finally{synthetic=false}}start=null;},{passive:true});
document.addEventListener('pointercancel',e=>{if(e.pointerType==='touch')start=null;},{passive:true});
document.addEventListener('click',e=>{if(synthetic)return;if(suppressEl&&Date.now()<suppressUntil&&actionOf(e.target)===suppressEl){e.preventDefault();e.stopImmediatePropagation()}suppressEl=null;suppressUntil=0},true);
})();
/* ==================== 1. 状態 & ユーティリティ ==================== */
if(window.top!==window.self){document.documentElement.style.display='none';throw new Error('framed-context-blocked');}
const $=i=>document.getElementById(i);
const esc=s=>(s||'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]||c));
const escAttr=esc;

/* ==================== SECURITY HARDENING ==================== */
const SEC={maxCatalogBytes:30*1024*1024,maxCatalogText:32*1024*1024,maxLocalFileBytes:30*1024*1024,maxBookBytes:16*1024*1024,maxResponseHeadBytes:4096,maxStateChars:4*1024*1024};
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
  const isOllama=typeof isSafeOllamaUrl==='function'&&isSafeOllamaUrl(u.href);
  if(!isOllama&&!['GET','HEAD'].includes(method))throw new Error('blocked-network-method');
  return window.fetch(u.href,{...init,referrerPolicy:'no-referrer',cache:init.cache||'no-store'});
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
    const id=String(raw.id||'').slice(0,80),t=String(raw.t||'').slice(0,300),a=String(raw.a||'').slice(0,300),x=String(raw.x||'').slice(0,500);
    if(!safeStateKey(id)||seen.has(id)||!t||!x||x.length>500||x.includes('..')||x.includes('\\')||x.startsWith('http')||x.startsWith('//')||!/^[A-Za-z0-9._\/-]+$/.test(x))continue;
    seen.add(id);
    out.push({id,t,a,tk:String(raw.tk||'').slice(0,300),ak:String(raw.ak||'').slice(0,300),d:String(raw.d||'').slice(0,80),k:Number(raw.k)===1?1:0,c:Number(raw.c)===1?1:0,ndc:String(raw.ndc||'').slice(0,80),norm:String(raw.norm||'').slice(0,700),x});
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
  out.fav=safeStateArray(d.fav);out.want=safeStateArray(d.want);out.done=safeStateArray(d.done);
  out.favAuthors=safeStateArray(d.favAuthors,SEC_STATE.maxAuthors);
  out.dead=safeStateArray(d.dead,SEC_STATE.maxItems);
  out.searchHistory=safeStateArray(d.searchHistory,100);
  out.hist=Array.isArray(d.hist)?d.hist.filter(x=>x&&safeStateKey(String(x.id))&&Number.isFinite(Number(x.t))).slice(0,SEC_STATE.maxHistory).map(x=>({id:String(x.id).slice(0,80),t:Math.max(0,Math.min(Number(x.t),Date.now()+86400000))})):[];
  out.calData=sanitizeStateMap(d.calData,v=>Number.isFinite(Number(v))?Math.max(0,Math.min(1440,Math.round(Number(v)))):undefined);
  out.pos=sanitizeStateMap(d.pos,v=>v&&typeof v==='object'?{f:Math.max(0,Math.min(1,Number(v.f)||0)),t:Math.max(0,Math.min(Number(v.t)||0,Date.now()+86400000))}:undefined);
  out.bm=sanitizeStateMap(d.bm,v=>Array.isArray(v)?v.slice(0,SEC_STATE.maxNotesPerBook).filter(x=>x&&typeof x==='object').map(x=>({f:Math.max(0,Math.min(1,Number(x.f)||0)),s:safeStateText(x.s,500),t:Math.max(0,Math.min(Number(x.t)||0,Date.now()+86400000))})):[],SEC_STATE.maxMapKeys);
  out.notes=sanitizeStateMap(d.notes,v=>Array.isArray(v)?v.slice(0,SEC_STATE.maxNotesPerBook).filter(x=>x&&typeof x==='object').map(x=>({s:safeStateText(x.s,500),m:safeStateText(x.m,2000),t:Math.max(0,Math.min(Number(x.t)||0,Date.now()+86400000))})):[],SEC_STATE.maxMapKeys);
  out.hls=sanitizeStateMap(d.hls,v=>Array.isArray(v)?v.slice(0,SEC_STATE.maxNotesPerBook).filter(x=>x&&typeof x==='object').map(x=>({t:safeStateText(x.t,500),c:safeStateText(x.c,40),d:Math.max(0,Math.min(Number(x.d)||0,Date.now()+86400000))})):[],SEC_STATE.maxMapKeys);
  if(d.st&&typeof d.st==='object'&&!Array.isArray(d.st)){
    out.st={
      fs:Math.max(14,Math.min(32,Number(d.st.fs)||18)),
      lh:Math.max(1.6,Math.min(2.6,Number(d.st.lh)||2.1)),
      theme:['auto','sepia','dark'].includes(d.st.theme)?d.st.theme:'auto',
      font:['mincho','gothic'].includes(d.st.font)?d.st.font:'mincho',
      warm:!!d.st.warm,kp:!!d.st.kp,offline:!!d.st.offline,lowSpec:!!d.st.lowSpec,ollamaEnabled:!!d.st.ollamaEnabled,
      oUrl:safeStateText(d.st.oUrl,500),oHist:Array.isArray(d.st.oHist)?d.st.oHist.slice(-100):[],
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
    return u.protocol==='https:'||isPrivateHost(u.hostname);
  }catch{return false}
};
const sanitizeReaderHtml=html=>{
  const doc=new DOMParser().parseFromString(String(html||''),'text/html');
  const allowed=new Set(['BR','RUBY','RT','EM','U','B','SPAN','H2','H3','HR']);
  [...doc.body.querySelectorAll('*')].forEach(el=>{
    const tag=el.tagName;
    if(!allowed.has(tag)){el.replaceWith(doc.createTextNode(el.textContent||''));return;}
    [...el.attributes].forEach(a=>{
      const ok=((tag==='SPAN'||tag==='EM')&&a.name==='class')||((tag==='H2'||tag==='H3')&&(a.name==='class'||a.name==='data-hid'));
      if(!ok)el.removeAttribute(a.name);
    });
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
  async del(s,k){try{const db=await this.d;db.transaction(s,'readwrite').objectStore(s).delete(k)}catch{}}
};

let allWorks=[], works=[], byId=new Map(), dead=new Set();
let fav=new Set(), want=new Set(), done=new Set(), favAuthors=new Set();
let pos={}, bm={}, notes={}, hls={}, hist=[], savedKeys=new Set(), searchHistory=[];
let calData={}, goalMin=30;
let st={ fs:18, lh:2.1, theme:'auto', font:'mincho', warm:true, kp:true, offline:false, lowSpec:false, ollamaEnabled:false, oUrl:'http://127.0.0.1:11434', oHist:[], oMod:'', v:true, rMode:'normal', readSpeed:500, todayBook:null };
let aiConn={ ok:false, models:[], err:'' };
let activeBook=null;
const isPublicWork = w => !!w && Number(w.c) === 1;
const localDateKey=()=>{const d=new Date();return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;};
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
const safeEl = id => document.getElementById(id) || null;
const safeText = (id, value) => { const el = safeEl(id); if (el) el.textContent = String(value ?? ''); };
const safeHTML = (id, value) => { const el = safeEl(id); if (el) el.innerHTML = String(value ?? ''); };
const safeDisplay = (id, show) => { const el = safeEl(id); if (el) el.style.display = show ? '' : 'none'; };
const closeOneLineMode = () => {};
const escRe = s => (s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

let searchState={
  query: '',
  scope: null,
  filter: { k: true, c: true, saved: false, time: null },
  sort: 'new'
};

const save=()=>{
  try {
    const d={fav:[...fav],want:[...want],done:[...done],favAuthors:[...favAuthors],pos,bm,notes,hls,hist,calData,goalMin,st,searchHistory,dead:[...dead]};
    localStorage.setItem('aozora_terminal_v17',JSON.stringify(d));
    localStorage.setItem('aozora_terminal_settings_v1',JSON.stringify(st));
    idb.set('k','state',d);
  } catch (err) {
    console.warn('save failed', err);
  }
};
const load=async()=>{
  try {
    const raw = localStorage.getItem('aozora_terminal_v17') || localStorage.getItem('aozora_terminal_v16') || 'null';
    if(raw.length>SEC.maxStateChars) throw new Error('state-too-large');
    const localState=raw!=='null'?JSON.parse(raw):null;
    const d=sanitizePersistedState(localState || await idb.get('k','state'));
    const savedSettingsRaw=localStorage.getItem('aozora_terminal_settings_v1');
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

window.addEventListener('error', (event) => {
  console.warn('Captured app error:', event.message);
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
  $('sheet-t').textContent=title;
  $('sheet-b').innerHTML=html;
  $('sheet').classList.add('open');
  $('scrim').classList.add('open');
  pushLayer('sheet');
}
function closeSheet(){
  $('sheet').classList.remove('open');
  $('scrim').classList.remove('open');
  popLayer('sheet');
}

let toastTimer=null, undoFn=null;
function toast(m, undo){
  $('toast-m').textContent=m; undoFn=undo;
  $('toast-u').style.display=undo?'block':'none';
  const t=$('toast'); t.classList.add('open');
  clearTimeout(toastTimer);
  toastTimer=setTimeout(()=>t.classList.remove('open'), undo?5000:2600);
}

/* ==================== 3. 画面層 & 戻る管理 ==================== */
const layers=[];
function pushLayer(n){ if(layers[layers.length-1]!==n){ layers.push(n); history.pushState({layer:n},''); } }
function popLayer(n){ const idx=layers.lastIndexOf(n); if(idx>=0) layers.splice(idx,1); }

window.addEventListener('popstate',()=>{
  if(layers.length){
    const l=layers.pop();
    if(l==='sheet') closeSheet();
    else if(l==='reader') closeReader(true);
    else if(l==='pop') $('pop').classList.remove('open');
  }
});
window.addEventListener('keydown',e=>{
  if(e.key==='Escape'){
    if(layers.length){
      const l=layers[layers.length-1];
      if(l==='sheet') closeSheet();
      else if(l==='reader') closeReader();
      else if(l==='pop') $('pop').classList.remove('open');
      history.back();
    }
  }
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){ e.preventDefault(); openSearchPage(); }
});

const URLS=[
  'https://www.aozora.gr.jp/index_pages/list_person_all_extended_utf8.zip',
  'https://corsproxy.org/?'+encodeURIComponent('https://www.aozora.gr.jp/index_pages/list_person_all_extended_utf8.zip'),
  'https://api.allorigins.win/raw?url='+encodeURIComponent('https://www.aozora.gr.jp/index_pages/list_person_all_extended_utf8.zip')
];

async function checkCatalog(){
  const c=await idb.get('k','cat');
  const safeCatalog=sanitizeCatalogRecords(c);
  if(safeCatalog.length){
    allWorks=safeCatalog;
    if(safeCatalog.length!==c.length)await idb.set('k','cat',safeCatalog);
    filterWorks();
    renderHome();
  }else{
    filterWorks();
    renderHome();
    showBanner('作品カタログがまだありません。「設定」からカタログを読み込めます。');
  }
}
function filterWorks(){
  works = allWorks.filter(w => !dead.has(w.id) && isPublicWork(w));
  byId = new Map(works.map(w => [w.id, w]));
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

async function fetchCatalog(){
  $('c-log').textContent='配信元へ接続中…'; $('c-bar').style.width='20%';
  let buf=null;
  for(let i=0;i<URLS.length;i++){
    try {
      const res=await secureFetch(URLS[i],{signal:sig(30000)});
      if(!res.ok) continue;
      const b=await readResponseBytes(res,SEC.maxCatalogBytes);
      const u8=b&&new Uint8Array(b);
      if(u8&&u8.length>=4&&u8[0]===0x50&&u8[1]===0x4b&&[0x03,0x05,0x07].includes(u8[2])){buf=b;break;}
    }catch{}
  }
  if(!buf){ $('c-log').textContent='自動取得に失敗しました。ファイルを選択してください。'; return; }
  $('c-bar').style.width='50%'; $('c-log').textContent='解凍中…';
  if(!buf||buf.byteLength>SEC.maxCatalogBytes)throw new Error('catalog-too-large');
  const z=await JSZip.loadAsync(buf,{checkCRC32:true});
  const names=Object.keys(z.files);
  const totalUncompressed=names.reduce((sum,n)=>sum+Number(z.files[n]?._data?.uncompressedSize||0),0);
  if(totalUncompressed>SEC.maxCatalogText*2)throw new Error('catalog-uncompressed-too-large');
  if(names.length>60000)throw new Error('catalog-entries-too-many');
  const cf=names.find(n=>n.toLowerCase().endsWith('.csv'));
  if(!cf||!z.files[cf]||z.files[cf].dir)throw new Error('catalog-csv-missing');
  const csvText=await z.files[cf].async('string');
  if(csvText.length>SEC.maxCatalogText)throw new Error('catalog-text-too-large');
  parseCsv(csvText);
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
        parseCsv(txt);
      }else{
        if(typeof r.result!=='string'||r.result.length>SEC.maxCatalogText)throw new Error('catalog-text-too-large');
        parseCsv(r.result);
      }
    }catch(e){
      console.warn('catalog file rejected:',e);
      toast('カタログを安全に読み込めませんでした');
    }
  };
  if(file.name.toLowerCase().endsWith('.zip')) r.readAsArrayBuffer(file); else r.readAsText(file);
}

async function parseCsv(csv){
  if(typeof csv!=='string'||csv.length>SEC.maxCatalogText)throw new Error('catalog-text-too-large');
  $('c-bar').style.width='70%'; $('c-log').textContent='解析中…';
  const lines=csv.split('\n');
  if(lines.length>20000)throw new Error('catalog-rows-too-many');
  if(!lines.length||lines[0].length>200000)throw new Error('catalog-header-invalid');
  const h=lines[0].split(',').map(s=>s.replace(/^["\uFEFF]|["\r]/g,'').trim()).slice(0,100);
  const col={ id:h.indexOf('作品ID'), t:h.indexOf('作品名'), a:h.indexOf('姓'), am:h.indexOf('名'), tk:h.indexOf('作品名読み'), ak:h.indexOf('姓読み'), x:h.indexOf('テキストファイルURL'), d:h.indexOf('公開日'), k:h.indexOf('文字遣い種別'), c:h.indexOf('作品著作権フラグ'), ndc:h.indexOf('分類番号') };
  const m=new Map();

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
    const rawUrl=String(cols[col.x]||'').trim();
    let parsedUrl=null;try{parsedUrl=new URL(rawUrl);}catch{}
    if(!rawId||!parsedUrl||parsedUrl.protocol!=='https:'||parsedUrl.hostname!=='www.aozora.gr.jp'||!rawUrl.toLowerCase().endsWith('.zip'))continue;
    if(!safeStateKey(rawId))continue;
    const id=rawId;
    const author=((cols[col.a]||'')+' '+(cols[col.am]||'')).trim();
    if(m.has(id)){
      const ex=m.get(id);
      if(author&&!ex.a.includes(author)) ex.a+='・'+author;
      continue;
    }
    const t=cols[col.t]||'', tk=(cols[col.tk]||'').toLowerCase(), ak=(cols[col.ak]||'').toLowerCase();
    const rightsFlag = cols[col.c];
    const isPublic = rightsFlag === 'なし' || rightsFlag === '1' || rightsFlag === 1 || rightsFlag === '1.0';
    m.set(id,{
      id, t, a:author, tk, ak, d:cols[col.d]||'',
      k:cols[col.k]?.includes('新字新仮名')?1:0, c:isPublic ? 1 : 0,
      ndc:cols[col.ndc]||'',
      norm:(t+' '+tk+' '+author+' '+ak).replace(/[\s　]/g,'').toLowerCase(),
      x:cols[col.x].replace('https://www.aozora.gr.jp/','').replace(/\.zip$/,'').replace(/\/([^\/]+)$/,'/$1/$1.txt').replace(/^\/+|\.\.+/g,'')
    });
    if(i%2500===0){ $('c-bar').style.width=(70+Math.round(i/lines.length*28))+'%'; await new Promise(r=>setTimeout(r,0)); }
  }
  allWorks=sanitizeCatalogRecords([...m.values()]);
  filterWorks();
  await idb.set('k','cat',allWorks);
  $('c-bar').style.width='100%'; $('c-log').textContent='完了しました！';
  setTimeout(()=>{ closeSheet(); renderHome(); toast('作品カタログを取り込みました'); },400);
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

function renderHome(){
  $('home-clock').textContent=new Date().toLocaleTimeString('ja-JP',{hour:'2-digit',minute:'2-digit'});

  if(!allWorks.length) showBanner('作品カタログが未登録です');
  else if(st.ollamaEnabled && !st.offline && !aiConn.ok && canUseOllama()) showBanner('Ollamaが未接続です');
  else $('banner').style.display='none';

  // オンボーディング
  const ob=[];
  if(!allWorks.length) ob.push('① カタログの導入');
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
    let curKey=curD.toISOString().slice(0,10);
    if(!calData[curKey]){
      curD.setDate(curD.getDate()-1);
      curKey=curD.toISOString().slice(0,10);
    }
    while(calData[curKey]>0){
      streak++;
      curD.setDate(curD.getDate()-1);
      curKey=curD.toISOString().slice(0,10);
    }
  }
  $('st-streak').textContent=(streak||1)+'日';

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
      candidate=shortWorks[Math.floor(Math.random()*shortWorks.length)];
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
  if(!featList.length) return;
  const w=featList[featIdx];
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
  $('ban-txt').textContent=msg;
  $('banner').style.display='flex';
}

/* ==================== 7. 探す (分離・完全検索パイプライン) ==================== */
let searchPool=[], searchCursor=0;
const GENRES=[{n:'小説',c:'913'},{n:'童話',c:'童話'},{n:'詩歌',c:'911'},{n:'随筆',c:'914'},{n:'評論',c:'910'},{n:'戯曲',c:'912'}];
const KANA=['あ','か','さ','た','な','は','ま','や','ら','わ'];

function openSearchPage(){
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
  if(reset){
    searchCursor=0;
    $('search-tiles').innerHTML='';
  }

  const q=searchState.query.trim().toLowerCase().replace(/[\s　]/g,'');
  $('q-clear').style.display=q?'block':'none';

  const hasScope=!!searchState.scope;
  const hasQuery=!!q;
  const hasTimeFilter=!!searchState.filter.time;

  if(!hasScope && !hasQuery && !hasTimeFilter && searchState.filter.k && searchState.filter.c && !searchState.filter.saved){
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

  if(searchState.filter.k) list=list.filter(w=>w.k===1);
  if(searchState.filter.c) list=list.filter(w=>w.c===1);
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
  Object.entries(bm).forEach(([id,arr])=>arr.forEach(it=>all.push({id,t:'栞',txt:it.s,f:it.f,d:it.t})));
  Object.entries(notes).forEach(([id,arr])=>arr.forEach(it=>all.push({id,t:'メモ',txt:it.m,d:it.t})));
  Object.entries(hls).forEach(([id,arr])=>arr.forEach(it=>all.push({id,t:'蛍光ペン',txt:it.t,d:it.t})));
  all.sort((a,b)=>b.d-a.d);

  $('shelf-empty').style.display=all.length?'none':'block';
  $('shelf-tiles').innerHTML=all.map(n=>{
    const w=byId.get(n.id); if(!w) return '';
    return `
      <div class="block" data-act="open-book" data-id="${escAttr(w.id)}" style="min-height:100px; padding:16px">
        <div style="display:flex; justify-content:space-between"><span class="badge" style="background:var(--ac); color:#fff">${n.t}</span><span style="font-size:var(--fs-s); color:var(--sub)">${esc(w.t)}</span></div>
        <div style="font-size:var(--fs-b); font-weight:700; margin-top:8px">${esc(n.txt)}</div>
      </div>`;
  }).join('');
}

// 本の詳細シート
function openBookDetail(w){
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
  fetchHead(w).then(q=>{const el=$('b-quote');if(el) el.textContent=q;});
}

/* ==================== 8. 本文取得 & パース ==================== */
async function fetchHead(w){
  if(!w||typeof w.id!=='string'||!safeStateKey(w.id)||typeof w.x!=='string'||w.x.length>500||w.x.includes('..')||w.x.includes('\\')||w.x.startsWith('http'))return '本文の取得をお試しください。';
  const c=await idb.get('docs',w.id); if(c?.plain) return c.plain.slice(0,90);
  const u=`https://raw.githubusercontent.com/aozorahack/aozorabunko_text/master/${w.x}`;
  try {
    const res=await secureFetch(u,{headers:{'Range':'bytes=0-3500'},signal:sig(5000)});
    if(res.ok){
      const b=await readResponseBytes(res,SEC.maxResponseHeadBytes);if(!b)return '本文の取得をお試しください。';
      const t=new TextDecoder('shift_jis').decode(b);
      return toPlain(parseAozora(t)).slice(0,90);
    }
  }catch{}
  return '本文の取得をお試しください。';
}

let readerTok=0;
async function fetchBody(w){
  if(!w||typeof w.id!=='string'||!safeStateKey(w.id)||typeof w.x!=='string'||w.x.length>500||w.x.includes('..')||w.x.includes('\\')||w.x.startsWith('http'))throw new Error('invalid-book-path');
  const c=await idb.get('docs',w.id); if(c?.html){c.html=sanitizeReaderHtml(c.html);c.plain=toPlain(c.html);return c;}
  if(st.offline) throw new Error('オフラインです');
  const urls=[
    `https://raw.githubusercontent.com/aozorahack/aozorabunko_text/master/${w.x}`,
    `https://aozorahack.org/aozorabunko_text/${w.x}`,
    `https://www.aozora.gr.jp/${w.x}`,
    `https://corsproxy.io/?url=`+encodeURIComponent(`https://www.aozora.gr.jp/${w.x}`)
  ];
  let buf=null, is404=true;
  for(const u of urls){
    try {
      const res=await secureFetch(u,{signal:sig(10000)});
      if(res.status===404) continue;
      is404=false;
      if(res.ok){ const b=await readResponseBytes(res,SEC.maxBookBytes); if(b&&b.byteLength>=200){buf=b;break;} }
    }catch{ is404=false; }
  }
  if(!buf){
    if(is404){ dead.add(w.id); filterWorks(); save(); throw {dead:true}; }
    throw new Error('通信エラーが発生しました');
  }
  const txt=new TextDecoder('shift_jis').decode(buf);
  const html=sanitizeReaderHtml(parseAozora(txt)),plain=toPlain(html);
  const doc={html,plain};
  await idb.set('docs',w.id,doc);
  savedKeys.add(w.id);
  return doc;
}

let midashiSeq=0;
function parseAozora(raw){
  midashiSeq=0;
  let t=raw.replace(/\r\n?/g,'\n');
  const ls=t.split('\n'), d=[];
  ls.forEach((l,i)=>{ if(/^-{20,}$/.test(l)&&i<60) d.push(i); });
  t=d.length>=2?ls.slice(d[1]+1).join('\n'):ls.slice(2).join('\n');
  const b=t.search(/\n底本：/); if(b>0) t=t.slice(0,b);

  t=t.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
   .replace(/[０-９]/g,s=>String.fromCharCode(s.charCodeAt(0)-0xFEE0))
   .replace(/\b(\d{1,2})\b/g,'<span class="tcy">$1</span>')
   .replace(/｜([^《\n]+)《([^》\n]+)》/g,'<ruby>$1<rt>$2</rt></ruby>')
   .replace(/([\u4E00-\u9FFF々〆ヶ〇]+)《([^》\n]+)》/g,'<ruby>$1<rt>$2</rt></ruby>')
   .replace(/［＃「([^」]+)」に傍点］/g,'<em class="em">$1</em>')
   .replace(/［＃傍点］(.*?)［＃傍点終わり］/g,'<em class="em">$1</em>')
   .replace(/［＃「([^」]+)」に傍線］/g,'<u>$1</u>')
   .replace(/［＃太字］(.*?)［＃太字終わり］/g,'<b>$1</b>')
   .replace(/［＃大見出し］([^\n]+)/g,()=>`<h2 class="serif" data-hid="h-${midashiSeq++}">$1</h2>`)
   .replace(/［＃中見出し］([^\n]+)/g,()=>`<h3 class="serif" data-hid="h-${midashiSeq++}">$1</h3>`)
   .replace(/［＃(改ページ|改丁)］/g,'<hr class="aozora-page-break">')
   .replace(/［＃[^］]*］/g,'');
  return t.replace(/\n/g,'<br>');
}
function toPlain(h){ const d=document.createElement('div'); d.innerHTML=h.replace(/<br>/g,'\n'); d.querySelectorAll('rt').forEach(x=>x.remove()); return d.textContent||''; }

/* ==================== 9. 読書画面 & 表示 ==================== */
let curDoc=null, curWork=null;
let lastUserActivityTime=Date.now();
let inBookSearchResults=[], inBookSearchIdx=0;

async function openReader(w){
  closeSheet();
  closeOneLineMode();
  curWork=w;
  lastProgressPct=-1;
  lastProgressSave=0;
  if(progressRaf!==null){cancelAnimationFrame(progressRaf);progressRaf=null;}
  const tId=++readerTok;
  $('r-title').textContent=w.t;
  setReaderLoading(true);
  $('reader').classList.add('open');
  pushLayer('reader');

  try {
    const doc=await fetchBody(w);
    if(tId!==readerTok) return;
    curDoc=doc;
    renderReaderBody();
    setReaderLoading(false);
    applyReaderConfig();

    // 位置復元
    requestAnimationFrame(()=>{
      requestAnimationFrame(()=>{
        const f=pos[w.id]?.f||0;
        const b=$('body'), isV=b.classList.contains('v');
        const max=isV?b.scrollWidth-b.clientWidth:b.scrollHeight-b.clientHeight;
        if(isV) b.scrollLeft=-Math.abs(f*max); else b.scrollTop=f*max;
        updateProgress();
      });
    });

    if(st.kp && !document.body.classList.contains('low-power')) extractKeyphrases(doc.plain);
} catch(e){
    setReaderLoading(false);
    if(e.dead) toast('取得できない作品のため除外しました');
    else $('body').innerHTML='<div class="reader-error-state"><div class="reader-error-icon">!</div><div class="reader-error-title">本文を読み込めませんでした</div><div class="reader-error-text">通信状態を確認して、もう一度お試しください。</div><button class="primary" data-act="r-retry" style="margin-top:16px">再試行</button></div>';
  }
}

function setReaderLoading(show){
  const body=$('body');
  if(!body)return;
  body.setAttribute('aria-busy',show?'true':'false');
  if(show){
    body.innerHTML='<div class="reader-loading" role="status" aria-live="polite"><div class="reader-loading-orb"></div><div class="reader-loading-title">本文を読み込んでいます</div><div class="reader-loading-sub">青空文庫から本文を準備中…</div><div class="reader-loading-bar"><span></span></div></div>';
  }
}
function pulseState(el){
  if(!el||document.body.classList.contains('low-power'))return;
  el.classList.remove('state-bump');
  void el.offsetWidth;
  el.classList.add('state-bump');
  window.setTimeout(()=>el.classList.remove('state-bump'),360);
}

function renderReaderBody(){
  if(!curDoc) return;
  $('body').innerHTML=sanitizeReaderHtml(curDoc.html);
}

function closeReader(fromPop=false){
  closeOneLineMode();
  $('reader').classList.remove('open');
  $('reader').classList.remove('reader-night', 'mode-focus');
  applySettings();
  if(window.speechSynthesis) speechSynthesis.cancel();
  popLayer('reader');
  save(); renderHome();
}

let progressRaf=null;
let lastProgressPct=-1;
let lastProgressSave=0;

function updateProgress(force=false){
  if(!curWork) return;
  const b=$('body'), isV=b.classList.contains('v');
  const max=isV?Math.max(1,b.scrollWidth-b.clientWidth):Math.max(1,b.scrollHeight-b.clientHeight);
  const f=Math.min(1,Math.max(0,(isV?Math.abs(b.scrollLeft):b.scrollTop)/max));
  const pct=Math.round(f*100);
  const now=Date.now();

  pos[curWork.id]={f,t:now};
  if(f>=0.97) done.add(curWork.id);

  // DOM更新は進捗率が変わった時だけ
  if(force || pct!==lastProgressPct){
    lastProgressPct=pct;
    $('r-prog').textContent=pct+'%';
    $('r-slider').value=pct;

    const totalChars=curWork.plain?.length||8000;
    const readChars=Math.floor(totalChars*f);
    const totalP=Math.max(1,Math.ceil(totalChars/800));
    const curP=Math.max(1,Math.ceil(totalP*f));
    const remM=Math.max(1,Math.ceil((totalChars*(1-f))/st.readSpeed));
    $('r-page-lbl').textContent=`${pct}% · ${curP}/${totalP}ページ · 残り約${remM}分 · ${readChars}/${totalChars}字読了`;
  }

  // 履歴は最大3秒に1回だけ更新
  if(force || now-lastProgressSave>=3000){
    lastProgressSave=now;
    hist=hist.filter(h=>h.id!==curWork.id);
    hist.unshift({id:curWork.id,t:now});
    if(hist.length>50) hist.pop();
  }
}

$('body').onscroll=()=>{
  lastUserActivityTime=Date.now();
  if(progressRaf===null){
    progressRaf=requestAnimationFrame(()=>{
      progressRaf=null;
      updateProgress();
    });
  }
};

// 本文タップ
$('body').onclick=(e)=>{
  lastUserActivityTime=Date.now();
  if(e.target.closest('.keyphrase,u,b,ruby')||getSelection().toString()) return;
  const w=innerWidth, x=e.clientX;

  if($('reader').classList.contains('mode-focus')){
    const topBar=$('r-top'), dock=$('r-dock'), botBar=$('r-bottom-info');
    topBar.classList.toggle('show-temp');
    dock.classList.toggle('show-temp');
    botBar.classList.toggle('show-temp');
    return;
  }

  if(x>w*0.35 && x<w*0.65){
    $('r-top').classList.toggle('hide');
    $('r-dock').classList.toggle('hide');
    $('r-bottom-info').classList.toggle('hide');
    return;
  }
  const b=$('body'), isV=b.classList.contains('v'), step=(isV?b.clientWidth:b.clientHeight)*0.88;
  const dir=isV ? ((x<=w*0.35)?'prev':'next') : ((x>=w*0.65)?'next':'prev');
  animateReaderPage(dir);
  b.scrollBy({left:isV?(x<=w*0.35?-step:step):0, top:isV?0:(x>=w*0.65?step:-step), behavior:'smooth'});
};

// 本文内検索
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

function applyReaderConfig(){
  $('body').style.setProperty('--r-fs',st.fs+'px');
  $('body').style.setProperty('--r-lh',st.lh);
  $('body').style.fontFamily=st.font==='gothic'?'var(--font-sans)':'var(--font-serif)';
  $('body').classList.toggle('v',st.v!==false);
  applyReaderMode();
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
  const nds=[]; let n; while((n=w.nextNode())) nds.push(n);
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
  aiConn.ok=false; aiConn.models=[]; aiConn.err='';
  if (!st.ollamaEnabled || !canUseOllama()) {
    renderHome();
    return;
  }
  try {
    const url = normalizeOllamaUrl(st.oUrl);
    const res=await secureFetch(url+'/api/tags',{signal:sig(4000)});
    if(res.ok){
      const raw=await readResponseBytes(res,64*1024); if(!raw)throw new Error('AI model list unavailable');
      const d=JSON.parse(new TextDecoder().decode(raw));
      const models=Array.isArray(d.models)?d.models.map(m=>String(m?.name||'').trim()).filter(n=>/^[A-Za-z0-9._:/-]{1,128}$/.test(n)).slice(0,200):[];
      aiConn.ok=true; aiConn.models=models;
      if(!st.oMod&&models.length) st.oMod=models[0];
    } else {
      aiConn.err='Ollama が応答しませんでした';
    }
  }catch(e){
    aiConn.err = e && e.message ? e.message : '接続失敗';
    aiConn.ok=false;
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
    const k=d.toISOString().slice(0,10);
    const m=calData[k]||0;
    const bg=m===0?'var(--card-sub)':m>=goalMin?'var(--ac)':'color-mix(in srgb, var(--ac) 45%, var(--card-sub))';
    hm.insertAdjacentHTML('beforeend',`<div style="width:18px; height:18px; border-radius:4px; background:${bg}" title="${escAttr(k)}: ${m}分"></div>`);
    d.setDate(d.getDate()+1);
  }
}

// 読書分数タイマー
setInterval(()=>{
  if($('reader').classList.contains('open') && !document.hidden){
    if(Date.now() - lastUserActivityTime < 65000){
      const todayKey=localDateKey();
      calData[todayKey]=(calData[todayKey]||0)+1;
      save();
      // 読書中はホーム全体を再描画しない。閉じた時にまとめて更新する。
    }
  }
},60000);

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
    if(same && same.scrollTop>24 && !document.body.classList.contains('low-power')) same.scrollTo({top:0,behavior:'smooth'});
    return;
  }
  const prev=currentView;
  const direction=viewOrder.indexOf(vid)>=viewOrder.indexOf(prev)?'forward':'backward';
  const current=$(prev), next=$(vid), low=document.body.classList.contains('low-power');
  document.querySelectorAll('.view').forEach(v=>{
    v.classList.remove('view-slide-forward','view-slide-backward','view-exit-forward','view-exit-backward');
  });
  if(!next)return;
  if(!low && current){
    current.classList.add('active','view-exit-'+direction);
    setTimeout(()=>current.classList.remove('active','view-exit-'+direction),320);
  }else if(current){
    current.classList.remove('active','view-exit-forward','view-exit-backward');
  }
  next.classList.add('active',direction==='forward'?'view-slide-forward':'view-slide-backward');
  currentView=vid;
  window.clearTimeout(window.__viewInTimer);
  window.__viewInTimer=window.setTimeout(()=>next.classList.remove('view-slide-forward','view-slide-backward'),480);
  document.querySelectorAll('.nav-btn, .b-nav-btn').forEach(b=>{
    const active=b.dataset.v===vid;
    b.classList.toggle('active',active);
    if(active) b.setAttribute('aria-current','page'); else b.removeAttribute('aria-current');
  });
  const targetView=$(vid);
  if(targetView && !document.body.classList.contains('low-power')) targetView.scrollTop=0;
  if(vid==='v-home') renderHome();
  else if(vid==='v-search') renderSearchInit();
  else if(vid==='v-shelf') renderShelf();
  else if(vid==='v-cal') renderCalendar();
  else if(vid==='v-settings') renderSettingsPage();
}

document.addEventListener('input',e=>{
  const el=e.target.closest?.('[data-act]');if(!el)return;
  if(el.dataset.act==='set-fs-range'){st.fs=Math.max(14,Math.min(32,Number(el.value)||18));applyReaderConfig();save();}
  else if(el.dataset.act==='set-lh-range'){st.lh=Math.max(1.6,Math.min(2.6,Number(el.value)||2.1));applyReaderConfig();save();}
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
  else if(act==='close-sheet') closeSheet();
  else if(act==='ban-btn') switchView('v-settings');
  else if(act==='nav-settings') switchView('v-settings');

  // 検索画面
  else if(act==='open-search') openSearchPage();
  else if(act==='q-clear') { $('q-input').value=''; searchState.query=''; applySearch(true); }
  else if(act==='scroll-top') $('v-search').scrollTo({top:0,behavior:'smooth'});
  else if(act==='clear-scope') { searchState.scope=null; searchState.query=''; $('q-input').value=''; applySearch(true); }
  else if(act==='chip-toggle') {
    const k=b.dataset.k;
    searchState.filter[k]=!searchState.filter[k];
    b.classList.toggle('active',searchState.filter[k]);
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

  // 本の操作
  else if(act==='resume-click'){
    const wid=b.dataset.wid;
    if(wid&&byId.has(wid)) openReader(byId.get(wid));
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
  else if(act==='read-now'){ closeSheet(); openReader(activeBook, false); }
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
      <div style="display:flex; flex-direction:column; gap:20px">
        <div style="display:flex; justify-content:space-between; align-items:center">
          <span>文字サイズ (${st.fs}px)</span>
          <input type="range" min="14" max="32" value="${st.fs}" data-act="set-fs-range" style="height:44px; width:160px">
        </div>
        <div style="display:flex; justify-content:space-between; align-items:center">
          <span>行間 (${st.lh})</span>
          <input type="range" min="1.6" max="2.6" step="0.1" value="${st.lh}" data-act="set-lh-range" style="height:44px; width:160px">
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
  else if(act==='pop-copy'){
    const txt=getSelection().toString();
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
    const blob=new Blob([JSON.stringify({allWorks,fav:[...fav],want:[...want],done:[...done],favAuthors:[...favAuthors],pos,bm,notes,hls,hist,calData,goalMin,st,searchHistory})],{type:'application/json'});
    const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='aozora_terminal_backup.json'; a.click();
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
  const f=e.target.value/100;
  const b=$('body'), isV=b.classList.contains('v');
  const max=isV?b.scrollWidth-b.clientWidth:b.scrollHeight-b.clientHeight;
  if(isV) b.scrollLeft=-Math.abs(f*max); else b.scrollTop=f*max;
  updateProgress();
};

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
  applyPerformanceMode();
  await load();
  applyPerformanceMode();
  applySettings();
  applyReaderConfig();
  initHomeHeroMotion();
  bindPressPhysics();
  bindUiRipple();
  await checkCatalog();
  if(!document.body.classList.contains('low-power')) startFeatTimer();
  if(!document.body.classList.contains('low-power')) startAudit();
  
  // Ollama接続確認
  pingOllama();

  // 検索入力遅延実行
  let searchTimer=null;
  $('q-input').oninput=()=>{
    clearTimeout(searchTimer);
    searchTimer=setTimeout(()=>{
      searchState.query=$('q-input').value;
      applySearch(true);
    },250);
  };

  // 検索無限スクロール
  new IntersectionObserver(entries=>{
    if(entries[0].isIntersecting && searchCursor<searchPool.length){
      const chunk=searchPool.slice(searchCursor,searchCursor+40);
      searchCursor+=40;
      $('search-tiles').insertAdjacentHTML('beforeend',rows(chunk,w=>tileHtml(w)));
    }
  }).observe($('search-sentinel'));
});