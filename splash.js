/* 青空文庫 本の開架スプラッシュ */
window.addEventListener('load',()=>{
  const splash=document.getElementById('aozora-splash');
  if(!splash)return;
  window.setTimeout(()=>splash.classList.add('loaded'),2400);
  window.setTimeout(()=>splash.remove(),3400);
},{once:true});
