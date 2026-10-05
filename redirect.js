(function(){
  'use strict';
  const params=new URLSearchParams(location.search);
  params.set('shell-version','20261005-44');
  const target='./index.html?'+params.toString()+location.hash;
  try{location.replace(target);}catch{location.href=target;}
})();
