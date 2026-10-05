(function(){
  'use strict';
  const target='./index.html'+location.search+location.hash;
  try{location.replace(target);}catch{location.href=target;}
})();
