'use strict';
(() => {
  const toggle=document.querySelector('.nav-toggle');
  const nav=document.querySelector('.nav');
  if(toggle&&nav) toggle.addEventListener('click',()=>{const open=nav.classList.toggle('open');toggle.setAttribute('aria-expanded',String(open));});
  document.querySelectorAll('[data-search-target]').forEach(input=>{
    const target=document.querySelector(input.dataset.searchTarget);
    if(!target)return;
    const cards=Array.from(target.querySelectorAll('[data-search-text]'));
    const empty=target.querySelector('[data-search-empty]');
    const update=()=>{const q=input.value.trim().toLowerCase();let n=0;cards.forEach(card=>{const show=card.dataset.searchText.toLowerCase().includes(q);card.hidden=!show;if(show)n++;});if(empty)empty.hidden=n!==0;};
    input.addEventListener('input',update);update();
  });
  document.querySelectorAll('[data-confirm]').forEach(el=>el.addEventListener('click',event=>{if(!confirm(el.dataset.confirm||'Are you sure?'))event.preventDefault();}));
})();

// Approval nudge is intentionally not dismissible without opening the decision queue.