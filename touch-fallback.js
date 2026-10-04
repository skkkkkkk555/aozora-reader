(() => {
  'use strict';

  let syntheticTap = false;
  let suppressNativeEl = null;
  let suppressNativeUntil = 0;
  let start = null;

  const getAction = target => {
    const el = target?.closest?.('[data-act]');
    return el && document.contains(el) ? el : null;
  };

  const markTouchTargets = root => {
    const base = root?.querySelectorAll ? root : document;
    base.querySelectorAll('[data-act],button,input,select,textarea,label').forEach(el => {
      if (el.style.touchAction !== 'none') el.style.touchAction = 'manipulation';
    });
  };

  document.addEventListener('DOMContentLoaded', () => markTouchTargets(), { once: true });
  new MutationObserver(muts => {
    for (const m of muts) {
      for (const n of m.addedNodes) {
        if (n.nodeType === 1) {
          if (n.matches?.('[data-act],button,input,select,textarea,label')) n.style.touchAction = 'manipulation';
          markTouchTargets(n);
        }
      }
    }
  }).observe(document.documentElement, { childList: true, subtree: true });

  document.addEventListener('pointerdown', e => {
    if (e.pointerType !== 'touch') return;
    const el = getAction(e.target);
    if (!el) return;
    start = { x: e.clientX, y: e.clientY, el };
  }, { passive: true });

  document.addEventListener('pointercancel', e => {
    if (e.pointerType === 'touch') start = null;
  }, { passive: true });

  document.addEventListener('pointerup', e => {
    if (e.pointerType !== 'touch' || !start) return;
    const el = getAction(e.target);
    const dx = e.clientX - start.x;
    const dy = e.clientY - start.y;
    const same = el && el === start.el;
    const tap = dx * dx + dy * dy <= 18 * 18;

    if (same && tap) {
      syntheticTap = true;
      suppressNativeEl = el;
      suppressNativeUntil = Date.now() + 900;
      try { el.click(); } finally { syntheticTap = false; }
    }
    start = null;
  }, { passive: true });

  document.addEventListener('click', e => {
    if (syntheticTap) return;
    if (suppressNativeEl && Date.now() < suppressNativeUntil) {
      const el = getAction(e.target);
      if (el === suppressNativeEl) {
        suppressNativeEl = null;
        suppressNativeUntil = 0;
        e.preventDefault();
        e.stopImmediatePropagation();
        return;
      }
    }
    suppressNativeEl = null;
    suppressNativeUntil = 0;
  }, true);
})();