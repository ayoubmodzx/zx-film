'use strict';
(function () {
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const coarse = matchMedia('(pointer: coarse)').matches;
  if (reduce || coarse) return;
  const MAX = 9;
  const view = document.getElementById('view');
  if (!view) return;
  let active = null;
  let frame = 0;
  let pending = null;
  function apply() {
    frame = 0;
    if (!pending) return;
    const { card, rx, ry, mx, my } = pending;
    card.style.setProperty('--rx', rx.toFixed(2) + 'deg');
    card.style.setProperty('--ry', ry.toFixed(2) + 'deg');
    card.style.setProperty('--mx', mx.toFixed(1) + '%');
    card.style.setProperty('--my', my.toFixed(1) + '%');
  }
  function reset(card) {
    if (!card) return;
    card.classList.remove('tilting');
    card.style.setProperty('--rx', '0deg');
    card.style.setProperty('--ry', '0deg');
  }
  view.addEventListener('pointermove', (e) => {
    const card = e.target.closest('.card[data-id]');
    if (card !== active) { reset(active); active = card; if (card) card.classList.add('tilting'); }
    if (!card) return;
    const r = card.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width;
    const py = (e.clientY - r.top) / r.height;
    pending = {
      card,
      ry: (px - 0.5) * 2 * MAX,
      rx: (0.5 - py) * 2 * MAX,
      mx: px * 100,
      my: py * 100,
    };
    if (!frame) frame = requestAnimationFrame(apply);
  }, { passive: true });
  view.addEventListener('pointerleave', () => { reset(active); active = null; }, { passive: true });
  window.addEventListener('hashchange', () => { reset(active); active = null; });
})();
