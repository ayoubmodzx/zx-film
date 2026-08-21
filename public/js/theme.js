'use strict';
(function () {
  const KEY = 'zx-theme';
  const root = document.documentElement;
  const btn = document.getElementById('themeToggle');
  const meta = document.querySelector('meta[name="theme-color"]');
  const isLight = () => root.getAttribute('data-theme') === 'light';
  function paint() {
    const light = isLight();
    if (btn) {
      const span = btn.querySelector('span');
      span.innerHTML = ZXIcons.get(light ? 'sun' : 'moon');
      btn.setAttribute('aria-pressed', String(light));
      btn.title = light ? 'Switch to dark' : 'Switch to light';
    }
    if (meta) meta.setAttribute('content', light ? '#f4f1fb' : '#050308');
  }
  function set(theme) {
    if (theme === 'light') root.setAttribute('data-theme', 'light');
    else root.removeAttribute('data-theme');
    try { localStorage.setItem(KEY, theme); } catch (_) {  }
    paint();
  }
  if (btn) btn.addEventListener('click', () => set(isLight() ? 'dark' : 'light'));
  paint();
})();
