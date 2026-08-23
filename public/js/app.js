'use strict';
(function () {
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const view = $('#view');
  const searchInput = $('#searchInput');
  const searchClear = $('#searchClear');
  let ZX_TOKEN = null;
  let refreshingToken = null;
  let ZX_TS_SITEKEY = null;
  const ZX_AUTO = (typeof navigator !== 'undefined' && navigator.webdriver) ? { 'X-ZX-Auto': '1' } : {};
  const _zk = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  function _za(msg) {
    const rotr = (n, x) => (x >>> n) | (x << (32 - n));
    let H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const bytes = [];
    for (let i = 0; i < msg.length; i++) bytes.push(msg.charCodeAt(i) & 0xff);
    const bl = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    bytes.push(0, 0, 0, 0, (bl >>> 24) & 0xff, (bl >>> 16) & 0xff, (bl >>> 8) & 0xff, bl & 0xff);
    const w = new Array(64);
    for (let off = 0; off < bytes.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = (bytes[off + i * 4] << 24) | (bytes[off + i * 4 + 1] << 16) | (bytes[off + i * 4 + 2] << 8) | bytes[off + i * 4 + 3];
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(7, w[i - 15]) ^ rotr(18, w[i - 15]) ^ (w[i - 15] >>> 3);
        const s1 = rotr(17, w[i - 2]) ^ rotr(19, w[i - 2]) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(6, e) ^ rotr(11, e) ^ rotr(25, e);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + _zk[i] + w[i]) | 0;
        const S0 = rotr(2, a) ^ rotr(13, a) ^ rotr(22, a);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    let hex = '';
    for (let i = 0; i < 8; i++) hex += ((H[i] >>> 0).toString(16)).padStart(8, '0');
    return hex;
  }
  function _zb(hex) {
    let n = 0;
    for (let i = 0; i < hex.length; i++) {
      const v = parseInt(hex[i], 16);
      if (v === 0) { n += 4; continue; }
      n += Math.clz32(v) - 28; break;
    }
    return n;
  }
  function _zc(x, y) {
    return new Promise((resolve) => {
      let k = 0;
      const step = () => {
        const end = k + 4096;
        for (; k < end; k++) {
          if (_zb(_za(x + ':' + k)) >= y) return resolve(k);
        }
        setTimeout(step, 0);
      };
      step();
    });
  }
  async function _zd() {
    const s = await fetch('/api/session', { credentials: 'same-origin', headers: ZX_AUTO }).then(r => r.json()).catch(() => null);
    if (!s) return null;
    if (s.token) { ZX_TOKEN = s.token; return s; }
    if (s.vx && s.vx.c) {
      const n = await _zc(s.vx.c, s.vx.b || 16);
      const h = await fetch('/api/handshake?c=' + encodeURIComponent(s.vx.c) + '&n=' + n, { credentials: 'same-origin', headers: ZX_AUTO }).then(r => r.json()).catch(() => null);
      if (h && h.token) ZX_TOKEN = h.token;
    }
    return s;
  }
  function refreshToken() {
    if (refreshingToken) return refreshingToken;
    refreshingToken = _zd().catch(() => null).then(() => { refreshingToken = null; return ZX_TOKEN; });
    return refreshingToken;
  }
  async function api(p, opts, tried) {
    tried = tried || {};
    const o = Object.assign({ credentials: 'same-origin' }, opts || {});
    o.headers = Object.assign({}, ZX_AUTO, o.headers, ZX_TOKEN ? { 'X-ZX-Token': ZX_TOKEN } : {});
    const r = await fetch(p, o);
    if (r.status === 401) {
      let last = 0; try { last = +sessionStorage.getItem('zx-reload') || 0; } catch (_) {}
      const now = Date.now();
      if (now - last > 8000) {
        try { sessionStorage.setItem('zx-reload', String(now)); } catch (_) {}
        toast('Session expired — reloading…', 'warn');
        setTimeout(() => location.reload(), 900);
      } else {
        toast('Can’t start a session right now — please try again shortly', 'warn');
      }
      throw new Error('session');
    }
    if (r.status === 403) {
      const body = await r.json().catch(() => null);
      // Step-up: the server flagged this session for a human check. Solve an
      // invisible Turnstile challenge once, then retry — a real user sees nothing.
      if (body && body.needVerify && ZX_TS_SITEKEY && !tried.verify) {
        tried.verify = true;
        const ok = await verifyTurnstile(ZX_TS_SITEKEY);
        if (ok) return api(p, opts, tried);
      } else if (!tried.token) {
        // Otherwise treat it as an expired page token: re-handshake and retry once.
        tried.token = true;
        const t = await refreshToken();
        if (t) return api(p, opts, tried);
      }
      toast('Request blocked', 'warn'); throw new Error('forbidden');
    }
    if (r.status === 429) { toast('Slow down a moment…', 'warn'); throw new Error('rate'); }
    return r.json();
  }
  const enc = encodeURIComponent;
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  function initials(name) {
    const w = String(name || '?').trim().split(/\s+/).filter(Boolean);
    return ((w[0] || '?')[0] + (w[1] ? w[1][0] : '')).toUpperCase();
  }
  function typeIcon(t) {
    const s = String(t || '').toLowerCase();
    if (s.includes('movie') || s.includes('film')) return 'film';
    return 'tv';
  }
  function fmtTime(sec) {
    sec = Math.max(0, Math.floor(sec || 0));
    const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
    const p = (n) => String(n).padStart(2, '0');
    return h ? `${h}:${p(m)}:${p(s)}` : `${m}:${p(s)}`;
  }
  function toast(msg, icon) {
    const t = $('#toast');
    t.innerHTML = `<span>${ZXIcons.get(icon || 'sparkle')}</span><span>${esc(msg)}</span>`;
    t.hidden = false; requestAnimationFrame(() => t.classList.add('show'));
    clearTimeout(toast._t); toast._t = setTimeout(() => {
      t.classList.remove('show'); setTimeout(() => (t.hidden = true), 300);
    }, 3200);
  }
  function cardHTML(it) {
    const cover = it.cover || '';
    const badge = it.type ? `<span class="badge">${ZXIcons.get(typeIcon(it.type))}${esc(it.type)}</span>` : '';
    const score = it.score ? `<span class="chip-score">${ZXIcons.get('star')}${it.score.toFixed(1)}</span>` : '';
    const sub = [it.year, it.episodes ? `${it.episodes} EP` : ''].filter(Boolean)
      .map(esc).join('<span class="dot"></span>');
    const img = cover
      ? `<img src="${esc(cover)}" alt="" loading="lazy"
           onerror="this.style.display='none';this.parentNode.querySelector('.poster-fallback').style.display='grid'">`
      : '';
    return `
      <button class="card" data-id="${esc(it.id)}" data-cat="${it.category != null ? it.category : ''}">
        <div class="poster">
          ${badge}${score}
          ${img}
          <div class="poster-fallback" ${cover ? 'style="display:none"' : ''}>${esc(initials(it.name))}</div>
          <div class="poster-scrim"></div>
          <div class="poster-play"><span>${ZXIcons.get('play')}</span></div>
        </div>
        <div class="card-body">
          <p class="card-title">${esc(it.name)}</p>
          ${sub ? `<div class="card-sub">${sub}</div>` : ''}
        </div>
      </button>`;
  }
  function railHTML(section) {
    return `
      <section class="section">
        <div class="section-head">
          <h2 class="section-title">${esc(section.title)}</h2>
          <span class="head-rule"></span>
          <div class="row-nav">
            <button class="row-arrow" data-dir="-1" aria-label="Scroll left">${ZXIcons.get('chevronL')}</button>
            <button class="row-arrow" data-dir="1" aria-label="Scroll right">${ZXIcons.get('chevronR')}</button>
          </div>
        </div>
        <div class="rail">
          <div class="rail-track">${section.items.map(cardHTML).join('')}</div>
        </div>
      </section>`;
  }
  function skeletonRail(n) {
    return `<section class="section"><div class="section-head"><h2 class="section-title">&nbsp;</h2></div>
      <div class="rail"><div class="rail-track">${Array.from({ length: n || 7 })
        .map(() => `<div class="card"><div class="poster sk sk-card"></div></div>`).join('')}</div></div></section>`;
  }
  function stateHTML(icon, title, text) {
    return `<div class="state"><div class="ico">${ZXIcons.get(icon)}</div>
      <h3>${esc(title)}</h3><p>${esc(text || '')}</p></div>`;
  }
  function backBtn() {
    return `<button class="zx-back" aria-label="Back">${ZXIcons.get('back')}<span>Back</span></button>`;
  }
  async function renderHome() {
    setActiveSearch('');
    view.innerHTML = `<div class="section-pad"></div>` + skeletonRail(7) + skeletonRail(7);
    ZXIcons.apply(view);
    let data;
    try { data = await api('/api/home'); }
    catch (e) { view.innerHTML = stateHTML('warn', 'Connection issue', 'Could not reach the service.'); ZXIcons.apply(view); return; }
    const sections = (data && data.sections) || [];
    if (!sections.length) { view.innerHTML = stateHTML('film', 'Nothing here yet', 'Try searching for a title above.'); ZXIcons.apply(view); return; }
    const featured = pickFeatured(sections);
    const html = `<div class="section-pad"></div>` +
      (featured ? heroHTML(featured) : '') +
      sections.map(railHTML).join('');
    view.innerHTML = html;
    ZXIcons.apply(view);
    if (featured) enrichHero(featured);
  }
  function pickFeatured(sections) {
    for (const sec of sections) {
      const hit = sec.items.find(i => i.cover);
      if (hit) return hit;
    }
    return sections[0] && sections[0].items[0];
  }
  function heroHTML(it) {
    const score = it.score ? `<span class="meta-pill score">${ZXIcons.get('star')}${it.score.toFixed(1)}</span>` : '';
    return `
      <section class="hero" id="hero">
        <div class="hero-bg" style="background-image:url('${esc(it.backdrop || it.cover)}')"></div>
        <div class="hero-inner">
          <div class="hero-badge"><span class="rule"></span> Featured</div>
          <h1 class="hero-title">${esc(it.name)}</h1>
          <div class="hero-meta">
            ${it.type ? `<span class="meta-pill">${ZXIcons.get(typeIcon(it.type))}${esc(it.type)}</span>` : ''}
            ${it.year ? `<span class="meta-pill">${ZXIcons.get('calendar')}${esc(it.year)}</span>` : ''}
            ${score}
          </div>
          <p class="hero-desc" id="heroDesc"></p>
          <button class="btn" data-id="${esc(it.id)}" data-cat="${it.category != null ? it.category : ''}">
            ${ZXIcons.get('play')} Watch Now
          </button>
        </div>
      </section>`;
  }
  async function enrichHero(it) {
    try {
      const d = await api(`/api/title/${enc(it.id)}`);
      const hero = $('#hero'); if (!hero || !d || d.error) return;
      if (d.backdrop) $('.hero-bg', hero).style.backgroundImage = `url('${d.backdrop}')`;
      if (d.intro) $('#heroDesc').textContent = d.intro;
    } catch (e) {  }
  }
  let searchSeq = 0;
  async function renderSearch(q) {
    setActiveSearch(q);
    const my = ++searchSeq;
    view.innerHTML = `${backBtn()}
      <section class="section"><h2 class="section-title">Results for “${esc(q)}”</h2>
      <div class="grid">${Array.from({ length: 12 }).map(() => `<div class="card"><div class="poster sk sk-card"></div></div>`).join('')}</div></section>`;
    ZXIcons.apply(view);
    let data;
    try { data = await api(`/api/search?q=${enc(q)}`); }
    catch (e) { if (my === searchSeq) { view.innerHTML = backBtn() + stateHTML('warn', 'Search failed', 'Please try again.'); ZXIcons.apply(view); } return; }
    if (my !== searchSeq) return;
    const results = (data && data.results) || [];
    const recommended = !!(data && data.recommended);
    if (!results.length) {
      view.innerHTML = backBtn() +
        stateHTML('search', 'No matches', `Nothing found for “${q}”. Try another title.`);
      ZXIcons.apply(view); return;
    }
    if (recommended) {
      // No title matched the query — show a popular rail, like the app does.
      view.innerHTML = `${backBtn()}
        <section class="section">
          <div class="section-head"><h2 class="section-title">No matches for “${esc(q)}”</h2>
          <span class="head-rule"></span>
          <span class="head-count">Popular right now</span></div>
          <div class="grid">${results.map(cardHTML).join('')}</div>
        </section>`;
      ZXIcons.apply(view); return;
    }
    view.innerHTML = `${backBtn()}
      <section class="section">
        <div class="section-head"><h2 class="section-title">Results for “${esc(q)}”</h2>
        <span class="head-rule"></span>
        <span class="head-count">${results.length} ${results.length === 1 ? 'title' : 'titles'}</span></div>
        <div class="grid">${results.map(cardHTML).join('')}</div>
      </section>`;
    ZXIcons.apply(view);
  }
  async function renderDetail(id, cat) {
    window.scrollTo(0, 0);
    view.innerHTML = `${backBtn()}<div class="detail-hero"><div class="detail-top">
      <div class="detail-poster sk"></div>
      <div class="detail-info"><div class="sk" style="height:44px;width:60%;border-radius:10px;margin-bottom:16px"></div>
      <div class="sk" style="height:20px;width:40%;border-radius:8px;margin-bottom:24px"></div>
      <div class="sk" style="height:80px;width:80%;border-radius:8px"></div></div></div></div>`;
    let d;
    try { d = await api(`/api/title/${enc(id)}${cat !== undefined && cat !== '' ? `?category=${enc(cat)}` : ''}`); }
    catch (e) { view.innerHTML = backBtn() + stateHTML('warn', 'Could not load', 'Failed to load this title.'); ZXIcons.apply(view); return; }
    if (!d || d.error) { view.innerHTML = backBtn() + stateHTML('warn', 'Not available', 'This title could not be found.'); ZXIcons.apply(view); return; }
    const eps = d.episodes || [];
    const isSeries = eps.length > 1;
    const score = d.score ? `<span class="meta-pill score">${ZXIcons.get('star')}${d.score.toFixed(1)}</span>` : '';
    const meta = [
      d.year ? `<span class="meta-pill">${ZXIcons.get('calendar')}${esc(d.year)}</span>` : '',
      d.type ? `<span class="meta-pill">${ZXIcons.get(typeIcon(d.type))}${esc(d.type)}</span>` : '',
      isSeries ? `<span class="meta-pill">${ZXIcons.get('layers')}${eps.length} Episodes</span>` : '',
      (d.areas && d.areas.length) ? `<span class="meta-pill">${ZXIcons.get('globe')}${esc(d.areas.slice(0, 2).join(', '))}</span>` : '',
      score,
    ].filter(Boolean).join('');
    const tags = (d.tags || []).slice(0, 6).map(t => `<span class="tag">${esc(t)}</span>`).join('');
    const posterImg = d.cover
      ? `<img src="${esc(d.cover)}" alt="" onerror="this.style.display='none'">`
      : `<div class="poster-fallback" style="display:grid">${esc(initials(d.name))}</div>`;
    const epGrid = isSeries ? `
      <section class="episodes">
        <div class="section-head"><h2 class="section-title">Episodes</h2>
        <span class="head-rule"></span>
        <span class="head-count">${eps.length} ${eps.length === 1 ? 'episode' : 'episodes'}</span></div>
        <div class="ep-grid" id="epGrid">
          ${eps.map(e => `
            <button class="ep" data-ep="${esc(e.episodeId)}" data-no="${esc(e.seriesNo)}">
              <span class="n">${esc(e.seriesNo)}</span>
              <span class="l">${e.totalTime ? ZXIcons.get('play') + fmtTime(e.totalTime) : (e.name ? esc(e.name) : 'Episode')}</span>
            </button>`).join('')}
        </div>
      </section>` : '';
    view.innerHTML = `
      ${backBtn()}
      <div class="detail-hero">
        <div class="detail-bg" style="background-image:url('${esc(d.backdrop || d.cover)}')"></div>
        <div class="detail-top">
          <div class="detail-poster">${posterImg}</div>
          <div class="detail-info">
            <h1>${esc(d.name)}</h1>
            ${d.enName && d.enName !== d.name ? `<div class="detail-en">${esc(d.enName)}</div>` : ''}
            <div class="meta-row">${meta}</div>
            ${tags ? `<div class="tags">${tags}</div>` : ''}
            <p class="detail-desc">${esc(d.intro || 'No description available.')}</p>
            <div class="detail-actions">
              <button class="btn" data-play-ep="${eps[0] ? esc(eps[0].episodeId) : ''}" data-no="${isSeries && eps[0] ? esc(eps[0].seriesNo) : ''}">
                ${ZXIcons.get('play')} ${isSeries ? 'Play Episode 1' : 'Play Now'}
              </button>
            </div>
          </div>
        </div>
      </div>
      ${epGrid}`;
    ZXIcons.apply(view);
    view.__title = { id: String(id), category: d.category, name: d.name };
  }
  function setActiveSearch(q) {
    if (document.activeElement !== searchInput) searchInput.value = q || '';
    searchClear.hidden = !(searchInput.value);
  }
  function route() {
    const h = location.hash.replace(/^#/, '') || '/';
    const parts = h.split('/').filter(Boolean);
    closePlayer(true);
    if (parts[0] === 't' && parts[1]) return renderDetail(decodeURIComponent(parts[1]), parts[2] !== undefined ? parts[2] : '');
    if (parts[0] === 'search' && parts[1] !== undefined) return renderSearch(decodeURIComponent(parts.slice(1).join('/')));
    return renderHome();
  }
  function go(hash) { if (location.hash === hash) route(); else location.hash = hash; }
  window.addEventListener('hashchange', route);
  let backTarget = '#/';
  window.addEventListener('hashchange', (e) => {
    try {
      const oldH = new URL(e.oldURL).hash, newH = new URL(e.newURL).hash;
      if (oldH && oldH !== newH) backTarget = oldH;
    } catch (_) {  }
  });
  view.addEventListener('click', (e) => {
    if (e.target.closest('.zx-back')) {
      if (location.hash.startsWith('#/search')) return go('#/');
      return go(backTarget && !backTarget.startsWith('#/t/') && backTarget !== location.hash ? backTarget : '#/');
    }
    const card = e.target.closest('.card[data-id], .btn[data-id]');
    if (card && card.dataset.id) { const c = card.dataset.cat; go(`#/t/${enc(card.dataset.id)}${c !== '' && c != null ? '/' + enc(c) : ''}`); return; }
    const arrow = e.target.closest('.row-arrow');
    if (arrow) { const track = $('.rail-track', arrow.closest('.section')); track.scrollBy({ left: (+arrow.dataset.dir) * track.clientWidth * 0.85, behavior: 'smooth' }); return; }
    const epBtn = e.target.closest('.ep[data-ep], .btn[data-play-ep]');
    if (epBtn) {
      const epId = epBtn.dataset.ep || epBtn.dataset.playEp || null;
      const no = epBtn.dataset.no || '';
      const ctx = view.__title || {};
      $$('.ep.playing').forEach(x => x.classList.remove('playing'));
      const target = $(`.ep[data-ep="${CSS.escape(epId || '')}"]`);
      if (target) target.classList.add('playing');
      openPlayer({ contentId: ctx.id, episodeId: epId, category: ctx.category, name: ctx.name, epNo: no });
    }
  });
  let searchTimer;
  searchInput.addEventListener('input', () => {
    searchClear.hidden = !searchInput.value;
    clearTimeout(searchTimer);
    const q = searchInput.value.trim();
    searchTimer = setTimeout(() => {
      if (!q) { if (location.hash.startsWith('#/search')) go('#/'); return; }
      go(`#/search/${enc(q)}`);
    }, 380);
  });
  $('#searchForm').addEventListener('submit', (e) => {
    e.preventDefault(); clearTimeout(searchTimer);
    const q = searchInput.value.trim(); searchInput.blur();
    q ? go(`#/search/${enc(q)}`) : go('#/');
  });
  searchClear.addEventListener('click', () => { searchInput.value = ''; searchClear.hidden = true; searchInput.focus(); if (location.hash.startsWith('#/search')) go('#/'); });
  const P = {
    el: $('#player'), stage: $('#playerStage'), video: $('#video'),
    hls: null, qualities: [], subs: [], ctx: null, def: 'GROOT_LD',
    seeking: false, hideTimer: null,
  };
  const V = P.video;
  async function openPlayer(ctx) {
    if (!ctx.contentId) return;
    P.ctx = ctx; P.def = 'GROOT_LD';
    P.el.hidden = false; document.body.style.overflow = 'hidden';
    showUI(); $('#plLoading').hidden = false;
    $('#plTitle').textContent = ctx.name || 'Now Playing';
    $('#plSub').textContent = (ctx.epNo && ctx.epNo !== '0') ? `Episode ${ctx.epNo}` : '';
    clearTracks();
    await loadPlay(ctx.def || 'GROOT_LD', 0, true);
  }
  async function loadPlay(definition, resumeTime, buildMenus, requested) {
    const c = P.ctx; if (!c) return;
    const url = `/api/play?contentId=${enc(c.contentId)}` +
      (c.episodeId ? `&episodeId=${enc(c.episodeId)}` : '') +
      (c.category != null && c.category !== '' ? `&category=${enc(c.category)}` : '') +
      `&definition=${enc(definition)}`;
    let d;
    try { d = await api(url); }
    catch (e) { $('#plLoading').hidden = true; toast('Playback service error', 'warn'); return; }
    if (!d || d.error || !d.mediaUrl) { $('#plLoading').hidden = true; toast(d && d.error ? d.error : 'Stream unavailable', 'warn'); return; }
    P.def = d.currentDefinition || definition;
    if (buildMenus) {
      P.qualities = d.qualities || [];
      P.subs = d.subtitles || [];
      buildQualityMenu(); buildSubs();
    }
    updateQualLabel();
    loadSource(d.mediaUrl, resumeTime || 0);
    if (requested && P.def !== requested) {
      const want = P.qualities.find(x => x.code === requested);
      const got = P.qualities.find(x => x.code === P.def);
      toast(`${want ? want.label : 'That quality'} isn’t available — playing ${got ? got.label : P.def}`, 'warn');
    }
  }
  function loadSource(url, resumeTime) {
    const src = url;
    $('#plLoading').hidden = false;
    if (P.hls) { try { P.hls.destroy(); } catch (e) {} P.hls = null; }
    const start = () => { if (resumeTime) { try { V.currentTime = resumeTime; } catch (e) {} } V.play().catch(() => {}); };
    if (window.Hls && Hls.isSupported()) {
      const hls = new Hls({ maxBufferLength: 30, enableWorker: true });
      P.hls = hls;
      hls.loadSource(src); hls.attachMedia(V);
      hls.on(Hls.Events.MANIFEST_PARSED, start);
      hls.on(Hls.Events.ERROR, (evt, data) => {
        if (data && data.fatal) {
          if (data.type === Hls.ErrorTypes.NETWORK_ERROR) hls.startLoad();
          else if (data.type === Hls.ErrorTypes.MEDIA_ERROR) hls.recoverMediaError();
          else { toast('Stream error', 'warn'); }
        }
      });
    } else if (V.canPlayType('application/vnd.apple.mpegurl')) {
      V.src = src; V.addEventListener('loadedmetadata', start, { once: true });
    } else {
      toast('HLS not supported in this browser', 'warn');
    }
  }
  function buildQualityMenu() {
    const pop = $('#popQual');
    P.pickedIdx = null;
    if (!P.qualities.length) { pop.innerHTML = `<div class="pl-pop-title">Quality</div><div class="pl-opt active">Auto ${ZXIcons.get('check')}</div>`; return; }
    const act = activeQualityIndex();
    pop.innerHTML = `<div class="pl-pop-title">Quality</div>` + P.qualities.map((q, i) => `
      <button class="pl-opt${i === act ? ' active' : ''}" data-idx="${i}">
        <span>${esc(q.label)}</span>
        <span class="r"><span class="check">${ZXIcons.get('check')}</span></span>
      </button>`).join('');
  }
  function activeQualityIndex() {
    const qs = P.qualities;
    if (P.pickedIdx != null && qs[P.pickedIdx] && qs[P.pickedIdx].code === P.def) return P.pickedIdx;
    let i = qs.findIndex(q => q.code === P.def && !q.vip);
    if (i < 0) i = qs.findIndex(q => q.code === P.def);
    return i;
  }
  function updateQualLabel() {
    const act = activeQualityIndex();
    const q = P.qualities[act];
    $('#qualLabel').textContent = q ? q.label : 'Auto';
    $$('#popQual .pl-opt').forEach(o => o.classList.toggle('active', +o.dataset.idx === act));
  }
  function clearTracks() {
    $$('#video track').forEach(t => t.remove());
    if (P.subTrack) { try { P.subTrack.removeEventListener('cuechange', renderCue); } catch (_) {} P.subTrack = null; }
    const box = $('#plSubs'); if (box) { box.hidden = true; box.textContent = ''; }
  }
  function buildSubs() {
    clearTracks();
    P.subs.forEach((s, i) => {
      const tr = document.createElement('track');
      tr.kind = 'subtitles'; tr.label = s.label || s.lang || ('Sub ' + (i + 1));
      tr.srclang = (s.lang || 'und').slice(0, 8); tr.src = s.url;
      V.appendChild(tr);
    });
    const pop = $('#popSubs');
    pop.innerHTML = `<div class="pl-pop-title">Subtitles</div>` +
      `<button class="pl-opt active" data-sub="-1"><span>Off</span><span class="r"><span class="check">${ZXIcons.get('check')}</span></span></button>` +
      P.subs.map((s, i) => `<button class="pl-opt" data-sub="${i}"><span>${esc(s.label || s.lang)}</span><span class="r"><span class="check">${ZXIcons.get('check')}</span></span></button>`).join('');
    $('#btnSubs').style.opacity = P.subs.length ? '1' : '.4';
  }
  function selectSub(idx) {
    const tracks = V.textTracks;
    if (P.subTrack) { try { P.subTrack.removeEventListener('cuechange', renderCue); } catch (_) {} P.subTrack = null; }
    for (let i = 0; i < tracks.length; i++) tracks[i].mode = (i === idx) ? 'hidden' : 'disabled';
    if (idx >= 0 && tracks[idx]) { P.subTrack = tracks[idx]; P.subTrack.addEventListener('cuechange', renderCue); }
    renderCue();
    $$('#popSubs .pl-opt').forEach(o => o.classList.toggle('active', (+o.dataset.sub) === idx));
  }
  function renderCue() {
    const box = $('#plSubs'); if (!box) return;
    const tr = P.subTrack;
    let txt = '';
    if (tr && tr.activeCues) {
      for (let i = 0; i < tr.activeCues.length; i++) { if (txt) txt += '\n'; txt += tr.activeCues[i].text || ''; }
    }
    txt = txt.replace(/<[^>]+>/g, '').trim();
    if (!txt) { box.hidden = true; box.textContent = ''; return; }
    box.innerHTML = txt.split('\n').map(l => l.trim()).filter(Boolean).map(l => '<span>' + esc(l) + '</span>').join('');
    box.hidden = false;
    positionSubs();
  }
  function positionSubs() {
    const box = $('#plSubs'); if (!box || box.hidden) return;
    const cw = P.stage.clientWidth, ch = P.stage.clientHeight;
    let bar = 0;
    if (V.videoWidth && V.videoHeight && cw && ch) {
      const picH = Math.min(ch, cw * V.videoHeight / V.videoWidth);
      bar = Math.max(0, (ch - picH) / 2);
    }
    let bottom = Math.round(bar + ch * 0.04) + 6;
    if (!P.el.classList.contains('hide-ui')) {
      const ctrls = $('#plControls');
      const need = (ctrls ? ctrls.offsetHeight : 0) + 8;
      if (bottom < need) bottom = need;
    }
    const cap = Math.round(ch * 0.6);
    if (bottom > cap) bottom = cap;
    box.style.bottom = bottom + 'px';
  }
  function togglePop(which) {
    const q = $('#popQual'), s = $('#popSubs');
    if (which === 'q') { q.hidden = !q.hidden; s.hidden = true; }
    else { s.hidden = !s.hidden; q.hidden = true; }
  }
  $('#btnQual').addEventListener('click', (e) => { e.stopPropagation(); togglePop('q'); });
  $('#btnSubs').addEventListener('click', (e) => { e.stopPropagation(); togglePop('s'); });
  $('#popQual').addEventListener('click', (e) => {
    const b = e.target.closest('.pl-opt[data-idx]'); if (!b) return;
    const idx = +b.dataset.idx;
    const q = P.qualities[idx]; if (!q) return;
    $('#popQual').hidden = true;
    if (idx === activeQualityIndex()) return;
    P.pickedIdx = idx;
    toast('Switching to ' + q.label, 'quality');
    loadPlay(q.code, V.currentTime, false, q.code);
  });
  $('#popSubs').addEventListener('click', (e) => {
    const b = e.target.closest('.pl-opt[data-sub]'); if (!b) return;
    selectSub(+b.dataset.sub); $('#popSubs').hidden = true;
  });
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.pl-menu')) { $('#popQual').hidden = true; $('#popSubs').hidden = true; }
  });
  function togglePlay() { V.paused ? V.play().catch(() => {}) : V.pause(); }
  $('#btnPlay').addEventListener('click', togglePlay);
  $('#plCenter').addEventListener('click', togglePlay);
  V.addEventListener('click', togglePlay);
  function setPlayIcons() {
    const ic = V.paused ? 'play' : 'pause';
    $('#btnPlay span').innerHTML = ZXIcons.get(ic);
    $('#plCenter span').innerHTML = ZXIcons.get(ic);
    $('#plCenter').classList.toggle('hide', !V.paused);
  }
  V.addEventListener('play', setPlayIcons);
  V.addEventListener('pause', setPlayIcons);
  V.addEventListener('playing', () => { $('#plLoading').hidden = true; });
  V.addEventListener('canplay', () => { $('#plLoading').hidden = true; });
  V.addEventListener('waiting', () => { $('#plLoading').hidden = false; });
  V.addEventListener('seeking', () => { $('#plLoading').hidden = false; });
  V.addEventListener('seeked', () => { $('#plLoading').hidden = true; });
  V.addEventListener('timeupdate', () => {
    if (P.seeking) return;
    const pct = V.duration ? (V.currentTime / V.duration) * 100 : 0;
    $('#seekFill').style.width = pct + '%';
    $('#seekKnob').style.left = pct + '%';
    $('#tCur').textContent = fmtTime(V.currentTime);
  });
  V.addEventListener('durationchange', () => { $('#tDur').textContent = fmtTime(V.duration); });
  V.addEventListener('progress', () => {
    if (V.buffered.length && V.duration) {
      const end = V.buffered.end(V.buffered.length - 1);
      $('#seekBuffer').style.width = (end / V.duration * 100) + '%';
    }
  });
  const track = $('#seekTrack');
  function seekAt(clientX) {
    const r = track.getBoundingClientRect();
    const ratio = Math.min(1, Math.max(0, (clientX - r.left) / r.width));
    if (V.duration) { V.currentTime = ratio * V.duration; $('#seekFill').style.width = (ratio * 100) + '%'; $('#seekKnob').style.left = (ratio * 100) + '%'; $('#tCur').textContent = fmtTime(V.currentTime); }
  }
  track.addEventListener('pointerdown', (e) => { P.seeking = true; track.setPointerCapture(e.pointerId); seekAt(e.clientX); });
  track.addEventListener('pointermove', (e) => { if (P.seeking) seekAt(e.clientX); });
  track.addEventListener('pointerup', (e) => { P.seeking = false; try { track.releasePointerCapture(e.pointerId); } catch (_) {} });
  track.addEventListener('pointercancel', () => { P.seeking = false; });
  const vol = $('#volRange');
  vol.addEventListener('input', () => { V.volume = +vol.value; V.muted = (+vol.value === 0); setMuteIcon(); });
  $('#btnMute').addEventListener('click', () => { V.muted = !V.muted; if (!V.muted && V.volume === 0) { V.volume = 1; vol.value = 1; } setMuteIcon(); });
  function setMuteIcon() { $('#btnMute span').innerHTML = ZXIcons.get(V.muted || V.volume === 0 ? 'mute' : 'volume'); if (!P.seeking) vol.value = V.muted ? 0 : V.volume; }
  V.addEventListener('volumechange', setMuteIcon);
  $('#btnFull').addEventListener('click', toggleFull);
  function toggleFull() {
    const fsEl = document.fullscreenElement || document.webkitFullscreenElement;
    if (!fsEl) { (P.stage.requestFullscreen || P.stage.webkitRequestFullscreen || (() => {})).call(P.stage); }
    else { (document.exitFullscreen || document.webkitExitFullscreen || (() => {})).call(document); }
  }
  document.addEventListener('fullscreenchange', () => {
    const on = !!document.fullscreenElement;
    P.stage.classList.toggle('fs', on);
    $('#btnFull span').innerHTML = ZXIcons.get(on ? 'exitfull' : 'fullscreen');
    setTimeout(positionSubs, 60);
  });
  window.addEventListener('resize', positionSubs);
  window.addEventListener('orientationchange', () => setTimeout(positionSubs, 250));
  V.addEventListener('loadedmetadata', positionSubs);
  function showUI() { P.el.classList.remove('hide-ui'); positionSubs(); clearTimeout(P.hideTimer); P.hideTimer = setTimeout(() => { if (!V.paused && !$('#popQual').hidden === false) { P.el.classList.add('hide-ui'); positionSubs(); } }, 3000); }
  P.stage.addEventListener('pointermove', showUI);
  P.stage.addEventListener('pointerleave', () => { if (!V.paused) { P.el.classList.add('hide-ui'); positionSubs(); } });
  V.addEventListener('pause', () => { P.el.classList.remove('hide-ui'); clearTimeout(P.hideTimer); });
  $('#plBack').addEventListener('click', () => closePlayer());
  function closePlayer(silent) {
    if (P.el.hidden) return;
    if (document.fullscreenElement) { try { document.exitFullscreen(); } catch (_) {} }
    try { V.pause(); } catch (_) {}
    if (P.hls) { try { P.hls.destroy(); } catch (_) {} P.hls = null; }
    V.removeAttribute('src'); try { V.load(); } catch (_) {}
    clearTracks();
    P.el.hidden = true; document.body.style.overflow = '';
    $('#popQual').hidden = true; $('#popSubs').hidden = true;
    P.ctx = null;
  }
  document.addEventListener('keydown', (e) => {
    if (P.el.hidden) return;
    switch (e.key) {
      case ' ': case 'k': e.preventDefault(); togglePlay(); showUI(); break;
      case 'ArrowLeft': V.currentTime = Math.max(0, V.currentTime - 5); showUI(); break;
      case 'ArrowRight': V.currentTime = Math.min(V.duration || 1e9, V.currentTime + 5); showUI(); break;
      case 'ArrowUp': V.volume = Math.min(1, V.volume + 0.1); showUI(); break;
      case 'ArrowDown': V.volume = Math.max(0, V.volume - 0.1); showUI(); break;
      case 'f': toggleFull(); break;
      case 'm': V.muted = !V.muted; setMuteIcon(); break;
      case 'Escape': if (!document.fullscreenElement) closePlayer(); break;
    }
  });
  const SUPPORT_I18N = {
    ar: {
      dir: 'rtl',
      eyebrow: 'من صاحب الموقع',
      title: 'شكرًا لمشاهدتك.',
      body0: 'ZX موقع يبنيه ويديره شخص واحد — بدون إعلانات، بدون اشتراكات، وبدون أي أقفال VIP. مجرّد أفلام ومسلسلات، مجانية للجميع، دائمًا.',
      body1: 'وإن وجد له مكانًا في أمسياتك وأحببت أن تساهم في استمراره، فأي دعم بسيط يعني الكثير. لا ضغط إطلاقًا — وجودك هنا وحده أكثر من كافٍ.',
      binTitle: 'معرّف Binance Pay',
      binHint: 'من تطبيق Binance: اضغط Pay ثم أرسِل إلى هذا المعرّف',
      cryptoTitle: 'عملات رقمية — BEP20',
      cryptoHint: 'شبكة BNB Smart Chain ‏(BEP20)‏ فقط — USDT وBNB وغيرها',
      foot: 'أيًّا كان الطريق الذي أوصلك إلى هنا — شكرًا لك. استمتع بالمشاهدة.',
      copy: 'نسخ', copied: 'تم النسخ',
      binLabel: 'معرّف Binance', cryptoLabel: 'عنوان المحفظة',
      toast: (l) => `تم نسخ ${l} — شكرًا لك 🤍`,
      copyFail: 'تعذّر النسخ — حدّده وانسخه يدويًا',
      langBtn: 'EN', langBtnAria: 'Switch to English', closeAria: 'إغلاق',
    },
    en: {
      dir: 'ltr',
      eyebrow: 'From the creator',
      title: 'Thanks for watching.',
      body0: 'ZX is built and run by one person — no ads, no paywalls, no VIP locks. Just films and series, free for everyone, always.',
      body1: 'If it’s found a place in your evenings and you’d like to help keep it going, a small tip goes a long way. There’s no pressure at all — you being here is already more than enough.',
      binTitle: 'Binance Pay ID',
      binHint: 'In the Binance app: Pay → send to this ID',
      cryptoTitle: 'Crypto — BEP20',
      cryptoHint: 'BNB Smart Chain (BEP20) only — USDT, BNB & more',
      foot: 'However you found your way here — thank you. Enjoy the show.',
      copy: 'Copy', copied: 'Copied',
      binLabel: 'Binance ID', cryptoLabel: 'Wallet address',
      toast: (l) => `${l} copied — thank you 🤍`,
      copyFail: 'Couldn’t copy — select and copy manually',
      langBtn: 'ع', langBtnAria: 'التبديل إلى العربية', closeAria: 'Close',
    },
  };
  function setupSupport() {
    const el = $('#support');
    if (!el) return;
    let lastFocus = null;
    let lang = 'ar';
    try { const s = localStorage.getItem('zx-support-lang'); if (s === 'en' || s === 'ar') lang = s; } catch (_) { }
    function applyLang(next) {
      lang = SUPPORT_I18N[next] ? next : 'ar';
      try { localStorage.setItem('zx-support-lang', lang); } catch (_) { }
      const t = SUPPORT_I18N[lang];
      $('#supportCard').dir = t.dir;
      el.querySelectorAll('[data-sup]').forEach(node => {
        const v = t[node.getAttribute('data-sup')];
        if (typeof v === 'string') node.textContent = v;
      });
      el.querySelectorAll('.pay-copy').forEach(btn => {
        const txt = btn.querySelector('.pay-copy-txt');
        if (txt) txt.textContent = btn.classList.contains('copied') ? t.copied : t.copy;
      });
      const lb = $('#supportLang');
      lb.textContent = t.langBtn; lb.setAttribute('aria-label', t.langBtnAria);
      $('#supportClose').setAttribute('aria-label', t.closeAria);
    }
    function open() {
      lastFocus = document.activeElement;
      el.hidden = false;
      document.body.style.overflow = 'hidden';
      requestAnimationFrame(() => $('#supportClose').focus());
    }
    function close() {
      el.hidden = true;
      if ($('#player').hidden) document.body.style.overflow = '';
      if (lastFocus && lastFocus.focus) lastFocus.focus();
    }
    $('#supportBtn').addEventListener('click', open);
    $('#supportClose').addEventListener('click', close);
    $('#supportScrim').addEventListener('click', close);
    $('#supportLang').addEventListener('click', () => applyLang(lang === 'ar' ? 'en' : 'ar'));
    document.addEventListener('keydown', (e) => { if (!el.hidden && e.key === 'Escape') close(); });
    async function copyText(text) {
      try {
        if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); return true; }
      } catch (_) {  }
      try {
        const ta = document.createElement('textarea');
        ta.value = text; ta.setAttribute('readonly', '');
        ta.style.position = 'fixed'; ta.style.top = '-1000px'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        return ok;
      } catch (_) { return false; }
    }
    function paintCopy(btn, copied) {
      const t = SUPPORT_I18N[lang];
      const ico = btn.querySelector('[data-ico]');
      const txt = btn.querySelector('.pay-copy-txt');
      if (ico) ico.innerHTML = ZXIcons.get(copied ? 'check' : 'copy');
      if (txt) txt.textContent = copied ? t.copied : t.copy;
      btn.classList.toggle('copied', copied);
    }
    el.addEventListener('click', async (e) => {
      const btn = e.target.closest('.pay-copy[data-copy]'); if (!btn) return;
      const t = SUPPORT_I18N[lang];
      const label = btn.dataset.kind === 'binance' ? t.binLabel : t.cryptoLabel;
      const ok = await copyText(btn.dataset.copy);
      if (!ok) { toast(t.copyFail, 'warn'); return; }
      toast(t.toast(label), 'check');
      paintCopy(btn, true);
      clearTimeout(btn._t);
      btn._t = setTimeout(() => paintCopy(btn, false), 1800);
    });
    applyLang(lang);
  }
  async function initSession() {
    try {
      const s = await _zd();
      try { sessionStorage.removeItem('zx-reload'); } catch (_) {}
      setInterval(refreshToken, 6 * 60 * 1000);
      // Remember the Turnstile sitekey but DON'T challenge anyone up front — the
      // widget is only rendered on demand when a sensitive call returns
      // {needVerify:true} (step-up). Normal browsing never triggers it.
      if (s && s.turnstile && s.turnstile.enabled && s.turnstile.sitekey) {
        ZX_TS_SITEKEY = s.turnstile.sitekey;
      }
    } catch (_) {  }
  }
  // Render an invisible Turnstile widget on demand and POST the token to /api/verify.
  // Resolves true only if the server accepted the token (session upgraded to human).
  // Called from api()'s 403 handler, so it fires solely for stepped-up sessions.
  function verifyTurnstile(sitekey) {
    return new Promise((resolve) => {
      let settled = false, box = null;
      const finish = (ok) => {
        if (settled) return; settled = true;
        if (box && box.parentNode) box.parentNode.removeChild(box);
        resolve(!!ok);
      };
      const render = () => {
        if (!window.turnstile) return finish(false);
        box = document.createElement('div');
        box.id = 'zx-turnstile';
        box.style.position = 'fixed'; box.style.bottom = '12px'; box.style.right = '12px'; box.style.zIndex = '2147483647';
        document.body.appendChild(box);
        try {
          window.turnstile.render(box, {
            sitekey, appearance: 'interaction-only',
            callback: (token) => {
              fetch('/api/verify', {
                method: 'POST', credentials: 'same-origin',
                headers: Object.assign({ 'content-type': 'application/json', 'X-ZX-Token': ZX_TOKEN || '' }, ZX_AUTO),
                body: JSON.stringify({ token }),
              })
                .then(r => (r.ok ? r.json().catch(() => null) : null))
                .then(j => finish(j && j.ok), () => finish(false));
            },
            'error-callback': () => finish(false),
            'timeout-callback': () => finish(false),
          });
        } catch (_) { finish(false); }
      };
      if (window.turnstile) return render();
      const sc = document.createElement('script');
      sc.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      sc.async = true; sc.defer = true;
      sc.onload = render; sc.onerror = () => finish(false);
      document.head.appendChild(sc);
      setTimeout(() => finish(false), 12000);
    });
  }
  ZXIcons.apply(document);
  setPlayIcons();
  setupSupport();
  initSession().then(route);
})();
