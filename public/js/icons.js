'use strict';
window.ZXIcons = (function () {
  const S = (inner, extra) =>
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9"
      stroke-linecap="round" stroke-linejoin="round" ${extra || ''}>${inner}</svg>`;
  const ICONS = {
    search: S('<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>'),
    close:  S('<path d="M6 6l12 12M18 6L6 18"/>'),
    home:   S('<path d="M3 11l9-8 9 8"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>'),
    play:   S('<path d="M8 5.5v13l11-6.5z" fill="currentColor" stroke="none"/>'),
    pause:  S('<rect x="7" y="5" width="3.4" height="14" rx="1.1" fill="currentColor" stroke="none"/><rect x="13.6" y="5" width="3.4" height="14" rx="1.1" fill="currentColor" stroke="none"/>'),
    back:   S('<path d="M15 5l-7 7 7 7"/>'),
    cc:     S('<rect x="3" y="5" width="18" height="14" rx="3"/><path d="M9.5 10.2a2.4 2.4 0 100 3.6M15.5 10.2a2.4 2.4 0 100 3.6"/>'),
    quality: S('<path d="M5 6h14M5 12h14M5 18h9"/><circle cx="16.5" cy="18" r="2.2" fill="currentColor" stroke="none"/>'),
    volume: S('<path d="M4 9v6h4l5 4V5L8 9z" fill="currentColor" stroke="none"/><path d="M16.5 8.5a5 5 0 010 7M19 6a8.5 8.5 0 010 12"/>'),
    mute:   S('<path d="M4 9v6h4l5 4V5L8 9z" fill="currentColor" stroke="none"/><path d="M16 9l5 6M21 9l-5 6"/>'),
    fullscreen: S('<path d="M4 9V5a1 1 0 011-1h4M20 9V5a1 1 0 00-1-1h-4M4 15v4a1 1 0 001 1h4M20 15v4a1 1 0 01-1 1h-4"/>'),
    exitfull:   S('<path d="M9 4v3a2 2 0 01-2 2H4M15 4v3a2 2 0 002 2h3M9 20v-3a2 2 0 00-2-2H4M15 20v-3a2 2 0 012-2h3"/>'),
    star:   S('<path d="M12 3.6l2.5 5.2 5.7.8-4.1 4 1 5.7L12 16.9 6.9 19.4l1-5.7-4.1-4 5.7-.8z" fill="currentColor" stroke="none"/>'),
    film:   S('<rect x="3" y="4" width="18" height="16" rx="2.5"/><path d="M8 4v16M16 4v16M3 9h5M16 9h5M3 15h5M16 15h5"/>'),
    tv:     S('<rect x="3" y="6" width="18" height="12" rx="2.5"/><path d="M8 21h8M12 6V3"/>'),
    calendar: S('<rect x="3.5" y="5" width="17" height="16" rx="2.5"/><path d="M3.5 10h17M8 3v4M16 3v4"/>'),
    layers: S('<path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/>'),
    globe:  S('<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>'),
    sparkle: S('<path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z" fill="currentColor" stroke="none"/>'),
    chevronR: S('<path d="M9 6l6 6-6 6"/>'),
    chevronL: S('<path d="M15 6l-6 6 6 6"/>'),
    check:  S('<path d="M5 12.5l4.5 4.5L19 7"/>'),
    warn:   S('<path d="M12 3l9.5 16.5H2.5z"/><path d="M12 10v4.5M12 17.5v.01"/>'),
    moon:   S('<path d="M21 12.8A8.6 8.6 0 1111.2 3 6.7 6.7 0 0021 12.8z" fill="currentColor" stroke="none"/>'),
    sun:    S('<circle cx="12" cy="12" r="4.1" fill="currentColor" stroke="none"/><path d="M12 2.4v2.6M12 19v2.6M4.5 4.5l1.9 1.9M17.6 17.6l1.9 1.9M2.4 12H5M19 12h2.6M4.5 19.5l1.9-1.9M17.6 6.4l1.9-1.9"/>'),
    heart:  S('<path d="M12 20.3l-1.45-1.32C5.4 14.24 2 11.16 2 7.5 2 4.42 4.42 2 7.5 2c1.74 0 3.41.81 4.5 2.09C13.09 2.81 14.76 2 16.5 2 19.58 2 22 4.42 22 7.5c0 3.66-3.4 6.74-8.55 11.48z" fill="currentColor" stroke="none"/>'),
    copy:   S('<rect x="9" y="9" width="12" height="12" rx="2.4"/><path d="M6 15a2 2 0 01-2-2V5a2 2 0 012-2h8a2 2 0 012 2"/>'),
    wallet: S('<rect x="3" y="6.5" width="18" height="13" rx="2.6"/><path d="M3 10.5h18"/><circle cx="16.5" cy="15" r="1.3" fill="currentColor" stroke="none"/>'),
    binance: S('<path d="M12 3.2l2.4 2.4L12 8 9.6 5.6 12 3.2zM5.6 9.6L8 12l-2.4 2.4L3.2 12l2.4-2.4zM18.4 9.6L20.8 12l-2.4 2.4L16 12l2.4-2.4zM12 16l2.4 2.4L12 20.8l-2.4-2.4L12 16z" fill="currentColor" stroke="none"/>'),
  };
  function apply(root) {
    (root || document).querySelectorAll('[data-ico]').forEach(el => {
      const name = el.getAttribute('data-ico');
      if (ICONS[name] && !el.__ico) { el.innerHTML = ICONS[name]; el.__ico = name; }
    });
  }
  return { get: n => ICONS[n] || '', apply };
})();
