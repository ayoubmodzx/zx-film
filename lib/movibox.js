'use strict';
/**
 * lib/movibox.js — Movi / aoneroom (Transsion "wefeed" BFF) client, as a module.
 *
 * Adapted from the standalone movibox.js CLI into a reusable library so the ZX
 * server can expose MovieBox ("ZX 2") alongside Loklok ("ZX 1"). Keeps the whole
 * signing scheme, the DNS-over-HTTPS routing, and — importantly — the self-healing
 * auth: it logs into a stored account, renews the token forever, and if that fails
 * (or none exists) provisions a throwaway mailbox and REGISTERS a fresh account so
 * search keeps working. Auto-account creation is deliberately kept (disable only
 * with MOVI_AUTO_ACCOUNT=0).
 *
 *   Signature : HMAC-MD5, key = base64Decode(gateway_secret_online), out base64
 *   Header    : x-tr-signature: <timestampMs>|2|<base64 sig>
 *
 * Most endpoints (tab-operating-page browse, subject get, resource, play-info,
 * season-info, stream captions) answer with just a valid signature — no token.
 * Only keyword search needs an account token, which self-heals on 401/441.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const https = require('https');
const dns = require('dns');

// ---- constants pulled from the APK ----------------------------------------
const SECRET_ONLINE = '76iRl07s0xSN9jqmEWAt79EBJZulIQIsV64FZr2O'; // gateway_secret_online
const KEY_VERSION = 2;
const HOST = process.env.MOVI_HOST || 'api6.aoneroom.com';
const BASE = `https://${HOST}`;
// Keep the token beside the Loklok account.json (data/), not in lib/.
const TOKEN_FILE = process.env.MOVI_TOKEN_FILE || path.join(__dirname, '..', 'data', 'movibox.token.json');

const MAIL_API = (process.env.MOVI_MAIL_API || 'https://api.mail.tm').replace(/\/+$/, '');
const AUTO_ACCOUNT = process.env.MOVI_AUTO_ACCOUNT !== '0';
const OTP_TIMEOUT_MS = Number(process.env.MOVI_OTP_TIMEOUT_MS || 120000);
const DEBUG = process.env.MOVI_DEBUG === '1';

// ---- DNS-over-HTTPS -------------------------------------------------------
const USE_DOH = process.env.MOVI_DOH !== '0';
const DOH_URL = process.env.MOVI_DOH_URL || 'https://1.1.1.1/dns-query';
const _dohCache = new Map();

async function resolveDoH(host) {
  if (_dohCache.has(host)) return _dohCache.get(host);
  const url = DOH_URL + (DOH_URL.includes('?') ? '&' : '?') + 'name=' + encodeURIComponent(host) + '&type=A';
  const r = await fetch(url, { headers: { accept: 'application/dns-json' } });
  if (!r.ok) throw new Error('DoH HTTP ' + r.status);
  const j = await r.json();
  const ips = ((j && j.Answer) || []).filter(a => a.type === 1 && a.data).map(a => a.data);
  if (!ips.length) throw new Error('DoH: no A record for ' + host);
  _dohCache.set(host, ips);
  return ips;
}

function dohLookup(hostname, options, callback) {
  const cb = typeof options === 'function' ? options : callback;
  const opts = (typeof options === 'function' ? {} : options) || {};
  resolveDoH(hostname)
    .then(ips => opts.all ? cb(null, ips.map(address => ({ address, family: 4 }))) : cb(null, ips[0], 4))
    .catch(() => dns.lookup(hostname, opts, cb));
}

function httpsFetch(urlStr, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const outHeaders = { ...headers, 'accept-encoding': 'identity' };
    if (body != null) outHeaders['content-length'] = Buffer.byteLength(body);
    const req = https.request({
      hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, method,
      headers: outHeaders,
      servername: u.hostname,
      lookup: USE_DOH ? dohLookup : undefined,
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, ok: res.statusCode >= 200 && res.statusCode < 300, text: async () => text });
      });
    });
    req.on('error', reject);
    req.setTimeout(25000, () => req.destroy(new Error('request timeout')));
    if (body != null) req.write(body);
    req.end();
  });
}

const CLIENT_INFO = {
  package_name: 'com.community.oneroom',
  version_name: '4.0.02.0831.99',
  version_code: 500201999,
  os: 'android',
  os_version: '11',
  install_ch: 'ps',
  device_id: '588c8f4e53b1dfefbba45c345088bd84',
  install_store: 'ps',
  gaid: '9c67cf9514858c93',
  brand: 'OnePlus',
  model: 'GM1910',
  system_language: 'en',
  net: 'NETWORK_WIFI',
  region: 'US',
  timezone: 'Africa/Algiers',
  sp_code: '60303',
};
const USER_AGENT =
  'com.community.oneroom/500201999 (Linux; U; Android 11; en_US; GM1910; Build/RKQ1.201022.002; Cronet/151.0.7922.83)';

// Premium ("PM") unlock. The cracked/premium MovieBox app advertises its premium
// status on every request — both as standalone headers and mirrored inside
// x-client-info — and the BFF then returns the real signed CDN links instead of
// the ~20s "update your app" promo it serves plain clients. The x-tr-signature
// does NOT cover request headers, so adding these is transparent to signing.
// X-Client-Build is a constant build fingerprint captured from the premium app.
const PM_ACTIVE = process.env.MOVI_PM_ACTIVE || 'true';
const PM_LEVEL = process.env.MOVI_PM_LEVEL || '2';
const CLIENT_BUILD = process.env.MOVI_CLIENT_BUILD ||
  '1789508696282966774.b5d356766a798296c21ff78d459ab2a9-1789508591176005821.27c0a4b4f8642780cc5f55d2ec6abf81';

// ---- signature core -------------------------------------------------------
const md5hex = (s) => crypto.createHash('md5').update(s, 'utf8').digest('hex');

function canonicalPathQuery(fullUrl) {
  const u = new URL(fullUrl);
  let out = u.pathname;
  if (u.search && u.search.length > 1) {
    const map = new Map();
    for (const pair of u.search.slice(1).split('&')) {
      if (!pair) continue;
      const i = pair.indexOf('=');
      const k = decodeURIComponent(i < 0 ? pair : pair.slice(0, i));
      const v = i < 0 ? '' : decodeURIComponent(pair.slice(i + 1));
      map.set(k, v);
    }
    const parts = [];
    for (const k of [...map.keys()].sort()) {
      if (k === '') continue;
      parts.push(`${k}=${map.get(k)}`);
    }
    if (parts.length) out += '?' + parts.join('&');
  }
  return out;
}

function sign(method, fullUrl, body = '', contentType = '', opts = {}) {
  const ts = opts.timestamp != null ? String(opts.timestamp) : String(Date.now());
  const hasBody = body != null && body.length > 0;
  const contentLen = hasBody ? String(body.length) : '';
  const bodyMd5 = hasBody ? md5hex(body.length > 102400 ? body.slice(0, 102400) : body) : '';
  const stringToSign = [
    method.toUpperCase(), '', contentType || '', contentLen, ts, bodyMd5, canonicalPathQuery(fullUrl),
  ].join('\n');
  const key = Buffer.from(SECRET_ONLINE, 'base64');
  const mac = crypto.createHmac('md5', key).update(stringToSign, 'utf8').digest('base64');
  return { header: `${ts}|${KEY_VERSION}|${mac}`, stringToSign, ts, sig: mac };
}

// ---- token storage / helpers ----------------------------------------------
function loadStore() {
  try { return JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8')) || {}; } catch { return {}; }
}
function loadToken() {
  if (process.env.MOVI_TOKEN) return process.env.MOVI_TOKEN;
  return loadStore().token || null;
}
function saveToken(token, extra = {}) {
  const prev = loadStore();
  try {
    fs.mkdirSync(path.dirname(TOKEN_FILE), { recursive: true });
    fs.writeFileSync(TOKEN_FILE, JSON.stringify({ ...prev, ...extra, token, savedAt: Date.now() }, null, 2));
  } catch {}
}
function loadCreds() {
  if (process.env.MOVI_EMAIL && process.env.MOVI_PASSWORD)
    return { email: process.env.MOVI_EMAIL, password: process.env.MOVI_PASSWORD, source: 'env' };
  const s = loadStore();
  if (s.email && s.password) return { email: s.email, password: s.password, source: 'cache' };
  return null;
}
function decodeJwt(token) {
  try {
    const p = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(p, 'base64').toString('utf8'));
  } catch { return null; }
}
function tokenExpired(token) {
  const p = decodeJwt(token);
  return !p || (p.exp && p.exp * 1000 < Date.now() + 60_000);
}

// ---- HTTP helper (token-aware, auto-refresh) ------------------------------
// Build the x-client-info header for a given device identity, always mirroring
// the premium (PM) flags the app appends — this is part of what unlocks real
// content (see PM_ACTIVE/CLIENT_BUILD above).
function clientInfoHeader(deviceId, gaid) {
  const base = deviceId
    ? { ...CLIENT_INFO, device_id: deviceId, gaid: gaid || deviceId.slice(0, 16) }
    : { ...CLIENT_INFO };
  return JSON.stringify({
    ...base,
    'X-Child-UID': '',
    'X-PM-Active': PM_ACTIVE,
    'X-Client-Build': CLIENT_BUILD,
    'X-PM-Level': PM_LEVEL,
    'X-Play-Mode': '2',
    'X-Idle-Data': '1',
    'X-Family-Mode': '0',
    'X-Content-Mode': '0',
  });
}
// The device identity MUST stay consistent between the account that was
// registered and every content request made with its token — the real app uses
// one fixed device_id for everything. Mixing devices makes MovieBox treat the
// session as suspect and serve a ~20s "update your app" promo instead of the
// film. So each auto-created account gets ONE random device_id (registration
// burns a per-device OTP quota, hence per-account and not global), and we persist
// it and reuse it for all its calls.
function activeDevice() {
  const s = loadStore();
  if (s.device) return { deviceId: s.device, gaid: s.gaid || s.device.slice(0, 16) };
  return null;
}

async function api(method, apiPath, { query, body, token, noRetry, deviceId, gaid } = {}) {
  if (!deviceId) { const d = activeDevice(); if (d) { deviceId = d.deviceId; gaid = gaid || d.gaid; } }
  const url = new URL(BASE + apiPath);
  if (query) for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
  }
  const bodyStr = body != null ? JSON.stringify(body) : '';
  const contentType = body != null ? 'application/json; charset=utf-8' : '';
  const s = sign(method, url.toString(), bodyStr, contentType);

  const headers = {
    'x-tr-signature': s.header,
    'x-client-info': clientInfoHeader(deviceId, gaid),
    'x-client-status': '1',
    'x-play-mode': '2',
    'x-content-mode': '0',
    'x-family-mode': '0',
    'x-idle-data': '1',
    // Premium flags as standalone headers too (the app sends both forms).
    'x-child-uid': '',
    'x-pm-active': PM_ACTIVE,
    'x-pm-level': PM_LEVEL,
    'x-client-build': CLIENT_BUILD,
    'user-agent': USER_AGENT,
  };
  if (body != null) headers['content-type'] = contentType;
  if (token) headers['authorization'] = `Bearer ${token}`;

  let res;
  for (let attempt = 1; ; attempt++) {
    try {
      res = await httpsFetch(url.toString(), { method, headers, body: body != null ? bodyStr : undefined });
      break;
    } catch (e) {
      if (attempt >= 3) throw e;
      _dohCache.delete(HOST);
      if (DEBUG) console.error(`[mb net] ${apiPath} ${e.message} — retry ${attempt}/2`);
    }
  }
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = null; }

  const tokenIssue = res.status === 401 || (json && (json.code === 441 || json.code === 401));
  if (tokenIssue && !noRetry && (loadCreds() || AUTO_ACCOUNT)) {
    const fresh = await refreshToken({ reason: `token rejected (${(json && json.code) || res.status})` });
    if (fresh) return api(method, apiPath, { query, body, token: fresh, noRetry: true });
  }
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${apiPath}\n${text.slice(0, 300)}`);
  if (json && json.code !== 0 && json.code !== undefined)
    throw new Error(`API code ${json.code}: ${json.message || ''} (${apiPath})`);
  return json ?? text;
}

function canAutoLogin() { return !!loadCreds(); }

async function ensureToken() {
  const t = loadToken();
  if (t && !tokenExpired(t)) return t;
  if (canAutoLogin() || AUTO_ACCOUNT) return refreshToken({ reason: t ? 'token expired' : 'no token' });
  return t;
}

// ---- auth: login to a stored account --------------------------------------
async function login(email, password) {
  if (!email || !password) throw new Error('login needs email + password');
  const body = { mail: email, password: md5hex(password), authType: 1 };
  const r = await api('POST', '/wefeed-mobile-bff/user-api/login', { body, noRetry: true });
  const token = r && r.data && r.data.token;
  if (!token) throw new Error('login: no token in response');
  saveToken(token, { userId: r.data.userId, email });
  return token;
}

// ---- throwaway mailbox (mail.tm) — kept so auth self-heals -----------------
async function mail(pathname, opts = {}) {
  const res = await fetch(MAIL_API + pathname, {
    ...opts,
    headers: { 'content-type': 'application/json', accept: 'application/json', ...(opts.headers || {}) },
  });
  const text = await res.text();
  let body; try { body = JSON.parse(text); } catch { body = text; }
  return { status: res.status, body };
}
function mailList(body) {
  if (Array.isArray(body)) return body;
  return (body && (body['hydra:member'] || body.member)) || [];
}
async function newMailbox() {
  const dom = await mail('/domains');
  const members = mailList(dom.body).filter(d => d.isActive !== false);
  const domain = members[0] && members[0].domain;
  if (!domain) throw new Error('mail provider: no domain available');
  const address = 'mv' + crypto.randomBytes(5).toString('hex') + '@' + domain;
  const mailPass = 'Mp!' + crypto.randomBytes(6).toString('hex');
  const acc = await mail('/accounts', { method: 'POST', body: JSON.stringify({ address, password: mailPass }) });
  if (acc.status !== 201) throw new Error('mail provider: account create failed (' + acc.status + ')');
  const tok = await mail('/token', { method: 'POST', body: JSON.stringify({ address, password: mailPass }) });
  if (!tok.body || !tok.body.token) throw new Error('mail provider: token failed (' + tok.status + ')');
  return { address, token: tok.body.token };
}
async function waitForOtp(mailToken, { timeoutMs = OTP_TIMEOUT_MS, intervalMs = 3000, log = () => {} } = {}) {
  const deadline = Date.now() + timeoutMs;
  const auth = { authorization: 'Bearer ' + mailToken };
  while (Date.now() < deadline) {
    const list = await mail('/messages', { headers: auth });
    const items = mailList(list.body);
    for (const m of items) {
      const full = await mail('/messages/' + m.id, { headers: auth });
      const bodyText = [full.body && full.body.text, full.body && full.body.html, m.intro, m.subject]
        .flat().filter(Boolean).join(' \n ');
      const hit = bodyText.match(/(?:verification|code|otp|pin)[^0-9]{0,20}([0-9]{4,6})/i)
        || bodyText.match(/\b([0-9]{6})\b/)
        || bodyText.match(/\b([0-9]{4,6})\b/);
      if (hit) return hit[1];
    }
    await new Promise(r => setTimeout(r, intervalMs));
  }
  throw new Error('OTP did not arrive within ' + Math.round(timeoutMs / 1000) + 's');
}
function genPassword() {
  return 'Mv' + crypto.randomBytes(9).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 10) + '9';
}
async function createAccount({ log = () => {} } = {}) {
  const { address, token: mailToken } = await newMailbox();
  const password = genPassword();
  // Fresh device identity for THIS sign-up so the per-device OTP quota resets.
  const device = crypto.randomBytes(16).toString('hex');
  const gaid = crypto.randomBytes(8).toString('hex');
  const dev = { deviceId: device, gaid, noRetry: true };
  log('mailbox ' + address);
  await api('POST', '/wefeed-mobile-bff/user-api/check-mail-account', { body: { mail: address }, ...dev }).catch(() => {});
  const sent = await api('POST', '/wefeed-mobile-bff/user-api/get-sms-code',
    { body: { mail: address, type: 1, authType: 1 }, ...dev });
  if (sent && sent.code !== 0) throw new Error('get-sms-code failed (' + sent.code + ')');
  log('OTP requested; waiting for email…');
  const code = await waitForOtp(mailToken, { log });
  log('OTP ' + code);
  await api('POST', '/wefeed-mobile-bff/user-api/check-sms-code',
    { body: { authType: 1, mail: address, type: 1, verificationCode: code }, ...dev }).catch(() => {});
  const r = await api('POST', '/wefeed-mobile-bff/user-api/register', {
    body: { mail: address, verificationCode: code, password: md5hex(password), inviteCode: '', authType: 1 },
    ...dev,
  });
  const token = r && r.data && r.data.token;
  if (!token) throw new Error('register returned no token');
  // Persist the SAME device used to register so every later content request
  // presents the identical device_id (otherwise MovieBox serves the promo clip).
  saveToken(token, { email: address, password, userId: r.data.userId, device, gaid });
  log('registered userId ' + r.data.userId);
  return { email: address, password, token, userId: r.data.userId };
}

// coalesce concurrent refreshes so parallel calls don't each mint a new account
let _refreshing = null;
// After a failed recovery, back off before trying again — otherwise a burst of
// token-less calls (a home load fires several) would each kick off a new account
// registration and blow through the OTP quota. During the cooldown, callers get
// whatever cached token exists (possibly null) and fail gracefully.
let _lastFail = 0;
const RECOVER_COOLDOWN_MS = Number(process.env.MOVI_RECOVER_COOLDOWN_MS || 45000);
function refreshToken({ reason = '' } = {}) {
  if (_refreshing) return _refreshing;
  if (Date.now() - _lastFail < RECOVER_COOLDOWN_MS) return Promise.resolve(loadToken());
  _refreshing = (async () => {
    if (reason) console.error(`[mb] auth: ${reason} — recovering…`);
    const creds = loadCreds();
    if (creds) {
      try {
        const tok = await login(creds.email, creds.password);
        console.error(`[mb] auth: re-logged in (${creds.source} creds)`);
        return tok;
      } catch (e) {
        console.error('[mb] auth: login failed (' + e.message.split('\n')[0] + ')');
        if (!AUTO_ACCOUNT) { _lastFail = Date.now(); throw e; }
      }
    }
    if (!AUTO_ACCOUNT) return null;
    try {
      const acc = await createAccount({ log: (m) => console.error('  [mb new account] ' + m) });
      console.error(`[mb] auth: new account ready (${acc.email})`);
      return acc.token;
    } catch (e) {
      _lastFail = Date.now();
      console.error('[mb] auth: account creation failed (' + e.message.split('\n')[0] + ') — backing off ' + Math.round(RECOVER_COOLDOWN_MS / 1000) + 's');
      return loadToken(); // may be null; callers handle it
    }
  })().finally(() => { _refreshing = null; });
  return _refreshing;
}

// ---- endpoints ------------------------------------------------------------
// Home / browse: the app's operating page (curated rows). Signature-only.
async function tabOperatingPage({ tabId = 0, pageNum = 1, pageSize = 8 } = {}) {
  const r = await api('GET', '/wefeed-mobile-bff/tab-operating-page', {
    query: { pageNum, pageSize, tabId }, token: loadToken() || undefined,
  });
  return r.data;
}

// Keyword search — the one endpoint that needs a token (self-heals).
async function search(keyword, { page = 1, perPage = 20, tabId } = {}) { // perPage max 20 upstream
  const body = { page, perPage, keyword };
  if (tabId) body.tabId = tabId;
  const token = await ensureToken();
  const r = await api('POST', '/wefeed-mobile-bff/subject-api/search/v2', { body, token });
  return r.data;
}

// Subject detail (title, cover, cast, genre, embedded resource links). Signature-only.
async function subjectGet(subjectId, { se = 0 } = {}) {
  const r = await api('GET', '/wefeed-mobile-bff/subject-api/get', {
    query: { subjectId, se }, token: loadToken() || undefined,
  });
  return r.data;
}

// Seasons + episode counts (for series). Signature-only.
async function seasonInfo(subjectId) {
  const r = await api('GET', '/wefeed-mobile-bff/subject-api/season-info/v2', {
    query: { subjectId, isVip: false }, token: loadToken() || undefined,
  });
  return r.data;
}

// Direct .mp4 resource links per resolution. Signature-only.
// The app always requests positions starting at 1 (se=1, startPosition=1) — even
// for a movie, whose season-info reports se=0. Requesting se=0/ep=0 here returns
// the promo/preview instead of the film, so callers pass se>=1, ep>=1.
async function resources(subjectId, { se = 1, ep = 1, page = 1, perPage = 10 } = {}) {
  const r = await api('GET', '/wefeed-mobile-bff/subject-api/resource/v2', {
    query: { subjectId, page, perPage, all: 0, startPosition: ep, endPosition: ep,
             pagerMode: 0, resolution: 0, se, epFrom: ep, epTo: ep, isVip: false },
    token: loadToken() || undefined,
  });
  return r.data;
}

// Adaptive stream info (DASH .mpd + streamId + duration). Used only for the
// streamId that unlocks subtitles. Signature-only.
async function playInfo(subjectId, { se = 0, ep = 0 } = {}) {
  const r = await api('GET', '/wefeed-mobile-bff/subject-api/play-info/v2', {
    query: { subjectId, se, ep, isVip: false }, token: loadToken() || undefined,
  });
  return r.data;
}

// Subtitles for a given stream (CloudFront-signed .srt urls). Signature-only.
async function streamCaptions(subjectId, streamId) {
  const r = await api('GET', '/wefeed-mobile-bff/subject-api/get-stream-captions', {
    query: { subjectId, streamId }, token: loadToken() || undefined,
  });
  return r.data;
}

/** flatten a search/browse response -> [{subjectId, title, cover, ...}] */
function extractSubjects(data) {
  const out = [], seen = new Set();
  const walk = (node) => {
    if (Array.isArray(node)) return node.forEach(walk);
    if (node && typeof node === 'object') {
      const id = node.subjectId || (node.subject && node.subject.subjectId);
      if (id && !seen.has(id)) {
        seen.add(id);
        const s = node.subject || node;
        out.push({
          subjectId: id,
          title: s.title || s.subjectTitle || node.title || '',
          subjectType: s.subjectType,
          genre: s.genre,
          releaseDate: s.releaseDate,
          imdb: s.imdbRatingValue || s.imdbRate || null,
          cover: (s.cover && s.cover.url) || '',
          country: s.countryName || '',
        });
      }
      for (const v of Object.values(node)) walk(v);
    }
  };
  walk(data);
  return out;
}

module.exports = {
  BASE, HOST,
  tabOperatingPage, search, subjectGet, seasonInfo, resources, playInfo, streamCaptions,
  extractSubjects, ensureToken, loadToken, decodeJwt,
};
