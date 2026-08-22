'use strict';
/**
 * lib/loklok.js — Node port of loklok_api.py (the signature-free Loklok client).
 *
 * Key facts (see ../LOKLOK_API_FINDINGS.md):
 *   - No request `sign` needed: the server only validates a signature if one is
 *     volunteered. We omit it entirely -> 00000.
 *   - Content/search endpoints need a Google-login JWT in the `token` header.
 *   - Responses with header `ecy: 1` carry `data` as base64 AES-192-ECB (PKCS5)
 *     ciphertext; key = base64decode(newVersionCode) from the public version/config
 *     endpoint. We fetch it lazily and decrypt in place.
 *   - `category` (0 vs 1 ...) is content-dependent; movie() auto-sweeps on B0300.
 *
 * Uses only Node built-ins: global fetch (Node >=18) + crypto + fs.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
// undici ships INSIDE Node (>=18) — this is a built-in, not a new dependency.
// ProxyAgent lets us route upstream calls through an outbound HTTP proxy. This is
// now only a FALLBACK: the search catalog is region-gated, but the primary fix is
// the device-reported `geo*` headers (see LoklokClient ctor) which claim a full-
// catalog country regardless of host — no proxy needed. LOKLOK_PROXY remains for
// the rare case a region ever starts enforcing by egress IP. See the region map in
// memory:loklok-search-region-locked.
let ProxyAgent = null;
try { ({ ProxyAgent } = require('undici')); } catch (_) { /* pre-18 Node: no proxy */ }

const DEFAULT_HOST = 'api.despseek.com';
const DEFAULT_DEVICE_ID = '9eb736c9875d4115';
// captured x-request-source (optional, never enforced) — reused verbatim for fidelity.
const DEFAULT_XRS = 'eCQjdnBnLAtCb2AlA2FdB2scO0FJQQ';

// Human labels for the server's quality tier codes.
const DEFINITION_LABELS = {
  GROOT_HD: '1080P',
  GROOT_SD: '720P',
  GROOT_LD: '540P',
  GROOT_FD: '360P',
};

/** Load a login JWT from $LOKLOK_TOKEN or the captured request dump. */
function loadToken() {
  if (process.env.LOKLOK_TOKEN) return process.env.LOKLOK_TOKEN;
  const candidates = [
    path.join(__dirname, '..', '..', 'capture', 'signed_reqs.json'),
    path.join(__dirname, '..', 'capture', 'signed_reqs.json'),
  ];
  for (const p of candidates) {
    try {
      const d = JSON.parse(fs.readFileSync(p, 'utf8'));
      for (const e of d) {
        for (const [k, v] of Object.entries(e.headers || {})) {
          if (k.toLowerCase() === 'token' && v) return v;
        }
      }
    } catch (_) { /* try next */ }
  }
  return null;
}

/** Decrypt an ecy:1 response body. AES-192-ECB, PKCS5, key = base64decode(newVersionCode). */
function decryptEcy(bodyB64, keyB64) {
  const ct = Buffer.from(bodyB64, 'base64');
  const key = Buffer.from(keyB64, 'base64'); // 24 bytes -> AES-192
  const d = crypto.createDecipheriv('aes-192-ecb', key, null);
  d.setAutoPadding(true); // strips PKCS#5/7
  const pt = Buffer.concat([d.update(ct), d.final()]);
  return pt.toString('utf8');
}

// ---- search relevance ------------------------------------------------------
// (Removed) Local re-rank/filter of search results. It dropped valid titles in
// regions where the API returns a different catalog, so search now surfaces the
// upstream results unmodified (see /api/search in server.js).

class LoklokClient {
  constructor(opts = {}) {
    this.host = opts.host || DEFAULT_HOST;
    this.deviceId = opts.deviceId || DEFAULT_DEVICE_ID;
    this.token = opts.token || null;
    this.xrs = opts.xrs || DEFAULT_XRS;
    this.versionCode = String(opts.versionCode || '236');
    this.clientType = opts.clientType || 'android_Official';
    this.userAgent = opts.userAgent || 'okhttp/4.12.0';
    this.lang = opts.lang || 'en';
    this.timezone = opts.timezone || 'GMT+01:00';
    // NOTE: the `mcc` header does NOT drive the content region — verified live:
    // every mcc value returns the same catalog. The region is geo-located from
    // the outbound IP (response header `um_event_country`). Exposed anyway.
    this.mcc = opts.mcc || process.env.LOKLOK_MCC || '603';
    // `keke` is ONE OF TWO search catalog gates (found 2026-08-22, decompiled
    // interceptor com.loklok.flash.android.net.o00oO0o line 291-295). keke='true'
    // returns the restricted/fuzzy catalog that HIDES Hollywood ("spider man" ->
    // Panda Man, The Other Man…); keke='false' returns the FULL catalog. It gates
    // ONLY searchContent — detail/playInfo are identical under either value.
    // SECOND gate = REGION. The catalog region is chosen from the DEVICE-reported
    // geolocation headers below when they're marked reliable; otherwise the server
    // falls back to geolocating the egress IP (response header `um_event_country`).
    // Only Arab (SA/AE/MA/DZ) and CIS (RU/UZ/BG) regions get the full Hollywood
    // catalog; US/EU/Asia get fuzzy junk. The `geo` headers let us CLAIM a full
    // catalog region regardless of where the server is hosted — see `this.geo`.
    this.keke = String(opts.keke != null ? opts.keke : (process.env.LOKLOK_KEKE || 'false'));
    // ── Device-reported geolocation = the request-level defeat of gate #2 ──────
    // The Android app attaches geoLatitude/geoLongitude/geoIsoCode/geoIsoName/
    // geoReliable, reporting the phone's GPS country. despseek's search catalog
    // gate TRUSTS these over the egress IP when geoReliable === '1'. So sending
    // geoIsoCode='SA' + geoReliable='1' makes a US/EU-hosted server look like it's
    // in Saudi Arabia (a full-catalog country) and returns the full Hollywood
    // catalog with NO proxy / Gulf VM — which is exactly how the app shows
    // Spider-Man worldwide. Verified 2026-08-22: the identical header set unlocked
    // the catalog through Mexican AND German egress proxies, and the response
    // um_event_country flipped from MX/DE to SA. CRITICAL: geoReliable must be the
    // literal '1' — the string 'true' is NOT honored (server treats it as unreliable
    // and falls back to the egress IP). geoIsoCode must be uppercase ('SA', not 'sa'),
    // and the full set is required (isoCode alone → junk). Defaults claim Saudi
    // Arabia (Riyadh); override via LOKLOK_GEO_* env. Set geoIsoCode='' to disable
    // the override and use pure egress-IP geolocation (the app's stale-GPS fallback).
    this.geo = {
      isoCode:   opts.geoIsoCode   != null ? opts.geoIsoCode   : (process.env.LOKLOK_GEO_ISO      != null ? process.env.LOKLOK_GEO_ISO  : 'SA'),
      isoName:   opts.geoIsoName   != null ? opts.geoIsoName   : (process.env.LOKLOK_GEO_NAME      || 'Saudi Arabia'),
      latitude:  opts.geoLatitude  != null ? opts.geoLatitude  : (process.env.LOKLOK_GEO_LAT       || '24.7136'),
      longitude: opts.geoLongitude != null ? opts.geoLongitude : (process.env.LOKLOK_GEO_LON       || '46.6753'),
      reliable:  opts.geoReliable  != null ? opts.geoReliable  : (process.env.LOKLOK_GEO_RELIABLE  || '1'),
    };
    this.ecyKey = opts.ecyKey || null;
    this.timeout = opts.timeout || 20000;
    // Optional outbound proxy (full-catalog egress). Value is a proxy URL, e.g.
    // http://user:pass@host:port. Only worth setting when the host country is NOT
    // in the full-catalog set (Arab/CIS) — see class-header note & LOKLOK_PROXY.
    this.proxy = opts.proxy != null ? opts.proxy : (process.env.LOKLOK_PROXY || null);
    this._dispatcher = null;
  }

  /** Lazily build the undici dispatcher that routes upstream calls through
   *  this.proxy. Returns null when no proxy is configured (direct egress). */
  _getDispatcher() {
    if (!this.proxy || !ProxyAgent) return null;
    if (!this._dispatcher) this._dispatcher = new ProxyAgent(this.proxy);
    return this._dispatcher;
  }

  _headers(withToken = true) {
    const h = {
      clienttype: this.clientType,
      versioncode: this.versionCode,
      deviceid: this.deviceId,
      lang: this.lang,
      timezone: this.timezone,
      mcc: this.mcc,
      keke: this.keke,
      vm: 'false',
      'x-request-source': this.xrs,
      currenttime: String(Date.now()),
      'user-agent': this.userAgent,
    };
    // Device-reported geolocation. When geoReliable==='1' the upstream uses this
    // (not the egress IP) to pick the search catalog region, so claiming a
    // full-catalog country here (default Saudi Arabia) unlocks the Hollywood
    // catalog from any host. isoName is URL-encoded to match the app. See ctor.
    if (this.geo && this.geo.isoCode) {
      h.geoLatitude = String(this.geo.latitude || '');
      h.geoLongitude = String(this.geo.longitude || '');
      h.geoIsoCode = String(this.geo.isoCode);
      h.geoIsoName = encodeURIComponent(String(this.geo.isoName || ''));
      h.geoReliable = String(this.geo.reliable != null ? this.geo.reliable : '1');
    }
    if (withToken && this.token) h.token = this.token;
    return h;
  }

  async _request(method, reqPath, { body = null, withToken = true } = {}) {
    const url = `https://${this.host}${reqPath}`;
    const headers = this._headers(withToken);
    let bodyData;
    if (body !== null && body !== undefined) {
      bodyData = (typeof body === 'string') ? body : JSON.stringify(body);
      headers['content-type'] = 'application/json;charset=UTF-8';
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeout);
    let resp, text, ecy, region;
    try {
      const fetchOpts = { method, headers, body: bodyData, signal: ctrl.signal };
      const disp = this._getDispatcher();
      if (disp) fetchOpts.dispatcher = disp; // route via full-catalog egress
      resp = await fetch(url, fetchOpts);
      ecy = resp.headers.get('ecy');
      region = resp.headers.get('um_event_country'); // IP-geolocated content region
      text = await resp.text();
    } finally {
      clearTimeout(timer);
    }
    let obj;
    try {
      obj = JSON.parse(text);
    } catch (_) {
      return { _status: resp.status, _region: region || null, _raw: text };
    }
    if (obj && typeof obj === 'object') {
      obj._status = resp.status;
      obj._region = region || null;
      if (String(ecy) === '1' && typeof obj.data === 'string' && obj.data) {
        try {
          const pt = decryptEcy(obj.data, await this._getEcyKey());
          try { obj.data = JSON.parse(pt); } catch (_) { obj.data = pt; }
          obj._ecy = true;
        } catch (e) {
          obj._ecy_error = String(e && e.message || e);
        }
      }
    }
    return obj;
  }

  async get(reqPath, params = null, withToken = true) {
    if (params) {
      const usp = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (v === null || v === undefined) continue;
        usp.append(k, String(v));
      }
      const qs = usp.toString();
      if (qs) reqPath += (reqPath.includes('?') ? '&' : '?') + qs;
    }
    return this._request('GET', reqPath, { withToken });
  }

  async post(reqPath, body = '', withToken = true) {
    return this._request('POST', reqPath, { body, withToken });
  }

  // ---- ecy response key ----------------------------------------------------
  async versionConfig() {
    return this.get('/official/config/version/info/get', null, false);
  }

  async _getEcyKey() {
    if (this.ecyKey) return this.ecyKey;
    const cfg = await this.versionConfig();
    const data = cfg && cfg.data;
    let key = null;
    if (data && typeof data === 'object') {
      key = data.newVersionCode || (data.updateInfo && data.updateInfo.newVersionCode);
    }
    if (!key) throw new Error('could not fetch ecy key (newVersionCode)');
    this.ecyKey = key;
    return key;
  }

  // ---- content -------------------------------------------------------------
  /** /official/movieDrama/get — detail. Auto-resolves category on B0300. */
  async movie(contentId, { category = 0, reliableDef = 0, autoCategory = true } = {}) {
    const fetchCat = async (cat) => {
      const r = await this.get('/official/movieDrama/get',
        { id: contentId, category: cat, reliableDef }, true);
      if (r && r.code === '00000') r._category = cat;
      return r;
    };
    let resp = await fetchCat(category);
    if (autoCategory && resp && resp.code === 'B0300') {
      for (const cat of [0, 1, 2, 3, 4]) {
        if (cat === category) continue;
        const r2 = await fetchCat(cat);
        if (r2 && r2.code === '00000') return r2;
      }
    }
    return resp;
  }

  /** Return (detail, workingCategory). */
  async _detailCategory(contentId, category = 0) {
    const detail = await this.movie(contentId, { category });
    const cat = (detail && detail._category !== undefined) ? detail._category : category;
    return { detail, cat };
  }

  /** /official/media/playInfo — playback info incl. HLS mediaUrl. Needs full param set. */
  async playInfo(contentId, { episodeId = null, category = 0, definition = 'GROOT_LD' } = {}) {
    // adComplete:'true' is the ad-gate the official app trips after playing a
    // rewarded ad — it's what unlocks the VIP GROOT_HD (1080P+) stream. The
    // upstream never verifies an ad was actually watched, so setting it here
    // serves those tiers free, matching the app's post-ad behavior. Without it
    // the server silently downgrades a GROOT_HD request to GROOT_SD (720P).
    const p = {
      category, contentId, definition,
      projection: 'false', adComplete: 'true', advanced: 'false',
      tryCode: 0, reliableDef: 0,
    };
    if (episodeId !== null && episodeId !== undefined) p.episodeId = episodeId;
    return this.get('/official/media/playInfo', p, true);
  }

  // ---- search / browse -----------------------------------------------------
  async search(keyword, { size = 24, page = 0, searchType = 'all' } = {}) {
    return this.post('/aggregation/search/v4/searchContent',
      { searchKeyWord: keyword, size, page, searchType }, true);
  }

  async browse({ params = '', crTagIds = [], area = '', category = '', year = '',
                 order = 'count', size = 24 } = {}) {
    return this.post('/official/search/v1/search',
      { size, params, crTagIds, area, category, year, order }, true);
  }

  async autocomplete(keyword, size = 12) {
    return this.post('/official/search/v3/searchLenovo',
      { size, searchKeyWord: keyword }, false);
  }

  async leaderboard(code = 'TOP_SEARCH', crTagIds = []) {
    return this.post('/official/search/v3/searchLeaderboard',
      { code, crTagIds }, false);
  }
}

module.exports = { LoklokClient, loadToken, decryptEcy, DEFINITION_LABELS,
                   DEFAULT_HOST, DEFAULT_DEVICE_ID };
