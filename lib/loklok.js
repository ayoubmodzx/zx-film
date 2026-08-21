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
    this.ecyKey = opts.ecyKey || null;
    this.timeout = opts.timeout || 20000;
  }

  _headers(withToken = true) {
    const h = {
      clienttype: this.clientType,
      versioncode: this.versionCode,
      deviceid: this.deviceId,
      lang: this.lang,
      timezone: this.timezone,
      mcc: this.mcc,
      keke: 'true',
      vm: 'false',
      'x-request-source': this.xrs,
      currenttime: String(Date.now()),
      'user-agent': this.userAgent,
    };
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
      resp = await fetch(url, { method, headers, body: bodyData, signal: ctrl.signal });
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
