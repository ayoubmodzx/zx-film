'use strict';
/**
 * lib/security.js — dependency-free session & token primitives for ZX.
 *
 * Everything here uses only Node's built-in `crypto`. No cookie-parser, no
 * jsonwebtoken — this matches server.js's hand-rolled, dependency-free security
 * posture (no helmet either). Two things live here:
 *   - a signed session cookie (HMAC-SHA256) so /api/* can require that the
 *     caller first loaded the real page, and
 *   - a short-lived "page token" bound to that session (double-submit) that the
 *     SPA echoes in an X-ZX-Token header — a raw scraper that only harvested the
 *     cookie still can't call the JSON API.
 *
 * The server secret comes from $ZX_SECRET. If it's unset we generate a random
 * one per boot (EPHEMERAL=true) so the site still works, but every restart then
 * invalidates live cookies/tokens — set ZX_SECRET in production.
 */
const crypto = require('crypto');

let SECRET = process.env.ZX_SECRET || '';
let EPHEMERAL = false;
if (!SECRET) { SECRET = crypto.randomBytes(32).toString('hex'); EPHEMERAL = true; }

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  return Buffer.from(String(str).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}
function hmac(data) {
  return b64url(crypto.createHmac('sha256', SECRET).update(String(data)).digest());
}
// constant-time string compare (avoids leaking sig via timing)
function safeEq(a, b) {
  const A = Buffer.from(String(a)); const B = Buffer.from(String(b));
  if (A.length !== B.length) return false;
  try { return crypto.timingSafeEqual(A, B); } catch (_) { return false; }
}

// ---- signed value: "<value>.<sig>" ----
function sign(value) { return value + '.' + hmac(value); }
function unsign(signed) {
  if (typeof signed !== 'string') return null;
  const i = signed.lastIndexOf('.');
  if (i <= 0) return null;
  const value = signed.slice(0, i), sig = signed.slice(i + 1);
  return safeEq(sig, hmac(value)) ? value : null;
}

function newSid() { return crypto.randomBytes(18).toString('hex'); }

// ---- minimal cookie parse / serialize ----
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    if (k) { try { out[k] = decodeURIComponent(part.slice(idx + 1).trim()); } catch (_) { out[k] = part.slice(idx + 1).trim(); } }
  }
  return out;
}
function serializeCookie(name, value, opts = {}) {
  let s = `${name}=${encodeURIComponent(value)}`;
  if (opts.maxAge != null) s += `; Max-Age=${Math.floor(opts.maxAge)}`;
  s += `; Path=${opts.path || '/'}`;
  if (opts.httpOnly) s += '; HttpOnly';
  if (opts.secure) s += '; Secure';
  s += `; SameSite=${opts.sameSite || 'Strict'}`;
  return s;
}

// Short, stable fingerprint of the client's User-Agent. Tokens are bound to it so
// a token lifted out of a real browser can't be replayed by a client presenting a
// different UA. It's HMAC'd (not raw) so the token never discloses the UA, and
// truncated to keep the token small. Not a wall — a scraper can copy the UA too —
// but it removes the "grabbed cookie+token, replayed from curl" shortcut.
function uaKey(req) {
  const ua = String((req && req.headers && req.headers['user-agent']) || '');
  return hmac('ua|' + ua).slice(0, 16);
}

// ---- page token (double-submit), bound to sid + UA, short-lived ----
function issuePageToken(sid, ttlMs, uaHash) {
  const payload = b64url(JSON.stringify({
    s: sid, u: uaHash || '', e: Date.now() + (ttlMs || 10 * 60 * 1000),
  }));
  return sign(payload);
}
function verifyPageToken(token, sid, uaHash) {
  const payload = unsign(token);
  if (!payload) return false;
  let obj;
  try { obj = JSON.parse(b64urlDecode(payload).toString('utf8')); } catch (_) { return false; }
  if (!obj || obj.s !== sid || !obj.e || Date.now() > obj.e) return false;
  if ((obj.u || '') !== (uaHash || '')) return false;
  return true;
}

// ---- proof-of-work verification ----
// The SPA must find a nonce such that sha256(challenge + ':' + nonce) has at least
// `bits` leading zero bits. Verifying is one cheap hash; solving costs the client
// ~2^bits hashes. The real point isn't the CPU cost — it's that a plain HTTP client
// (requests / axios-cookiejar / node-fetch) never runs our page JS, so it can't
// solve this and thus never earns a page token. A real browser (or Puppeteer)
// solves it transparently on load.
function powOk(challenge, nonce, bits) {
  const dig = crypto.createHash('sha256').update(String(challenge) + ':' + String(nonce)).digest('hex');
  let n = 0;
  for (let i = 0; i < dig.length; i++) {
    const v = parseInt(dig[i], 16);
    if (v === 0) { n += 4; continue; }
    n += Math.clz32(v) - 28; // leading zero bits within this nibble
    break;
  }
  return n >= bits;
}

module.exports = {
  EPHEMERAL, sign, unsign, newSid, hmac, safeEq, uaKey, powOk,
  parseCookies, serializeCookie, issuePageToken, verifyPageToken,
};
