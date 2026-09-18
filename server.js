'use strict';
/**
 * server.js — ZX streaming site backend.
 *
 * Ports the Python client's role: talks to the Loklok API (signature-free,
 * captured token, ecy AES decrypt, auto-category) and exposes clean JSON to the
 * browser, plus an SRT->VTT subtitle proxy so HTML5 <track> can render them.
 *
 *   GET /api/home                 -> curated sections (movies / series)
 *   GET /api/search?q=            -> normalized result cards
 *   GET /api/title/:id?category=  -> detail + episodes
 *   GET /api/play?contentId&episodeId&definition&category -> mediaUrl + qualities + subtitles
 *   GET /api/sub?t=<opaque handle>  -> WEBVTT (converted, CORS-open)
 */
const path = require('path');
const { Readable } = require('stream');
const express = require('express');
const { LoklokClient, loadToken, DEFINITION_LABELS } = require('./lib/loklok');
const { TokenManager } = require('./lib/auth');
const sec = require('./lib/security');
const mb = require('./lib/movibox'); // MovieBox ("ZX 2") content source

const PORT = process.env.PORT || 7817;

// ---- anti-scrape / anti-clone config --------------------------------------
// The whole point of the session/token/pattern machinery below is that /api/*
// must only be reachable from someone who actually loaded the real page — a
// competing site, a movie bot, or a curl/requests scraper should not be able to
// consume the JSON API. Everything here is free and dependency-free (crypto +
// Cloudflare's free tier out in front). See lib/security.js.
const SITE_HOST = (process.env.ZX_SITE_HOST || '').toLowerCase(); // e.g. "zx.example.com" (empty => derive from Host)
// The Turnstile SITE key is PUBLIC — it ships inside the client JS, so it's safe to
// hardcode. The SECRET key is normally kept out of source; it's hardcoded here at the
// owner's explicit request so the widget works without any host-side env config. If
// this repo is ever made public, ROTATE the secret in the Cloudflare dashboard and
// move it back to the ZX_TURNSTILE_SECRET env var — anyone with it can forge a pass.
// Either value can still be overridden by an env var without touching code.
const TS_SITEKEY_DEFAULT = '0x4AAAAAAEZdWAFIumYg0rqM';
const TS_SECRET_DEFAULT = '0x4AAAAAAEZdWLClijqSJV0lOlidR_t0-Zk';
const TS_SITEKEY = process.env.ZX_TURNSTILE_SITEKEY || TS_SITEKEY_DEFAULT;
const TS_SECRET = process.env.ZX_TURNSTILE_SECRET || TS_SECRET_DEFAULT;
const TURNSTILE_ON = !!(TS_SITEKEY && TS_SECRET);
if (sec.EPHEMERAL) {
  console.warn('[sec] ZX_SECRET not set — using an ephemeral per-boot secret; every restart invalidates live sessions/tokens. Set ZX_SECRET in production.');
}

// Honeypot paths: never linked from the real UI (except one invisible trap link
// in index.html). Any caller that requests one is a crawler probing for a bulk
// endpoint — we ban the session and answer 404 so we don't confirm the trap.
const HONEYPOTS = new Set([
  '/api/all', '/api/all-titles', '/api/catalog', '/api/contents', '/api/content',
  '/api/export', '/api/dump', '/api/list', '/api/titles', '/api/v1/list', '/api/v1/contents',
]);
// A honeypot hit is an unambiguous crawler, so we ban the source IP outright —
// this catches a link-following crawler that hit the bait without ever loading the
// page (and thus without a cookie), which a session-only ban would miss.
const HONEYPOT_BAN_MS = 6 * 60 * 60 * 1000;
// Per-IP session-mint caps (real client IP behind Cloudflare). Minting many fresh
// sessions from one IP is cookie-farming; SOFT flags them suspect (tighter
// enumeration thresholds), HARD refuses new cookies. Kept generous so shared
// NAT/mobile IPs aren't punished — Cloudflare's rate-limit is the hard wall.
const IP_MINT_WINDOW = 10 * 60 * 1000;
const IP_MINT_SOFT = Number(process.env.ZX_IP_MINT_SOFT || 25);
const IP_MINT_HARD = Number(process.env.ZX_IP_MINT_HARD || 60);
// Cross-site Sec-Fetch is always rejected (JS can't forge it). Requiring the
// header be *present* on JSON endpoints catches lazy non-browser clients too, but
// browsers older than ~2023 (Safari <16.4) don't send it — set ZX_REQUIRE_SECFETCH=0
// to relax the presence check if old-browser users report being blocked.
const REQUIRE_SECFETCH = process.env.ZX_REQUIRE_SECFETCH !== '0';
// Token is managed dynamically: TokenManager logs into a stored email account
// (renewing forever) and creates a replacement account if that one dies. The
// captured token is only a last-resort seed if no account is stored yet.
const client = new LoklokClient({ token: loadToken() });
const auth = new TokenManager(client).attach();

const app = express();
app.disable('x-powered-by');
// Number of reverse-proxy hops in front of us, so req.ip is the REAL client IP
// (all the IP-based defences — mint cap, rate limit, escalating PoW — depend on it).
// Northflank's ingress = 1 hop (default). Add Cloudflare in front later => set 2.
app.set('trust proxy', Number(process.env.TRUST_PROXY || 1));

// ---- security hardening ----------------------------------------------------
// Baseline headers on every response. Hand-rolled (no helmet dep) so it stays
// dependency-free: the CSP locks the SPA to first-party scripts, despseek covers
// load over https, hls.js feeds the <video> a blob, and every fetch (api / hls /
// subs) is same-origin.
const CSP = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  // the only inline script is the anti-flash theme setter in index.html's <head>;
  // whitelisted by hash so script-src never needs 'unsafe-inline'. If that inline
  // script changes, recompute the hash or the theme flash-guard will be blocked.
  // Turnstile (when enabled) also loads its challenge script from Cloudflare.
  "script-src 'self' 'sha256-/nn9NeD2aZjhGlFzBHEl7H310EiT0uSWiGLCv7VeiYY='" +
    (TURNSTILE_ON ? ' https://challenges.cloudflare.com' : ''),
  // hls.js spins up its demuxer in a Worker created from a blob: URL. worker-src
  // is scoped to workers only, so this doesn't loosen script-src for page scripts.
  "worker-src 'self' blob:",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' https: data:",
  "media-src 'self' blob:",
  // Turnstile posts its challenge over connect + renders in an iframe.
  "connect-src 'self'" + (TURNSTILE_ON ? ' https://challenges.cloudflare.com' : ''),
  "frame-src 'self'" + (TURNSTILE_ON ? ' https://challenges.cloudflare.com' : ''),
].join('; ');

app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.set('X-DNS-Prefetch-Control', 'off');
  res.set('Cross-Origin-Opener-Policy', 'same-origin');
  res.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=(), usb=()');
  res.set('Content-Security-Policy', CSP);
  if (isHttps(req)) res.set('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');

  // Session handshake: mint a signed session cookie on a real page navigation
  // (an HTML document load), and never on /api/* or static subresources — issuing
  // one per parallel asset request would churn the cookie. This is the choke
  // point: /api/* below refuses any caller without a valid cookie, so a scraper
  // is forced to load the page first and carry an identifiable session.
  const wantsHtml = String(req.headers.accept || '').includes('text/html');
  if (wantsHtml && !(req.path || '').startsWith('/api/') && !getSession(req)) {
    // Per-IP session-mint cap. A single client needs ~1 session; a scraper
    // farming fresh cookies burns through many. Windowed + generous so CGNAT
    // (many real users behind one IP) doesn't get caught. Hard cap → don't mint
    // (page still renders, but /api/* will 401); soft cap → mint but flag suspect.
    const level = ipMintLevel(clientIp(req));
    if (level !== 'hard') {
      const sid = sec.newSid();
      const s = freshSession(sid);
      if (level === 'soft') s.suspect = true;
      sessions.set(sid, s);
      res.append('Set-Cookie', sec.serializeCookie('zx_sid', sec.sign(sid), {
        httpOnly: true, secure: isHttps(req), sameSite: 'Strict', path: '/', maxAge: SESS_TTL / 1000,
      }));
    }
  }
  next();
});

// ---- rate limiting ---------------------------------------------------------
// In-memory sliding window keyed by client IP. Two tiers: the media proxy pulls
// many segments per minute so it gets a high ceiling; the JSON API hits the
// metered upstream token, so it's capped tighter. Expired entries are swept so
// the maps can't grow unbounded. Single-process only — front with a shared
// store (e.g. Redis) if you ever run multiple instances.
function rateLimiter(windowMs, max) {
  const hits = new Map(); // ip -> [timestamps]
  const sweep = setInterval(() => {
    const cutoff = Date.now() - windowMs;
    for (const [ip, arr] of hits) {
      const kept = arr.filter(t => t > cutoff);
      if (kept.length) hits.set(ip, kept); else hits.delete(ip);
    }
  }, windowMs);
  if (sweep.unref) sweep.unref();
  return (req, res, next) => {
    const now = Date.now(), cutoff = now - windowMs;
    const ip = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
    const arr = (hits.get(ip) || []).filter(t => t > cutoff);
    if (arr.length >= max) {
      res.set('Retry-After', String(Math.ceil(windowMs / 1000)));
      return fail(res, 429, 'too many requests — slow down');
    }
    arr.push(now);
    hits.set(ip, arr);
    next();
  };
}

const RL_WINDOW = 60_000;
const apiLimiter = rateLimiter(RL_WINDOW, Number(process.env.RL_API || 120));
const mediaLimiter = rateLimiter(RL_WINDOW, Number(process.env.RL_MEDIA || 1200));
app.use('/api', (req, res, next) => {
  const p = (req.originalUrl || '').split('?')[0];
  // hls/sub (Loklok) and mbmpd/mbseg (MovieBox DASH) all pull many segments —
  // give them the high-ceiling media limiter, not the tight JSON API one.
  const isMedia = MEDIA_RE.test(p);
  return (isMedia ? mediaLimiter : apiLimiter)(req, res, next);
});
app.use('/api', apiGate); // session/origin/token/pattern gate (defined below)

// ---- session store + anti-scrape gate --------------------------------------
// In-memory, single-process (same tradeoff as rateLimiter above): a shared store
// is only needed if this ever runs multi-instance.
const SESS_TTL = 6 * 60 * 60 * 1000;   // idle session lifetime (also cookie Max-Age)
const sessions = new Map();            // sid -> session record
const sessSweep = setInterval(() => {
  const now = Date.now();
  for (const [sid, s] of sessions) if (now - s.last > SESS_TTL) sessions.delete(sid);
}, 10 * 60 * 1000);
if (sessSweep.unref) sessSweep.unref();

function freshSession(sid) {
  const now = Date.now();
  return {
    sid, created: now, last: now, human: false, suspect: false, verified: false, stepUp: false,
    ids: new Set(), idsWindowStart: now,   // distinct titles per 5-min window (enumeration signal)
    apiHits: 0, apiWindowStart: now,        // api calls per 1-min window (burst signal)
    strikes: 0, bannedUntil: 0,
  };
}

// Per-IP session-mint counters (see IP_MINT_* above). Swept on the same cadence.
const ipMints = new Map(); // ip -> { count, windowStart }
const ipSweep = setInterval(() => {
  const now = Date.now();
  for (const [ip, m] of ipMints) if (now - m.windowStart > IP_MINT_WINDOW) ipMints.delete(ip);
}, IP_MINT_WINDOW);
if (ipSweep.unref) ipSweep.unref();
// Returns 'ok' | 'soft' | 'hard' for an about-to-be-minted session from this IP.
function ipMintLevel(ip) {
  const now = Date.now();
  let m = ipMints.get(ip);
  if (!m || now - m.windowStart > IP_MINT_WINDOW) { m = { count: 0, windowStart: now }; ipMints.set(ip, m); }
  m.count++;
  if (m.count > IP_MINT_HARD) return 'hard';
  if (m.count > IP_MINT_SOFT) return 'soft';
  return 'ok';
}
// Read the current mint count for an IP without touching it (used to scale PoW).
function ipMintCount(ip) {
  const m = ipMints.get(ip);
  if (!m || Date.now() - m.windowStart > IP_MINT_WINDOW) return 0;
  return m.count;
}

// Honeypot IP bans (see HONEYPOT_BAN_MS). Swept lazily on read so no timer needed.
const ipBans = new Map(); // ip -> expiry ms
function ipBanned(ip) {
  const exp = ipBans.get(ip);
  if (!exp) return false;
  if (Date.now() > exp) { ipBans.delete(ip); return false; }
  return true;
}
function banIp(ip) { ipBans.set(ip, Date.now() + HONEYPOT_BAN_MS); }

// ---- proof-of-work handshake (JS-execution gate) ---------------------------
// A plain HTTP scraper (Python requests, node-fetch, axios-cookiejar) fetches
// pages/JSON but never EXECUTES our page JS. So we don't hand the page token to
// whoever asks /api/session — we hand a PoW challenge, and only issue the token
// once the client POSTs back a nonce our JS solved. Off-the-shelf scrapers can't
// solve it without reimplementing our solver (real reverse-engineering, and it
// breaks whenever we retune it); a real browser or Puppeteer solves it on load.
// Verifying is a single hash. Bound to sid+UA, single-use, short-lived.
const POW_BITS = Number(process.env.ZX_POW_BITS || 16);
const POW_MAX_BITS = Number(process.env.ZX_POW_MAX_BITS || 24);
const POW_TTL = 2 * 60 * 1000;
const powChallenges = new Map(); // challenge -> { sid, ua, bits, exp }
const powSweep = setInterval(() => {
  const now = Date.now();
  for (const [c, r] of powChallenges) if (now > r.exp) powChallenges.delete(c);
}, 60 * 1000);
if (powSweep.unref) powSweep.unref();
// Difficulty for the NEXT challenge from this caller. A single real visitor sits at
// the base cost (~0.4s once per session); the price then climbs with how many
// sessions this IP has already minted in the window and whether the session looks
// automated. A plain HTTP scraper can port our sha256 solver in a few lines — that's
// unavoidable for any server-verifiable client puzzle without unsafe-eval — so the
// defence isn't secrecy, it's economics: ripping the catalog needs many sessions
// (each is enumeration-capped), and every extra session from an IP costs
// exponentially more CPU. Farming 60 cookies stops being ~10s and becomes minutes.
function powBitsFor(req, s) {
  let bits = POW_BITS;
  if (s && s.suspect) bits += 4;
  const over = ipMintCount(clientIp(req)) - IP_MINT_SOFT;
  if (over > 0) bits += Math.min(8, 2 * Math.ceil(over / 5)); // +2 bits per 5 sessions past the soft cap
  return Math.max(8, Math.min(POW_MAX_BITS, bits));
}
function issueChallenge(req, bits) {
  const challenge = sec.newSid() + sec.newSid();
  powChallenges.set(challenge, { sid: req._zxSid, ua: sec.uaKey(req), bits, exp: Date.now() + POW_TTL });
  return challenge;
}
function redeemChallenge(challenge, nonce, req) {
  const rec = powChallenges.get(challenge);
  if (!rec) return false;
  powChallenges.delete(challenge); // single-use
  if (Date.now() > rec.exp) return false;
  if (rec.sid !== req._zxSid || rec.ua !== sec.uaKey(req)) return false;
  return sec.powOk(challenge, nonce, rec.bits);
}

// Cheap headless/automation signals, all free and server-visible (plus one hint
// the client volunteers). None blocks on its own — a hit just marks the session
// suspect, which tightens the enumeration thresholds (and forces Turnstile when
// it's enabled). Real browsers pass all of these.
const AUTO_UA = /(Headless|Electron|PhantomJS|SlimerJS|puppeteer|playwright|selenium|webdriver|python|Go-http|curl|wget|scrapy|http-client)/i;
function sniffSuspect(req) {
  if (AUTO_UA.test(String(req.headers['user-agent'] || ''))) return true;
  if (req.headers['x-zx-auto'] === '1') return true;         // client saw navigator.webdriver
  if (!req.headers['accept-language']) return true;          // browsers always send it; many scrapers don't
  return false;
}
// Whether this session must clear the Turnstile human-check before the sensitive
// endpoints open. Deliberately narrow: only sessions that tripped an automation
// signal (suspect) or the behavioral step-up (stepUp) are ever asked. A plain
// human visitor is neither, so they're never challenged — the gate is invisible
// to them. No-op unless Turnstile is configured and the session isn't human yet.
function needsHuman(s) {
  return TURNSTILE_ON && !s.human && (s.suspect || s.stepUp);
}
// Resolve the session from the signed cookie. A validly-signed sid whose record
// was swept/lost after a restart is re-registered so a live tab keeps working.
function getSession(req) {
  const cookies = sec.parseCookies(req.headers.cookie);
  const sid = cookies.zx_sid ? sec.unsign(cookies.zx_sid) : null;
  if (!sid) return null;
  let s = sessions.get(sid);
  if (!s) { s = freshSession(sid); sessions.set(sid, s); }
  return { sid, s };
}

// True HTTPS detection (direct TLS, or forwarded by Cloudflare/any proxy). Drives
// the cookie Secure flag so local http testing still stores the cookie.
function isHttps(req) {
  if (req.secure) return true;
  if (String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https') return true;
  return /"?scheme"?:"?https/i.test(String(req.headers['cf-visitor'] || ''));
}

// Real client IP. Behind Cloudflare the origin should be firewalled to CF ranges
// (see the Cloudflare setup notes), so CF-Connecting-IP can be trusted for
// banning/telemetry; without that origin lockdown a direct client could spoof it.
function clientIp(req) {
  return req.headers['cf-connecting-ip'] || req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
}

// ---- opaque, session-bound HLS tokens --------------------------------------
// /api/play no longer hands the browser a raw CDN url. It returns /api/hls?t=<id>
// where <id> is a random handle into this map, bound to the issuing session and
// short-lived. A movie bot can't reuse it (wrong sid), and no raw host/hdntl ever
// reaches the client.
// Must OUTLIVE a full movie. A VOD player fetches the media playlist exactly once,
// so every segment handle is minted upfront (rewriteManifest) with this TTL and then
// walked over the film's runtime. A 3-min TTL expired the later-segment handles before
// the player reached them, so playback died ~3 min in (the sliding refresh in /api/hls
// only helps handles that get RE-fetched, which VOD segments never are). Handles are
// session+UA-bound and dropped on ban, so a long life costs nothing — tie it to the
// session lifetime. Override via ZX_HLS_TTL_MS.
const HLS_TTL = Number(process.env.ZX_HLS_TTL_MS || SESS_TTL);
const SUB_TTL = SESS_TTL;              // subtitle handle is minted at play time but may
                                       // not be fetched until the viewer switches the track
                                       // mid-film — give it the session lifetime too.
const hlsTokens = new Map(); // id -> { u, sid, ua, exp }
const subTokens = new Map(); // id -> { u, sid, ua, exp }
const hlsSweep = setInterval(() => {
  const now = Date.now();
  for (const [id, t] of hlsTokens) if (now > t.exp) hlsTokens.delete(id);
  for (const [id, t] of subTokens) if (now > t.exp) subTokens.delete(id);
}, 60 * 1000);
if (hlsSweep.unref) hlsSweep.unref();
// Deterministic opaque handle per (kind, sid, ua, url). Repeated mints of the same
// url within one session (e.g. a segment referenced across manifest refreshes)
// reuse one entry and just slide its expiry, so a long VOD can't balloon the map
// with duplicate handles. Bound to sid + UA fingerprint: worthless cross-session
// and can't be replayed from a client presenting a different UA.
// anyHost: MovieBox ("ZX 2") streams live on CDN hosts the API only reveals at
// runtime (bcdn/vcdn/… across several domains), so those handles skip the static
// host allow-list — safe because the client never supplies the url (only an
// opaque handle), the server mints it solely from an authenticated upstream
// response, and the proxy still applies an SSRF guard (see safeProxyTarget).
// cookie: some MovieBox CDN urls (unsigned macdn/*.mp4) only return the real file
// when the CloudFront sign cookie from play-info is sent as a Cookie header; the
// proxy attaches it. Stored with the handle so the client never sees it.
function mintToken(map, ttl, u, sid, ua, anyHost, cookie) {
  const id = sec.hmac(['t', sid, ua || '', u].join('|')).replace(/[^A-Za-z0-9]/g, '').slice(0, 32);
  const exp = Date.now() + ttl;
  const ex = map.get(id);
  if (ex) { ex.exp = exp; if (cookie) ex.cookie = cookie; return id; }
  map.set(id, { u, sid, ua: ua || '', exp, anyHost: !!anyHost, cookie: cookie || '' });
  return id;
}
function mintHls(u, sid, ua, anyHost, cookie) { return mintToken(hlsTokens, HLS_TTL, u, sid, ua, anyHost, cookie); }
function mintSub(u, sid, ua, anyHost, cookie) { return mintToken(subTokens, SUB_TTL, u, sid, ua, anyHost, cookie); }
function dropSessionTokens(sid) {
  for (const [id, t] of hlsTokens) if (t.sid === sid) hlsTokens.delete(id);
  for (const [id, t] of subTokens) if (t.sid === sid) subTokens.delete(id);
  if (typeof dropSessionDash === 'function') dropSessionDash(sid);
}

// ---- gate internals --------------------------------------------------------
const API_OPEN = new Set(['/api/health']);          // no gate at all
const MEDIA_RE = /^\/api\/(hls|sub|mbmpd|mbseg)/;    // origin-lenient, token not required
const SENSITIVE_RE = /^\/api\/(mb\/)?(search|title|play)/; // gated behind Turnstile human-check when enabled
// Obvious non-browser clients. A speed bump, not a wall (UA is trivially spoofed);
// the cookie+token+Turnstile layers are what actually cost a scraper.
const BAD_UA = /(python-requests|python-urllib|aiohttp|httpx|scrapy|libwww|Go-http-client|java\/|curl\/|wget|node-fetch|axios\/|Postman|Insomnia|HeadlessChrome|PhantomJS|Bytespider|MJ12bot|AhrefsBot|SemrushBot|DotBot)/i;

function siteHost(req) {
  if (SITE_HOST) return SITE_HOST;
  return String(req.headers['x-forwarded-host'] || req.headers.host || '').split(':')[0].toLowerCase();
}
// Turnstile can't validate a loopback host (localhost / 127.0.0.1 isn't a real
// widget hostname), so a step-up challenge there is unsatisfiable and would brick
// local + preview use. Production clients never reach the origin over loopback,
// so waiving the Turnstile step-up for loopback is safe and only helps dev.
function isLoopbackHost(req) {
  const h = siteHost(req);
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]';
}
// A browser-based clone calling our API from its own page sends ITS origin (which
// JS can't forge), and a SameSite=Strict cookie isn't sent cross-site at all — so
// this check plus the cookie kills third-party sites embedding our API.
function originOk(req) {
  const host = siteHost(req);
  if (!host) return true; // can't determine our own host — don't hard-block
  const o = req.headers.origin || req.headers.referer || '';
  if (!o) return false;   // same-origin fetch still carries a Referer for us
  try { return new URL(o).host.split(':')[0].toLowerCase() === host; }
  catch (_) { return false; }
}

// Sliding-window enumeration detector. Humans browse a handful of titles; a
// scraper walks the catalog. Tripping a threshold escalates strikes into a
// temporary (not permanent) ban to limit false-positive damage.
function trackAndMaybeBan(s, req, p) {
  const now = Date.now();
  if (now - s.idsWindowStart > 5 * 60 * 1000) { s.ids = new Set(); s.idsWindowStart = now; }
  if (/^\/api\/(mb\/)?(title|play)/.test(p)) {
    const m = p.match(/^\/api\/(?:mb\/)?title\/([^/]+)/);
    const id = (m && m[1]) || req.query.contentId || req.query.id || '';
    if (id) s.ids.add(String(id));
  } else if (p === '/api/search' || p === '/api/mb/search') {
    // Search is a catalog-walking vector too: a metadata scraper enumerates keywords
    // to harvest ids/covers without ever touching /api/title. Count each distinct
    // query toward the same enumeration budget so broad keyword-walking trips the ban.
    const q = String(req.query.q || '').trim().toLowerCase();
    if (q) s.ids.add('q:' + q);
  }
  if (now - s.apiWindowStart > 60 * 1000) { s.apiHits = 0; s.apiWindowStart = now; }
  s.apiHits++;

  // Behavioral step-up (the invisible-to-humans layer). Before an outright ban,
  // a session browsing unusually hard is flagged for a ONE-TIME Turnstile check:
  // needsHuman() then makes the next sensitive call return {needVerify:true} and
  // the SPA solves an invisible challenge in the background. A real visitor who
  // simply browses fast clears it without seeing anything; an HTTP scraper can't
  // solve Turnstile, so it never passes the sensitive gate and trips the ban
  // below. Warn thresholds sit under the ban caps so the step-up always fires
  // first. Only meaningful when Turnstile is on and the session isn't human yet.
  if (TURNSTILE_ON && !s.human && !s.stepUp) {
    const idWarn = s.suspect ? 8 : 18;
    const hitWarn = s.suspect ? 30 : 70;
    if (s.ids.size > idWarn || s.apiHits > hitWarn) s.stepUp = true;
  }

  // Suspect sessions (headless/automation signals) get tighter thresholds:
  // real browsing rarely opens a dozen distinct titles a minute, but a bot does.
  const idCap = s.suspect ? 12 : 25;
  const hitCap = s.suspect ? 45 : 90;
  if (s.ids.size > idCap || s.apiHits > hitCap) {
    s.strikes++;
    const mins = Math.min(60, 5 * s.strikes); // 5, 10, 15 … capped at 60
    s.bannedUntil = now + mins * 60 * 1000;
    dropSessionTokens(s.sid); // kill live streams
    console.warn(`[sec] session throttled ${mins}m ids:${s.ids.size} hits:${s.apiHits} ip:${clientIp(req)} ua:${String(req.headers['user-agent'] || '').slice(0, 48)}`);
    s.ids = new Set(); s.apiHits = 0;
    return true;
  }
  return false;
}

// The gate itself. Runs on every /api/* except /api/health.
function apiGate(req, res, next) {
  const p = (req.originalUrl || '').split('?')[0];
  if (API_OPEN.has(p)) return next();

  const ip = clientIp(req);
  // Honeypot: these paths are never linked from real UI (one invisible decoy link
  // + robots Disallow bait a link-following scraper). Any hit is a scraper by
  // definition — ban the source IP for 6h (works even with no cookie) and, if it
  // did carry a session, ban that too and drop its streams. Checked before the
  // session requirement so a cookieless link-follower is caught.
  if (HONEYPOTS.has(p)) {
    banIp(ip);
    const seen = getSession(req);
    if (seen) { seen.s.strikes++; seen.s.bannedUntil = Date.now() + HONEYPOT_BAN_MS; dropSessionTokens(seen.sid); }
    console.warn(`[sec] honeypot hit — banned 6h path:${p} ip:${ip} ua:${String(req.headers['user-agent'] || '').slice(0, 48)}`);
    return fail(res, 404, 'not found');
  }
  if (ipBanned(ip)) { res.set('Retry-After', '3600'); return fail(res, 429, 'temporarily blocked'); }

  const info = getSession(req);
  if (!info) return fail(res, 401, 'session required'); // no valid cookie => load the page first
  const { sid, s } = info;
  s.last = Date.now();

  const banLeft = s.bannedUntil - Date.now();
  if (banLeft > 0) {
    res.set('Retry-After', String(Math.ceil(banLeft / 1000)));
    return fail(res, 429, 'temporarily blocked');
  }

  const isMedia = MEDIA_RE.test(p);

  // Sec-Fetch-Site: browsers set this and JS can't forge it. Same-origin XHR from
  // our own page sends 'same-origin'; a cross-site clone sends 'cross-site'. Block
  // cross-site/cross-origin everywhere; on JSON endpoints also require it present
  // (absent => a non-browser client). Media stays lenient (native player, some
  // proxies strip it) — media is already locked to session-bound ?t= tokens.
  const sfs = req.headers['sec-fetch-site'];
  if (sfs === 'cross-site' || sfs === 'cross-origin') return fail(res, 403, 'forbidden');
  // Require it present on JSON endpoints (a non-browser client omits it), but let
  // the /api/session bootstrap through so a slightly-odd same-origin client can
  // still start, and never enforce presence on media. Relaxable via env.
  if (REQUIRE_SECFETCH && !isMedia && sfs === undefined && p !== '/api/session') return fail(res, 403, 'forbidden');

  if (!isMedia && !originOk(req)) return fail(res, 403, 'forbidden origin');
  if (BAD_UA.test(String(req.headers['user-agent'] || ''))) return fail(res, 403, 'forbidden');

  // Fold automation signals into the session (sticky once suspected).
  if (!s.suspect && sniffSuspect(req)) s.suspect = true;

  // page token (double-submit): required for JSON endpoints, except the bootstrap
  // (/api/session), the PoW handshake (/api/handshake — how the token is earned),
  // and the Turnstile verify call, and not for media (uses ?t=).
  const tokenExempt = isMedia || p === '/api/session' || p === '/api/handshake' || (TURNSTILE_ON && p === '/api/verify');
  if (!tokenExempt && !sec.verifyPageToken(req.headers['x-zx-token'], sid, sec.uaKey(req))) {
    return fail(res, 403, 'bad token');
  }

  // Turnstile human-gate — STEP-UP only, never a blanket wall. A normal visitor
  // (not suspect, not flagged by the behavioral step-up in trackAndMaybeBan) is
  // never challenged: the valuable endpoints stay open and the site is instant.
  // The check engages only for a session that looks automated or is browsing like
  // a scraper, and it's satisfied by one invisible Turnstile solve. This is the
  // "doesn't break the site for real users" design: humans pass silently, a plain
  // HTTP scraper can't solve the challenge and stays locked out of search/title/play.
  if (SENSITIVE_RE.test(p) && needsHuman(s) && !isLoopbackHost(req)) {
    return fail(res, 403, 'verification required', { needVerify: true });
  }

  // Enumeration/burst ban tracking is for the JSON API only. Media segments
  // (HLS/DASH) legitimately fire many requests per minute — an adaptive stream
  // can pull dozens of /api/hls|mbseg segments while buffering — so counting
  // them would ban a normal viewer mid-playback. Media has its own high-ceiling
  // rate limiter (mediaLimiter) and session-bound ?t= tokens already.
  if (!isMedia && trackAndMaybeBan(s, req, p)) {
    res.set('Retry-After', String(Math.ceil((s.bannedUntil - Date.now()) / 1000)));
    return fail(res, 429, 'temporarily blocked');
  }

  req._zxSid = sid; req._zxSess = s;
  next();
}

// ---- helpers ---------------------------------------------------------------
function normType(subType, domainType) {
  const s = String(subType || '').toUpperCase();
  const map = {
    MOVIE: 'Movie', FILM: 'Movie', TV: 'Series', DRAMA: 'Series',
    VARIETY: 'Variety', TALK: 'Talk', COMIC: 'Anime', ANIME: 'Anime',
    DOCUMENTARY: 'Documentary', SETI: 'Series',
  };
  if (map[s]) return map[s];
  if (domainType === 1 || domainType === '1') return 'Series';
  if (domainType === 0 || domainType === '0') return 'Movie';
  return subType || '';
}

function normScore(raw) {
  if (raw === null || raw === undefined || raw === '') return null;
  let n = parseFloat(raw);
  if (!isFinite(n) || n <= 0) return null;
  if (n > 10) n = n / 10; // some scores come scaled by 10 (e.g. "49.0")
  return Math.round(n * 10) / 10;
}

// IMDb-sourced artwork reaches us via img.despseek.com capped at 808px wide
// (…MV5B…@._V1_QL75_UX808_.jpg) — blurry once stretched across a backdrop, and that
// CDN only ever cached the 808 rendition (other widths 404). But the embedded IMDb id
// (MV5B…) resolves against Amazon's own image CDN, which renders any width live, so we
// rebuild IMDb URLs there at the width we actually need. Non-IMDb art (plain CDN
// images, e.g. the Chinese-language posters) has no MV5B id and passes through as-is.
function hiResImg(url, width) {
  if (typeof url !== 'string' || !url) return url || '';
  const m = url.match(/(MV5B[^@/]+)@/);
  if (!m) return url;
  const w = Math.min(2000, Math.max(1, (width | 0) || 1280));
  return `https://m.media-amazon.com/images/M/${m[1]}@._V1_QL90_UX${w}_.jpg`;
}

// Unified card shape from either a search resultItem or a browse searchResult.
// The full-catalog regions localize titles with a trailing language tag, e.g.
// "Spider-Man: Brand New Day[AR SUB]" (Arab region) or "…[RU Audio]" (CIS). We
// claim a full-catalog region for discovery (see lib/loklok.js geo headers), so
// strip that trailing tag for display — it's a locale marker, not part of the name.
function cleanTitle(s) {
  return String(s || '').replace(/\s*\[[^\]]*(?:SUB|AUDIO|DUB)[^\]]*\]\s*$/i, '').trim();
}

function toCard(it) {
  return {
    id: String(it.id),
    name: cleanTitle(it.name || it.matchTitle || ''),
    type: normType(it.subType || (it.dramaType && it.dramaType.code), it.domainType),
    cover: hiResImg(it.coverVerticalUrl || it.coverHorizontalUrl || '', 720),
    backdrop: hiResImg(it.coverHorizontalUrl || '', 1280),
    year: it.releaseTime || it.year || '',
    score: normScore(it.doubanScore != null ? it.doubanScore : it.score),
    episodes: it.resourceNum || it.episodeCount || null,
    intro: it.introduction || '',
  };
}

// ---- search relevance ------------------------------------------------------
// With keke='false' (see lib/loklok.js) the upstream returns the FULL catalog,
// relevance-ranked with the best match first and looser "related" titles after
// — the exact list the official app renders verbatim as "Related Movies"
// ("spider man" -> Spider-Man: Brand New Day, Venom, Man Against Man, The
// Spider…). So we no longer DROP anything: isRelevant() below is used only as a
// sort key that floats the on-topic titles (distinctive-token matches) to the
// top and keeps the related ones beneath, mirroring the app's "results first,
// similar below" layout. The popular-rail fallback fires only when the upstream
// returns nothing at all (e.g. "deadpool" -> 0 hits).
const COMMON_WORDS = new Set(['the','a','an','of','and','or','to','in','on','my',
  'your','you','me','man','men','woman','women','girl','boy','love','story','life',
  'day','night','war','world','god','king','house','last','first','one','two','no',
  'not','is','are','was','be','with','for','from','who','what','season','movie','film']);

function normText(s) {
  return String(s || '').toLowerCase()
    .normalize('NFKD').replace(/[̀-ͯ]/g, '')      // strip accents
    .replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
}

function queryTokens(q) {
  const words = normText(q).split(/\s+/).filter(Boolean);
  const latin = words.filter(w => /^[a-z0-9]+$/.test(w));
  const distinctive = latin.filter(w => w.length >= 3 && !COMMON_WORDS.has(w));
  return { words, distinctive };
}

function titleHaystack(it) {
  const f = [it.name, it.matchTitle, it.aliasName, it.enName];
  if (Array.isArray(it.allLanguageNames)) f.push(...it.allLanguageNames);
  if (Array.isArray(it.allLanguageAliasNames)) f.push(...it.allLanguageAliasNames);
  return normText(f.filter(Boolean).join(' '));
}

function isRelevant(it, tk) {
  const hay = titleHaystack(it);
  if (!hay) return false;
  const hayWords = hay.split(/\s+/);
  const haySet = new Set(hayWords);
  if (tk.distinctive.length) {
    // at least one distinctive query word present whole, or sharing a >=4 stem
    return tk.distinctive.some(t => haySet.has(t) ||
      (t.length >= 4 && hayWords.some(w => w.length >= 4 &&
        (w.startsWith(t.slice(0, 4)) || t.startsWith(w.slice(0, 4))))));
  }
  // query is only common words (e.g. "man") or non-latin — loose substring match
  return tk.words.some(t => t.length >= 2 && (haySet.has(t) || hay.includes(t)));
}

// Normalize a query for the upstream tokenizer, which matches on word
// boundaries: "spider-man" / "SpiderMan" both expand to "spider man" (which
// returns the full related set), while a bare concatenation ("spiderman") can
// only resolve to its single exact title. Hyphens/dots/underscores and
// camelCase boundaries become spaces; runs of whitespace collapse.
function searchQuery(raw) {
  const spaced = String(raw || '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[-_.]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return spaced || String(raw || '');
}

// Popular titles used as the search fallback rail, mirroring the app's Recommend
// section. Same source that powers the home page's curated rows (browse by count).
async function trendingCards(limit = 18) {
  try {
    const [mv, tv] = await Promise.all([
      client.browse({ params: 'MOVIE', order: 'count', size: limit }),
      client.browse({ params: 'TV,SETI,VARIETY,DOCUMENTARY', order: 'count', size: limit }),
    ]);
    const m = (mv && mv.data && mv.data.searchResults) || [];
    const t = (tv && tv.data && tv.data.searchResults) || [];
    const seen = new Set(); const out = [];
    for (let i = 0; i < Math.max(m.length, t.length) && out.length < limit; i++) {
      for (const row of [m[i], t[i]]) {
        if (row && row.id && !seen.has(String(row.id))) { seen.add(String(row.id)); out.push(toCard(row)); }
      }
    }
    return out.slice(0, limit);
  } catch { return []; }
}

function fail(res, code, msg, extra) {
  res.status(code).json(Object.assign({ error: msg }, extra || {}));
}

// Log the real error server-side; hand the client a generic message so internal
// details (upstream hosts, stack hints) never leak in an API response body.
function oops(res, code, msg, err) {
  if (err) console.error('[' + code + '] ' + msg + ':', (err && err.message) || err);
  return fail(res, code, msg);
}

// Content ids / episode ids are opaque upstream tokens — reject anything that
// isn't a short safe slug before it reaches the client library.
const ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
function badId(v) { return v == null || !ID_RE.test(String(v)); }

// SRT -> WebVTT (idempotent if already VTT).
function srtToVtt(src) {
  let s = String(src).replace(/^﻿/, '').replace(/\r+/g, '');
  if (/^\s*WEBVTT/.test(s)) return s; // already VTT
  s = s.replace(/(\d{2}:\d{2}:\d{2}),(\d{3})/g, '$1.$2'); // comma -> dot in timestamps
  return 'WEBVTT\n\n' + s.trim() + '\n';
}

// ---- API -------------------------------------------------------------------
app.get('/api/health', (req, res) => {
  res.json({
    ok: !!client.token,
    token: !!client.token,
    daysLeft: auth.daysLeft(),
    account: auth.acct && auth.acct.email ? auth.acct.email.replace(/(.{3}).*(@.*)/, '$1***$2') : null,
    host: client.host,
    // Catalog gate — 'full' means search returns Hollywood; 'restricted' means a
    // stale deploy is sending keke=true and hiding it. See boot-log banner.
    catalog: client.keke === 'false' ? 'full' : 'restricted',
    keke: client.keke,
    // Claimed region (device-geo override). When set, the upstream picks the
    // catalog region from this instead of the host's egress IP — see lib/loklok.js.
    geoRegion: (client.geo && client.geo.isoCode) || null,
    proxy: !!client.proxy, // routing upstream via a proxy egress? (fallback only)
  });
});

// Session bootstrap: the SPA calls this once on load (cookie + origin already
// enforced by the gate) to receive its short-lived page token, which it then
// echoes as X-ZX-Token on every other /api/* call. Also advertises whether the
// Turnstile human-check is active so the client can render the widget.
// Session bootstrap. If this session hasn't cleared the JS-execution gate yet, we
// return a proof-of-work challenge instead of a token — a plain HTTP scraper stops
// here (no token => every JSON call 403s). Once /api/handshake marks the session
// verified, refreshes take the fast path and just re-issue a fresh short-lived token
// (no repeat PoW). Also advertises whether the Turnstile human-check is active.
app.get('/api/session', (req, res) => {
  res.set('Cache-Control', 'no-store');
  const ts = TURNSTILE_ON ? { enabled: true, sitekey: TS_SITEKEY } : { enabled: false };
  if (!req._zxSess.verified) {
    const bits = powBitsFor(req, req._zxSess);
    // Opaque wire shape (vx.c = challenge, vx.b = difficulty). The names are
    // deliberately meaningless so the shipped client JS doesn't advertise the
    // handshake scheme to anyone reading it.
    return res.json({ vx: { c: issueChallenge(req, bits), b: bits }, turnstile: ts });
  }
  res.json({ token: sec.issuePageToken(req._zxSid, 10 * 60 * 1000, sec.uaKey(req)), turnstile: ts });
});

// PoW handshake: the SPA solves the challenge from /api/session and echoes the
// nonce here. A correct proof marks the session verified and mints the page token.
app.get('/api/handshake', (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (!redeemChallenge(String(req.query.c || ''), String(req.query.n || ''), req)) {
    return fail(res, 403, 'bad proof');
  }
  req._zxSess.verified = true;
  res.json({ token: sec.issuePageToken(req._zxSid, 10 * 60 * 1000, sec.uaKey(req)) });
});

// Turnstile verification (only mounted when keys are configured). On success the
// session is upgraded to "human" and the sensitive endpoints open up.
if (TURNSTILE_ON) {
  app.post('/api/verify', express.json({ limit: '2kb' }), async (req, res) => {
    const token = req.body && req.body.token;
    if (!token) return fail(res, 400, 'token required');
    try {
      const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ secret: TS_SECRET, response: token, remoteip: clientIp(req) }),
      });
      const j = await r.json().catch(() => ({}));
      if (j && j.success) { req._zxSess.human = true; return res.json({ ok: true }); }
      return fail(res, 403, 'verification failed');
    } catch (e) {
      return oops(res, 502, 'verification unavailable', e);
    }
  });
}

app.get('/api/home', async (req, res) => {
  try {
    // COMIC (animation) gets its own rail below, so keep it out of the series mix.
    const [mv, tv, an] = await Promise.all([
      client.browse({ params: 'MOVIE', order: 'count', size: 18 }),
      client.browse({ params: 'TV,SETI,VARIETY,DOCUMENTARY', order: 'count', size: 18 }),
      client.browse({ params: 'COMIC', order: 'count', size: 18 }),
    ]);
    const movies = ((mv && mv.data && mv.data.searchResults) || []).map(toCard);
    const series = ((tv && tv.data && tv.data.searchResults) || []).map(toCard);
    const anime  = ((an && an.data && an.data.searchResults) || []).map(toCard);
    const sections = [];
    if (movies.length) sections.push({ title: 'Popular Movies', items: movies });
    if (series.length) sections.push({ title: 'Trending Series', items: series });
    if (anime.length)  sections.push({ title: 'Animation', items: anime });
    res.json({ sections });
  } catch (e) {
    oops(res, 502, 'home unavailable', e);
  }
});

app.get('/api/search', async (req, res) => {
  const raw = String(req.query.q || '').slice(0, 80).trim(); // cap length to curb abuse
  if (!raw) return res.json({ query: '', results: [], rawCount: 0 });
  try {
    const q = searchQuery(raw);                 // expand hyphen/camelCase for the tokenizer
    const sr = await client.search(q, { size: 30 });
    const region = sr && sr._region ? sr._region : null;
    let items = [];
    if (!(sr && sr.code && sr.code !== '00000')) {
      items = (sr && sr.data && sr.data.resultItems) || [];
    }
    // Only real, enterable titles.
    const enterable = items.filter(it => it && it.id && it.allowEnterDetail !== 0);
    if (enterable.length) {
      // Keep every upstream hit (the app shows the "related" titles too), but
      // float the on-topic ones to the front so it reads "matches first, similar
      // below". Array.sort is stable, so equal-relevance items keep upstream order.
      const tk = queryTokens(q);
      const ranked = enterable
        .map((it, i) => ({ it, i, rel: isRelevant(it, tk) ? 1 : 0 }))
        .sort((a, b) => b.rel - a.rel || a.i - b.i)
        .map(x => x.it);
      return res.json({ query: raw, results: ranked.map(toCard), rawCount: enterable.length, region });
    }
    // Upstream returned nothing at all — show a popular rail, like the app does.
    const recommended = await trendingCards(18);
    return res.json({ query: raw, results: recommended, rawCount: 0, region, recommended: true });
  } catch (e) {
    oops(res, 502, 'search unavailable', e);
  }
});

app.get('/api/title/:id', async (req, res) => {
  const id = req.params.id;
  if (badId(id)) return fail(res, 400, 'bad id');
  const category = req.query.category !== undefined ? Number(req.query.category) : 0;
  try {
    const det = await client.movie(id, { category });
    if (!det || det.code !== '00000' || !det.data || typeof det.data !== 'object') {
      return fail(res, 404, 'title not found', { code: det && det.code });
    }
    const d = det.data;
    const eps = (d.episodeVo || []).map((e, i) => ({
      episodeId: e.id,
      seriesNo: e.seriesNo != null ? e.seriesNo : (i + 1),
      name: e.name || '',
      totalTime: e.totalTime || 0,
      viewable: e.viewable !== false,
    })).sort((a, b) => a.seriesNo - b.seriesNo);
    res.json({
      id: String(id),
      category: det._category != null ? det._category : category,
      name: cleanTitle(d.name || ''),
      enName: cleanTitle(d.enName || ''),
      year: d.year || '',
      type: normType((d.drameTypeVo && d.drameTypeVo.drameType), d.domainType),
      cover: hiResImg(d.coverVerticalUrl || '', 720),
      backdrop: hiResImg(d.coverHorizontalUrl || d.coverVerticalUrl || '', 1280),
      intro: d.introduction || '',
      tags: d.tagNameList || [],
      areas: d.areaNameList || [],
      score: normScore(d.score),
      episodeCount: d.episodeCount || eps.length,
      episodes: eps,
    });
  } catch (e) {
    oops(res, 502, 'title unavailable', e);
  }
});

app.get('/api/play', async (req, res) => {
  const contentId = req.query.contentId;
  if (badId(contentId)) return fail(res, 400, 'contentId required');
  const episodeId = req.query.episodeId || null;
  if (episodeId && badId(episodeId)) return fail(res, 400, 'bad episodeId');
  let definition = String(req.query.definition || 'GROOT_LD');
  if (!/^[A-Z0-9_]{1,32}$/.test(definition)) definition = 'GROOT_LD'; // allowlist shape
  let category = req.query.category !== undefined ? Number(req.query.category) : null;
  try {
    if (category === null || Number.isNaN(category)) {
      const r = await client._detailCategory(contentId, 0);
      category = r.cat;
    }
    const info = await client.playInfo(contentId, { episodeId, category, definition });
    if (!info || info.code !== '00000' || !info.data || typeof info.data !== 'object') {
      return fail(res, 502, 'playInfo failed', { code: info && info.code });
    }
    const d = info.data;
    if (!d.mediaUrl) {
      return fail(res, 502, 'no stream url (wrong category?)', { category });
    }
    // Only what the player consumes: the code (to switch), a label (to show),
    // and vip (to prefer the free row when two tiers share a code). Drop `size`
    // (exact upstream byte counts) and `login` — pure internal leak, unused by UI.
    const qualities = (d.definitionList || []).map(q => ({
      code: q.code,
      label: q.description || DEFINITION_LABELS[q.code] || q.code,
      vip: !!q.vip,
    }));
    const subtitles = (d.subtitlingList || [])
      .filter(s => s && s.subtitlingUrl)
      .map(s => ({
        lang: s.languageAbbr || s.language || 'sub',
        label: s.language || s.languageAbbr || 'Subtitle',
        url: '/api/sub?t=' + mintSub(s.subtitlingUrl, req._zxSid, sec.uaKey(req)),
      }));
    // Lean response: the client already knows contentId/episodeId/category (it
    // sent them) and pulls name/cover/duration from the title call + the video
    // element itself. Echoing them back just feeds a scraper — so we don't.
    res.json({
      // Never hand the browser the raw CDN url. Return an opaque, session-bound,
      // short-lived handle instead — the /api/hls proxy resolves it (and refuses
      // it from any other session), so /api/play is worthless to a movie bot.
      mediaUrl: '/api/hls?t=' + mintHls(d.mediaUrl, req._zxSid, sec.uaKey(req)),
      currentDefinition: d.currentDefinition || definition,
      qualities,
      subtitles,
    });
  } catch (e) {
    oops(res, 502, 'playback unavailable', e);
  }
});

app.get('/api/sub', async (req, res) => {
  // Opaque, session+UA-bound handle (like /api/hls) — the old ?u=<raw url> form is
  // gone, so this can't be pointed at an arbitrary despseek.com URL or reused across
  // sessions, and the real subtitle CDN host never reaches the client.
  const rec = req.query.t ? subTokens.get(String(req.query.t)) : null;
  if (!rec) return fail(res, 403, 'forbidden');
  if (Date.now() > rec.exp) { subTokens.delete(String(req.query.t)); return fail(res, 403, 'expired'); }
  if (rec.sid !== req._zxSid || rec.ua !== sec.uaKey(req)) return fail(res, 403, 'forbidden');
  rec.exp = Date.now() + SUB_TTL; // sliding

  let target;
  try { target = new URL(rec.u); } catch (_) { return fail(res, 400, 'bad url'); }
  if (!/^https?:$/.test(target.protocol)) return fail(res, 400, 'bad url');
  if (rec.anyHost ? !safeProxyHost(target.hostname) : !HLS_HOST_RE.test(target.host))
    return fail(res, 403, 'host not allowed');
  try {
    const r = await fetch(target.toString(), { headers: { 'user-agent': 'okhttp/4.12.0' } });
    if (!r.ok) return fail(res, 502, 'subtitle fetch failed', { status: r.status });
    const raw = await r.text();
    const vtt = srtToVtt(raw);
    res.set('Content-Type', 'text/vtt; charset=utf-8');
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Cache-Control', 'public, max-age=3600');
    res.send(vtt);
  } catch (e) {
    oops(res, 502, 'subtitle unavailable', e);
  }
});

// ---- HLS proxy -------------------------------------------------------------
// The CDN (akm-cdn-play.despseek.com) rejects browser-originated requests:
// a Chrome User-Agent / Referer / Origin gets 403, while an okhttp UA (or no
// browser headers) gets 200. So we proxy the playlist + segments server-side
// with the app's UA and rewrite child URIs back through this route. Each child
// URI is re-issued as an opaque, session-bound ?t= handle (same as /api/play),
// so no raw CDN host/hdntl token ever reaches the client.
const OKHTTP_UA = 'okhttp/4.12.0';
// Loklok streams live on despseek.com; MovieBox ("ZX 2") media lives on the Movi
// CDN families — hakunaymatata.com (bcdn/sacdn/cacdn) and shalltry.com (dsu-a /
// ire-dsu). All are proxied server-side with the app UA so the CDN (which 403s
// browser-origin requests) serves them, and no raw CDN host reaches the client.
// The proxy is still gated by session+UA-bound ?t= handles the server itself
// mints from upstream responses, so this allow-list is defence-in-depth.
const HLS_HOST_RE = /(^|\.)(despseek\.com|hakunaymatata\.com|shalltry\.com)$/i;

// SSRF guard for the anyHost (MovieBox) proxy path: require https and refuse any
// loopback / link-local / private-range literal so a handle can never be turned
// into a request against the origin's own network. Public CDN hostnames pass.
function safeProxyHost(host) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return false;
  if (h === 'localhost' || h.endsWith('.localhost')) return false;
  if (h === '::1' || h.startsWith('fe80:') || h.startsWith('fc') || h.startsWith('fd')) return false;
  // IPv4 literal in a private / loopback / link-local range?
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 10 || a === 127 || a === 0 || (a === 192 && b === 168) ||
        (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254) || a >= 224) return false;
  }
  return true;
}

function proxifyUri(uri, baseUrl, parentSearch, sid, ua) {
  let abs;
  try { abs = new URL(uri, baseUrl); } catch (_) { return uri; }
  if (!abs.search && parentSearch) abs.search = parentSearch; // inherit token if bare
  return '/api/hls?t=' + mintHls(abs.toString(), sid, ua);
}

function rewriteManifest(text, playlistUrl, sid, ua) {
  let parentSearch = '';
  try { parentSearch = new URL(playlistUrl).search; } catch (_) {}
  return text.split('\n').map(line => {
    if (!line) return line;
    if (line[0] === '#') {
      // rewrite URI="..." attributes (EXT-X-KEY / EXT-X-MEDIA / EXT-X-MAP)
      return line.replace(/URI="([^"]+)"/g,
        (m, uri) => 'URI="' + proxifyUri(uri, playlistUrl, parentSearch, sid, ua) + '"');
    }
    const t = line.trim();
    if (!t) return line;
    return proxifyUri(t, playlistUrl, parentSearch, sid, ua);
  }).join('\n');
}

app.get('/api/hls', async (req, res) => {
  // Only opaque, session+UA-bound tokens are accepted — the old ?u=<raw url> open
  // proxy is gone, so /api/hls can't be pointed at an arbitrary URL or reused
  // across sessions.
  const rec = req.query.t ? hlsTokens.get(String(req.query.t)) : null;
  if (!rec) return fail(res, 403, 'forbidden');
  if (Date.now() > rec.exp) { hlsTokens.delete(String(req.query.t)); return fail(res, 403, 'expired'); }
  if (rec.sid !== req._zxSid || rec.ua !== sec.uaKey(req)) return fail(res, 403, 'forbidden');
  rec.exp = Date.now() + HLS_TTL; // sliding: keep long playbacks alive

  let target;
  try { target = new URL(rec.u); } catch (_) { return fail(res, 400, 'bad url'); }
  if (!/^https?:$/.test(target.protocol)) return fail(res, 400, 'bad url');
  if (rec.anyHost ? !safeProxyHost(target.hostname) : !HLS_HOST_RE.test(target.host))
    return fail(res, 403, 'host not allowed');

  const headers = { 'user-agent': OKHTTP_UA, accept: '*/*' };
  if (req.headers.range) headers.range = req.headers.range; // segment seeking
  if (rec.cookie) headers.cookie = rec.cookie; // CloudFront sign cookie (MovieBox)

  // Abort the upstream fetch if it stalls, or when the browser disconnects (seek/
  // close) — without this a dropped client leaks a hung upstream socket.
  const ac = new AbortController();
  const killTimer = setTimeout(() => ac.abort(), 30_000);
  const onClientClose = () => ac.abort();
  res.on('close', onClientClose);
  const cleanup = () => { clearTimeout(killTimer); res.off('close', onClientClose); };

  let up;
  try {
    up = await fetch(target.toString(), { headers, signal: ac.signal });
  } catch (e) {
    cleanup();
    return oops(res, 502, 'stream unavailable', e);
  }
  if (!up.ok && up.status !== 206) {
    cleanup();
    return fail(res, 502, 'hls upstream status', { status: up.status });
  }

  res.set('Access-Control-Allow-Origin', '*');
  const ct = (up.headers.get('content-type') || '').toLowerCase();
  const isManifest = /mpegurl|vnd\.apple/.test(ct) || /\.m3u8(\?|$)/i.test(target.pathname);

  if (isManifest) {
    let text;
    try { text = await up.text(); }
    catch (e) { cleanup(); return oops(res, 502, 'stream unavailable', e); }
    cleanup();
    res.set('Content-Type', 'application/vnd.apple.mpegurl; charset=utf-8');
    res.set('Cache-Control', 'no-cache');
    return res.send(rewriteManifest(text, target.toString(), req._zxSid, rec.ua));
  }

  // binary passthrough (segments)
  res.status(up.status);
  res.set('Content-Type', ct || 'video/mp2t');
  for (const h of ['content-length', 'content-range', 'accept-ranges']) {
    const v = up.headers.get(h);
    if (v) res.set(h, v);
  }
  res.set('Cache-Control', 'public, max-age=86400');
  if (up.body) {
    // .pipe() does NOT forward source errors, and an unhandled 'error' on the
    // source Readable would crash the process — so handle it explicitly. A mid-
    // segment CDN reset (routine on seek) then just ends this one response.
    const src = Readable.fromWeb(up.body);
    src.on('error', (e) => { cleanup(); if (!res.headersSent) fail(res, 502, 'stream error'); else res.destroy(e); });
    res.on('error', () => { try { src.destroy(); } catch (_) {} });
    src.on('end', cleanup);
    src.pipe(res);
  } else {
    try { res.end(Buffer.from(await up.arrayBuffer())); }
    catch (e) { if (!res.headersSent) oops(res, 502, 'stream unavailable', e); }
    finally { cleanup(); }
  }
});

// ---- DASH proxy (MovieBox series) ------------------------------------------
// Series on MovieBox stream only as DASH (.mpd, usually HEVC) behind a
// CloudFront cookie. dash.js in the browser plays them, but it fetches the
// manifest + every segment itself, and those hit the CDN which 403s browser
// requests and needs the cookie. So we proxy: /api/mbmpd fetches the manifest
// (with cookie + app UA) and injects a <BaseURL> that routes every segment back
// through /api/mbseg, which re-attaches the cookie/UA. Handles are session+UA
// bound, exactly like /api/hls, and dash.js sends no page token (these paths are
// in MEDIA_RE). Both are cleaned up with the session.
const dashTokens = new Map(); // id -> { mpd?, base?, cookie, sid, ua, exp }
const dashSweep = setInterval(() => {
  const now = Date.now();
  for (const [id, t] of dashTokens) if (now > t.exp) dashTokens.delete(id);
}, 60 * 1000);
if (dashSweep.unref) dashSweep.unref();
function mintDash(rec) {
  const id = sec.newSid();
  dashTokens.set(id, { ...rec, exp: Date.now() + HLS_TTL });
  return id;
}

app.get('/api/mbmpd', async (req, res) => {
  const rec = req.query.t ? dashTokens.get(String(req.query.t)) : null;
  if (!rec || !rec.mpd) return fail(res, 403, 'forbidden');
  if (Date.now() > rec.exp) { dashTokens.delete(String(req.query.t)); return fail(res, 403, 'expired'); }
  if (rec.sid !== req._zxSid || rec.ua !== sec.uaKey(req)) return fail(res, 403, 'forbidden');
  let target;
  try { target = new URL(rec.mpd); } catch (_) { return fail(res, 400, 'bad url'); }
  if (!safeProxyHost(target.hostname)) return fail(res, 403, 'host not allowed');
  const headers = { 'user-agent': OKHTTP_UA, accept: '*/*' };
  if (rec.cookie) headers.cookie = rec.cookie;
  try {
    const up = await fetch(target.toString(), { headers });
    if (!up.ok) return fail(res, 502, 'manifest upstream', { status: up.status });
    let xml = await up.text();
    // Absolute directory the manifest's relative segment paths resolve against.
    const base = target.toString().replace(/[^/]*(\?.*)?$/, '');
    const segTok = mintDash({ base, cookie: rec.cookie, sid: rec.sid, ua: rec.ua });
    const proxyBase = '/api/mbseg/' + segTok + '/';
    // Drop any manifest-declared BaseURL and force ours so every segment/init
    // URL routes back through the segment proxy.
    xml = xml.replace(/<BaseURL>[\s\S]*?<\/BaseURL>/gi, '');
    xml = xml.replace(/(<MPD\b[^>]*>)/i, '$1<BaseURL>' + proxyBase + '</BaseURL>');
    res.set('Content-Type', 'application/dash+xml; charset=utf-8');
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Cache-Control', 'no-cache');
    res.send(xml);
  } catch (e) {
    oops(res, 502, 'manifest unavailable', e);
  }
});

app.get(/^\/api\/mbseg\/([^/]+)\/(.*)$/, async (req, res) => {
  const rec = dashTokens.get(String(req.params[0]));
  const rest = req.params[1] || '';
  if (!rec || !rec.base) return fail(res, 403, 'forbidden');
  if (Date.now() > rec.exp) { dashTokens.delete(String(req.params[0])); return fail(res, 403, 'expired'); }
  if (rec.sid !== req._zxSid || rec.ua !== sec.uaKey(req)) return fail(res, 403, 'forbidden');
  rec.exp = Date.now() + HLS_TTL; // sliding
  const qs = (req.originalUrl.split('?')[1] ? '?' + req.originalUrl.split('?')[1] : '');
  let target;
  try { target = new URL(rec.base + rest + qs); } catch (_) { return fail(res, 400, 'bad url'); }
  if (!safeProxyHost(target.hostname)) return fail(res, 403, 'host not allowed');
  const headers = { 'user-agent': OKHTTP_UA, accept: '*/*' };
  if (req.headers.range) headers.range = req.headers.range;
  if (rec.cookie) headers.cookie = rec.cookie;
  const ac = new AbortController();
  const killTimer = setTimeout(() => ac.abort(), 30_000);
  const onClose = () => ac.abort();
  res.on('close', onClose);
  const cleanup = () => { clearTimeout(killTimer); res.off('close', onClose); };
  let up;
  try { up = await fetch(target.toString(), { headers, signal: ac.signal }); }
  catch (e) { cleanup(); return oops(res, 502, 'segment unavailable', e); }
  if (!up.ok && up.status !== 206) { cleanup(); return fail(res, 502, 'segment upstream', { status: up.status }); }
  res.status(up.status);
  res.set('Access-Control-Allow-Origin', '*');
  const ct = up.headers.get('content-type');
  if (ct) res.set('Content-Type', ct);
  for (const h of ['content-length', 'content-range', 'accept-ranges']) {
    const v = up.headers.get(h); if (v) res.set(h, v);
  }
  res.set('Cache-Control', 'public, max-age=86400');
  if (up.body) {
    const src = Readable.fromWeb(up.body);
    src.on('error', (e) => { cleanup(); if (!res.headersSent) fail(res, 502, 'segment error'); else res.destroy(e); });
    res.on('error', () => { try { src.destroy(); } catch (_) {} });
    src.on('end', cleanup);
    src.pipe(res);
  } else {
    try { res.end(Buffer.from(await up.arrayBuffer())); }
    catch (e) { if (!res.headersSent) oops(res, 502, 'segment unavailable', e); }
    finally { cleanup(); }
  }
});
function dropSessionDash(sid) { for (const [id, t] of dashTokens) if (t.sid === sid) dashTokens.delete(id); }

// ============================================================================
// MovieBox ("ZX 2") — a second content source, same UI. Mirrors the Loklok
// /api/* endpoints under /api/mb/* so the SPA just swaps a path prefix. Browse /
// detail / play work signature-only (no account); keyword search self-heals a
// throwaway account (kept on purpose). Streams are proxied through /api/hls and
// subtitles through /api/sub, exactly like Loklok, so the client never sees a
// raw CDN url. See lib/movibox.js.
// ============================================================================

// Localization tags the catalog appends to titles, e.g. "The Runner[مدبلج
// للعربية]" or "Prison Break [Version française]" — strip for display.
function mbClean(s) {
  return String(s || '').replace(/\s*[\[(][^\])]*[\])]\s*$/u, '').trim() || String(s || '').trim();
}
// subjectType: 1 movie, 2 TV/series, 7 short-drama, 9 clips/other.
function mbType(t) {
  const n = Number(t);
  if (n === 2 || n === 7) return 'Series';
  return 'Movie';
}
function mbCard(s) {
  const rd = String(s.releaseDate || '');
  return {
    id: String(s.subjectId),
    name: mbClean(s.title),
    type: mbType(s.subjectType),
    cover: s.cover || '',
    backdrop: s.cover || '',
    year: (rd.match(/\d{4}/) || [''])[0],
    score: normScore(s.imdb),
    episodes: null,
    intro: '',
    category: 0, // se; the SPA echoes it back, /api/mb/play derives se/ep from episodeId
  };
}

app.get('/api/mb/home', async (req, res) => {
  try {
    // Every MovieBox endpoint needs an account token; acquire (or self-heal) it
    // ONCE here so the parallel browse calls below all reuse the cached one
    // instead of each racing into a fresh registration.
    await mb.ensureToken().catch(() => null);
    // Two pages of the operating page give a good spread of curated rows.
    const pages = await Promise.all([
      mb.tabOperatingPage({ tabId: 0, pageNum: 1, pageSize: 8 }).catch(() => null),
      mb.tabOperatingPage({ tabId: 0, pageNum: 2, pageSize: 8 }).catch(() => null),
    ]);
    const sections = [];
    const seenTitles = new Set();
    for (const data of pages) {
      const items = (data && data.items) || [];
      for (const it of items) {
        // Only the clean poster rows — skip banners, filters, clip/CUSTOM rails.
        if (it.type !== 'SUBJECTS_MOVIE') continue;
        const subs = (it.subjects || []).filter(s => s && s.subjectId && s.cover && s.cover.url);
        if (!subs.length) continue;
        const title = String(it.title || '').trim() || 'Featured';
        if (seenTitles.has(title.toLowerCase())) continue;
        seenTitles.add(title.toLowerCase());
        sections.push({
          title,
          items: subs.slice(0, 18).map(s => mbCard({
            subjectId: s.subjectId, title: s.title, subjectType: s.subjectType,
            releaseDate: s.releaseDate, imdb: s.imdbRatingValue || s.imdbRate, cover: s.cover.url,
          })),
        });
        if (sections.length >= 10) break;
      }
      if (sections.length >= 10) break;
    }
    res.json({ sections });
  } catch (e) {
    oops(res, 502, 'home unavailable', e);
  }
});

app.get('/api/mb/search', async (req, res) => {
  const raw = String(req.query.q || '').slice(0, 80).trim();
  if (!raw) return res.json({ query: '', results: [], rawCount: 0 });
  try {
    // perPage caps at 20 upstream, so pull several pages and merge to match the
    // app's fuller result list (e.g. all the Spider-Man titles, not just 20).
    await mb.ensureToken().catch(() => null);
    const pages = await Promise.all([1, 2, 3].map(p =>
      mb.search(raw, { page: p, perPage: 20 }).catch(() => null)));
    const seen = new Set();
    const subs = [];
    for (const data of pages) {
      for (const s of mb.extractSubjects(data)) {
        if (s.subjectId && s.cover && !seen.has(s.subjectId)) { seen.add(s.subjectId); subs.push(s); }
      }
    }
    if (subs.length) {
      return res.json({ query: raw, results: subs.map(mbCard), rawCount: subs.length });
    }
    // Nothing matched — show a popular rail from the home rows, like ZX 1 does.
    const home = await mb.tabOperatingPage({ tabId: 0, pageNum: 2, pageSize: 8 }).catch(() => null);
    const rec = [];
    for (const it of ((home && home.items) || [])) {
      if (it.type !== 'SUBJECTS_MOVIE') continue;
      for (const s of (it.subjects || [])) {
        if (s && s.subjectId && s.cover && s.cover.url && rec.length < 18)
          rec.push(mbCard({ subjectId: s.subjectId, title: s.title, subjectType: s.subjectType,
            releaseDate: s.releaseDate, imdb: s.imdbRatingValue || s.imdbRate, cover: s.cover.url }));
      }
    }
    res.json({ query: raw, results: rec, rawCount: 0, recommended: true });
  } catch (e) {
    oops(res, 502, 'search unavailable', e);
  }
});

// MovieBox ids are numeric strings; keep them short-slug safe.
const MB_ID_RE = /^[0-9]{1,32}$/;
function badMbId(v) { return v == null || !MB_ID_RE.test(String(v)); }

app.get('/api/mb/title/:id', async (req, res) => {
  const id = req.params.id;
  if (badMbId(id)) return fail(res, 400, 'bad id');
  try {
    await mb.ensureToken().catch(() => null);
    const [d, seas] = await Promise.all([
      mb.subjectGet(id, { se: 0 }),
      mb.seasonInfo(id).catch(() => null),
    ]);
    if (!d || typeof d !== 'object') return fail(res, 404, 'title not found');
    const seasons = (seas && seas.seasons) || [];
    const isSeries = mbType(d.subjectType) === 'Series' || seasons.some(s => Number(s.maxEp) > 1);
    const episodes = [];
    if (isSeries) {
      // Flatten seasons -> a single episode list; episodeId encodes "se_ep" so
      // /api/mb/play can recover both without a title-level season field.
      let running = 0;
      for (const s of seasons) {
        const se = Number(s.se) || 0;
        const maxEp = Math.max(1, Number(s.maxEp) || 0);
        for (let ep = 1; ep <= maxEp; ep++) {
          running++;
          episodes.push({
            episodeId: se + '_' + ep,
            seriesNo: seasons.length > 1 ? running : ep,
            name: seasons.length > 1 ? ('S' + se + 'E' + ep) : '',
            totalTime: 0,
            viewable: true,
          });
        }
      }
    }
    const genre = String(d.genre || '').split(/[,،]/).map(x => x.trim()).filter(Boolean);
    const rd = String(d.releaseDate || '');
    res.json({
      id: String(id),
      category: 0,
      name: mbClean(d.title),
      enName: '',
      year: (rd.match(/\d{4}/) || [''])[0],
      type: mbType(d.subjectType),
      cover: (d.cover && d.cover.url) || '',
      backdrop: (d.cover && d.cover.url) || '',
      intro: d.description || '',
      tags: genre.slice(0, 6),
      areas: d.countryName ? [d.countryName] : [],
      score: normScore(d.imdbRatingValue),
      episodeCount: isSeries ? episodes.length : 1,
      episodes,
    });
  } catch (e) {
    oops(res, 502, 'title unavailable', e);
  }
});

// Pick one playable .mp4 per resolution, preferring browser-friendly H.264 over
// HEVC and always requiring a non-empty signed link.
//
// MovieBox slips a ~20s "Installation Failed — download the latest version"
// promo into the resource list (often as the top-resolution entry, to bait the
// picker). It's far shorter than the real film, so we drop any entry whose
// duration is a tiny fraction of the longest one — that removes the ad/preview
// while keeping the genuine full-length uploads. If everything is short (a truly
// VIP-locked title that only exposes the promo), nothing survives and the caller
// reports it unavailable rather than playing the ad as if it were the film.
function mbPickResources(list) {
  // Only self-signed links (…?sign=…&t=…) are playable as-is. Unsigned CDN urls
  // (e.g. macdn.aoneroom.com/other/*.mp4) return a ~20s promo unless the play-info
  // CloudFront cookie is attached, so we don't treat those as direct sources —
  // the caller falls back to the play-info stream+cookie for them.
  const withLink = (list || []).filter(r => r && r.resourceLink && /[?&]sign=/.test(r.resourceLink));
  const maxDur = withLink.reduce((m, r) => Math.max(m, Number(r.duration) || 0), 0);
  const real = withLink.filter(r => {
    const d = Number(r.duration) || 0;
    if (maxDur >= 120 && d > 0 && d < 60 && d < maxDur * 0.3) return false; // promo/preview clip
    return true;
  });
  const byRes = new Map();
  for (const r of real) {
    const res = Number(r.resolution) || 0;
    const codec = String(r.codecName || '').toLowerCase();
    const h264 = codec === 'h264' || codec === 'avc';
    const prev = byRes.get(res);
    if (!prev) byRes.set(res, { res, codec, link: r.resourceLink, h264 });
    else if (!prev.h264 && h264) byRes.set(res, { res, codec, link: r.resourceLink, h264 });
  }
  return [...byRes.values()].sort((a, b) => b.res - a.res);
}

app.get('/api/mb/play', async (req, res) => {
  const subjectId = req.query.contentId;
  if (badMbId(subjectId)) return fail(res, 400, 'contentId required');
  // episodeId encodes "se_ep" (movies: absent -> 0_0).
  let se = 0, ep = 0;
  const epRaw = String(req.query.episodeId || '');
  const m = epRaw.match(/^(\d+)_(\d+)$/);
  if (m) { se = Number(m[1]); ep = Number(m[2]); }
  const want = String(req.query.definition || '');
  try {
    await mb.ensureToken().catch(() => null);
    // resource/v2 indexes from 1 (movies report season 0 but still live at se=1).
    const rse = se > 0 ? se : 1;
    const rep = ep > 0 ? ep : 1;
    // A transient upstream hiccup on resource/v2 must not sink playback — series
    // don't need it at all (DASH comes from play-info). Try twice, then continue.
    let rdata = null;
    for (let a = 0; a < 2 && !rdata; a++) {
      try { rdata = await mb.resources(subjectId, { se: rse, ep: rep }); }
      catch (_) { if (a === 0) await new Promise(r => setTimeout(r, 400)); }
    }
    if (process.env.ZX_MB_DEBUG === '1') {
      console.error('[mb play] subject=' + subjectId + ' se=' + se + ' ep=' + ep + ' list=' +
        JSON.stringify(((rdata && rdata.list) || []).map(r => ({ res: r.resolution, codec: r.codecName,
          dur: r.duration, size: r.size, link: (r.resourceLink || '').slice(0, 90), vip: r.vipInfo && r.vipInfo.requireMemberType }))));
    }
    const picks = mbPickResources(rdata && rdata.list);
    const ua = sec.uaKey(req);
    // play-info gives the CloudFront-signed stream (url + signCookie) and the
    // streamId that unlocks subtitles. With the premium (PM) headers the BFF
    // returns the real stream here; movies usually also expose self-signed .mp4
    // resource links (played natively), while series expose only a DASH .mpd.
    let pi = null;
    for (let a = 0; a < 2 && !(pi && pi.streams && pi.streams.length); a++) {
      try { pi = await mb.playInfo(subjectId, { se, ep }); } catch (_) {}
      if (!(pi && pi.streams && pi.streams.length) && a === 0) await new Promise(r => setTimeout(r, 400));
    }
    const streams = (pi && pi.streams) || [];
    // MovieBox's shared promo placeholder — never play it as the feature.
    const AD_RE = /b164fbfb4347792950bdfbfb563d39d9\.mp4/i;
    const piMp4 = streams.find(s => s && s.url && /\.mp4(\?|$)/i.test(s.url) && !AD_RE.test(s.url));
    const piDash = streams.find(s => s && s.url && /\.mpd(\?|$)/i.test(s.url));

    if (process.env.ZX_MB_DEBUG === '1') {
      console.error('[mb play2] picks=' + picks.length + ' streams=' +
        JSON.stringify(streams.map(s => ({ fmt: s.format, url: (s.url || '').slice(0, 70), ck: !!s.signCookie }))));
    }
    let mediaUrl, currentDefinition, qualities, isMp4 = true, isDash = false, hevc = false;
    if (picks.length) {
      // Self-signed resource links — best path: multiple resolutions, no cookie.
      const def = picks.find(p => p.h264) || picks[0];
      let chosen = def;
      const wm = want.match(/^r(\d+)$/);
      if (wm) { const hit = picks.find(p => p.res === Number(wm[1])); if (hit) chosen = hit; }
      mediaUrl = '/api/hls?t=' + mintHls(chosen.link, req._zxSid, ua, true);
      currentDefinition = 'r' + chosen.res;
      qualities = picks.map(p => ({ code: 'r' + p.res, label: p.res + 'p', vip: false }));
    } else if (piMp4) {
      // Progressive MP4 stream with its CloudFront cookie (proxy attaches it).
      const res0 = Number(String(piMp4.resolutions || '').split(',')[0]) || 0;
      mediaUrl = '/api/hls?t=' + mintHls(piMp4.url, req._zxSid, ua, true, piMp4.signCookie || '');
      currentDefinition = res0 ? 'r' + res0 : 'auto';
      qualities = res0 ? [{ code: 'r' + res0, label: res0 + 'p', vip: false }] : [];
    } else if (piDash) {
      // Series (and some films): adaptive DASH, played by dash.js. Proxy the
      // manifest so its segments carry the cookie; dash.js handles quality.
      mediaUrl = '/api/mbmpd?t=' + mintDash({ mpd: piDash.url, cookie: piDash.signCookie || '', sid: req._zxSid, ua });
      currentDefinition = 'auto';
      qualities = [];
      isMp4 = false; isDash = true;
      hevc = /h265|hevc/i.test(piDash.url); // flag HEVC so the client can warn if unsupported
    } else {
      return fail(res, 502, 'no playable source for this title');
    }

    // Subtitles from the play-info streamId (best-effort).
    let subtitles = [];
    try {
      const streamId = streams[0] && streams[0].id;
      if (streamId) {
        const cap = await mb.streamCaptions(subjectId, streamId);
        subtitles = ((cap && cap.extCaptions) || [])
          .filter(c => c && c.url)
          .map(c => ({
            lang: (c.lan || 'sub').slice(0, 8),
            label: c.lanName || c.lan || 'Subtitle',
            url: '/api/sub?t=' + mintSub(c.url, req._zxSid, ua, true),
          }));
      }
    } catch (_) { /* subtitles are best-effort */ }

    res.json({
      mediaUrl,
      currentDefinition,
      qualities,
      subtitles,
      mp4: isMp4,   // progressive MP4 — played natively
      dash: isDash, // DASH .mpd — played via dash.js
      hevc,         // true when the DASH stream is HEVC (client checks browser support)
    });
  } catch (e) {
    oops(res, 502, 'playback unavailable', e);
  }
});

// unknown /api route -> JSON 404 (don't fall through to the SPA shell / static)
app.use('/api', (req, res) => fail(res, 404, 'not found'));

// ---- static ----------------------------------------------------------------
app.use('/vendor', express.static(path.join(__dirname, 'node_modules', 'hls.js', 'dist')));
app.use('/vendor-dash', express.static(path.join(__dirname, 'node_modules', 'dashjs', 'dist')));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Last-resort error handler: log the stack server-side, never ship it to a client.
app.use((err, req, res, next) => {
  console.error('[unhandled]', (err && err.stack) || err);
  if (res.headersSent) return next(err);
  fail(res, 500, 'internal error');
});

// ---- startup ---------------------------------------------------------------
// Bring up a valid token first (login/create), then listen. If auth is briefly
// unreachable we still start serving and retry in the background, so static
// pages and cached content keep working instead of the whole site failing.
async function start() {
  try {
    await auth.init();
  } catch (e) {
    console.error('[auth] initial token setup failed:', e.message, '— retrying in background');
    const retry = setInterval(() => {
      auth.init().then(() => clearInterval(retry)).catch(() => {});
    }, 60000);
    if (retry.unref) retry.unref();
  }
  app.listen(PORT, () => {
    console.log(`ZX server on http://localhost:${PORT}  (token: ${client.token ? auth.daysLeft() + 'd left' : 'PENDING'})`);
    // Boot-time catalog gate banner. This is the fastest way to tell a STALE
    // deploy from a fresh one: keke='false' => full catalog (Spider-Man etc.);
    // keke='true' => restricted/fuzzy catalog that HIDES Hollywood. If a host
    // ever shows search junk again, read this line first before re-diagnosing.
    console.log(
      client.keke === 'false'
        ? `[zx] search catalog: FULL (keke=false) — Hollywood visible`
        : `[zx] search catalog: RESTRICTED (keke=${client.keke}) — Hollywood HIDDEN! set LOKLOK_KEKE=false or redeploy current code`
    );
    // Region gate #2 is defeated by the device-reported geo headers (lib/loklok.js):
    // we CLAIM geoIsoCode=<full-catalog country> with geoReliable='1', so the upstream
    // picks the catalog region from that instead of this host's egress IP. The
    // self-check below fires "spider man" and prints the region the upstream actually
    // used — if the geo override is working, region == our claimed country (default SA)
    // and Spider-Man shows, no matter where the host physically is. Fire-and-forget.
    console.log(
      client.geo && client.geo.isoCode
        ? `[zx] region override: claiming geoIsoCode=${client.geo.isoCode} reliable=${client.geo.reliable} (no proxy/Gulf host needed)`
        : `[zx] region override: DISABLED (geoIsoCode empty) — catalog will follow this host's egress IP`
    );
    (async () => {
      try {
        const r = await client.search('spider man', { size: 24 });
        const names = ((r && r.data && r.data.resultItems) || []).map(x => x.name || x.matchTitle);
        const spider = names.some(n => /spider-?man/i.test(n));
        const via = client.proxy ? 'via proxy' : (client.geo && client.geo.isoCode ? `via geo=${client.geo.isoCode}` : 'direct');
        console.log(spider
          ? `[zx] catalog self-check: region=${r._region} (${via}) — FULL, Spider-Man visible ✔`
          : `[zx] catalog self-check: region=${r._region} (${via}) — RESTRICTED (no Spider-Man). Geo override not honored: check geoReliable is the literal '1' (not 'true') and geoIsoCode is an uppercase full-catalog country (SA/AE/MA/DZ/RU). As a last resort set LOKLOK_PROXY to a MENA/RU egress.`);
      } catch (e) {
        console.log('[zx] catalog self-check skipped:', (e && e.message || e).toString().slice(0, 60));
      }
    })();
  });
}
start();
