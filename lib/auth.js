'use strict';
/**
 * auth.js — self-sustaining Loklok token lifecycle.
 *
 * A Loklok *email* account mints a 30-day JWT. Re-login rebuilds a fresh 30-day
 * token from just {email,password} — no OTP, no mailbox — so once an account
 * exists we renew forever. A throwaway mailbox (mail.tm) is only needed ONCE, to
 * receive the signup OTP, or rarely to create a replacement account if the
 * current one is banned/deleted.
 *
 * Proven live 2026-08-19 (see memory loklok-token-two-tier):
 *   create:  newCheck -> captcha/send -> (OTP via mail.tm) -> registerAndLogin -> token
 *   renew:   login -> token   (30-day exp each time; content endpoints accept it)
 *
 * The manager keeps `client.token` fresh in place, so server routes need no
 * changes. attach() also wraps the low-level request so any content call that
 * comes back A0230/A0800 transparently refreshes the token and retries once.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// The app identifies as this device/phone when logging in. Reusing the captured
// values keeps our traffic indistinguishable from the real client.
const PHONE_MODEL = 'OnePlus7Pro GM1910';
const PHONE_SYSTEM = 'android_11_OnePlus_RKQ1.201022.002';

const STORE_PATH = path.join(__dirname, '..', 'data', 'account.json');
const RENEW_BEFORE_MS = 3 * 24 * 3600 * 1000;   // refresh when < 3 days remain
const CHECK_EVERY_MS = 6 * 3600 * 1000;          // background staleness check
const AUTH_FAIL = new Set(['A0230', 'A0800']);   // session-expired / missing identity

// --------------------------------------------------------------- mail.tm -----
// Clean programmatic temp-mail (create account -> JWT -> read inbox). Chosen over
// temp-mail.io whose /messages endpoint refuses API-created mailboxes.
const MAILTM = 'https://api.mail.tm';

async function mt(pathname, opts = {}) {
  const r = await fetch(MAILTM + pathname, {
    ...opts,
    headers: { 'content-type': 'application/json', accept: 'application/json', ...(opts.headers || {}) },
  });
  const t = await r.text();
  let body; try { body = JSON.parse(t); } catch (_) { body = t; }
  return { status: r.status, body };
}

/** Provision a throwaway mailbox. Returns { address, token }. */
async function newMailbox() {
  const dom = await mt('/domains');
  const members = (dom.body && dom.body['hydra:member']) || [];
  const domain = members[0] && members[0].domain;
  if (!domain) throw new Error('mail.tm: no domain available');
  const address = 'zx' + crypto.randomBytes(5).toString('hex') + '@' + domain;
  const mailPass = 'Mt!' + crypto.randomBytes(6).toString('hex');
  const acc = await mt('/accounts', { method: 'POST', body: JSON.stringify({ address, password: mailPass }) });
  if (acc.status !== 201) throw new Error('mail.tm: account create failed (' + acc.status + ')');
  const tok = await mt('/token', { method: 'POST', body: JSON.stringify({ address, password: mailPass }) });
  if (!tok.body || !tok.body.token) throw new Error('mail.tm: token failed (' + tok.status + ')');
  return { address, token: tok.body.token };
}

/** Poll a mailbox for the Loklok OTP. Returns the numeric code as a string. */
async function waitForOtp(mailToken, { timeoutMs = 90000, intervalMs = 3000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  const auth = { authorization: 'Bearer ' + mailToken };
  while (Date.now() < deadline) {
    const list = await mt('/messages', { headers: auth });
    const items = (list.body && list.body['hydra:member']) || [];
    const hit = items.find(m =>
      /loklok/i.test((m.from && m.from.address) || '') || /verification|otp|code/i.test(m.subject || ''));
    if (hit) {
      const full = await mt('/messages/' + hit.id, { headers: auth });
      const text = [full.body && full.body.text, hit.intro, hit.subject].filter(Boolean).join(' ');
      const m = text.match(/Loklok:\s*([0-9]{4,6})/i) || text.match(/\b([0-9]{4,6})\b/);
      if (m) return m[1];
    }
    await new Promise(r => setTimeout(r, intervalMs));
  }
  throw new Error('OTP did not arrive within ' + Math.round(timeoutMs / 1000) + 's');
}

// ------------------------------------------------------------- loklok auth ---
function genPassword() {
  return 'Zx' + crypto.randomBytes(9).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 10) + '9';
}

/** POST /official/user/email/login — returns the raw API response. */
async function emailLogin(client, email, password) {
  return client.post('/official/user/email/login',
    { email, password, phoneModel: PHONE_MODEL, phoneSystem: PHONE_SYSTEM }, false);
}

/** Full signup: mailbox -> OTP -> registerAndLogin. Returns {email,password,token,userId}. */
async function createAccount(client, { log = () => {} } = {}) {
  const { address, token: mailToken } = await newMailbox();
  const password = genPassword();
  log('mailbox ' + address);

  await client.post('/official/user/email/register/newCheck', { email: address, invitationCode: '' }, false);
  const sent = await client.post('/official/user/email/register/captcha/send', { email: address }, false);
  if (!sent || sent.code !== '00000') throw new Error('captcha/send failed (' + (sent && sent.code) + ')');
  log('OTP requested; waiting for email…');

  const captcha = await waitForOtp(mailToken);
  log('OTP ' + captcha);

  const reg = await client.post('/official/user/email/registerAndLogin',
    { email: address, password, captcha, phoneModel: PHONE_MODEL, phoneSystem: PHONE_SYSTEM,
      registerType: '1', userId: '0', invitationCode: '' }, false);
  const token = reg && reg.data && reg.data.token;
  if (!token) throw new Error('registerAndLogin returned no token (' + (reg && reg.code) + ')');
  const userId = reg.data.userInfo && reg.data.userInfo.userId;
  log('registered userId ' + userId);
  return { email: address, password, token, userId };
}

// ----------------------------------------------------------------- store -----
function decodeExpMs(token) {
  try {
    const seg = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const p = JSON.parse(Buffer.from(seg, 'base64').toString('utf8'));
    return p.exp ? p.exp * 1000 : 0;
  } catch (_) { return 0; }
}
function readStore() {
  try { return JSON.parse(fs.readFileSync(STORE_PATH, 'utf8')); } catch (_) { return null; }
}
function writeStore(obj) {
  try {
    fs.mkdirSync(path.dirname(STORE_PATH), { recursive: true });
    fs.writeFileSync(STORE_PATH, JSON.stringify(obj, null, 2));
  } catch (_) { /* best-effort persistence */ }
}

// --------------------------------------------------------------- manager -----
class TokenManager {
  constructor(client, { log = console.log } = {}) {
    this.client = client;
    this.log = (m) => log('[auth] ' + m);
    this.acct = readStore() || {};      // { email, password, userId, token, exp }
    this._refreshing = null;            // coalesces concurrent refreshes
    this._timer = null;
  }

  msLeft() { return this.client.token ? decodeExpMs(this.client.token) - Date.now() : -1; }
  daysLeft() { return Math.max(0, Math.floor(this.msLeft() / 86400000)); }

  _save() {
    this.acct = { ...this.acct, token: this.client.token, exp: decodeExpMs(this.client.token) };
    writeStore({ ...this.acct, savedAt: new Date().toISOString() });
  }

  /** Ensure a valid token sits on the client. Reuses a fresh stored one, else refreshes. */
  async init() {
    if (this.acct.token && (decodeExpMs(this.acct.token) - Date.now()) > RENEW_BEFORE_MS) {
      this.client.token = this.acct.token;
      this.log('stored token OK, ' + this.daysLeft() + 'd left');
    } else {
      await this.refresh();
    }
    this._schedule();
    return this.client.token;
  }

  /** Mint a fresh token: re-login with stored creds, else create a new account. */
  refresh() {
    if (this._refreshing) return this._refreshing;
    this._refreshing = (async () => {
      if (this.acct.email && this.acct.password) {
        try {
          const r = await emailLogin(this.client, this.acct.email, this.acct.password);
          const tok = r && r.data && r.data.token;
          if (tok) { this.client.token = tok; this._save(); this.log('renewed via login, ' + this.daysLeft() + 'd'); return tok; }
          this.log('login rejected (' + (r && r.code) + ') — creating a new account');
        } catch (e) { this.log('login error: ' + e.message + ' — creating a new account'); }
      }
      const acc = await createAccount(this.client, { log: (m) => this.log(m) });
      this.acct = { email: acc.email, password: acc.password, userId: acc.userId };
      this.client.token = acc.token;
      this._save();
      this.log('new account live, ' + this.daysLeft() + 'd');
      return acc.token;
    })().finally(() => { this._refreshing = null; });
    return this._refreshing;
  }

  _schedule() {
    if (this._timer) clearInterval(this._timer);
    this._timer = setInterval(() => {
      if (this.msLeft() < RENEW_BEFORE_MS) this.refresh().catch(e => this.log('auto-renew failed: ' + e.message));
    }, CHECK_EVERY_MS);
    if (this._timer.unref) this._timer.unref();
  }

  /**
   * Wrap client._request so token-bearing content calls transparently recover
   * from A0230/A0800: refresh the token once, then replay the request.
   */
  attach() {
    const orig = this.client._request.bind(this.client);
    const self = this;
    this.client._request = async function (method, reqPath, opts = {}) {
      const r = await orig(method, reqPath, opts);
      const isAuthPath = /\/user\/email\/|\/auth\//.test(reqPath);
      if (r && opts.withToken !== false && !opts._retry && !isAuthPath && AUTH_FAIL.has(r.code)) {
        self.log('content call ' + reqPath.split('?')[0] + ' -> ' + r.code + '; refreshing + retrying');
        await self.refresh().catch(e => self.log('refresh during retry failed: ' + e.message));
        return orig(method, reqPath, { ...opts, _retry: true });
      }
      return r;
    };
    return this;
  }
}

module.exports = { TokenManager, createAccount, emailLogin, newMailbox, waitForOtp, decodeExpMs, readStore };
