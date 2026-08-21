'use strict';
// One-shot: strip ALL comments from shipped client JS in place. Comments in
// browser-delivered code hand a scraper the anti-scrape/token blueprint, so they
// must not ship. Character scanner that respects strings, template literals
// (incl. nested ${}), and regex literals so it never corrupts real code.
const fs = require('fs');
const path = require('path');

function stripComments(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  let prev = ''; // last meaningful (non-ws) char emitted — decides regex vs divide
  // stack of template-literal frames; each tracks the ${} brace depth we're inside
  const tpl = [];
  const isRegexPrev = () => {
    // A '/' starts a regex unless it follows a value (ident/number/close bracket).
    if (prev === '') return true;
    if (/[)\]}]/.test(prev)) return false;
    if (/[A-Za-z0-9_$]/.test(prev)) return false;
    return true;
  };
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    const frame = tpl.length ? tpl[tpl.length - 1] : null;

    // Inside a template literal's text portion (not inside its ${expr})
    if (frame && frame.braces === 0) {
      if (c === '\\') { out += c + (d || ''); i += 2; continue; }
      if (c === '`') { out += c; i++; tpl.pop(); prev = '`'; continue; }
      if (c === '$' && d === '{') { out += '${'; i += 2; frame.braces = 1; continue; }
      out += c; i++; continue;
    }

    // Line comment
    if (c === '/' && d === '/') {
      i += 2;
      while (i < n && src[i] !== '\n') i++;
      continue; // leave the newline; blank line collapsed later
    }
    // Block comment
    if (c === '/' && d === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    // String literals
    if (c === '"' || c === "'") {
      out += c; i++;
      while (i < n) {
        const s = src[i];
        if (s === '\\') { out += s + (src[i + 1] || ''); i += 2; continue; }
        out += s; i++;
        if (s === c) break;
      }
      prev = c; continue;
    }
    // Template literal open
    if (c === '`') {
      out += c; i++;
      tpl.push({ braces: 0 });
      prev = '`'; continue;
    }
    // Regex literal
    if (c === '/' && isRegexPrev()) {
      out += c; i++;
      let inClass = false;
      while (i < n) {
        const s = src[i];
        if (s === '\\') { out += s + (src[i + 1] || ''); i += 2; continue; }
        if (s === '[') inClass = true;
        else if (s === ']') inClass = false;
        out += s; i++;
        if (s === '/' && !inClass) break;
      }
      // flags
      while (i < n && /[a-z]/i.test(src[i])) { out += src[i]; i++; }
      prev = '/'; continue;
    }
    // Braces while inside a template expression: track depth to find the close
    if (frame && frame.braces > 0) {
      if (c === '{') frame.braces++;
      else if (c === '}') frame.braces--;
    }
    out += c; i++;
    if (!/\s/.test(c)) prev = c;
  }
  return out;
}

function tidy(src) {
  // Drop lines that are now empty/whitespace-only; trim trailing whitespace.
  // (Inter-tag whitespace in the HTML template strings is insignificant.)
  return src
    .split('\n')
    .map(l => l.replace(/[ \t]+$/, ''))
    .filter(l => l.trim() !== '')
    .join('\n') + '\n';
}

const files = process.argv.slice(2);
for (const f of files) {
  const abs = path.resolve(f);
  const src = fs.readFileSync(abs, 'utf8');
  const out = tidy(stripComments(src));
  fs.writeFileSync(abs, out);
  console.log(`stripped ${f}: ${src.length} -> ${out.length} bytes`);
}
