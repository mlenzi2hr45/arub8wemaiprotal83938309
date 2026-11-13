export const config = { runtime: 'edge', regions: ['fra1'] };

const ORIGIN = process.env.ORIGIN || 'https://europolus.ru';
const PREFIX = process.env.PREFIX || '/ar';
const BLOCK_REDIRECT = process.env.BLOCK_REDIRECT || 'https://www.google.com/';
const MY_IP = process.env.MY_IP || '';
const SECRET = process.env.SECRET || 'k9x2mQ7vLp4Rt8Zb';
const SITE_KEY = process.env.SITE_KEY || '';
const SECRET_KEY = process.env.SECRET_KEY || '';

const CH_COOKIE = 'hv';
const CH_TTL = 86400;
const LIMIT = 60;
const WINDOW = 60000;
const THRESHOLD = 5;
const MIN_MS = 800;

const HARD_UA = ['nmap','sqlmap','nikto','masscan','zgrab','curl/','wget/','python-requests','python-urllib','go-http-client','java/','okhttp','libwww-perl','httpclient','headlesschrome','phantomjs','puppeteer','playwright','selenium','ahrefs','semrush','mj12bot','dotbot','petalbot','bytespider','dataforseo','screaming frog','sitebulb','gptbot','claudebot','ccbot','perplexitybot'];

const DC = parseList('5.9.0.0/16 88.99.0.0/16 138.201.0.0/16 159.69.0.0/16 162.55.0.0/16 176.9.0.0/16 178.63.0.0/16 188.40.0.0/16 195.201.0.0/16 116.202.0.0/15 104.131.0.0/16 104.236.0.0/16 138.68.0.0/16 138.197.0.0/16 143.198.0.0/16 159.65.0.0/16 159.89.0.0/16 164.90.0.0/16 165.22.0.0/16 167.71.0.0/16 174.138.0.0/16 178.128.0.0/16 188.166.0.0/16 206.189.0.0/16 3.0.0.0/9 13.32.0.0/15 18.0.0.0/8 20.0.0.0/8 40.64.0.0/10 52.0.0.0/8 34.64.0.0/10 34.128.0.0/10 35.184.0.0/13 104.154.0.0/15 104.196.0.0/14 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22');
const SEARCH = parseList('66.249.64.0/19 66.249.66.0/23 64.233.160.0/19 72.14.192.0/18 209.85.128.0/17 216.239.32.0/19 142.250.0.0/15 172.217.0.0/16 2001:4860::/32 2a00:1450::/32');

function parseList(s) { return s.trim().split(/\s+/).filter(Boolean).map(parseCidr).filter(Boolean); }

function parseCidr(s) {
  const [ip, bits] = s.split('/');
  const base = ipToBig(ip);
  if (base === null) return null;
  return { fam: ip.includes(':') ? 6 : 4, base, bits: parseInt(bits, 10) };
}

function ipToBig(ip) {
  try {
    if (!ip.includes('.')) {
      const [h1, h2] = ip.split('::');
      const head = h1 ? h1.split(':').filter(Boolean) : [];
      const tail = h2 ? h2.split(':').filter(Boolean) : [];
      const pad = 8 - head.length - tail.length;
      const parts = [...head, ...Array(Math.max(pad, 0)).fill('0'), ...tail];
      let out = 0n;
      for (const p of parts) out = (out << 16n) | BigInt(parseInt(p || '0', 16));
      return out;
    }
    const p = ip.split('.').map(Number);
    if (p.length !== 4 || p.some(n => !(n >= 0 && n <= 255))) return null;
    return (BigInt(p[0]) << 24n) | (BigInt(p[1]) << 16n) | (BigInt(p[2]) << 8n) | BigInt(p[3]);
  } catch { return null; }
}

function inList(ip, list) {
  const v = ipToBig(ip);
  if (v === null) return false;
  const fam = ip.includes(':') ? 6 : 4;
  for (const c of list) {
    if (c.fam !== fam) continue;
    const shift = BigInt((fam === 4 ? 32 : 128) - c.bits);
    if (c.bits === 0 || (v >> shift) === (c.base >> shift)) return true;
  }
  return false;
}

async function hmac(data) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function eq(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function cookie(request, name) {
  for (const p of (request.headers.get('cookie') || '').split(';')) {
    const [k, ...v] = p.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

function clientIp(request) {
  const xff = request.headers.get('x-forwarded-for') || '';
  return xff.split(',')[0].trim() || '0.0.0.0';
}

const memLimit = new Map();

function rateLimited(ip) {
  const now = Date.now();
  let e = memLimit.get(ip);
  if (!e || now - e.start > WINDOW) { e = { start: now, n: 0 }; memLimit.set(ip, e); }
  e.n++;
  if (memLimit.size > 5000) for (const [k, v] of memLimit) if (now - v.start > WINDOW) memLimit.delete(k);
  return e.n > LIMIT;
}

function cleanPath(u) {
  const p = u.searchParams.get('__p') || '';
  const q = new URLSearchParams(u.searchParams);
  q.delete('__p'); q.delete('c'); q.delete('debug');
  const qs = q.toString();
  return '/' + p + (qs ? '?' + qs : '');
}

function targetUrl(request) {
  const u = new URL(request.url);
  const p = u.searchParams.get('__p') || '';
  const q = new URLSearchParams(u.searchParams);
  q.delete('__p'); q.delete('c'); q.delete('debug');
  const qs = q.toString();
  return new URL(PREFIX + '/' + p + (qs ? '?' + qs : ''), ORIGIN);
}

function proxyHeaders(request, ip) {
  const h = new Headers(request.headers);
  for (const k of [...h.keys()]) if (k.startsWith('cf-') || k.startsWith('x-vercel-')) h.delete(k);
  h.delete('host');
  h.set('host', new URL(ORIGIN).host);
  h.set('x-forwarded-for', ip);
  h.set('x-forwarded-proto', 'https');
  return h;
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function challenge(request, ip, err) {
  const u = new URL(request.url);
  const ts = Date.now();
  const base = cleanPath(u);
  const action = base + (base.includes('?') ? '&' : '?') + 'c=3';

  const html = '<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">'
    + '<title>checking</title>'
    + '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
    + '<body style="font:14px system-ui;margin:0;display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa">'
    + '<form id=cf method=POST action="' + esc(action) + '" style="text-align:center">'
    + '<div class="cf-turnstile" data-sitekey="' + esc(SITE_KEY) + '" data-theme="auto" data-callback="go"></div>'
    + '<script>function go(){document.getElementById("cf").submit()}</script>'
    + '<input type=hidden name=ts value="' + ts + '">'
    + '<input type=text name=website value="" tabindex=-1 autocomplete=off style="position:absolute;left:-9999px">'
    + '<noscript><button type=submit>continue</button></noscript>'
    + (err ? '<p style="color:#b00">' + esc(err) + '</p>' : '')
    + '</form></body>';

  return new Response(html, {
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }
  });
}

async function verifyTurnstile(request, ip) {
  let fd;
  try { fd = await request.formData(); } catch { return false; }

  if ((fd.get('website') || '').trim() !== '') return false;

  const ts = parseInt(fd.get('ts') || '0', 10);
  if (!ts || Date.now() - ts < MIN_MS) return false;

  const token = fd.get('cf-turnstile-response') || '';
  if (!token) return false;

  const body = new URLSearchParams();
  body.set('secret', SECRET_KEY);
  body.set('response', token);
  if (ip && ip !== '0.0.0.0') body.set('remoteip', ip);

  let out;
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body
    });
    out = await r.json();
  } catch {
    return true;
  }
  return out && out.success === true;
}

async function verifyCookie(request, ip) {
  const v = cookie(request, CH_COOKIE);
  if (!v) return false;
  const [ts, sig] = v.split('.');
  if (!ts || !sig) return false;
  if (Math.abs(Math.floor(Date.now() / 1000) - parseInt(ts, 10)) > CH_TTL) return false;
  return eq(sig, await hmac(ip + '|' + ts));
}

function score(request, ip) {
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  const h = request.headers;
  let s = 0;
  const why = [];

  if (!ua) { s += 3; why.push('no-ua'); }
  else if (ua.length < 25) { s += 2; why.push('short-ua'); }
  for (const b of HARD_UA) if (ua.includes(b)) { s += 6; why.push('ua:' + b); break; }

  if (['accept', 'accept-language', 'sec-fetch-mode', 'sec-ch-ua'].filter(k => !h.get(k)).length >= 3) { s += 2; why.push('no-headers'); }
  if (h.get('accept-language') === '*') { s += 1; why.push('lang-star'); }
  if (request.method === 'HEAD') { s += 1; why.push('head'); }

  if (inList(ip, DC)) { s += 3; why.push('dc'); }
  if (inList(ip, SEARCH)) { s -= 2; why.push('search'); }

  return { s, why };
}

async function passthrough(request, ip) {
  const init = { method: request.method, headers: proxyHeaders(request, ip), redirect: 'manual' };
  if (request.method !== 'GET' && request.method !== 'HEAD') init.body = request.body;

  let res;
  try {
    res = await fetch(targetUrl(request).toString(), init);
  } catch (e) {
    return new Response('origin error: ' + e.message, { status: 502 });
  }

  const origin = ORIGIN.replace(/\/$/, '');
  const self = new URL(request.url).origin;
  const h = new Headers(res.headers);

  const loc = h.get('location');
  if (loc) h.set('location', loc.split(origin).join(self));
  const sc = h.get('set-cookie');
  if (sc) h.set('set-cookie', sc.replace(/;\s*Domain=[^;]*/gi, ''));
  h.set('x-robots-tag', 'noindex');

  const ct = h.get('content-type') || '';
  let body = res.body;
  if (ct.includes('text/html') && request.method !== 'HEAD') {
    const text = await res.text();
    body = text.split(origin).join(self).split(new URL(origin).host).join(new URL(self).host);
    h.delete('content-length');
    if (request.method === 'GET' && !h.get('set-cookie')) {
      h.set('cache-control', 'public, s-maxage=60, stale-while-revalidate=300');
    }
  }
  return new Response(body, { status: res.status, statusText: res.statusText, headers: h });
}

async function handle(request) {
  const ip = clientIp(request);
  const mine = MY_IP.split(',').map(x => x.trim()).filter(Boolean);
  const isMine = mine.includes(ip);
  const u = new URL(request.url);
  const debug = isMine && u.searchParams.get('debug') === '1';

  if (isMine && !debug) return passthrough(request, ip);
  if (request.headers.get('upgrade') === 'websocket') return passthrough(request, ip);

  if (rateLimited(ip)) {
    if (debug) return new Response('rate', { status: 429 });
    return Response.redirect(BLOCK_REDIRECT, 302);
  }

  const { s, why } = score(request, ip);

  if (s >= THRESHOLD) {
    if (debug) return new Response('bot score=' + s + ' ' + why.join(','), { status: 403 });
    return Response.redirect(BLOCK_REDIRECT, 302);
  }

  if (u.searchParams.get('c') === '3' && request.method === 'POST') {
    const ok = await verifyTurnstile(request, ip);
    if (ok) {
      const ts = Math.floor(Date.now() / 1000);
      const sig = await hmac(ip + '|' + ts);
      return new Response(null, {
        status: 302,
        headers: {
          'location': cleanPath(u),
          'cache-control': 'no-store',
          'set-cookie': CH_COOKIE + '=' + ts + '.' + sig + '; Path=/; Max-Age=' + CH_TTL + '; HttpOnly; Secure; SameSite=Lax'
        }
      });
    }
    if (debug) return new Response('turnstile fail score=' + s, { status: 403 });
    return challenge(request, ip, 'verification failed, try again');
  }

  if (await verifyCookie(request, ip)) {
    if (debug) return new Response('pass score=' + s + ' ' + why.join(','), { status: 200 });
    return passthrough(request, ip);
  }

  if (debug) return new Response('challenge score=' + s + ' ' + why.join(','), { status: 403 });
  return challenge(request, ip, '');
}

export default async function handler(request) {
  try {
    return await handle(request);
  } catch (e) {
    try { return await passthrough(request, clientIp(request)); }
    catch (e2) { return new Response('worker error: ' + e.message + ' / ' + e2.message, { status: 502 }); }
  }
}
