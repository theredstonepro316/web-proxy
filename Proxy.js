#!/usr/bin/env node
// Forward web proxy: HTTP, HTTPS tunnels, caching, blocklist, live stats, web UI. No dependencies.
//
// Usage:
//   node proxy.js
//   PORT=9000 PROXY_USER=me PROXY_PASS=secret node proxy.js
//
// Then either open http://127.0.0.1:8080 (web page), or set your browser's proxy to 127.0.0.1:8080.
// Stats: http://127.0.0.1:8080/stats      Blocklist: edit blocklist.txt (reloads automatically)

const http = require('http');
const https = require('https');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = parseInt(process.env.PORT || '8080', 10);
const HOST = process.env.HOST || '0.0.0.0'; // required by hosted container platforms
const USER = process.env.PROXY_USER;
const PASS = process.env.PROXY_PASS;
const TIMEOUT_MS = parseInt(process.env.TIMEOUT_MS || '30000', 10);
const ALLOWED_ORIGINS = (process.env.FRONTEND_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);

const log = (...a) => console.log(new Date().toISOString(), ...a);
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ---------- 1. BLOCKLIST: refuse requests to listed sites ----------
const BLOCKLIST_FILE = path.join(__dirname, 'blocklist.txt');
let blocked = new Set();
function loadBlocklist() {
  try {
    blocked = new Set(fs.readFileSync(BLOCKLIST_FILE, 'utf8').split(/\r?\n/)
      .map(l => l.trim().toLowerCase()).filter(l => l && !l.startsWith('#')));
    log(`Blocklist loaded: ${blocked.size} entries`);
  } catch { blocked = new Set(); }
}
loadBlocklist();
fs.watchFile(BLOCKLIST_FILE, { interval: 2000 }, loadBlocklist);

function isBlocked(host) {
  const parts = host.toLowerCase().split('.');
  // "example.com" in the list also blocks "ads.example.com"
  for (let i = 0; i < parts.length; i++) if (blocked.has(parts.slice(i).join('.'))) return true;
  return false;
}

// ---------- 2. STATS: count what passes through ----------
const stats = { started: Date.now(), requests: 0, cacheHits: 0, blocked: 0, bytes: 0, hosts: {} };
function countRequest(host) {
  stats.requests++;
  (stats.hosts[host] ||= { requests: 0, bytes: 0 }).requests++;
}
function countBytes(host, n) {
  stats.bytes += n;
  (stats.hosts[host] ||= { requests: 0, bytes: 0 }).bytes += n;
}

// ---------- 3. CACHE: remember recent responses so repeat visits are instant ----------
const CACHE_MAX_ITEMS = 200, CACHE_MAX_BYTES = 2 * 1024 * 1024;
const cache = new Map(); // key -> { status, headers, body, expires }

function cacheGet(key) {
  const e = cache.get(key);
  if (!e) return null;
  if (e.expires < Date.now()) { cache.delete(key); return null; }
  cache.delete(key); cache.set(key, e); // move to the "most recently used" end
  return e;
}
function ttlMs(headers) {
  const cc = (headers['cache-control'] || '').toLowerCase();
  if (/no-store|no-cache|private/.test(cc) || headers['set-cookie']) return 0; // not safe to share
  const m = cc.match(/max-age=(\d+)/);
  return Math.min(m ? parseInt(m[1], 10) : 60, 600) * 1000; // default 1 min, max 10 min
}
function cacheSet(key, status, headers, body) {
  const ttl = ttlMs(headers);
  if (!ttl) return;
  cache.set(key, { status, headers, body, expires: Date.now() + ttl });
  while (cache.size > CACHE_MAX_ITEMS) cache.delete(cache.keys().next().value); // drop least recently used
}

// Send an upstream response to the client, counting bytes and (optionally) saving a copy in the cache.
function deliver(upRes, res, { key, host, status, headers }) {
  const chunks = []; let size = 0, tooBig = false;
  upRes.on('data', c => {
    countBytes(host, c.length);
    if (!key || tooBig) return;
    size += c.length;
    if (size > CACHE_MAX_BYTES) { tooBig = true; chunks.length = 0; } else chunks.push(c);
  });
  upRes.on('end', () => { if (key && !tooBig && status === 200) cacheSet(key, status, headers, Buffer.concat(chunks)); });
  upRes.pipe(res);
}

// ---------- Auth + header helpers ----------
const HOP_BY_HOP = ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade'];

function stripHopByHop(headers) {
  const out = { ...headers };
  const extra = (headers.connection || '').split(',').map(s => s.trim().toLowerCase());
  for (const h of [...HOP_BY_HOP, ...extra]) delete out[h];
  return out;
}
function basicOk(header) {
  if (!USER) return true;
  const [scheme, enc] = (header || '').split(' ');
  return scheme === 'Basic' && !!enc && Buffer.from(enc, 'base64').toString() === `${USER}:${PASS}`;
}

// ---------- Full proxy engine (rewrites pages, relays WebSockets) ----------
const full = require('./Fullproxy.js');
full.init({
  log, isBlocked, countRequest, countBytes, basicOk, authOn: !!USER, timeoutMs: TIMEOUT_MS,
  onBlocked: (u) => { stats.blocked++; log('BLOCKED', u); },
});

// ---------- Built-in web UI: web-proxy.html, /fetch relay, /stats ----------
function relay(target, redirectsLeft, res) {
  let t;
  try { t = new URL(target); } catch { res.writeHead(400); return res.end('Bad URL\n'); }
  if (!/^https?:$/.test(t.protocol)) { res.writeHead(400); return res.end('Only http(s) URLs\n'); }
  if (isBlocked(t.hostname)) {
    stats.blocked++; log('BLOCKED', t.href);
    res.writeHead(403, { 'Content-Type': 'text/plain' }); return res.end('Blocked by proxy blocklist\n');
  }
  const key = 'relay:' + t.href;
  const hit = cacheGet(key);
  if (hit) {
    stats.cacheHits++; countRequest(t.hostname); log('CACHE', t.href);
    res.writeHead(hit.status, { ...hit.headers, 'X-Cache': 'HIT' }); return res.end(hit.body);
  }
  log('FETCH', t.href); countRequest(t.hostname);

  const lib = t.protocol === 'https:' ? https : http;
  const upReq = lib.get(t, {
    timeout: TIMEOUT_MS,
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WebProxy/1.0)', 'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8', 'Accept-Encoding': 'identity' },
  }, (upRes) => {
    const loc = upRes.headers.location;
    if (upRes.statusCode >= 300 && upRes.statusCode < 400 && loc && redirectsLeft > 0) {
      upRes.resume();
      let next;
      try { next = new URL(loc, t); } catch { res.writeHead(502); return res.end('Bad redirect\n'); }
      return full.checkTarget(next.hostname, (ok) => ok ? relay(next.href, redirectsLeft - 1, res)
        : (res.writeHead(403, { 'Content-Type': 'text/plain' }), res.end('Blocked: private/local address\n')));
    }
    const headers = { 'Content-Type': upRes.headers['content-type'] || 'text/html', 'X-Final-Url': t.href };
    res.writeHead(upRes.statusCode, { ...headers, 'X-Cache': 'MISS' });
    deliver(upRes, res, { key, host: t.hostname, status: upRes.statusCode, headers });
  });
  upReq.on('timeout', () => upReq.destroy(new Error('Upstream timeout')));
  upReq.on('error', (err) => {
    if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end(`Bad gateway: ${err.message}\n`);
  });
}

function statsSnapshot() {
  return { uptimeSeconds: Math.round((Date.now() - stats.started) / 1000), requests: stats.requests,
    cacheHits: stats.cacheHits, cacheItems: cache.size, blocked: stats.blocked,
    blocklistEntries: blocked.size, megabytes: +(stats.bytes / 1048576).toFixed(2), hosts: stats.hosts };
}

function serveLocal(req, res) {
  const requestUrl = new URL(req.url, 'http://localhost');
  if (requestUrl.pathname === '/healthz') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('ok\n'); }
  if (!basicOk(req.headers.authorization)) {
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="proxy"' }); return res.end();
  }
  if (full.handle(req, res)) return; // /p/... pages and /__px/... helpers
  const u = new URL(req.url, 'http://localhost');
  if (u.pathname === '/') {
    return fs.readFile(path.join(__dirname, 'web-proxy.html'), (err, data) => {
      if (err) { res.writeHead(404); return res.end('web-proxy.html must be in the same folder as proxy.js\n'); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(data);
    });
  }
  if (u.pathname === '/fetch') {
    const target = u.searchParams.get('url') || '';
    let host = '';
    try { host = new URL(target).hostname; } catch { /* relay will answer 400 */ }
    return full.checkTarget(host, (ok) => ok ? relay(target, 5, res)
      : (res.writeHead(403, { 'Content-Type': 'text/plain' }), res.end('Blocked: private/local address\n')));
  }
  if (u.pathname === '/stats.json') {
    res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(statsSnapshot(), null, 2));
  }
  if (u.pathname === '/stats') {
    const s = statsSnapshot();
    const rows = Object.entries(s.hosts).sort((a, b) => b[1].requests - a[1].requests).slice(0, 50)
      .map(([h, v]) => `<tr><td>${esc(h)}</td><td>${v.requests}</td><td>${(v.bytes / 1024).toFixed(1)} KB</td></tr>`).join('');
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><meta charset="utf-8"><meta http-equiv="refresh" content="3"><title>Proxy stats</title>
<style>:root{color-scheme:light dark}body{font:15px system-ui;max-width:720px;margin:2rem auto;padding:0 1rem}
td,th{text-align:left;padding:4px 16px 4px 0}.k{display:flex;gap:2rem;flex-wrap:wrap;margin-bottom:1rem}.k div b{display:block;font-size:1.6rem}</style>
<h1>Proxy stats</h1><div class="k"><div><b>${s.requests}</b>requests</div><div><b>${s.cacheHits}</b>from cache</div>
<div><b>${s.blocked}</b>blocked</div><div><b>${s.megabytes} MB</b>received</div><div><b>${s.uptimeSeconds}s</b>uptime</div></div>
<table><tr><th>Site</th><th>Requests</th><th>Data</th></tr>${rows || '<tr><td colspan=3>Nothing yet</td></tr>'}</table>`);
  }
  if (full.fallback(req, res)) return; // stray request from a proxied page: send it to the right site
  res.writeHead(404); res.end('Not found\n');
}

// ---------- Browser CORS for a GitHub Pages frontend ----------
function applyCors(req, res) {
  const origin = req.headers.origin;
  if (!origin) return false;
  const allowed = ALLOWED_ORIGINS.includes(origin);
  if (allowed) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(allowed ? 204 : 403);
    res.end();
    return true;
  }
  return false;
}

// ---------- Plain HTTP through the proxy ----------
const server = http.createServer((req, res) => {
  if (applyCors(req, res)) return;
  if (req.url.startsWith('/')) return serveLocal(req, res); // a request to the proxy itself

  if (!basicOk(req.headers['proxy-authorization'])) {
    res.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="proxy"', 'Content-Length': 0 }); return res.end();
  }
  let target;
  try { target = new URL(req.url); } catch { res.writeHead(400); return res.end('Bad request\n'); }
  if (target.protocol !== 'http:') { res.writeHead(400); return res.end('Only http: here; https uses CONNECT.\n'); }

  const host = target.hostname;
  if (isBlocked(host)) {
    stats.blocked++; log('BLOCKED', req.url);
    res.writeHead(403, { 'Content-Type': 'text/plain' }); return res.end('Blocked by proxy blocklist\n');
  }
  countRequest(host);

  // Only cache plain GETs with no logins/cookies (anything personal must never be shared).
  const cacheable = req.method === 'GET' && !req.headers.cookie && !req.headers.authorization && !req.headers.range;
  const key = cacheable ? `${target.href}|${req.headers['accept-encoding'] || ''}` : null;
  const hit = key && cacheGet(key);
  if (hit) {
    stats.cacheHits++; log('CACHE', req.url);
    res.writeHead(hit.status, { ...hit.headers, 'X-Cache': 'HIT' }); return res.end(hit.body);
  }
  log(req.socket.remoteAddress, req.method, req.url);

  const upReq = http.request({
    hostname: host, port: target.port || 80, path: target.pathname + target.search,
    method: req.method, headers: stripHopByHop(req.headers), timeout: TIMEOUT_MS,
  }, (upRes) => {
    const headers = stripHopByHop(upRes.headers);
    res.writeHead(upRes.statusCode, { ...headers, 'X-Cache': 'MISS' });
    deliver(upRes, res, { key, host, status: upRes.statusCode, headers });
  });
  upReq.on('timeout', () => upReq.destroy(new Error('Upstream timeout')));
  upReq.on('error', (err) => {
    log('upstream error:', err.message);
    if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end(`Bad gateway: ${err.message}\n`);
  });
  req.on('aborted', () => upReq.destroy());
  req.pipe(upReq);
});

// ---------- HTTPS and WebSockets: CONNECT tunnels (encrypted, so no caching or editing possible) ----------
server.on('connect', (req, clientSocket, head) => {
  if (!basicOk(req.headers['proxy-authorization'])) {
    clientSocket.end('HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="proxy"\r\n\r\n');
    return;
  }
  const [host, portStr] = req.url.split(':');
  const port = parseInt(portStr, 10) || 443;
  if (isBlocked(host)) {
    stats.blocked++; log('BLOCKED', req.url);
    clientSocket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return;
  }
  countRequest(host);
  log(clientSocket.remoteAddress, 'CONNECT', req.url);

  const upstream = net.connect(port, host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length) upstream.write(head);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  });
  upstream.on('data', c => countBytes(host, c.length));
  upstream.setTimeout(TIMEOUT_MS * 4, () => upstream.destroy());
  upstream.on('error', (err) => {
    log('tunnel error:', err.message);
    if (clientSocket.writable) clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n');
  });
  clientSocket.on('error', () => upstream.destroy());
  clientSocket.on('close', () => upstream.destroy());
});

server.on('upgrade', (req, socket, head) => full.upgrade(req, socket, head)); // WebSockets for the full proxy

server.on('clientError', (err, socket) => { if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); });

server.listen(PORT, HOST, () => {
  log(`Proxy listening on ${HOST}:${PORT}${USER ? ' (auth enabled)' : ''}`);
  log(`Web page: http://${HOST}:${PORT}   Stats: http://${HOST}:${PORT}/stats`);
  if (!USER || !PASS) log('WARNING: PROXY_USER and PROXY_PASS are not set; protect this public proxy before sharing it.');
});
process.on('SIGINT', () => { log('Shutting down'); server.close(() => process.exit(0)); });
