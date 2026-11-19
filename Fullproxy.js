'use strict';
// fullproxy.js - the "Full proxy" engine used by the web page (requires proxy.js; keep both in one folder).
//
// How it works:
//   /p/<real url>   A page or file is fetched for you. Its links, scripts and styles are rewritten so every
//                   follow-up request comes back through /p/ too. Relative links work on their own because
//                   the real address is part of the path.
//   /w/<ws url>     WebSocket connections are relayed (this is what live apps use).
//   /__px/shim.js   A script injected into every page. It patches fetch, XHR, WebSocket, history, cookies...
//                   so requests the page builds at runtime also go through the proxy.
//   Cookies         Kept in the proxy (a "cookie jar") per site, so sites don't see each other's cookies.
//
// Safety: private/local addresses are blocked unless you start with ALLOW_PRIVATE=1.

const http = require('http');
const https = require('https');
const tls = require('tls');
const net = require('net');
const zlib = require('zlib');
const dns = require('dns');
const { URL } = require('url');

const PREFIX = '/p/';
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1';
let deps = {};
const init = (d) => { deps = d; };

const unbracket = (h) => h.replace(/^\[|\]$/g, '');
const fixScheme = (s) => s.replace(/^(https?|wss?):\/(?!\/)/i, '$1://'); // some servers collapse "//" to "/"

// ---------- Safety: refuse local/private network targets ----------
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const l = ip.toLowerCase();
  return l === '::1' || l === '::' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') ||
    /^::ffff:(127|10|0)\./.test(l) || l.startsWith('::ffff:192.168.');
}
function checkTarget(host, cb) {
  if (ALLOW_PRIVATE) return cb(true);
  host = unbracket(host);
  if (net.isIP(host)) return cb(!isPrivateIp(host));
  dns.lookup(host, { all: true }, (err, addrs) => cb(err ? true : addrs.every((a) => !isPrivateIp(a.address))));
}

// ---------- Cookie jar ----------
const jar = new Map(); // domain -> Map("name|path" -> cookie)
function storeCookies(host, setCookies) {
  for (const sc of setCookies) {
    const [nv, ...attrs] = sc.split(';').map((s) => s.trim());
    const i = nv.indexOf('=');
    if (i < 1) continue;
    const c = { name: nv.slice(0, i), value: nv.slice(i + 1), path: '/', httpOnly: false, expires: 0 };
    let domain = host.toLowerCase();
    for (const a of attrs) {
      const [k, ...rest] = a.split('=');
      const key = k.toLowerCase(), val = rest.join('=');
      if (key === 'domain') domain = val.replace(/^\./, '').toLowerCase();
      else if (key === 'path') c.path = val || '/';
      else if (key === 'httponly') c.httpOnly = true;
      else if (key === 'max-age') c.expires = Date.now() + parseInt(val, 10) * 1000;
      else if (key === 'expires' && !c.expires) c.expires = Date.parse(val) || 0;
    }
    if (!(host === domain || host.endsWith('.' + domain))) continue; // a site can't set cookies for others
    const m = jar.get(domain) || new Map();
    jar.set(domain, m);
    const id = c.name + '|' + c.path;
    if (c.expires && c.expires <= Date.now()) m.delete(id); else m.set(id, c);
  }
}
function cookieHeader(host, pathname, includeHttpOnly) {
  const out = [];
  for (const [domain, m] of jar) {
    if (!(host === domain || host.endsWith('.' + domain))) continue;
    for (const [id, c] of m) {
      if (c.expires && c.expires < Date.now()) { m.delete(id); continue; }
      if (pathname.startsWith(c.path) && (includeHttpOnly || !c.httpOnly)) out.push(c.name + '=' + c.value);
    }
  }
  return out.join('; ');
}

// ---------- Rewriting ----------
// Relative links ("img.png", "../a") already resolve correctly under /p/<page url>.
// Only absolute, protocol-relative and root-relative ("/x") links need rewriting.
function rewriteUrl(v, base) {
  v = v.trim();
  if (!v || v[0] === '#' || /^(data|blob|javascript|mailto|tel|about):/i.test(v) || v.startsWith(PREFIX)) return v;
  if (v.startsWith('//')) return PREFIX + base.protocol + v;
  if (/^https?:\/\//i.test(v)) return PREFIX + v;
  if (v[0] === '/') return PREFIX + base.origin + v;
  return v;
}

function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (m, q, u) => `url(${q}${rewriteUrl(u, base)}${q})`)
    .replace(/@import\s+(['"])([^'"]+)\1/gi, (m, q, u) => `@import ${q}${rewriteUrl(u, base)}${q}`);
}

function rewriteHtml(html, base) {
  html = html
    .replace(/<meta\b[^>]*http-equiv\s*=\s*["']?content-security-policy[^>]*>/gi, '')
    .replace(/<base\b[^>]*>/gi, '')
    .replace(/\s+integrity\s*=\s*("[^"]*"|'[^']*')/gi, '')
    .replace(/(<meta\b[^>]*http-equiv\s*=\s*["']?refresh[^>]*content\s*=\s*["']\s*\d+\s*;\s*url=)([^"'>]+)/gi,
      (m, pre, u) => pre + rewriteUrl(u, base));
  html = html.replace(/(\s(?:href|src|action|formaction|poster|data|background)\s*=\s*)(?:"([^"]*)"|'([^']*)')/gi,
    (m, pre, dq, sq) => (dq !== undefined ? `${pre}"${rewriteUrl(dq, base)}"` : `${pre}'${rewriteUrl(sq, base)}'`));
  html = html.replace(/(\s(?:srcset|imagesrcset)\s*=\s*)"([^"]*)"/gi, (m, pre, v) =>
    `${pre}"${v.split(',').map((p) => { const s = p.trim().split(/\s+/); s[0] = rewriteUrl(s[0], base); return s.join(' '); }).join(', ')}"`);
  html = html.replace(/(<style\b[^>]*>)([\s\S]*?)(<\/style>)/gi, (m, a, css, c) => a + rewriteCss(css, base) + c);
  html = html.replace(/(\sstyle\s*=\s*)"([^"]*)"/gi, (m, pre, css) => `${pre}"${rewriteCss(css, base)}"`);

  const tag = '<script src="/__px/shim.js"></script>'; // must run before the page's own scripts
  if (/<head\b[^>]*>/i.test(html)) return html.replace(/<head\b[^>]*>/i, (m) => m + tag);
  if (/<html\b[^>]*>/i.test(html)) return html.replace(/<html\b[^>]*>/i, (m) => m + tag);
  return tag + html;
}

// ---------- Client-side shim (runs inside every proxied page) ----------
function clientShim() {
  'use strict';
  const rawOpen = XMLHttpRequest.prototype.open;
  const base = () => (location.pathname.slice(3) + location.search).replace(/^(https?):\/(?!\/)/i, '$1://');
  const SKIP = /^(data|blob|javascript|mailto|tel|about):/i;

  function proxify(u) {
    if (u == null) return u;
    try {
      if (typeof u === 'object' && 'href' in u) u = u.href;
      u = String(u);
      if (!u || u[0] === '#' || SKIP.test(u)) return u;
      if (u.startsWith(location.origin + '/p/') || u.startsWith('/p/') || u.startsWith('/__px/') || u.startsWith(location.origin + '/__px/')) return u;
      if (u.startsWith(location.origin + '/')) u = u.slice(location.origin.length); // built from location.origin
      return '/p/' + new URL(u, base()).href;
    } catch (e) { return u; }
  }
  const isUrlLike = (x) => typeof x === 'string' || x instanceof URL;

  // fetch / Request / XHR / beacon / EventSource
  if (window.fetch) {
    const of = window.fetch.bind(window);
    window.fetch = (i, o) => of(isUrlLike(i) ? proxify(i) : i, o);
  }
  if (window.Request) {
    const OR = window.Request;
    window.Request = class extends OR { constructor(i, o) { super(isUrlLike(i) ? proxify(i) : i, o); } };
  }
  XMLHttpRequest.prototype.open = function (m, u, ...rest) { return rawOpen.call(this, m, proxify(u), ...rest); };
  if (navigator.sendBeacon) { const ob = navigator.sendBeacon.bind(navigator); navigator.sendBeacon = (u, d) => ob(proxify(u), d); }
  if (window.EventSource) {
    const OE = window.EventSource;
    window.EventSource = function (u, o) { return new OE(proxify(u), o); };
    window.EventSource.prototype = OE.prototype;
  }

  // WebSocket: relayed through /w/
  const OW = window.WebSocket;
  if (OW) window.WebSocket = function (url, protocols) {
    const abs = new URL(String(url), base()).href.replace(/^http/i, 'ws');
    const u = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/w/' + abs;
    return protocols === undefined ? new OW(u) : new OW(u, protocols);
  };
  if (OW) {
    window.WebSocket.prototype = OW.prototype;
    ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach((k) => { window.WebSocket[k] = OW[k]; });
  }

  // Elements whose address is set from JavaScript
  [[HTMLScriptElement, 'src'], [HTMLImageElement, 'src'], [HTMLIFrameElement, 'src'], [HTMLEmbedElement, 'src'],
    [HTMLSourceElement, 'src'], [HTMLMediaElement, 'src'], [HTMLTrackElement, 'src'], [HTMLInputElement, 'src'],
    [HTMLLinkElement, 'href'], [HTMLAnchorElement, 'href'], [HTMLFormElement, 'action'], [HTMLObjectElement, 'data'],
  ].forEach(([C, p]) => {
    const d = Object.getOwnPropertyDescriptor(C.prototype, p);
    if (d && d.set) Object.defineProperty(C.prototype, p, { configurable: true, enumerable: d.enumerable, get: d.get, set(v) { d.set.call(this, proxify(v)); } });
  });
  const sa = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (n, v) {
    if (typeof v === 'string' && ['src', 'href', 'action', 'data', 'poster'].includes(String(n).toLowerCase())) v = proxify(v);
    return sa.call(this, n, v);
  };

  // Workers, history, service workers
  ['Worker', 'SharedWorker'].forEach((n) => {
    const O = window[n];
    if (O) window[n] = class extends O { constructor(u, o) { super(proxify(u), o); } };
  });
  ['pushState', 'replaceState'].forEach((m) => {
    const o = history[m];
    history[m] = function (s, t, url) { return o.call(this, s, t, url == null ? url : proxify(url)); };
  });
  if (navigator.serviceWorker) navigator.serviceWorker.register = () => Promise.reject(new Error('Service workers are disabled by the proxy'));

  // New tabs and windows: window.open, links created by the page's own code, and navigations like location.href = ...
  const oo = window.open;
  if (oo) window.open = function (u, ...rest) { return oo.call(this, u == null || u === '' ? u : proxify(u), ...rest); };
  const fixLink = (e) => { // runs just before a link is followed, middle-clicked or right-clicked ("open in new tab")
    const el = e.target && e.target.closest ? e.target.closest('a[href], area[href]') : null;
    if (!el) return;
    const h = el.getAttribute('href'), p = proxify(h);
    if (p !== h) sa.call(el, 'href', p);
  };
  ['mousedown', 'click', 'auxclick', 'contextmenu', 'touchstart', 'keydown'].forEach((t) => document.addEventListener(t, fixLink, true));
  document.addEventListener('submit', (e) => {
    const f = e.target, a = f && f.getAttribute ? f.getAttribute('action') : null;
    if (a) { const p = proxify(a); if (p !== a) sa.call(f, 'action', p); }
  }, true);
  if (window.navigation && window.navigation.addEventListener) { // catches location.href = "..." / location.assign(...)
    window.navigation.addEventListener('navigate', (e) => {
      if (!e.cancelable || e.destination.sameDocument || e.hashChange || e.formData || e.downloadRequest != null) return;
      if (e.navigationType !== 'push' && e.navigationType !== 'replace') return;
      const d = e.destination.url;
      // Do not intercept a URL that is already routed through this proxy. This guard
      // prevents a proxified redirect from being wrapped a second time (redirect loops).
      if (d.startsWith(location.origin + PREFIX) || d.startsWith(PREFIX)) return;
      const p = new URL(proxify(d), location.href).href;
      if (p === d || !p.startsWith(location.origin + PREFIX)) return;
      e.preventDefault();
      location[e.navigationType === 'replace' ? 'replace' : 'assign'](p);
    });
  }

  // Cookies live in the proxy's jar, not in the browser
  Object.defineProperty(document, 'cookie', {
    configurable: true,
    get() { const x = new XMLHttpRequest(); rawOpen.call(x, 'GET', '/__px/cookie?u=' + encodeURIComponent(base()), false); x.send(); return x.responseText; },
    set(v) { const x = new XMLHttpRequest(); rawOpen.call(x, 'POST', '/__px/cookie?u=' + encodeURIComponent(base()), false); x.send(String(v)); },
  });
}
const SHIM = '(' + clientShim.toString() + ')();';

// ---------- Request handling ----------
function realFromProxyUrl(str) {
  try {
    const u = new URL(str);
    if (!u.pathname.startsWith(PREFIX)) return null;
    return new URL(fixScheme(u.pathname.slice(PREFIX.length) + u.search));
  } catch { return null; }
}

const STRIP = new Set(['content-security-policy', 'content-security-policy-report-only', 'x-frame-options',
  'strict-transport-security', 'set-cookie', 'cross-origin-opener-policy', 'cross-origin-embedder-policy',
  'cross-origin-resource-policy', 'report-to', 'nel', 'permissions-policy', 'clear-site-data', 'alt-svc', 'link',
  'connection', 'keep-alive', 'transfer-encoding']);
const SKIP_REQ = new Set(['host', 'connection', 'keep-alive', 'upgrade', 'te', 'trailer', 'transfer-encoding',
  'proxy-connection', 'proxy-authorization', 'cookie', 'referer', 'origin', 'accept-encoding']);

function decoderFor(enc) {
  enc = (enc || '').toLowerCase();
  if (enc === 'gzip' || enc === 'x-gzip') return zlib.createGunzip();
  if (enc === 'deflate') return zlib.createInflate();
  if (enc === 'br') return zlib.createBrotliDecompress();
  return null;
}

function fail(res, code, msg) {
  if (!res.headersSent) res.writeHead(code, { 'Content-Type': 'text/plain' });
  res.end(msg + '\n');
}

function proxyRequest(req, res, t) {
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (SKIP_REQ.has(k)) continue;
    if (k === 'authorization' && deps.authOn && deps.basicOk(v)) continue; // that's the proxy's own login
    headers[k] = v;
  }
  const ref = realFromProxyUrl(req.headers.referer);
  headers.host = t.host;
  headers['accept-encoding'] = 'gzip, deflate, br';
  const ck = cookieHeader(t.hostname, t.pathname, true);
  if (ck) headers.cookie = ck;
  if (ref) headers.referer = ref.href;
  if (req.headers.origin) headers.origin = (ref || t).origin;

  const secure = t.protocol === 'https:';
  deps.countRequest(t.hostname);
  deps.log(req.method, t.href);
  const up = (secure ? https : http).request({
    hostname: unbracket(t.hostname), port: t.port || (secure ? 443 : 80), path: t.pathname + t.search,
    method: req.method, headers, timeout: deps.timeoutMs,
  }, (upRes) => onResponse(req, res, t, upRes));
  up.on('timeout', () => up.destroy(new Error('Upstream timeout')));
  up.on('error', (err) => { deps.log('upstream error:', err.message); fail(res, 502, 'Bad gateway: ' + err.message); });
  req.on('aborted', () => up.destroy());
  req.pipe(up);
}

function onResponse(req, res, t, upRes) {
  const status = upRes.statusCode;
  if (upRes.headers['set-cookie']) storeCookies(t.hostname, upRes.headers['set-cookie']);
  const out = {};
  for (const [k, v] of Object.entries(upRes.headers)) if (!STRIP.has(k)) out[k] = v;
  if (out.location) { try { out.location = rewriteUrl(new URL(out.location, t).href, t); } catch { /* leave as is */ } }

  const ct = (upRes.headers['content-type'] || '').toLowerCase();
  const kind = /text\/html|application\/xhtml\+xml/.test(ct) ? 'html' : /text\/css/.test(ct) ? 'css' : null;
  const enc = upRes.headers['content-encoding'];
  const dec = decoderFor(enc);
  const canRewrite = kind && status !== 206 && status !== 204 && status !== 304 && req.method !== 'HEAD' && (!enc || dec);

  if (!canRewrite) { // images, video, scripts, JSON, streams...: pass straight through
    res.writeHead(status, out);
    upRes.on('data', (c) => deps.countBytes(t.hostname, c.length));
    upRes.pipe(res);
    return;
  }
  const src = dec ? upRes.pipe(dec) : upRes;
  const chunks = [];
  src.on('data', (c) => { chunks.push(c); deps.countBytes(t.hostname, c.length); });
  src.on('error', (err) => fail(res, 502, 'Decode error: ' + err.message));
  src.on('end', () => {
    const buf = Buffer.concat(chunks);
    const charset = (ct.match(/charset=["']?([^;"'\s]+)/) || [])[1] || 'utf-8';
    let text;
    try { text = new TextDecoder(charset).decode(buf); } catch { text = buf.toString('utf8'); }
    text = kind === 'html' ? rewriteHtml(text, t) : rewriteCss(text, t);
    delete out['content-encoding']; delete out['content-length']; delete out.etag; delete out['last-modified'];
    out['content-type'] = (kind === 'html' ? 'text/html' : 'text/css') + '; charset=utf-8';
    res.writeHead(status, out);
    res.end(text);
  });
}

// Handles /p/... and /__px/... . Returns true if the request was handled here.
function handle(req, res) {
  if (req.url.startsWith('/__px/')) { px(req, res); return true; }
  if (!req.url.startsWith(PREFIX)) return false;

  const raw = fixScheme(req.url.slice(PREFIX.length));
  const bare = raw.match(/^(https?:\/\/[^/?#]+)(\?.*)?$/i); // "https://host" -> add the slash so relative links work
  if (bare) { res.writeHead(302, { Location: PREFIX + bare[1] + '/' + (bare[2] || '') }); res.end(); return true; }

  let t;
  try { t = new URL(raw); } catch { fail(res, 400, 'Bad URL'); return true; }
  if (!/^https?:$/.test(t.protocol)) { fail(res, 400, 'Only http(s) URLs'); return true; }
  if (deps.isBlocked(t.hostname)) { deps.onBlocked(t.href); fail(res, 403, 'Blocked by proxy blocklist'); return true; }
  checkTarget(t.hostname, (ok) => {
    if (!ok) return fail(res, 403, 'Blocked: private/local address (start with ALLOW_PRIVATE=1 to allow)');
    proxyRequest(req, res, t);
  });
  return true;
}

// A request that escaped the rewriting (e.g. "/favicon.ico"): use the page it came from to find the right site.
function fallback(req, res) {
  const ref = realFromProxyUrl(req.headers.referer);
  if (!ref) return false;
  res.writeHead(307, { Location: PREFIX + ref.origin + req.url });
  res.end();
  return true;
}

function px(req, res) {
  const u = new URL(req.url, 'http://localhost');
  if (u.pathname === '/__px/shim.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'no-cache' });
    return res.end(SHIM);
  }
  if (u.pathname === '/__px/cookie') {
    let site;
    try { site = new URL(fixScheme(u.searchParams.get('u') || '')); } catch { return fail(res, 400, 'Bad URL'); }
    if (req.method === 'POST') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => { storeCookies(site.hostname, [body]); res.writeHead(204); res.end(); });
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
    return res.end(cookieHeader(site.hostname, site.pathname, false));
  }
  fail(res, 404, 'Not found');
}

// WebSocket relay: /w/wss://host/path
function upgrade(req, socket, head) {
  if (!req.url.startsWith('/w/')) { socket.destroy(); return; }
  if (!deps.basicOk(req.headers.authorization)) { socket.end('HTTP/1.1 401 Unauthorized\r\n\r\n'); return; }
  let t;
  try { t = new URL(fixScheme(req.url.slice(3))); } catch { socket.destroy(); return; }
  if (!/^wss?:$/.test(t.protocol) || deps.isBlocked(t.hostname)) { socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }

  checkTarget(t.hostname, (ok) => {
    if (!ok) { socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }
    const secure = t.protocol === 'wss:';
    const hostname = unbracket(t.hostname), port = t.port || (secure ? 443 : 80);
    const lines = [`GET ${t.pathname}${t.search} HTTP/1.1`, `Host: ${t.host}`];
    for (const [k, v] of Object.entries(req.headers)) {
      if (['host', 'origin', 'cookie', 'referer', 'authorization'].includes(k)) continue;
      lines.push(`${k}: ${v}`);
    }
    lines.push(`Origin: ${secure ? 'https' : 'http'}://${t.host}`);
    const ck = cookieHeader(t.hostname, t.pathname, true);
    if (ck) lines.push(`Cookie: ${ck}`);

    deps.countRequest(t.hostname);
    deps.log('WS', t.href);
    const onConnect = () => {
      up.write(lines.join('\r\n') + '\r\n\r\n');
      if (head && head.length) up.write(head);
      up.pipe(socket);
      socket.pipe(up);
    };
    const up = secure ? tls.connect({ host: hostname, port, servername: hostname }, onConnect) : net.connect(port, hostname, onConnect);
    up.on('data', (c) => deps.countBytes(t.hostname, c.length));
    up.on('error', () => socket.destroy());
    up.on('close', () => socket.destroy());
    socket.on('error', () => up.destroy());
    socket.on('close', () => up.destroy());
  });
}

module.exports = { init, handle, fallback, upgrade, checkTarget, _test: { rewriteHtml, rewriteCss, rewriteUrl, SHIM } };
