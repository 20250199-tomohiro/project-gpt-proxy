import express from 'express';
import rateLimit from 'express-rate-limit';
import * as cheerio from 'cheerio';
import ipaddr from 'ipaddr.js';
import dns from 'node:dns';
import { Agent } from 'undici';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = Number(process.env.PORT) || 10000;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024; // 8 MB
const FETCH_TIMEOUT_MS = 12_000;
const MAX_REDIRECTS = 5;

app.disable('x-powered-by');
// Render sits behind a trusted reverse proxy. This makes req.ip reflect the visitor.
app.set('trust proxy', 1);
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

const proxyLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 90,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: 'アクセス回数が多すぎます。1分ほど待ってから再試行してください。'
});

app.get('/health', (_req, res) => res.status(200).send('ok'));

function isPublicIp(address) {
  try {
    // ipaddr.js labels private, loopback, link-local, multicast, documentation,
    // and other special-use ranges separately from ordinary unicast addresses.
    return ipaddr.parse(address).range() === 'unicast';
  } catch {
    return false;
  }
}

function validateTarget(rawUrl) {
  let target;
  try {
    target = new URL(rawUrl);
  } catch {
    throw new Error('URLの形式が正しくありません。');
  }
  if (!['http:', 'https:'].includes(target.protocol)) {
    throw new Error('http:// または https:// で始まるURLを入力してください。');
  }
  if (target.username || target.password) {
    throw new Error('ユーザー名・パスワードを含むURLにはアクセスできません。');
  }
  if (target.port && !['80', '443'].includes(target.port)) {
    throw new Error('安全のため、標準のWebポート（80/443）のみ利用できます。');
  }
  const host = target.hostname.toLowerCase().replace(/\.$/, '');
  if (!host || host === 'localhost' || host.endsWith('.localhost') ||
      host.endsWith('.local') || host.endsWith('.internal')) {
    throw new Error('ローカルネットワーク上のアドレスにはアクセスできません。');
  }
  return target;
}

// Validate DNS results at connection time and use the validated IP address,
// which helps prevent DNS-rebinding attacks against private network addresses.
function safeLookup(hostname, options, callback) {
  dns.lookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
    if (error) return callback(error);
    if (!addresses?.length || addresses.some(({ address }) => !isPublicIp(address))) {
      return callback(new Error('ローカルまたは予約済みのIPアドレスにはアクセスできません。'));
    }
    if (options?.all) return callback(null, addresses);
    const chosen = addresses[0];
    return callback(null, chosen.address, chosen.family);
  });
}

function toProxyUrl(url) {
  return `/proxy?url=${encodeURIComponent(url)}`;
}

function maybeAbsoluteUrl(value, baseUrl) {
  const trimmed = String(value ?? '').trim();
  if (!trimmed || trimmed.startsWith('#') || /^(?:javascript|data|mailto|tel|blob):/i.test(trimmed)) {
    return null;
  }
  try {
    const url = new URL(trimmed, baseUrl);
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    return url.href;
  } catch {
    return null;
  }
}

function rewriteCss(css, baseUrl) {
  // Rewrite url(...) and @import links. This intentionally covers common CSS
  // references; complex site-specific scripts may need additional handling.
  let output = String(css).replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (whole, quote, value) => {
    const absolute = maybeAbsoluteUrl(value, baseUrl);
    return absolute ? `url("${toProxyUrl(absolute)}")` : whole;
  });
  output = output.replace(/@import\s+(?:url\()?\s*(['"])(.*?)\1\s*\)?/gi, (whole, quote, value) => {
    const absolute = maybeAbsoluteUrl(value, baseUrl);
    return absolute ? `@import url("${toProxyUrl(absolute)}")` : whole;
  });
  return output;
}

function rewriteSrcset(value, baseUrl) {
  // Handles typical comma-separated srcset entries. Data URLs are left alone.
  return String(value).split(',').map((part) => {
    const bits = part.trim().split(/\s+/);
    if (!bits[0] || /^data:/i.test(bits[0])) return part.trim();
    const absolute = maybeAbsoluteUrl(bits[0], baseUrl);
    if (absolute) bits[0] = toProxyUrl(absolute);
    return bits.join(' ');
  }).join(', ');
}

function rewriteHtml(html, baseUrl) {
  const $ = cheerio.load(html, { decodeEntities: false });
  // Remove base tags so the proxied document can't redirect all browser-relative
  // requests around the proxy. Static URL-bearing attributes are rewritten below.
  $('base').remove();

  const urlAttributes = [
    'href', 'src', 'action', 'formaction', 'poster', 'cite', 'background',
    'xlink:href', 'data'
  ];
  $('*').each((_index, element) => {
    for (const attribute of urlAttributes) {
      const value = $(element).attr(attribute);
      if (value === undefined) continue;
      const absolute = maybeAbsoluteUrl(value, baseUrl);
      if (absolute) $(element).attr(attribute, toProxyUrl(absolute));
    }
    const srcset = $(element).attr('srcset');
    if (srcset) $(element).attr('srcset', rewriteSrcset(srcset, baseUrl));
    const style = $(element).attr('style');
    if (style) $(element).attr('style', rewriteCss(style, baseUrl));
  });

  $('style').each((_index, element) => {
    const css = $(element).html();
    if (css) $(element).html(rewriteCss(css, baseUrl));
  });

  // Add a small, dismissible navigation bar to return to the proxy home page.
  const toolbar = `
    <div id="basic-proxy-toolbar" style="position:sticky;top:0;z-index:2147483647;background:#172033;color:#fff;padding:8px 12px;font:14px/1.4 system-ui,sans-serif;display:flex;gap:10px;align-items:center;box-shadow:0 2px 8px #0003;">
      <a href="/" style="color:#fff;font-weight:700;text-decoration:none;white-space:nowrap;">← Proxy</a>
      <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;opacity:.9;flex:1;">${escapeHtml(baseUrl)}</span>
      <button type="button" onclick="document.getElementById('basic-proxy-toolbar').remove()" style="border:0;border-radius:6px;padding:4px 9px;cursor:pointer;">閉じる</button>
    </div>`;
  if ($('body').length) $('body').prepend(toolbar);
  else $.root().prepend(`<body>${toolbar}</body>`);

  // Keep a source URL hint for scripts which need to build absolute paths.
  const helperScript = `
    (function(){
      try { window.__BASIC_PROXY_SOURCE_URL__ = ${JSON.stringify(baseUrl)}; } catch (_) {}
      function proxify(value) {
        try {
          var raw = (typeof value === 'string') ? value : (value && value.url) ? value.url : String(value);
          var u = new URL(raw, window.__BASIC_PROXY_SOURCE_URL__);
          if ((u.protocol === 'http:' || u.protocol === 'https:') && u.origin !== location.origin) {
            return '/proxy?url=' + encodeURIComponent(u.href);
          }
        } catch (_) {}
        return value;
      }
      var originalFetch = window.fetch;
      if (originalFetch) window.fetch = function(input, init) {
        var next = proxify(input);
        if (input instanceof Request && typeof next === 'string') {
          try { next = new Request(next, input); } catch (_) { next = proxify(input.url); }
        }
        return originalFetch.call(this, next, init);
      };
      var originalOpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function(method, url) {
        var next = proxify(url);
        return originalOpen.apply(this, [method, next].concat([].slice.call(arguments, 2)));
      };
    })();`;
  if ($('head').length) $('head').append(`<script>${helperScript}</script>`);
  else $.root().prepend(`<head><script>${helperScript}</script></head>`);
  return $.html();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[char]);
}

async function readLimited(response) {
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
    throw new Error('取得したファイルが大きすぎます（上限8MB）。');
  }
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error('取得したファイルが大きすぎます（上限8MB）。');
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks);
}

app.get('/proxy', proxyLimiter, async (req, res) => {
  const rawUrl = req.query.url;
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return res.status(400).type('text/plain').send('URLが指定されていません。トップページに戻ってURLを入力してください。');
  }

  let target;
  let activeDispatcher = null;
  try {
    target = validateTarget(rawUrl.trim());
    let currentUrl = target.href;
    let upstream;

    for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
      // Validate every redirect target, not just the initial URL.
      target = validateTarget(currentUrl);
      activeDispatcher = new Agent({ connect: { lookup: safeLookup } });
      try {
        upstream = await fetch(target.href, {
          method: 'GET',
          redirect: 'manual',
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
          dispatcher: activeDispatcher,
          headers: {
            'user-agent': 'BasicWebProxy/1.0 (+limited public-web viewer)',
            'accept': req.get('accept') || '*/*',
            'accept-language': req.get('accept-language') || 'ja,en;q=0.8'
          }
        });
      } catch (error) {
        await activeDispatcher.close().catch(() => {});
        activeDispatcher = null;
        throw error;
      }

      if ([301, 302, 303, 307, 308].includes(upstream.status)) {
        const location = upstream.headers.get('location');
        if (!location) break;
        if (redirects === MAX_REDIRECTS) {
          await upstream.body?.cancel().catch(() => {});
          return res.status(502).type('text/plain').send('リダイレクトが多すぎます。');
        }
        currentUrl = new URL(location, target.href).href;
        await upstream.body?.cancel().catch(() => {});
        await activeDispatcher.close().catch(() => {});
        activeDispatcher = null;
        continue;
      }
      break;
    }

    if (!upstream) return res.status(502).type('text/plain').send('接続に失敗しました。');
    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
    const body = await readLimited(upstream);
    res.status(upstream.status);
    res.set('content-type', contentType);
    res.set('cache-control', 'no-store');
    res.set('x-content-type-options', 'nosniff');

    const finalUrl = target.href;
    if (/text\/html/i.test(contentType)) {
      return res.send(rewriteHtml(body.toString('utf8'), finalUrl));
    }
    if (/text\/css/i.test(contentType)) {
      return res.send(rewriteCss(body.toString('utf8'), finalUrl));
    }
    return res.send(body);
  } catch (error) {
    const message = error?.name === 'TimeoutError'
      ? '接続がタイムアウトしました。'
      : (error?.message || 'サイトの取得に失敗しました。');
    const status = /URLの形式|http:\/\/|ユーザー名|標準のWebポート|ローカル|予約済み|localhost/i.test(message) ? 400 : 502;
    return res.status(status).type('text/plain').send(message);
  } finally {
    if (activeDispatcher) await activeDispatcher.close().catch(() => {});
  }
});

app.all('/proxy', (_req, res) => {
  res.set('allow', 'GET').status(405).type('text/plain').send('この簡易プロキシはGETリクエストのみ対応しています。');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Basic Web Proxy listening on 0.0.0.0:${PORT}`);
});
