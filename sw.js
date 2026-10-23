// Decrypts the comps in the browser. Requests under ./site/ are mapped to ./d/<hmac(path)>.bin,
// decrypted with the keys the login page stored in IndexedDB, and answered with the original type.
const BASE = new URL('./', self.registration.scope);
const SITE = new URL('site/', BASE).pathname;
const TYPES = { html: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8', js: 'text/javascript; charset=utf-8', json: 'application/json', svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', gif: 'image/gif', mp4: 'video/mp4', webm: 'video/webm', woff2: 'font/woff2', pdf: 'application/pdf' };

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

function getKeys() {
  return new Promise(resolve => {
    const open = indexedDB.open('comps-keys', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('keys');
    open.onerror = () => resolve(null);
    open.onsuccess = () => {
      const req = open.result.transaction('keys').objectStore('keys').get('k');
      req.onsuccess = () => { const k = req.result; resolve(k && k.exp > Date.now() ? k : null); };
      req.onerror = () => resolve(null);
    };
  });
}

// Keep the last few decrypted files: <video> asks for many byte ranges of the same file
const memo = new Map();
async function decrypted(rel, keys) {
  if (memo.has(rel)) return memo.get(rel);
  const name = Array.from(new Uint8Array(await crypto.subtle.sign('HMAC', keys.mac, new TextEncoder().encode(rel))), b => b.toString(16).padStart(2, '0')).join('').slice(0, 40);
  const res = await fetch(new URL(`d/${name}.bin`, BASE));
  if (!res.ok) return null;
  const buf = await res.arrayBuffer();
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, keys.enc, buf.slice(12));
  memo.set(rel, plain);
  if (memo.size > 6) memo.delete(memo.keys().next().value);
  return plain;
}

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin || !url.pathname.startsWith(SITE)) return;
  e.respondWith((async () => {
    const keys = await getKeys();
    if (!keys) {
      if (e.request.mode === 'navigate') return Response.redirect(BASE.href, 302);
      return new Response('', { status: 401 });
    }
    let rel = decodeURIComponent(url.pathname.slice(SITE.length));
    if (rel === '' || rel.endsWith('/')) rel += 'index.html';
    const body = await decrypted(rel, keys);
    if (!body) return new Response('not found', { status: 404 });
    const type = TYPES[rel.split('.').pop().toLowerCase()] || 'application/octet-stream';
    const headers = { 'Content-Type': type, 'Accept-Ranges': 'bytes', 'Cache-Control': 'no-store' };
    const range = /bytes=(\d*)-(\d*)/.exec(e.request.headers.get('range') || '');
    if (range) {
      const size = body.byteLength;
      const start = range[1] ? +range[1] : Math.max(0, size - +range[2]);
      const end = range[1] && range[2] ? Math.min(+range[2], size - 1) : size - 1;
      return new Response(body.slice(start, end + 1), { status: 206, headers: { ...headers, 'Content-Range': `bytes ${start}-${end}/${size}`, 'Content-Length': String(end - start + 1) } });
    }
    return new Response(body, { headers: { ...headers, 'Content-Length': String(body.byteLength) } });
  })());
});
