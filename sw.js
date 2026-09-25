// sw.js — hält die App offline lauffähig. Bewusst simpel: alles wird beim
// Installieren gecacht, danach cache-first ausgeliefert. Neue Versionen
// bekommen einen neuen Cache-Namen; alte werden beim Aktivieren entfernt.

const CACHE = 'encryptor-one-v2.1.0';
const ASSETS = [
  '/',
  '/index.html',
  '/assets/styles.css',
  '/assets/seal.svg',
  '/manifest.webmanifest',
  '/src/boot.js',
  '/src/app.js',
  '/src/crypto.js',
  '/src/store.js',
  '/src/util.js',
  '/src/sigil.js',
  '/src/i18n.js'
];

self.addEventListener('install', (event) => {
  // cache: 'reload' umgeht den HTTP-Cache. Sonst koennte eine neue Version alte Dateien
  // einsammeln — /assets/* darf laut _headers eine Woche im Browser-Cache liegen.
  event.waitUntil(caches.open(CACHE).then((c) =>
    c.addAll(ASSETS.map((url) => new Request(url, { cache: 'reload' })))
  ));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  event.respondWith(
    caches.match(req, { ignoreSearch: true }).then((hit) => {
      if (hit) return hit;
      return fetch(req)
        .then((res) => {
          if (res.ok && res.type === 'basic') {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put(req, copy));
          }
          return res;
        })
        .catch(() => caches.match('/index.html'));
    })
  );
});
