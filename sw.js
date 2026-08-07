// Adrenalin PWA service worker.
//
// Registered from index.html as /sw.js?v=<APP_VERSION> — the version comes
// from the registration URL's query string rather than being duplicated
// here, so bumping APP_VERSION in index.html is the single place that
// forces a fresh cache on the next deploy.
//
// Strategy: network first, cache fallback. Every successful GET response
// (except API calls, which must never be served stale) gets cached as it
// goes by; if a later request fails (offline), the last cached copy is
// served instead of a hard failure.
const CACHE = 'adrenalin-' + (new URL(self.location.href).searchParams.get('v') || 'dev');
const URLS = ['/'];

self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE).then(function(c){ return c.addAll(URLS); }).catch(function(){})
  );
  self.skipWaiting(); // activate immediately
});

self.addEventListener('activate', function(e) {
  // Delete ALL old caches that don't match the current version
  e.waitUntil(
    caches.keys().then(function(keys){
      return Promise.all(
        keys.filter(function(k){ return k !== CACHE; })
           .map(function(k){ console.log('[SW] Deleting old cache:', k); return caches.delete(k); })
      );
    })
  );
  self.clients.claim(); // take control immediately
});

self.addEventListener('fetch', function(e) {
  if (e.request.method !== 'GET') return;
  // API calls: network only, never cache — this data is per-user and live.
  if (e.request.url.includes('/api') || e.request.url.includes('netlify/functions')) return;
  // Everything else (the app shell): network first, fall back to cache.
  e.respondWith(
    fetch(e.request).then(function(r){
      var clone = r.clone();
      caches.open(CACHE).then(function(c){ c.put(e.request, clone); });
      return r;
    }).catch(function(){
      return caches.match(e.request);
    })
  );
});
