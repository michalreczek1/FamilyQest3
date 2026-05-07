// FamilyQuest Service Worker
// Provides offline functionality and caching.

const CACHE_NAME = 'familyquest-v10';
const urlsToCache = [
  '/',
  '/?source=pwa',
  '/index.html',
  '/manifest.json',
  '/service-worker.js',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/icon-192-maskable.png',
  '/icons/icon-512-maskable.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(urlsToCache)),
  );
  self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // API must always come from network to avoid stale app state.
  if (url.pathname.startsWith('/api/') || url.pathname === '/health') {
    event.respondWith(fetch(event.request));
    return;
  }

  // Non-GET requests should not be cached.
  if (event.request.method !== 'GET') {
    event.respondWith(fetch(event.request));
    return;
  }

  // Navigation requests: network first, fallback to cached index.
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
          return response;
        })
        .catch(() => caches.match('/index.html')),
    );
    return;
  }

  // Scripts, styles and HTML must be network-first so app updates show up without a hard refresh.
  if (
    url.origin === self.location.origin &&
    (event.request.destination === 'script' ||
      event.request.destination === 'style' ||
      url.pathname.endsWith('.js') ||
      url.pathname.endsWith('.css') ||
      url.pathname.endsWith('.html') ||
      url.pathname === '/service-worker.js')
  ) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (response && response.status === 200 && response.type === 'basic') {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
          }
          return response;
        })
        .catch(() => caches.match(event.request)),
    );
    return;
  }

  // Other static assets: cache first.
  event.respondWith(
    caches.match(event.request).then((cached) => {
      if (cached) return cached;
      return fetch(event.request)
        .then((response) => {
          if (!response || response.status !== 200 || response.type !== 'basic') {
            return response;
          }
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
          return response;
        })
        .catch(() => caches.match('/index.html'));
    }),
  );
});

self.addEventListener('activate', (event) => {
  const whitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(
        names.map((name) => {
          if (!whitelist.includes(name)) {
            return caches.delete(name);
          }
          return null;
        }),
      ),
    ).then(() => self.clients.claim())
      .then(() => clients.matchAll({ type: 'window' }))
      .then((clientList) =>
        Promise.all(
          clientList.map((client) => {
            if ('navigate' in client) {
              return client.navigate(client.url);
            }
            return null;
          }),
        ),
      ),
  );
});

self.addEventListener('sync', (event) => {
  if (event.tag === 'sync-tasks') {
    event.waitUntil(Promise.resolve());
  }
});

self.addEventListener('push', (event) => {
  const options = {
    body: event.data ? event.data.text() : 'Nowe zadanie dostępne!',
    icon: '/icons/icon-192.png',
    badge: '/icons/icon-192.png',
    vibrate: [200, 100, 200],
    data: {
      dateOfArrival: Date.now(),
      primaryKey: 1,
    },
  };

  event.waitUntil(self.registration.showNotification('FamilyQuest', options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(clients.openWindow('/'));
});
