// FamilyQuest service worker cleanup.
// The app must prefer fresh code over offline caching, so existing SW installs are retired.

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) => Promise.all(names.map((name) => caches.delete(name))))
      .then(() => self.clients.claim())
      .then(() => self.registration.unregister())
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

self.addEventListener('fetch', (event) => {
  event.respondWith(fetch(event.request));
});
