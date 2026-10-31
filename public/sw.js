
const CACHE_NAME = "5m-chat-v1";

self.addEventListener("install", (event) => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      await self.clients.claim();
    })()
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;

  // Do not cache API requests, chat messages, or other live data.
  if (
    request.method !== "GET" ||
    new URL(request.url).origin !== self.location.origin ||
    new URL(request.url).pathname.startsWith("/api/") ||
    new URL(request.url).pathname.startsWith("/socket.io/")
  ) {
    return;
  }

  // Use the network for pages and assets so chat stays up to date.
  // This avoids storing private chat content in the app cache.
  event.respondWith(fetch(request));
});
