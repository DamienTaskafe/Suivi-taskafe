// TASKAFÉ — service worker PROPRE (anti-cache bloquant iPhone/Vercel)
// - HTML/navigation: network-first (toujours la dernière version)
// - assets (js/css/img/font): stale-while-revalidate
// - ne cache jamais les requêtes Supabase

const CACHE_NAME = "taskafe-static-v3";

self.addEventListener("install", () => self.skipWaiting());

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.map((k) => (k !== CACHE_NAME ? caches.delete(k) : null)));
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);

  if (req.method !== "GET") return;

  // Ne jamais cacher Supabase
  if (url.hostname.includes("supabase.co")) return;

  // HTML / navigation: toujours réseau (évite vieilles versions)
  if (req.mode === "navigate" || req.destination === "document") {
    event.respondWith((async () => {
      try {
        return await fetch(req, { cache: "no-store" });
      } catch {
        const cached = await caches.match(req);
        return cached || new Response("Offline", { status: 503 });
      }
    })());
    return;
  }

  // Assets: stale-while-revalidate
  if (["script", "style", "image", "font"].includes(req.destination)) {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE_NAME);
      const cached = await cache.match(req);

      const network = fetch(req)
        .then((res) => {
          if (res && res.ok) cache.put(req, res.clone());
          return res;
        })
        .catch(() => cached);

      return cached || network;
    })());
  }
});
