// TASKAFÉ — service worker PROPRE (anti-cache bloquant iPhone/Vercel)
// - HTML/navigation: network-first (toujours la dernière version)
// - assets (js/css/img/font): stale-while-revalidate
// - ne cache jamais les requêtes Supabase
// - gère les push notifications Android/PWA

const CACHE_NAME = "taskafe-static-v6";

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

// ── Push notification handler ─────────────────────────────────────────────────
self.addEventListener("push", (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (_) {}

  const title   = data.title   || "TASKAFÉ";
  const body    = data.body    || "";
  // icon-512.png.PNG is the actual filename in this repository (see manifest.json)
  const iconUrl = data.icon    || "/icon-512.png.PNG";
  const badgeUrl= data.badge   || "/icon-512.png.PNG";
  const tag     = data.tag     || "taskafe-notif";
  const urlPath = data.url     || "/";
  const vibrate = data.vibrate || [200, 100, 200];

  const options = {
    body,
    icon:               iconUrl,
    badge:              badgeUrl,
    vibrate,
    tag,
    renotify:           true,
    requireInteraction: false,
    data:               { url: urlPath }
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

// ── Notification click handler ────────────────────────────────────────────────
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const targetUrl = event.notification.data?.url || "/";

  event.waitUntil(
    clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then((windowClients) => {
        // Focus an existing tab/window if one is already open
        for (const client of windowClients) {
          if ("focus" in client) {
            client.navigate(targetUrl).catch(err => console.warn("[sw] navigate error:", err));
            return client.focus();
          }
        }
        // Otherwise open a new window
        if (clients.openWindow) return clients.openWindow(targetUrl);
      })
  );
});

