redeploy

trigger deploy

## Environment Variables

The following environment variables must be set in Vercel (or your hosting provider) for full functionality:

### Required for existing API functions
| Variable | Description |
|---|---|
| `SUPABASE_URL` | Your Supabase project URL (e.g. `https://xxxx.supabase.co`) |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service role key (secret, server-side only) |

### Required for Android/PWA Push Notifications
| Variable | Description |
|---|---|
| `VAPID_PUBLIC_KEY` | VAPID public key (base64url) — also set in `index.html` |
| `VAPID_PRIVATE_KEY` | VAPID private key (base64url) — **server-side only, never expose** |
| `VAPID_SUBJECT` | Contact URL or mailto (e.g. `mailto:admin@example.com`) |

### Generating VAPID keys

```bash
npx web-push generate-vapid-keys
```

Copy the public key into `index.html` (replace `REPLACE_WITH_YOUR_VAPID_PUBLIC_KEY`) and set all three as Vercel environment variables.

### Database migration

Run the migration at `supabase/migrations/20260505003000_push_subscriptions.sql` in your Supabase SQL editor to create the `push_subscriptions` table with RLS policies.

### Android / PWA compatibility notes

- **Android Chrome / PWA**: Full Web Push support ✅
- **iPhone (iOS 16.4+)**: Works when app is installed as PWA (Add to Home Screen) ⚠️
- **iPhone (< iOS 16.4)**: Push notifications not supported ❌
- Custom notification sounds are controlled by the OS, not the app
- Users must grant notification permission via the in-app settings button
