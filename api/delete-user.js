// Vercel Serverless Function — Admin user deletion
// Uses SUPABASE_SERVICE_ROLE_KEY (server-side only, never exposed to the browser)
// Required environment variables on Vercel:
//   SUPABASE_URL              — e.g. https://xxxx.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY — service_role secret from Supabase dashboard > Settings > API

const { createClient } = require('@supabase/supabase-js');

// Supabase project URL — same value already hardcoded in index.html (not a secret)
// Used as a reliable fallback so that token validation never hits the wrong endpoint
// even if the SUPABASE_URL environment variable is absent, has a typo, or trailing whitespace.
const SUPABASE_URL_FALLBACK = 'https://ogjljdjphawcminawtlv.supabase.co';

// Anon key — already present in the public frontend JS, safe to use server-side.
// Provides an alternative apikey header for the getUser() validation call so that
// both paths (service_role key and anon key) are attempted before giving up.
const SUPABASE_ANON_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
  'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9namxqZGpwaGF3Y21pbmF3dGx2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzYzNzQ5MjUsImV4cCI6MjA5MTk1MDkyNX0.' +
  'WVgrgx8Q1c9j_1UyNX7e2ilvttMBSHY2vnrBw_Ga05A';

module.exports = async (req, res) => {
  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  // ── Step 1 : Extract and validate the Authorization header ───────────────
  const authHeader = (req.headers['authorization'] || '').trim();
  if (!authHeader) {
    console.error('[delete-user] Diagnostic: Authorization header absent');
    return res.status(401).json({ error: 'En-tête Authorization manquant' });
  }
  if (!/^bearer\s+\S/i.test(authHeader)) {
    console.error('[delete-user] Diagnostic: Authorization mal formé :', authHeader.substring(0, 30));
    return res.status(401).json({ error: 'Format Authorization invalide (attendu : Bearer <token>)' });
  }

  const token = authHeader.replace(/^Bearer\s+/i, '').trim();

  // Basic JWT structure check (3 base64url parts separated by dots)
  const jwtParts = token.split('.');
  if (jwtParts.length !== 3) {
    console.error('[delete-user] Diagnostic: token non-JWT, parties =', jwtParts.length, 'longueur =', token.length);
    return res.status(401).json({ error: 'Token JWT malformé' });
  }

  // ── Step 2 : Validate request body ───────────────────────────────────────
  const { userId } = req.body || {};
  if (!userId || typeof userId !== 'string') {
    return res.status(400).json({ error: 'userId manquant ou invalide' });
  }

  // ── Step 3 : Initialise Supabase clients ──────────────────────────────────
  // Trim env vars to guard against accidental whitespace / newlines when
  // copy-pasting into the Vercel dashboard — this was a likely root cause.
  const envUrl = (process.env.SUPABASE_URL || '').trim();
  if (!envUrl) {
    // Log clearly so the misconfiguration is visible in Vercel function logs
    console.warn('[delete-user] SUPABASE_URL non définie — utilisation de la valeur de secours intégrée.');
  }
  // Remove any accidental trailing slash to avoid double-slash in REST URLs
  const supabaseUrl = (envUrl || SUPABASE_URL_FALLBACK).replace(/\/+$/, '');
  const serviceRoleKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();

  if (!serviceRoleKey) {
    console.error('[delete-user] SUPABASE_SERVICE_ROLE_KEY manquante');
    return res.status(500).json({ error: 'Configuration serveur manquante (SUPABASE_SERVICE_ROLE_KEY)' });
  }

  // Admin client — used for privileged operations (profile read, user deletion)
  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  });

  // ── Step 4 : Verify caller identity via JWT ───────────────────────────────
  // Try with the service_role client first; if that fails, retry with the
  // anon key client.  Both calls hit the same Supabase /auth/v1/user endpoint
  // but with different apikey headers — this covers mis-configured service_role
  // keys while keeping a reliable fallback.
  let caller;
  try {
    const { data, error: err1 } = await supabaseAdmin.auth.getUser(token);

    if (err1 || !data?.user) {
      console.error('[delete-user] getUser (service_role) échoué :', {
        error: err1?.message,
        status: err1?.status,
        supabaseUrl,
        tokenStart: token.substring(0, 20) + '…',
        tokenLength: token.length
      });

      // Fallback: try with the anon key
      const supabaseAnon = createClient(supabaseUrl, SUPABASE_ANON_KEY, {
        auth: { autoRefreshToken: false, persistSession: false }
      });
      const { data: data2, error: err2 } = await supabaseAnon.auth.getUser(token);

      if (err2 || !data2?.user) {
        console.error('[delete-user] getUser (anon) également échoué :', err2?.message);

        // Decode JWT payload (base64) for diagnostic — not used for auth decisions
        try {
          const payload = JSON.parse(
            Buffer.from(jwtParts[1], 'base64url').toString('utf8')
          );
          const now = Math.floor(Date.now() / 1000);
          const expired = payload.exp < now;
          console.error('[delete-user] JWT payload diagnostic :', {
            sub: payload.sub ? payload.sub.substring(0, 8) + '…' : null,
            role: payload.role,
            exp: payload.exp,
            now,
            expired
          });
          if (expired) {
            return res.status(401).json({ error: 'Token expiré. Reconnectez-vous puis réessayez.' });
          }
        } catch (decodeErr) {
          console.error('[delete-user] Impossible de décoder le payload JWT :', decodeErr.message);
        }

        return res.status(401).json({ error: 'Token invalide ou expiré' });
      }

      caller = data2.user;
    } else {
      caller = data.user;
    }
  } catch (e) {
    console.error('[delete-user] Exception lors de la vérification du token :', e.message);
    return res.status(503).json({ error: 'Service d\'authentification inaccessible, réessayez dans quelques instants' });
  }

  // ── Step 5 : Check caller has admin role ─────────────────────────────────
  // Four cascading fallbacks so that any single point of failure is covered:
  //   5a. REST fetch by id   (service-role key → bypasses RLS)
  //   5b. REST fetch by email (handles id mismatch between profiles & auth.users)
  //   5c. supabaseAdmin SDK  (alternative PostgREST path)
  //   5d. app_metadata.role  (set by create-user API, server-controlled)
  let callerRole = null;

  // ── 5a : REST fetch by id ─────────────────────────────────────────────────
  try {
    const profileUrl = `${supabaseUrl}/rest/v1/profiles?select=role&id=eq.${encodeURIComponent(caller.id)}&limit=1`;
    const profileResp = await fetch(profileUrl, {
      headers: {
        'apikey': serviceRoleKey,
        'Authorization': `Bearer ${serviceRoleKey}`,
        'Accept': 'application/json'
      }
    });

    if (profileResp.ok) {
      const rows = await profileResp.json();
      if (Array.isArray(rows) && rows.length > 0) {
        callerRole = String(rows[0].role || '').toLowerCase();
        console.log('[delete-user] Rôle obtenu via REST id :', callerRole, '| callerId =', caller.id);
      } else {
        console.warn('[delete-user] 5a: Profil introuvable par id =', caller.id, '| email =', caller.email);
      }
    } else {
      const errText = await profileResp.text().catch(() => '');
      console.error('[delete-user] 5a: REST profiles échoué :', profileResp.status, errText);
    }
  } catch (fetchErr) {
    console.error('[delete-user] 5a: Exception REST id :', fetchErr.message);
  }

  // ── 5b : REST fetch by email (fallback for id mismatch) ───────────────────
  // email is unique in auth.users, so this lookup is safe when id-based lookup
  // returns empty (e.g. profiles.id was set incorrectly during manual repair).
  if (!callerRole && caller.email) {
    try {
      const emailUrl = `${supabaseUrl}/rest/v1/profiles?select=role&email=eq.${encodeURIComponent(caller.email)}&limit=1`;
      const emailResp = await fetch(emailUrl, {
        headers: {
          'apikey': serviceRoleKey,
          'Authorization': `Bearer ${serviceRoleKey}`,
          'Accept': 'application/json'
        }
      });

      if (emailResp.ok) {
        const emailRows = await emailResp.json();
        if (Array.isArray(emailRows) && emailRows.length > 0) {
          callerRole = String(emailRows[0].role || '').toLowerCase();
          console.log('[delete-user] Rôle obtenu via REST email (fallback 5b) :', callerRole);
        } else {
          console.warn('[delete-user] 5b: Profil introuvable par email =', caller.email);
        }
      } else {
        const errText2 = await emailResp.text().catch(() => '');
        console.error('[delete-user] 5b: REST email échoué :', emailResp.status, errText2);
      }
    } catch (emailFetchErr) {
      console.error('[delete-user] 5b: Exception REST email :', emailFetchErr.message);
    }
  }

  // ── 5c : supabaseAdmin SDK (alternative PostgREST path) ───────────────────
  if (!callerRole) {
    try {
      const { data: sdkProfile, error: sdkErr } = await supabaseAdmin
        .from('profiles')
        .select('role')
        .eq('id', caller.id)
        .maybeSingle();

      if (sdkErr) {
        console.warn('[delete-user] 5c: SDK query erreur :', sdkErr.message);
      } else if (sdkProfile?.role) {
        callerRole = String(sdkProfile.role).toLowerCase();
        console.log('[delete-user] Rôle obtenu via SDK (fallback 5c) :', callerRole);
      } else {
        console.warn('[delete-user] 5c: SDK — profil non trouvé ou rôle vide pour id =', caller.id);
      }
    } catch (sdkException) {
      console.error('[delete-user] 5c: Exception SDK :', sdkException.message);
    }
  }

  // ── 5d : app_metadata.role (server-controlled, set by create-user API) ────
  if (!callerRole) {
    const metaRole = String(caller.app_metadata?.role || '').toLowerCase();
    if (metaRole) {
      callerRole = metaRole;
      console.log('[delete-user] Rôle obtenu depuis app_metadata (fallback 5d) :', callerRole);
    }
  }

  if (callerRole !== 'admin') {
    console.error('[delete-user] Accès refusé :', { callerId: caller.id, callerEmail: caller.email, callerRole });
    return res.status(403).json({
      error: callerRole
        ? `Accès refusé : rôle admin requis (rôle actuel : ${callerRole})`
        : 'Accès refusé : profil admin introuvable ou rôle non défini'
    });
  }

  // Prevent an admin from deleting their own account
  if (userId === caller.id) {
    return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
  }

  // ── Step 6 : Perform deletion ─────────────────────────────────────────────
  // Delete the application profile first (non-blocking)
  const { error: profileDeleteError } = await supabaseAdmin
    .from('profiles')
    .delete()
    .eq('id', userId);

  if (profileDeleteError) {
    console.warn('[delete-user] Avertissement suppression profil :', profileDeleteError.message);
  }

  // Delete the Auth account via admin privileges (service role)
  const { error: authDeleteError } = await supabaseAdmin.auth.admin.deleteUser(userId);

  if (authDeleteError) {
    console.error('[delete-user] Suppression Auth échouée :', authDeleteError.message);
    return res.status(500).json({ error: 'Suppression Auth échouée : ' + authDeleteError.message });
  }

  console.log('[delete-user] Suppression réussie pour userId =', userId);
  return res.status(200).json({ success: true });
};
