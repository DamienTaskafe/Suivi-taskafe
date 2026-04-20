// Vercel Serverless Function — Admin role update
// Uses SUPABASE_SERVICE_ROLE_KEY (server-side only, never exposed to the browser)
// Required environment variables on Vercel:
//   SUPABASE_URL              — e.g. https://xxxx.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY — service_role secret from Supabase dashboard > Settings > API

const { createClient } = require('@supabase/supabase-js');

// Supabase project URL — same value already hardcoded in index.html (not a secret)
const SUPABASE_URL_FALLBACK = 'https://ogjljdjphawcminawtlv.supabase.co';

// Anon key — already present in the public frontend JS, safe to use server-side.
const SUPABASE_ANON_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
  'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9namxqZGpwaGF3Y21pbmF3dGx2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzYzNzQ5MjUsImV4cCI6MjA5MTk1MDkyNX0.' +
  'WVgrgx8Q1c9j_1UyNX7e2ilvttMBSHY2vnrBw_Ga05A';

module.exports = async (req, res) => {
  // Always set JSON content-type header up front so that even unhandled errors
  // return JSON instead of Vercel's default HTML error page.
  res.setHeader('Content-Type', 'application/json');

  try {
  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  console.log('[update-role] → Entrée dans la fonction', { method: req.method, ts: new Date().toISOString() });

  // ── Step 1 : Require admin Authorization header ───────────────────────────
  const authHeader = (req.headers['authorization'] || '').trim();
  if (!authHeader || !/^bearer\s+\S/i.test(authHeader)) {
    return res.status(401).json({ error: 'En-tête Authorization manquant ou invalide' });
  }
  const callerToken = authHeader.replace(/^Bearer\s+/i, '').trim();

  // Basic JWT structure check (3 base64url parts separated by dots)
  const jwtParts = callerToken.split('.');
  if (jwtParts.length !== 3) {
    return res.status(401).json({ error: 'Token JWT malformé' });
  }

  // ── Step 2 : Validate request body ────────────────────────────────────────
  const { userId, role } = req.body || {};

  if (!userId || typeof userId !== 'string') {
    return res.status(400).json({ error: 'userId manquant ou invalide' });
  }
  const allowedRoles = ['employee', 'manager', 'admin'];
  if (!role || !allowedRoles.includes(role)) {
    return res.status(400).json({ error: 'Rôle invalide. Valeurs acceptées : employee, manager, admin' });
  }

  // ── Step 3 : Initialise Supabase admin client ─────────────────────────────
  const envUrl = (process.env.SUPABASE_URL || '').trim();
  if (!envUrl) {
    console.warn('[update-role] SUPABASE_URL non définie — utilisation de la valeur de secours.');
  }
  const supabaseUrl = (envUrl || SUPABASE_URL_FALLBACK).replace(/\/+$/, '');
  const serviceRoleKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();

  if (!serviceRoleKey) {
    console.error('[update-role] SUPABASE_SERVICE_ROLE_KEY manquante');
    return res.status(500).json({ error: 'Configuration serveur manquante (SUPABASE_SERVICE_ROLE_KEY)' });
  }

  // Admin client — never returned to the browser
  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  });

  // ── Step 4 : Verify caller identity via JWT ───────────────────────────────
  let caller;
  try {
    const { data, error: err1 } = await supabaseAdmin.auth.getUser(callerToken);

    if (err1 || !data?.user) {
      console.error('[update-role] getUser (service_role) échoué :', err1?.message);

      // Fallback: try with the anon key
      const supabaseAnon = createClient(supabaseUrl, SUPABASE_ANON_KEY, {
        auth: { autoRefreshToken: false, persistSession: false }
      });
      const { data: data2, error: err2 } = await supabaseAnon.auth.getUser(callerToken);

      if (err2 || !data2?.user) {
        console.error('[update-role] getUser (anon) également échoué :', err2?.message);

        // Decode JWT payload for diagnostic
        try {
          const payload = JSON.parse(Buffer.from(jwtParts[1], 'base64url').toString('utf8'));
          const now = Math.floor(Date.now() / 1000);
          if (payload.exp < now) {
            return res.status(401).json({ error: 'Token expiré. Reconnectez-vous puis réessayez.' });
          }
        } catch (_) { /* ignore decode errors */ }

        return res.status(401).json({ error: 'Token invalide ou expiré' });
      }

      caller = data2.user;
    } else {
      caller = data.user;
    }
  } catch (e) {
    console.error('[update-role] Exception lors de la vérification du token :', e.message);
    return res.status(503).json({ error: 'Service d\'authentification inaccessible, réessayez' });
  }

  console.log('[update-role] Token validé, appelant =', caller.id, '| email =', caller.email);

  // ── Step 5 : Verify caller has admin role ────────────────────────────────
  // 1. REST fetch profiles by caller.id (service-role key → bypasses RLS)
  // 2. Fallback to app_metadata.role (server-controlled, set by create-user)
  let callerRole = null;
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
        console.log('[update-role] Rôle obtenu via profiles :', callerRole, '| callerId =', caller.id);
      } else {
        console.warn('[update-role] Profil introuvable en table profiles pour id =', caller.id);
      }
    } else {
      const errText = await profileResp.text().catch(() => '');
      console.error('[update-role] REST profiles échoué :', profileResp.status, errText);
    }
  } catch (fetchErr) {
    console.error('[update-role] Exception REST profiles :', fetchErr.message);
  }

  // Fallback to app_metadata.role if profiles query returned no role
  if (!callerRole) {
    callerRole = String(caller.app_metadata?.role || '').toLowerCase();
    if (callerRole) {
      console.log('[update-role] Rôle obtenu depuis app_metadata (fallback) :', callerRole);
    }
  }

  if (callerRole !== 'admin') {
    console.error('[update-role] Accès refusé :', { callerId: caller.id, callerEmail: caller.email, callerRole });
    return res.status(403).json({
      error: callerRole
        ? `Accès refusé : rôle admin requis (rôle actuel : ${callerRole})`
        : 'Accès refusé : rôle admin non défini ou introuvable'
    });
  }

  // Prevent admin from changing their own role
  if (userId === caller.id) {
    return res.status(400).json({ error: 'Impossible de modifier votre propre rôle' });
  }

  // ── Step 6 : Update the profile role ─────────────────────────────────────
  const { error: profileUpdateError } = await supabaseAdmin
    .from('profiles')
    .update({ role })
    .eq('id', userId);

  if (profileUpdateError) {
    console.error('[update-role] Échec mise à jour profil :', profileUpdateError.message);
    return res.status(500).json({ error: 'Échec de la mise à jour du profil : ' + profileUpdateError.message });
  }

  // Also update app_metadata.role for consistency with create-user/delete-user role verification
  await supabaseAdmin.auth.admin.updateUserById(userId, {
    app_metadata: { role }
  }).catch((e) => console.warn('[update-role] app_metadata update failed:', e?.message));

  console.log('[update-role] Rôle mis à jour avec succès pour userId =', userId, '| nouveau rôle =', role);
  return res.status(200).json({ success: true, userId, role });
  } catch (unexpectedErr) {
    // Safety net: catch any unhandled exception and return JSON so the frontend
    // never receives an HTML error page that would trigger "Unexpected token '<'".
    console.error('[update-role] Erreur inattendue non gérée :', unexpectedErr);
    return res.status(500).json({ error: 'Erreur serveur interne. Veuillez réessayer.' });
  }
};
