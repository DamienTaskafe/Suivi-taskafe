// Vercel Serverless Function — Admin user creation
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
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // ── Step 1 : Require admin Authorization header ───────────────────────────
  const authHeader = (req.headers['authorization'] || '').trim();
  if (!authHeader) {
    console.error('[create-user] Diagnostic: Authorization header absent');
    return res.status(401).json({ error: 'En-tête Authorization manquant' });
  }
  if (!/^bearer\s+\S/i.test(authHeader)) {
    console.error('[create-user] Diagnostic: Authorization mal formé :', authHeader.substring(0, 30));
    return res.status(401).json({ error: 'Format Authorization invalide (attendu : Bearer <token>)' });
  }

  const callerToken = authHeader.replace(/^Bearer\s+/i, '').trim();

  // Basic JWT structure check (3 base64url parts separated by dots)
  const jwtParts = callerToken.split('.');
  if (jwtParts.length !== 3) {
    console.error('[create-user] Diagnostic: token non-JWT, parties =', jwtParts.length, 'longueur =', callerToken.length);
    return res.status(401).json({ error: 'Token JWT malformé' });
  }

  const { email, password, full_name, role } = req.body || {};

  // Basic validation
  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe obligatoires' });
  }
  // Validate email format — Supabase validates further server-side
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  if (!emailRegex.test(String(email))) {
    return res.status(400).json({ error: 'Format d\'email invalide' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Mot de passe minimum 6 caractères' });
  }
  const allowedRoles = ['employee', 'manager', 'admin'];
  const safeRole = allowedRoles.includes(role) ? role : 'employee';

  const envUrl = (process.env.SUPABASE_URL || '').trim();
  if (!envUrl) {
    console.warn('[create-user] SUPABASE_URL non définie — utilisation de la valeur de secours.');
  }
  // Remove any accidental trailing slash to avoid double-slash in REST URLs
  const supabaseUrl = (envUrl || SUPABASE_URL_FALLBACK).replace(/\/+$/, '');
  const serviceRoleKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();

  if (!serviceRoleKey) {
    console.error('[create-user] SUPABASE_SERVICE_ROLE_KEY manquante');
    return res
      .status(500)
      .json({ error: 'Configuration serveur manquante (SUPABASE_SERVICE_ROLE_KEY)' });
  }

  // Admin client — never returned to the browser
  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  });

  // ── Step 2 : Verify caller is admin ──────────────────────────────────────
  // Try with the service_role client first; if that fails, retry with the
  // anon key client.  Both calls hit the same Supabase /auth/v1/user endpoint
  // but with different apikey headers — this covers mis-configured service_role
  // keys while keeping a reliable fallback.
  let callerRole = null;
  let callerIdentity = null;
  try {
    let caller;
    const { data: callerData, error: callerError } = await supabaseAdmin.auth.getUser(callerToken);

    if (callerError || !callerData?.user) {
      console.error('[create-user] getUser (service_role) échoué :', {
        error: callerError?.message,
        status: callerError?.status,
        supabaseUrl,
        tokenStart: callerToken.substring(0, 20) + '…',
        tokenLength: callerToken.length
      });

      // Fallback: try with the anon key
      const supabaseAnon = createClient(supabaseUrl, SUPABASE_ANON_KEY, {
        auth: { autoRefreshToken: false, persistSession: false }
      });
      const { data: data2, error: err2 } = await supabaseAnon.auth.getUser(callerToken);

      if (err2 || !data2?.user) {
        console.error('[create-user] getUser (anon) également échoué :', err2?.message);

        // Decode JWT payload (base64) for diagnostic — not used for auth decisions
        try {
          const payload = JSON.parse(
            Buffer.from(jwtParts[1], 'base64url').toString('utf8')
          );
          const now = Math.floor(Date.now() / 1000);
          const expired = payload.exp < now;
          console.error('[create-user] JWT payload diagnostic :', {
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
          console.error('[create-user] Impossible de décoder le payload JWT :', decodeErr.message);
        }

        return res.status(401).json({ error: 'Token invalide ou expiré' });
      }

      caller = data2.user;
    } else {
      caller = callerData.user;
    }

    callerIdentity = { id: caller.id, email: caller.email };

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
        console.log('[create-user] Rôle obtenu via profiles :', callerRole, '| callerId =', caller.id);
      } else {
        console.warn('[create-user] Profil introuvable en table profiles pour id =', caller.id);
      }
    } else {
      const errText = await profileResp.text().catch(() => '');
      console.error('[create-user] REST profiles échoué :', profileResp.status, errText);
    }
    // Fallback to app_metadata if profiles table query failed or returned no role
    if (!callerRole) {
      callerRole = String(caller.app_metadata?.role || '').toLowerCase();
      if (callerRole) {
        console.log('[create-user] Rôle obtenu depuis app_metadata (fallback) :', callerRole);
      }
    }
  } catch (e) {
    console.error('[create-user] Erreur vérification appelant :', e.message);
    return res.status(503).json({ error: 'Service d\'authentification inaccessible, réessayez' });
  }

  if (callerRole !== 'admin') {
    console.error('[create-user] Accès refusé :', { callerId: callerIdentity?.id, callerEmail: callerIdentity?.email, callerRole });
    return res.status(403).json({
      error: callerRole
        ? `Accès refusé : rôle admin requis (rôle actuel : ${callerRole})`
        : 'Accès refusé : rôle admin non défini ou introuvable'
    });
  }

  let authData;
  try {
    // Create Auth user with admin API — bypasses email rate-limits and confirmation emails
    const { data, error: authError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true // mark email as confirmed immediately, no confirmation email sent
    });

    if (authError) {
      const msg = (authError.message || '').toLowerCase();
      const alreadyExists =
        msg.includes('already') ||
        msg.includes('already registered') ||
        msg.includes('duplicate') ||
        authError.code === 'email_exists' ||
        authError.status === 422;
      return res
        .status(alreadyExists ? 409 : 400)
        .json({ error: authError.message || 'Erreur lors de la création du compte' });
    }

    authData = data;
  } catch (networkError) {
    console.error('[create-user] Supabase admin API unreachable:', networkError);
    return res.status(502).json({ error: 'Service d\'authentification inaccessible, réessayez dans quelques instants' });
  }

  const newUserId = authData?.user?.id;

  if (newUserId) {
    // Store role in app_metadata (server-controlled) so the delete-user API can
    // verify admin role even if the profiles table query fails.
    await supabaseAdmin.auth.admin.updateUserById(newUserId, {
      app_metadata: { role: safeRole }
    }).catch((e) => console.warn('[create-user] app_metadata update failed:', e?.message));

    const { error: profileError } = await supabaseAdmin.from('profiles').insert({
      id: newUserId,
      email,
      full_name: full_name || '',
      role: safeRole
    });

    if (profileError) {
      // Profile creation failed — roll back the Auth user to avoid an orphaned account
      console.error('[create-user] Profile insert failed, rolling back auth user:', profileError.message);
      await supabaseAdmin.auth.admin.deleteUser(newUserId).catch((e) =>
        console.error('[create-user] Rollback deleteUser failed:', e)
      );
      return res.status(500).json({ error: 'Échec de la création du profil : ' + profileError.message });
    }
  }

  return res.status(201).json({
    success: true,
    userId: newUserId,
    message: `Utilisateur créé : ${email}`
  });
};
