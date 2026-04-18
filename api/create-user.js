// Vercel Serverless Function — Admin user creation
// Uses SUPABASE_SERVICE_ROLE_KEY (server-side only, never exposed to the browser)
// Required environment variables on Vercel:
//   SUPABASE_URL              — e.g. https://xxxx.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY — service_role secret from Supabase dashboard > Settings > API

const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL_FALLBACK = 'https://ogjljdjphawcminawtlv.supabase.co';

module.exports = async (req, res) => {
  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // ── Step 1 : Require admin Authorization header ───────────────────────────
  const authHeader = (req.headers['authorization'] || '').trim();
  if (!authHeader || !/^bearer\s+\S/i.test(authHeader)) {
    return res.status(401).json({ error: 'En-tête Authorization manquant ou invalide' });
  }
  const callerToken = authHeader.replace(/^Bearer\s+/i, '').trim();

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
  const supabaseUrl = envUrl || SUPABASE_URL_FALLBACK;
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
  // Use a direct REST fetch with explicit service-role headers so the caller's
  // session state cannot interfere with the admin role check.
  let callerRole = null;
  try {
    const { data: callerData, error: callerError } = await supabaseAdmin.auth.getUser(callerToken);
    if (callerError || !callerData?.user) {
      return res.status(401).json({ error: 'Token invalide ou expiré' });
    }
    const caller = callerData.user;

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
      callerRole = String(rows?.[0]?.role || '').toLowerCase();
    }
    // Fallback to app_metadata if profiles table query failed or returned no role
    if (!callerRole) {
      callerRole = String(caller.app_metadata?.role || '').toLowerCase();
    }
  } catch (e) {
    console.error('[create-user] Erreur vérification appelant :', e.message);
    return res.status(503).json({ error: 'Service d\'authentification inaccessible, réessayez' });
  }

  if (callerRole !== 'admin') {
    return res.status(403).json({ error: 'Accès refusé : rôle admin requis' });
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
