// Vercel Serverless Function — Admin user creation
// Uses SUPABASE_SERVICE_ROLE_KEY (server-side only, never exposed to the browser)
// Required environment variables on Vercel:
//   SUPABASE_URL              — e.g. https://xxxx.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY — service_role secret from Supabase dashboard > Settings > API

const { createClient } = require('@supabase/supabase-js');

module.exports = async (req, res) => {
  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
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

  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    return res
      .status(500)
      .json({ error: 'Configuration serveur manquante (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)' });
  }

  // Admin client — never returned to the browser
  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  });

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
