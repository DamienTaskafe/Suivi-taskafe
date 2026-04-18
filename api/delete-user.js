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
  const supabaseUrl = envUrl || SUPABASE_URL_FALLBACK;
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
  const { data: callerProfile, error: profileError } = await supabaseAdmin
    .from('profiles')
    .select('role')
    .eq('id', caller.id)
    .single();

  if (profileError || !callerProfile || callerProfile.role !== 'admin') {
    console.error('[delete-user] Accès refusé :', profileError?.message, callerProfile?.role);
    return res.status(403).json({ error: 'Accès refusé : rôle admin requis' });
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
