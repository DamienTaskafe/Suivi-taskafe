// Vercel Serverless Function — Admin user deletion
// Uses SUPABASE_SERVICE_ROLE_KEY (server-side only, never exposed to the browser)
// Required environment variables on Vercel:
//   SUPABASE_URL              — e.g. https://xxxx.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY — service_role secret from Supabase dashboard > Settings > API

const { createClient } = require('@supabase/supabase-js');

module.exports = async (req, res) => {
  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  // Verify Authorization header
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '');
  if (!token) {
    return res.status(401).json({ error: 'En-tête Authorization manquant' });
  }

  const { userId } = req.body || {};

  if (!userId || typeof userId !== 'string') {
    return res.status(400).json({ error: 'userId manquant ou invalide' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !serviceRoleKey) {
    console.error('[delete-user] Variables d\'environnement manquantes');
    return res
      .status(500)
      .json({ error: 'Configuration serveur manquante (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)' });
  }

  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  });

  // Vérifier l'identité et le rôle de l'appelant via son JWT
  let caller;
  try {
    const { data, error: callerError } = await supabaseAdmin.auth.getUser(token);
    if (callerError || !data?.user) {
      console.error('[delete-user] Token invalide :', callerError?.message);
      return res.status(401).json({ error: 'Token invalide ou expiré' });
    }
    caller = data.user;
  } catch (e) {
    console.error('[delete-user] Erreur vérification token :', e);
    return res.status(503).json({ error: 'Service d\'authentification inaccessible, réessayez dans quelques instants' });
  }

  // Vérifier que l'appelant est admin dans la table profiles
  const { data: callerProfile, error: profileError } = await supabaseAdmin
    .from('profiles')
    .select('role')
    .eq('id', caller.id)
    .single();

  if (profileError || !callerProfile || callerProfile.role !== 'admin') {
    console.error('[delete-user] Accès refusé :', profileError?.message, callerProfile);
    return res.status(403).json({ error: 'Accès refusé : rôle admin requis' });
  }

  // Empêcher un admin de se supprimer lui-même
  if (userId === caller.id) {
    return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
  }

  // Supprimer le profil applicatif (erreur non bloquante)
  const { error: profileDeleteError } = await supabaseAdmin
    .from('profiles')
    .delete()
    .eq('id', userId);

  if (profileDeleteError) {
    console.warn('[delete-user] Avertissement suppression profil :', profileDeleteError.message);
  }

  // Supprimer le compte Auth via les privilèges admin (service role)
  const { error: authDeleteError } = await supabaseAdmin.auth.admin.deleteUser(userId);

  if (authDeleteError) {
    console.error('[delete-user] Suppression Auth échouée :', authDeleteError.message);
    return res.status(500).json({ error: 'Suppression Auth échouée : ' + authDeleteError.message });
  }

  console.log('[delete-user] Suppression réussie pour userId =', userId);
  return res.status(200).json({ success: true });
};
