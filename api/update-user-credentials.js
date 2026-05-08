// Vercel Serverless Function — Admin/Manager: update employee email and/or password
const { handleOptions, parseBody, getBearerToken, getConfig, createAdminClient, getCaller, resolveCallerRole, sendError } = require('./_utils');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;

  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Méthode non autorisée' });
    }

    const token = getBearerToken(req);
    const { supabaseUrl, serviceRoleKey } = getConfig();
    const supabaseAdmin = createAdminClient(supabaseUrl, serviceRoleKey);
    const caller = await getCaller(supabaseAdmin, supabaseUrl, token);
    const callerRole = await resolveCallerRole({ supabaseAdmin, supabaseUrl, caller, token });

    if (!['admin', 'manager'].includes(callerRole)) {
      const err = new Error(
        callerRole
          ? `Accès refusé : rôle admin ou manager requis (rôle actuel : ${callerRole})`
          : 'Accès refusé : rôle non défini ou introuvable. Déconnectez-vous puis reconnectez-vous.'
      );
      err.status = 403;
      throw err;
    }

    const { userId, email, password } = parseBody(req);

    if (!userId || typeof userId !== 'string') {
      return res.status(400).json({ error: 'userId manquant ou invalide' });
    }

    // Prevent modifying own account through this endpoint
    if (userId === caller.id) {
      return res.status(400).json({ error: 'Impossible de modifier vos propres identifiants via cet endpoint' });
    }

    const hasEmail    = typeof email === 'string' && email.trim().length > 0;
    const hasPassword = typeof password === 'string' && password.length > 0;

    if (!hasEmail && !hasPassword) {
      return res.status(400).json({ error: 'Au moins un champ à modifier est requis : email ou mot de passe' });
    }

    if (hasEmail) {
      const cleanEmail = email.trim().toLowerCase();
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
      if (!emailRegex.test(cleanEmail)) {
        return res.status(400).json({ error: 'Format d\'email invalide' });
      }
    }

    if (hasPassword && password.length < 6) {
      return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 6 caractères' });
    }

    const updates = {};
    if (hasEmail)    updates.email    = email.trim().toLowerCase();
    if (hasPassword) updates.password = password;

    const { error: authError } = await supabaseAdmin.auth.admin.updateUserById(userId, updates);

    if (authError) {
      const rawMsg = String(authError.message || '').toLowerCase();
      const alreadyExists =
        rawMsg.includes('already') ||
        rawMsg.includes('registered') ||
        rawMsg.includes('duplicate') ||
        authError.code === 'email_exists' ||
        authError.status === 422;

      return res.status(alreadyExists ? 409 : 500).json({
        error: alreadyExists
          ? 'Cet email est déjà utilisé'
          : `Échec de la mise à jour : ${authError.message}`
      });
    }

    // If email changed, keep profiles table in sync
    if (hasEmail) {
      const cleanEmail = email.trim().toLowerCase();
      await supabaseAdmin
        .from('profiles')
        .update({ email: cleanEmail })
        .eq('id', userId);
      // Non-blocking: profile sync failure does not fail the request
    }

    return res.status(200).json({ success: true, userId, updatedFields: Object.keys(updates) });
  } catch (err) {
    return sendError(res, err);
  }
};
