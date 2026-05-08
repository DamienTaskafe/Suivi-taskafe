// Vercel Serverless Function — Secure employee credentials update (admin/manager)
const {
  handleOptions,
  parseBody,
  sendError,
  getBearerToken,
  getConfig,
  createAdminClient,
  getCaller,
  resolveCallerRole
} = require('./_utils');

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

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
      return res.status(403).json({ error: 'Accès refusé : rôle admin ou manager requis' });
    }

    const body = parseBody(req);
    const userId = String(body?.userId || '').trim();
    const rawEmail = body?.email;
    const rawPassword = body?.password;

    if (!userId) {
      return res.status(400).json({ error: 'userId manquant ou invalide' });
    }

    if (userId === caller.id) {
      return res.status(403).json({ error: 'Impossible de modifier vos propres identifiants via cette action' });
    }

    if (rawEmail != null && typeof rawEmail !== 'string') {
      return res.status(400).json({ error: 'email invalide' });
    }
    if (rawPassword != null && typeof rawPassword !== 'string') {
      return res.status(400).json({ error: 'password invalide' });
    }

    const email = typeof rawEmail === 'string' ? rawEmail.trim().toLowerCase() : '';
    const password = typeof rawPassword === 'string' ? rawPassword : '';

    const hasEmail = email.length > 0;
    const hasPassword = password.length > 0;
    if (!hasEmail && !hasPassword) {
      return res.status(400).json({ error: 'Aucun champ à modifier' });
    }

    if (hasEmail && !EMAIL_REGEX.test(email)) {
      return res.status(400).json({ error: 'Format d\'email invalide' });
    }

    if (hasPassword && password.length < 6) {
      return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 6 caractères' });
    }

    const { data: targetRows, error: targetProfileError } = await supabaseAdmin
      .from('profiles')
      .select('id,role')
      .eq('id', userId)
      .limit(1);

    if (targetProfileError) {
      return res.status(500).json({ error: `Échec lecture profil cible : ${targetProfileError.message}` });
    }

    const targetRole = String(targetRows?.[0]?.role || '').toLowerCase();
    if (callerRole === 'manager' && targetRole !== 'employee') {
      return res.status(403).json({ error: 'Un manager peut modifier uniquement les identifiants d\'un employé' });
    }

    const updates = {};
    if (hasEmail) updates.email = email;
    if (hasPassword) updates.password = password;

    const { error: authError } = await supabaseAdmin.auth.admin.updateUserById(userId, updates);
    if (authError) {
      const raw = String(authError.message || '').toLowerCase();
      const alreadyExists =
        raw.includes('already') ||
        raw.includes('registered') ||
        raw.includes('duplicate') ||
        authError.code === 'email_exists' ||
        authError.status === 422;
      return res.status(alreadyExists ? 409 : 500).json({ error: authError.message || 'Échec mise à jour utilisateur' });
    }

    if (hasEmail) {
      const { error: profileSyncError } = await supabaseAdmin
        .from('profiles')
        .update({ email })
        .eq('id', userId);

      if (profileSyncError) {
        return res.status(500).json({ error: `Email Auth mis à jour mais synchronisation profile échouée : ${profileSyncError.message}` });
      }
    }

    return res.status(200).json({
      success: true,
      userId,
      updated: {
        email: hasEmail,
        password: hasPassword
      }
    });
  } catch (err) {
    return sendError(res, err);
  }
};
