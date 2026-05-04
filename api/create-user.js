// Vercel Serverless Function — Admin user creation
const { handleOptions, parseBody, requireAdmin, sendError } = require('./_utils');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;

  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Méthode non autorisée' });
    }

    const { supabaseAdmin } = await requireAdmin(req, res);
    const body = parseBody(req);
    const { email, password, full_name, role } = body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email et mot de passe obligatoires' });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
    if (!emailRegex.test(cleanEmail)) {
      return res.status(400).json({ error: 'Format d\'email invalide' });
    }

    if (String(password).length < 6) {
      return res.status(400).json({ error: 'Mot de passe minimum 6 caractères' });
    }

    const allowedRoles = ['employee', 'manager', 'admin'];
    const safeRole = allowedRoles.includes(role) ? role : 'employee';

    const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
      email: cleanEmail,
      password,
      email_confirm: true,
      app_metadata: { role: safeRole },
      user_metadata: { full_name: full_name || '' }
    });

    if (authError) {
      const rawMsg = String(authError.message || '').toLowerCase();
      const alreadyExists =
        rawMsg.includes('already') ||
        rawMsg.includes('registered') ||
        rawMsg.includes('duplicate') ||
        authError.code === 'email_exists' ||
        authError.status === 422;

      return res.status(alreadyExists ? 409 : 400).json({
        error: alreadyExists ? 'Cet email est déjà utilisé' : authError.message
      });
    }

    const newUserId = authData?.user?.id;
    if (!newUserId) {
      return res.status(500).json({ error: 'Création Auth réussie mais userId introuvable' });
    }

    const { error: profileError } = await supabaseAdmin.from('profiles').upsert(
      {
        id: newUserId,
        email: cleanEmail,
        full_name: full_name || '',
        role: safeRole
      },
      { onConflict: 'id' }
    );

    if (profileError) {
      await supabaseAdmin.auth.admin.deleteUser(newUserId).catch(() => {});
      return res.status(500).json({ error: `Échec insertion profile : ${profileError.message}` });
    }

    return res.status(201).json({
      success: true,
      userId: newUserId,
      message: `Utilisateur créé : ${cleanEmail}`
    });
  } catch (err) {
    return sendError(res, err);
  }
};
