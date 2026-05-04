// Vercel Serverless Function — Admin role update
const { handleOptions, parseBody, requireAdmin, sendError } = require('./_utils');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;

  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Méthode non autorisée' });
    }

    const { caller, supabaseAdmin } = await requireAdmin(req, res);
    const { userId, role } = parseBody(req);

    if (!userId || typeof userId !== 'string') {
      return res.status(400).json({ error: 'userId manquant ou invalide' });
    }

    const allowedRoles = ['employee', 'manager', 'admin'];
    if (!role || !allowedRoles.includes(role)) {
      return res.status(400).json({ error: 'Rôle invalide. Valeurs acceptées : employee, manager, admin' });
    }

    if (userId === caller.id) {
      return res.status(400).json({ error: 'Impossible de modifier votre propre rôle' });
    }

    const { error: profileUpdateError } = await supabaseAdmin
      .from('profiles')
      .update({ role })
      .eq('id', userId);

    if (profileUpdateError) {
      return res.status(500).json({ error: `Échec de la mise à jour du profil : ${profileUpdateError.message}` });
    }

    const { error: metadataError } = await supabaseAdmin.auth.admin.updateUserById(userId, {
      app_metadata: { role }
    });

    if (metadataError) {
      return res.status(500).json({ error: `Profil mis à jour, mais metadata Auth non mise à jour : ${metadataError.message}` });
    }

    return res.status(200).json({ success: true, userId, role });
  } catch (err) {
    return sendError(res, err);
  }
};
