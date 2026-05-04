// Vercel Serverless Function — Admin user deletion
const { handleOptions, parseBody, requireAdmin, sendError } = require('./_utils');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;

  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Méthode non autorisée' });
    }

    const { caller, supabaseAdmin } = await requireAdmin(req, res);
    const { userId } = parseBody(req);

    if (!userId || typeof userId !== 'string') {
      return res.status(400).json({ error: 'userId manquant ou invalide' });
    }

    if (userId === caller.id) {
      return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
    }

    // Delete app profile first. If it is already absent, Auth deletion still proceeds.
    const { error: profileDeleteError } = await supabaseAdmin
      .from('profiles')
      .delete()
      .eq('id', userId);

    if (profileDeleteError) {
      console.warn('[delete-user] Suppression profil non bloquante :', profileDeleteError.message);
    }

    const { error: authDeleteError } = await supabaseAdmin.auth.admin.deleteUser(userId);
    if (authDeleteError) {
      return res.status(500).json({ error: `Suppression Auth échouée : ${authDeleteError.message}` });
    }

    return res.status(200).json({ success: true });
  } catch (err) {
    return sendError(res, err);
  }
};
