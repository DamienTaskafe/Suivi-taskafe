// Vercel Serverless Function — Admin password update for a target user
const { handleOptions, parseBody, requireAdmin, sendError } = require('./_utils');

module.exports = async (req, res) => {
  if (handleOptions(req, res)) return;

  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Méthode non autorisée' });
    }

    const { supabaseAdmin } = await requireAdmin(req, res);
    const { userId, password } = parseBody(req);

    if (!userId || typeof userId !== 'string') {
      return res.status(400).json({ error: 'userId manquant ou invalide' });
    }

    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 6 caractères' });
    }

    const { error } = await supabaseAdmin.auth.admin.updateUserById(userId, { password });

    if (error) {
      return res.status(500).json({ error: `Échec de la mise à jour du mot de passe : ${error.message}` });
    }

    return res.status(200).json({ success: true, userId });
  } catch (err) {
    return sendError(res, err);
  }
};
