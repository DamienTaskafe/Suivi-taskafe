// Vercel Serverless Function — deletes a Web Push subscription for the
// authenticated user.  Using the service-role key bypasses RLS and makes the
// delete reliable even when the user JWT has limited Supabase permissions.
//
// POST /api/delete-push-subscription
// Authorization: Bearer <user-jwt>
// Body: { endpoint?: string }
//   - If endpoint is provided, deletes only that subscription row.
//   - If omitted, deletes ALL subscription rows for the caller (stale cleanup).
//
// Returns: { ok: true } on success, or { error: "..." } with an appropriate HTTP status.

const {
  setCors,
  handleOptions,
  parseBody,
  sendError,
  getBearerToken,
  getConfig,
  createAdminClient,
  getCaller,
} = require('./_utils');

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;
  setCors(req, res);

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  try {
    // ── Authenticate caller ─────────────────────────────────────────────────
    const token = getBearerToken(req);
    const { supabaseUrl, serviceRoleKey } = getConfig();
    const supabaseAdmin = createAdminClient(supabaseUrl, serviceRoleKey);
    const caller = await getCaller(supabaseAdmin, supabaseUrl, token);

    // ── Parse body ──────────────────────────────────────────────────────────
    const body = parseBody(req);
    const { endpoint } = body;

    // ── Delete via service role (bypasses RLS) ──────────────────────────────
    let query = supabaseAdmin
      .from('push_subscriptions')
      .delete()
      .eq('user_id', caller.id);

    if (endpoint && typeof endpoint === 'string') {
      query = query.eq('endpoint', endpoint);
    }

    const { error: deleteErr } = await query;

    if (deleteErr) {
      console.error('[delete-push-subscription] delete error:', deleteErr.message);
      return res.status(500).json({ error: 'Erreur lors de la suppression de l\'abonnement. Réessayez.' });
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    return sendError(res, err, "Erreur lors de la suppression de l'abonnement push");
  }
};
