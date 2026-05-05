// Vercel Serverless Function — saves (upserts) a Web Push subscription for the
// authenticated user.  Using the service-role key bypasses RLS and makes the
// write reliable even when the user JWT has limited Supabase permissions.
//
// POST /api/save-push-subscription
// Authorization: Bearer <user-jwt>
// Body: { endpoint: string, subscription: object, user_agent?: string }
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

    // ── Parse and validate body ─────────────────────────────────────────────
    const body = parseBody(req);
    const { endpoint, subscription, user_agent } = body;

    if (!endpoint || typeof endpoint !== 'string') {
      return res.status(400).json({ error: 'Champ obligatoire : endpoint (chaîne)' });
    }
    if (!subscription || typeof subscription !== 'object' || Array.isArray(subscription)) {
      return res.status(400).json({ error: 'Champ obligatoire : subscription (objet)' });
    }

    // ── Upsert via service role (bypasses RLS) ──────────────────────────────
    const { error: upsertErr } = await supabaseAdmin
      .from('push_subscriptions')
      .upsert(
        {
          user_id:    caller.id,
          endpoint,
          subscription,
          user_agent: (typeof user_agent === 'string' ? user_agent : '').slice(0, 512),
          updated_at: new Date().toISOString(),
        },
        { onConflict: 'endpoint' }
      );

    if (upsertErr) {
      console.error('[save-push-subscription] upsert error:', upsertErr.message);
      return res.status(500).json({ error: 'Erreur lors de la sauvegarde de l\'abonnement. Réessayez.' });
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    return sendError(res, err, "Erreur lors de la sauvegarde de l'abonnement push");
  }
};
