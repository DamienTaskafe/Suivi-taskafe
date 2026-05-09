// Vercel Serverless Function — Web Push sender
// Sends push notifications to one or more subscribed devices.
// VAPID private key never leaves the server.
//
// Required environment variables:
//   VAPID_PUBLIC_KEY   — base64url VAPID public key (also used in the frontend)
//   VAPID_PRIVATE_KEY  — base64url VAPID private key (server-side only)
//   VAPID_SUBJECT      — mailto:... or https://... contact for push service
//   SUPABASE_SERVICE_ROLE_KEY — Supabase service role key (already required by other api/ functions)

const webpush = require('web-push');
const {
  setCors,
  handleOptions,
  parseBody,
  sendError,
  getBearerToken,
  getConfig,
  createAdminClient,
  getCaller,
  resolveCallerRole
} = require('./_utils');

const SUPPORTED_LANGS = new Set(['fr', 'ar', 'darija']);

function normalizeLang(value) {
  const lang = String(value || '').trim().toLowerCase();
  return SUPPORTED_LANGS.has(lang) ? lang : 'fr';
}

function statusLabel(lang, status) {
  const labels = {
    fr: {
      pending: '⏳ Envoyée',
      preparing: '📦 En préparation',
      ready_pickup: '✅ Prêt à récupérer',
      fulfilled: '✅ Remis / transféré',
      rejected: '❌ Refusée',
      cancelled: '🚫 Annulée'
    },
    ar: {
      pending: '⏳ تم الإرسال',
      preparing: '📦 قيد التحضير',
      ready_pickup: '✅ جاهز للاستلام',
      fulfilled: '✅ تم التسليم / التحويل',
      rejected: '❌ مرفوض',
      cancelled: '🚫 مُلغى'
    },
    darija: {
      pending: '⏳ Tsiftat',
      preparing: '📦 Kaytwejjed',
      ready_pickup: '✅ Wjdat bach tkhodha',
      fulfilled: '✅ Ttslmat / t7ewlat',
      rejected: '❌ Trfdat',
      cancelled: '🚫 Tlghat'
    }
  };
  return labels[lang]?.[status] || labels.fr[status] || status || '';
}

function formatItems(items = []) {
  if (!Array.isArray(items) || items.length === 0) return '';
  return items
    .map((it) => `- ${it?.category || '—'} : ${Number(it?.quantity ?? 0) || 0}`)
    .join('\n');
}

function buildLocalizedPush({ lang, type, payload, fallbackTitle, fallbackMessage }) {
  const actor = String(
    payload?.employee_name ||
    payload?.creator_name ||
    payload?.creator ||
    ''
  ).trim();
  const status = statusLabel(lang, payload?.status || '');
  const items = formatItems(payload?.items);

  if (type === 'new_stock_request' || type === 'stock_request') {
    const title = lang === 'ar'
      ? '📦 طلب مخزون'
      : lang === 'darija'
        ? '📦 Talab stock'
        : '📦 Demande de stock';
    let body = lang === 'ar'
      ? `${actor || 'موظف'} أرسل طلب مخزون.`
      : lang === 'darija'
        ? `${actor || 'Mokhdam'} sift talab stock.`
        : `${actor || 'Employé'} a envoyé une demande de stock.`;
    if (items) body += `\n${items}`;
    return { title, body };
  }

  if (type === 'stock_request_status') {
    const title = lang === 'ar'
      ? '📦 تحديث حالة الطلب'
      : lang === 'darija'
        ? '📦 Tbdil 7alat talab'
        : '📦 Mise à jour de la demande';
    let body = lang === 'ar'
      ? `الحالة الجديدة: ${status || '—'}`
      : lang === 'darija'
        ? `Statut jdid: ${status || '—'}`
        : `Nouveau statut : ${status || '—'}`;
    if (payload?.admin_notes) body += `\n📝 ${payload.admin_notes}`;
    return { title, body };
  }

  if (type === 'stock_request_cancelled') {
    const title = lang === 'ar'
      ? '🚫 تم إلغاء الطلب'
      : lang === 'darija'
        ? '🚫 Talab tlgha'
        : '🚫 Demande annulée';
    const body = lang === 'ar'
      ? 'تم إلغاء طلب المخزون.'
      : lang === 'darija'
        ? 'Talab stock tlgha.'
        : 'La demande de stock a été annulée.';
    return { title, body };
  }

  return {
    title: fallbackTitle || 'TASKAFÉ',
    body: fallbackMessage || ''
  };
}

module.exports = async function handler(req, res) {
  if (handleOptions(req, res)) return;
  setCors(req, res);

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  try {
    // ── VAPID config ────────────────────────────────────────────────────────
    const vapidPublicKey  = (process.env.VAPID_PUBLIC_KEY  || '').trim();
    const vapidPrivateKey = (process.env.VAPID_PRIVATE_KEY || '').trim();
    const vapidSubject    = (process.env.VAPID_SUBJECT     || '').trim();

    if (!vapidPublicKey || !vapidPrivateKey || !vapidSubject) {
      // Push is optional — inform the caller but do not hard-fail the app
      return res.status(503).json({ error: 'Push notifications non configurées côté serveur (VAPID manquant)' });
    }

    webpush.setVapidDetails(vapidSubject, vapidPublicKey, vapidPrivateKey);

    // ── Authenticate caller ─────────────────────────────────────────────────
    const token = getBearerToken(req);
    const { supabaseUrl, serviceRoleKey } = getConfig();
    const supabaseAdmin = createAdminClient(supabaseUrl, serviceRoleKey);
    const caller = await getCaller(supabaseAdmin, supabaseUrl, token);
    const callerRole = await resolveCallerRole({ supabaseAdmin, supabaseUrl, caller, token });

    // ── Parse request body ──────────────────────────────────────────────────
    const body = parseBody(req);
    const { type, title, message, url, employee_id, user_ids, payload } = body;

    if (!type) {
      return res.status(400).json({ error: 'Champ obligatoire : type' });
    }

    let targetUserIds = [];

    if (type === 'new_stock_request') {
      // Any authenticated user (employee) can notify all admins/managers
      const { data: admins, error: adminsErr } = await supabaseAdmin
        .from('profiles')
        .select('id')
        .in('role', ['admin', 'manager']);
      if (adminsErr) throw adminsErr;
      targetUserIds = (admins || []).map(p => p.id);
    } else if (type === 'stock_request_status') {
      // Only admin/manager can notify a specific employee
      if (!['admin', 'manager'].includes(callerRole)) {
        return res.status(403).json({ error: 'Accès refusé : rôle admin ou manager requis' });
      }
      if (employee_id) {
        targetUserIds = [employee_id];
      } else if (Array.isArray(user_ids) && user_ids.length > 0) {
        targetUserIds = user_ids;
      } else {
        return res.status(400).json({ error: 'employee_id ou user_ids requis pour ce type' });
      }
    } else if (type === 'stock_request_cancelled') {
      // Employee cancelling their own request → notify admins/managers
      // Admin/manager cancelling → notify the employee (passed as employee_id)
      if (employee_id) {
        // Admin cancelled: notify the requesting employee
        targetUserIds = [employee_id];
      } else {
        // Employee cancelled: notify all admins/managers
        const { data: admins, error: adminsErr } = await supabaseAdmin
          .from('profiles')
          .select('id')
          .in('role', ['admin', 'manager']);
        if (adminsErr) throw adminsErr;
        targetUserIds = (admins || []).map(p => p.id);
      }
    } else {
      return res.status(400).json({ error: 'Type inconnu. Utilisez new_stock_request, stock_request_status ou stock_request_cancelled' });
    }

    if (targetUserIds.length === 0) {
      return res.status(200).json({ sent: 0, message: 'Aucun destinataire' });
    }

    const { data: profiles, error: profilesErr } = await supabaseAdmin
      .from('profiles')
      .select('id, preferred_language')
      .in('id', targetUserIds);
    if (profilesErr) throw profilesErr;
    const languageByUserId = new Map((profiles || []).map(p => [p.id, normalizeLang(p.preferred_language)]));

    // ── Fetch subscriptions ─────────────────────────────────────────────────
    const { data: subs, error: subsErr } = await supabaseAdmin
      .from('push_subscriptions')
      .select('id, user_id, subscription')
      .in('user_id', targetUserIds);

    if (subsErr) throw subsErr;
    if (!subs || subs.length === 0) {
      return res.status(200).json({ sent: 0, message: 'Aucun abonnement push actif pour ces utilisateurs' });
    }

    // ── Send push notifications ─────────────────────────────────────────────
    const expiredIds = [];
    let sent = 0;

    await Promise.allSettled(
      subs.map(async sub => {
        try {
          const lang = languageByUserId.get(sub.user_id) || 'fr';
          const localized = buildLocalizedPush({
            lang,
            type,
            payload,
            fallbackTitle: title,
            fallbackMessage: message
          });
          const pushPayload = JSON.stringify({
            title:   localized.title || 'TASKAFÉ',
            body:    localized.body || '',
            url:     url || '/',
            // icon-512.png.PNG is the actual asset filename in this repository (see manifest.json)
            icon:    '/icon-512.png.PNG',
            badge:   '/icon-512.png.PNG',
            vibrate: [200, 100, 200],
            tag:     type
          });
          await webpush.sendNotification(sub.subscription, pushPayload);
          sent++;
        } catch (err) {
          // 410 Gone or 404 means the subscription is no longer valid
          if (err.statusCode === 410 || err.statusCode === 404) {
            expiredIds.push(sub.id);
          } else {
            console.warn('[send-push] push error for sub', sub.id, ':', err.message);
          }
        }
      })
    );

    // ── Clean up expired subscriptions ─────────────────────────────────────
    if (expiredIds.length > 0) {
      await supabaseAdmin
        .from('push_subscriptions')
        .delete()
        .in('id', expiredIds)
        .catch(e => console.warn('[send-push] cleanup error:', e.message));
    }

    return res.status(200).json({ sent, expired: expiredIds.length });
  } catch (err) {
    return sendError(res, err, 'Erreur lors de l\'envoi des notifications push');
  }
};
