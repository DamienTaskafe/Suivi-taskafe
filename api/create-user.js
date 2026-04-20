// Vercel Serverless Function — Admin user creation
// Uses SUPABASE_SERVICE_ROLE_KEY (server-side only, never exposed to the browser)
// Required environment variables on Vercel:
//   SUPABASE_URL              — e.g. https://xxxx.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY — service_role secret from Supabase dashboard > Settings > API

const { createClient } = require('@supabase/supabase-js');

// Supabase project URL — same value already hardcoded in index.html (not a secret)
const SUPABASE_URL_FALLBACK = 'https://ogjljdjphawcminawtlv.supabase.co';

// Anon key — already present in the public frontend JS, safe to use server-side.
// Used as fallback for the getUser() validation call if the service_role key fails.
const SUPABASE_ANON_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
  'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9namxqZGpwaGF3Y21pbmF3dGx2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzYzNzQ5MjUsImV4cCI6MjA5MTk1MDkyNX0.' +
  'WVgrgx8Q1c9j_1UyNX7e2ilvttMBSHY2vnrBw_Ga05A';

module.exports = async (req, res) => {
  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  console.log('[create-user] → Entrée dans la fonction', { method: req.method, ts: new Date().toISOString() });

  // ── Step 1 : Require admin Authorization header ───────────────────────────
  const authHeader = (req.headers['authorization'] || '').trim();
  if (!authHeader || !/^bearer\s+\S/i.test(authHeader)) {
    return res.status(401).json({ error: 'En-tête Authorization manquant ou invalide' });
  }
  const callerToken = authHeader.replace(/^Bearer\s+/i, '').trim();

  // Basic JWT structure check (3 base64url parts separated by dots)
  const jwtParts = callerToken.split('.');
  if (jwtParts.length !== 3) {
    console.error('[create-user] Token JWT malformé, parties =', jwtParts.length);
    return res.status(401).json({ error: 'Token JWT malformé' });
  }

  const { email, password, full_name, role } = req.body || {};

  // Basic validation
  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe obligatoires' });
  }
  // Validate email format — Supabase validates further server-side
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  if (!emailRegex.test(String(email))) {
    return res.status(400).json({ error: 'Format d\'email invalide' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Mot de passe minimum 6 caractères' });
  }
  const allowedRoles = ['employee', 'manager', 'admin'];
  const safeRole = allowedRoles.includes(role) ? role : 'employee';

  const envUrl = (process.env.SUPABASE_URL || '').trim();
  if (!envUrl) {
    console.warn('[create-user] SUPABASE_URL non définie — utilisation de la valeur de secours.');
  }
  // Remove any accidental trailing slashes to avoid double-slash in REST URLs
  const supabaseUrl = (envUrl || SUPABASE_URL_FALLBACK).replace(/\/+$/, '');
  const serviceRoleKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();

  if (!serviceRoleKey) {
    console.error('[create-user] SUPABASE_SERVICE_ROLE_KEY manquante');
    return res
      .status(500)
      .json({ error: 'Configuration serveur manquante (SUPABASE_SERVICE_ROLE_KEY)' });
  }

  // Admin client — never returned to the browser
  const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  });

  // ── Step 2 : Verify caller identity via JWT ───────────────────────────────
  // Try with the service_role client first; if that fails, retry with the
  // anon key client (same endpoint, different apikey header) for robustness.
  let caller;
  try {
    const { data, error: err1 } = await supabaseAdmin.auth.getUser(callerToken);

    if (err1 || !data?.user) {
      console.error('[create-user] getUser (service_role) échoué :', {
        error: err1?.message,
        status: err1?.status,
        supabaseUrl,
        tokenStart: callerToken.substring(0, 10) + '…',
        tokenLength: callerToken.length
      });

      // Fallback: try with the anon key
      const supabaseAnon = createClient(supabaseUrl, SUPABASE_ANON_KEY, {
        auth: { autoRefreshToken: false, persistSession: false }
      });
      const { data: data2, error: err2 } = await supabaseAnon.auth.getUser(callerToken);

      if (err2 || !data2?.user) {
        console.error('[create-user] getUser (anon) également échoué :', err2?.message);

        // Decode JWT payload for diagnostic
        try {
          const payload = JSON.parse(
            Buffer.from(jwtParts[1], 'base64url').toString('utf8')
          );
          const now = Math.floor(Date.now() / 1000);
          const expired = payload.exp < now;
          console.error('[create-user] JWT payload diagnostic :', {
            sub: payload.sub ? payload.sub.substring(0, 8) + '…' : null,
            role: payload.role,
            exp: payload.exp,
            now,
            expired
          });
          if (expired) {
            return res.status(401).json({ error: 'Token expiré. Reconnectez-vous puis réessayez.' });
          }
        } catch (decodeErr) {
          console.error('[create-user] Impossible de décoder le payload JWT :', decodeErr.message);
        }

        return res.status(401).json({ error: 'Token invalide ou expiré' });
      }

      caller = data2.user;
    } else {
      caller = data.user;
    }
  } catch (e) {
    console.error('[create-user] Exception lors de la vérification du token :', e.message);
    return res.status(503).json({ error: 'Service d\'authentification inaccessible, réessayez' });
  }

  console.log('[create-user] Token validé, appelant =', caller.id, '| email =', caller.email);

  // ── Step 3 : Verify caller has admin role ────────────────────────────────
  // Strategy (in order):
  //   1. supabaseAdmin SDK query on profiles (service-role key → bypasses RLS)
  //      → sdk_error path: REST fallback + email-based lookup
  //   2. Fallback to app_metadata.role carried in the JWT
  //   3. Fallback: query profiles using the caller's own JWT (anon key + caller token)
  //      — works even when SUPABASE_SERVICE_ROLE_KEY is misconfigured on the host
  //   4. Fresh admin.getUserById() to get the latest app_metadata
  // After any successful lookup: opportunistically sync role to app_metadata.
  let callerRole = null;
  let profileLookupStatus = 'pending';
  try {
    console.log('[create-user] Début vérification rôle admin :', {
      callerId: caller.id,
      callerEmail: caller.email,
      appMetadataHasRole: !!(caller.app_metadata?.role)
    });

    const { data: profileRows, error: profileQueryError } = await supabaseAdmin
      .from('profiles')
      .select('role')
      .eq('id', caller.id)
      .limit(1);

    if (profileQueryError) {
      profileLookupStatus = 'sdk_error';
      console.error('[create-user] Erreur SDK profiles :', {
        message: profileQueryError.message,
        code: profileQueryError.code,
        details: profileQueryError.details,
        hint: profileQueryError.hint
      });

      // Fallback: query profiles via REST API directly (bypasses SDK, uses service-role key)
      try {
        // Validate that caller.id is a UUID before interpolating into the REST URL.
        // Matches UUID v1–v5 (all variants); UUIDs from Supabase auth are always v4.
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(caller.id)) {
          console.warn('[create-user] REST profiles fallback ignoré: callerId non-UUID =', typeof caller.id);
        } else {
          const profileUrl = `${supabaseUrl}/rest/v1/profiles?select=role&id=eq.${encodeURIComponent(caller.id)}&limit=1`;
          const profileResp = await fetch(profileUrl, {
            headers: {
              'apikey': serviceRoleKey,
              'Authorization': `Bearer ${serviceRoleKey}`,
              'Accept': 'application/json'
            }
          });
          if (profileResp.ok) {
            const restRows = await profileResp.json();
            if (Array.isArray(restRows) && restRows.length > 0) {
              callerRole = String(restRows[0].role || '').toLowerCase();
              profileLookupStatus = 'found_via_rest';
              console.log('[create-user] Rôle obtenu via REST (fallback sdk_error) :', callerRole);
            } else {
              console.warn('[create-user] REST profiles: aucun profil trouvé pour callerId =', caller.id);
            }
          } else {
            let errBody = '';
            try { errBody = await profileResp.text(); } catch (parseEx) {
              console.warn('[create-user] REST profiles: impossible de lire le corps de la réponse :', parseEx?.message);
            }
            console.warn('[create-user] REST profiles: réponse non-OK, status =', profileResp.status, '| body =', errBody.substring(0, 200));
          }
        }
      } catch (restEx) {
        console.warn('[create-user] REST profiles fallback exception :', restEx?.message);
      }

      // Diagnostic (sdk_error path): also attempt email-based lookup to detect UUID mismatches
      if (!callerRole && caller.email) {
        try {
          const { data: emailRowsSdkErr } = await supabaseAdmin
            .from('profiles')
            .select('id,role')
            .eq('email', caller.email)
            .limit(1);
          if (Array.isArray(emailRowsSdkErr) && emailRowsSdkErr.length > 0) {
            console.warn('[create-user] sdk_error path: profil trouvé par email.', {
              profileIdByEmail: emailRowsSdkErr[0].id,
              callerId: caller.id,
              idsDiffer: emailRowsSdkErr[0].id !== caller.id,
              roleByEmail: emailRowsSdkErr[0].role
            });
            // Use the role even if IDs differ — the JWT identity was already validated in Step 2.
            // A mismatch here likely means the profile was migrated with a different UUID.
            if (!callerRole && emailRowsSdkErr[0].role) {
              callerRole = String(emailRowsSdkErr[0].role).toLowerCase();
              profileLookupStatus = 'found_via_email';
              console.log('[create-user] Rôle obtenu via email (sdk_error path) :', callerRole);
            }
          } else {
            console.warn('[create-user] sdk_error path: aucun profil par email non plus :', caller.email);
          }
        } catch (emailErrSdk) {
          console.warn('[create-user] sdk_error path: email lookup exception :', emailErrSdk?.message);
        }
      }
    } else if (Array.isArray(profileRows) && profileRows.length > 0) {
      callerRole = String(profileRows[0].role || '').toLowerCase();
      profileLookupStatus = 'found';
      console.log('[create-user] Rôle obtenu via profiles :', callerRole, '| callerId =', caller.id);
    } else {
      profileLookupStatus = 'not_found';
      console.warn('[create-user] Profil introuvable (par id) pour callerId =', caller.id);

      // Diagnostic: verify table access by checking total row count
      try {
        const { count: totalCount, error: countErr } = await supabaseAdmin
          .from('profiles')
          .select('id', { count: 'exact', head: true });
        console.warn('[create-user] Diagnostic table profiles — nb total lignes :', totalCount, '| erreur :', countErr?.message);
      } catch (countEx) {
        console.warn('[create-user] Diagnostic count profiles exception :', countEx?.message);
      }

      // Diagnostic: try lookup by email to detect a UUID mismatch
      if (caller.email) {
        try {
          const { data: emailRows } = await supabaseAdmin
            .from('profiles')
            .select('id,role')
            .eq('email', caller.email)
            .limit(1);
          if (Array.isArray(emailRows) && emailRows.length > 0) {
            console.warn('[create-user] Diagnostic: profil trouvé par email mais pas par id.', {
              profileIdByEmail: emailRows[0].id,
              callerId: caller.id,
              idsDiffer: emailRows[0].id !== caller.id,
              roleByEmail: emailRows[0].role
            });
          } else {
            console.warn('[create-user] Diagnostic: aucun profil par email non plus :', caller.email);
          }
        } catch (emailLookupEx) {
          console.warn('[create-user] Diagnostic email lookup exception :', emailLookupEx?.message);
        }
      }
    }

    // Fallback 1: app_metadata.role carried inside the JWT
    if (!callerRole) {
      const appRole = String(caller.app_metadata?.role || '').toLowerCase();
      if (appRole) {
        callerRole = appRole;
        console.log('[create-user] Rôle depuis app_metadata JWT (fallback 1) :', callerRole);
      }
    }

    // Fallback 2: query profiles using the caller's own JWT (anon key + caller's Authorization).
    // This works regardless of whether the service_role key is correctly configured on the host,
    // because any authenticated Supabase user can read all profiles (RLS: profiles_select_auth).
    // It covers the common case where SUPABASE_SERVICE_ROLE_KEY is missing/wrong on Vercel
    // but the user's session token is perfectly valid.
    if (!callerRole) {
      try {
        const supabaseAsUser = createClient(supabaseUrl, SUPABASE_ANON_KEY, {
          auth: { autoRefreshToken: false, persistSession: false },
          global: { headers: { Authorization: `Bearer ${callerToken}` } }
        });
        const { data: callerProfileRows, error: callerProfileErr } = await supabaseAsUser
          .from('profiles')
          .select('role')
          .eq('id', caller.id)
          .limit(1);
        if (callerProfileErr) {
          console.warn('[create-user] Profiles (caller token) erreur :', callerProfileErr.message);
        } else if (Array.isArray(callerProfileRows) && callerProfileRows.length > 0) {
          callerRole = String(callerProfileRows[0].role || '').toLowerCase();
          profileLookupStatus = 'found_via_caller_token';
          console.log('[create-user] Rôle depuis profiles (caller token, fallback 2) :', callerRole);
        } else {
          console.warn('[create-user] Profiles (caller token): aucun profil pour callerId =', caller.id);
        }
      } catch (callerTokenEx) {
        console.warn('[create-user] Profiles (caller token) exception :', callerTokenEx?.message);
      }
    }

    // Fallback 3: fresh admin API call to get the latest app_metadata
    // Needed when the admin account was created manually (no app_metadata set at creation)
    // and the profiles query returned empty (e.g., service_role key issue or UUID mismatch).
    if (!callerRole) {
      try {
        const { data: freshUserData, error: adminGetErr } = await supabaseAdmin.auth.admin.getUserById(caller.id);
        if (adminGetErr) {
          console.warn('[create-user] admin.getUserById erreur :', adminGetErr.message);
        } else {
          const freshAppRole = String(
            freshUserData?.user?.app_metadata?.role || ''
          ).toLowerCase();
          if (freshAppRole) {
            callerRole = freshAppRole;
            console.log('[create-user] Rôle depuis admin.getUserById (fallback 3) :', callerRole);
          } else {
            console.warn('[create-user] admin.getUserById : aucun rôle dans app_metadata');
          }
        }
      } catch (adminGetEx) {
        console.warn('[create-user] admin.getUserById exception :', adminGetEx?.message);
      }
    }

    // Opportunistic sync: if the role was resolved via profiles but app_metadata lacks it,
    // set it now so subsequent calls can short-circuit the profile lookup entirely.
    if (callerRole && !caller.app_metadata?.role) {
      supabaseAdmin.auth.admin.updateUserById(caller.id, {
        app_metadata: { role: callerRole }
      }).catch(e => console.warn('[create-user] Sync app_metadata (non-bloquant) :', e?.message));
    }
  } catch (e) {
    console.error('[create-user] Exception vérification rôle appelant :', e.message);
    return res.status(503).json({ error: 'Service d\'authentification inaccessible, réessayez' });
  }

  if (callerRole !== 'admin') {
    console.error('[create-user] Accès refusé :', {
      callerId: caller.id,
      callerEmail: caller.email,
      callerRole: callerRole || '(vide)',
      profileLookupStatus
    });

    let errorMsg;
    if (!callerRole && (profileLookupStatus === 'not_found' || profileLookupStatus === 'sdk_error')) {
      errorMsg = 'Accès refusé : votre compte n\'a pas de rôle admin configuré. Vérifiez que votre profil existe dans la table profiles avec role=admin, ou contactez un administrateur système.';
    } else if (!callerRole) {
      errorMsg = 'Accès refusé : rôle admin non défini ou introuvable';
    } else {
      errorMsg = `Accès refusé : rôle admin requis (rôle actuel : ${callerRole})`;
    }

    return res.status(403).json({ error: errorMsg });
  }

  let authData;
  try {
    // Create Auth user with admin API — bypasses email rate-limits and confirmation emails
    console.log('[create-user] Lancement de supabaseAdmin.auth.admin.createUser pour :', email);
    const { data, error: authError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true // mark email as confirmed immediately, no confirmation email sent
    });

    if (authError) {
      const msg = (authError.message || '').toLowerCase();
      const alreadyExists =
        msg.includes('already') ||
        msg.includes('already registered') ||
        msg.includes('duplicate') ||
        authError.code === 'email_exists' ||
        authError.status === 422;
      return res
        .status(alreadyExists ? 409 : 400)
        .json({ error: authError.message || 'Erreur lors de la création du compte' });
    }

    authData = data;
    console.log('[create-user] createUser réussi, newUserId =', authData?.user?.id);
  } catch (networkError) {
    console.error('[create-user] Supabase admin API unreachable:', networkError);
    return res.status(502).json({ error: 'Service d\'authentification inaccessible, réessayez dans quelques instants' });
  }

  const newUserId = authData?.user?.id;

  if (newUserId) {
    // Store role in app_metadata (server-controlled) so the delete-user API can
    // verify admin role even if the profiles table query fails.
    await supabaseAdmin.auth.admin.updateUserById(newUserId, {
      app_metadata: { role: safeRole }
    }).catch((e) => console.warn('[create-user] app_metadata update failed:', e?.message));

    console.log('[create-user] Insertion du profil en table profiles...');
    const { error: profileError } = await supabaseAdmin.from('profiles').insert({
      id: newUserId,
      email,
      full_name: full_name || '',
      role: safeRole
    });

    if (profileError) {
      // Profile creation failed — roll back the Auth user to avoid an orphaned account
      console.error('[create-user] Profile insert failed, rolling back auth user:', profileError.message);
      await supabaseAdmin.auth.admin.deleteUser(newUserId).catch((e) =>
        console.error('[create-user] Rollback deleteUser failed:', e)
      );
      return res.status(500).json({ error: 'Échec de la création du profil : ' + profileError.message });
    }
    console.log('[create-user] Profil inséré avec succès pour', newUserId);
  }

  return res.status(201).json({
    success: true,
    userId: newUserId,
    message: `Utilisateur créé : ${email}`
  });
};
