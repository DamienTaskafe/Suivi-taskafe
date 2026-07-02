const { createClient } = require('@supabase/supabase-js');

function setCors(req, res) {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Content-Type', 'application/json');
}

function handleOptions(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return true;
  }
  return false;
}

function getConfig() {
  const supabaseUrl = (process.env.SUPABASE_URL || '').trim().replace(/\/+$/, '');
  const serviceRoleKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
  const anonKey = (process.env.SUPABASE_ANON_KEY || '').trim();

  if (!supabaseUrl) {
    const err = new Error('Configuration serveur manquante (SUPABASE_URL)');
    err.status = 500;
    throw err;
  }

  if (!serviceRoleKey) {
    const err = new Error('Configuration serveur manquante (SUPABASE_SERVICE_ROLE_KEY)');
    err.status = 500;
    throw err;
  }

  if (!anonKey) {
    const err = new Error('Configuration serveur manquante (SUPABASE_ANON_KEY)');
    err.status = 500;
    throw err;
  }

  return { supabaseUrl, serviceRoleKey, anonKey };
}

function parseBody(req) {
  if (!req.body) return {};
  if (typeof req.body === 'string' || Buffer.isBuffer(req.body)) {
    return JSON.parse(Buffer.isBuffer(req.body) ? req.body.toString('utf8') : req.body);
  }
  return req.body;
}

function getBearerToken(req) {
  const authHeader = String(req.headers.authorization || '').trim();
  if (!/^bearer\s+\S+/i.test(authHeader)) {
    const err = new Error('En-tête Authorization manquant ou invalide');
    err.status = 401;
    throw err;
  }

  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (token.split('.').length !== 3) {
    const err = new Error('Token JWT malformé');
    err.status = 401;
    throw err;
  }

  return token;
}

function createAdminClient(supabaseUrl, serviceRoleKey) {
  return createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  });
}

function createAnonClient(supabaseUrl, anonKey) {
  return createClient(supabaseUrl, anonKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  });
}

async function getCaller(supabaseAdmin, supabaseUrl, anonKey, token) {
  const first = await supabaseAdmin.auth.getUser(token);
  if (first.data?.user && !first.error) return first.data.user;

  const supabaseAnon = createAnonClient(supabaseUrl, anonKey);
  const second = await supabaseAnon.auth.getUser(token);
  if (second.data?.user && !second.error) return second.data.user;

  const err = new Error('Token invalide ou expiré. Reconnectez-vous puis réessayez.');
  err.status = 401;
  throw err;
}

async function resolveCallerRole({ supabaseAdmin, supabaseUrl, anonKey, caller, token }) {
  // Fast path: after logout/login, Supabase JWT carries app_metadata.role.
  const metadataRole = String(caller.app_metadata?.role || '').toLowerCase();
  if (metadataRole) return metadataRole;

  // Service-role profile lookup by auth UUID.
  const byId = await supabaseAdmin
    .from('profiles')
    .select('id,email,role')
    .eq('id', caller.id)
    .limit(1);

  if (Array.isArray(byId.data) && byId.data.length > 0) {
    return String(byId.data[0].role || '').toLowerCase();
  }

  // Fallback by email protects against old/mismatched profile rows.
  if (caller.email) {
    const byEmail = await supabaseAdmin
      .from('profiles')
      .select('id,email,role')
      .ilike('email', caller.email)
      .limit(1);

    if (Array.isArray(byEmail.data) && byEmail.data.length > 0) {
      return String(byEmail.data[0].role || '').toLowerCase();
    }
  }

  // Last fallback with the user's own token, useful if service-role profile read fails.
  const supabaseAsUser = createAnonClient(supabaseUrl, anonKey);
  const asUser = await supabaseAsUser
    .from('profiles')
    .select('role')
    .eq('id', caller.id)
    .limit(1);

  if (Array.isArray(asUser.data) && asUser.data.length > 0) {
    return String(asUser.data[0].role || '').toLowerCase();
  }

  return '';
}

async function requireAdmin(req, res) {
  const token = getBearerToken(req);
  const { supabaseUrl, serviceRoleKey, anonKey } = getConfig();
  const supabaseAdmin = createAdminClient(supabaseUrl, serviceRoleKey);
  const caller = await getCaller(supabaseAdmin, supabaseUrl, anonKey, token);
  const callerRole = await resolveCallerRole({ supabaseAdmin, supabaseUrl, anonKey, caller, token });

  if (callerRole !== 'admin') {
    const err = new Error(
      callerRole
        ? `Accès refusé : rôle admin requis (rôle actuel : ${callerRole})`
        : 'Accès refusé : rôle admin non défini ou introuvable. Déconnectez-vous puis reconnectez-vous.'
    );
    err.status = 403;
    throw err;
  }

  return { caller, supabaseAdmin, supabaseUrl, serviceRoleKey };
}

function sendError(res, err, fallback = 'Erreur serveur interne. Veuillez réessayer.') {
  const status = Number(err?.status || err?.statusCode || 500);
  const message = err?.message || fallback;
  return res.status(status).json({ error: message });
}

module.exports = {
  setCors,
  handleOptions,
  parseBody,
  requireAdmin,
  sendError,
  // lower-level helpers consumed by send-push and other functions
  getBearerToken,
  getConfig,
  createAdminClient,
  createAnonClient,
  getCaller,
  resolveCallerRole
};
