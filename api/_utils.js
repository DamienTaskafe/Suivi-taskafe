const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL_FALLBACK = 'https://ogjljdjphawcminawtlv.supabase.co';
const SUPABASE_ANON_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
  'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9namxqZGpwaGF3Y21pbmF3dGx2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzYzNzQ5MjUsImV4cCI6MjA5MTk1MDkyNX0.' +
  'WVgrgx8Q1c9j_1UyNX7e2ilvttMBSHY2vnrBw_Ga05A';

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
  const supabaseUrl = (process.env.SUPABASE_URL || SUPABASE_URL_FALLBACK).trim().replace(/\/+$/, '');
  const serviceRoleKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();

  if (!serviceRoleKey) {
    const err = new Error('Configuration serveur manquante (SUPABASE_SERVICE_ROLE_KEY)');
    err.status = 500;
    throw err;
  }

  return { supabaseUrl, serviceRoleKey };
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

function createAnonClient(supabaseUrl, token) {
  return createClient(supabaseUrl, SUPABASE_ANON_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
    global: token ? { headers: { Authorization: `Bearer ${token}` } } : undefined
  });
}

async function getCaller(supabaseAdmin, supabaseUrl, token) {
  const first = await supabaseAdmin.auth.getUser(token);
  if (first.data?.user && !first.error) return first.data.user;

  const supabaseAnon = createAnonClient(supabaseUrl);
  const second = await supabaseAnon.auth.getUser(token);
  if (second.data?.user && !second.error) return second.data.user;

  const err = new Error('Token invalide ou expiré. Reconnectez-vous puis réessayez.');
  err.status = 401;
  throw err;
}

async function resolveCallerRole({ supabaseAdmin, supabaseUrl, caller, token }) {
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
  const supabaseAsUser = createAnonClient(supabaseUrl, token);
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
  const { supabaseUrl, serviceRoleKey } = getConfig();
  const supabaseAdmin = createAdminClient(supabaseUrl, serviceRoleKey);
  const caller = await getCaller(supabaseAdmin, supabaseUrl, token);
  const callerRole = await resolveCallerRole({ supabaseAdmin, supabaseUrl, caller, token });

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
  getCaller,
  resolveCallerRole
};
