// Vercel Serverless Function — exposes the VAPID public key to the frontend.
// The PRIVATE key never leaves the server; only the public key is returned here.
// No authentication required: the public key is not sensitive.

const { setCors, handleOptions } = require('./_utils');

module.exports = function handler(req, res) {
  if (handleOptions(req, res)) return;
  setCors(req, res);

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Méthode non autorisée' });
  }

  const vapidPublicKey = (process.env.VAPID_PUBLIC_KEY || '').trim();

  return res.status(200).json({ vapidPublicKey: vapidPublicKey || null });
};
