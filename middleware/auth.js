// middleware/auth.js – Route protection helpers
'use strict';

/**
 * requireAuth – Blocks unauthenticated requests.
 * Redirects to /login with a ?next= query param so the user
 * is sent back after successful login.
 */
const requireAuth = (req, res, next) => {
  if (req.session && req.session.userId) return next();
  const next_ = encodeURIComponent(req.originalUrl);
  return res.redirect(`/login?next=${next_}`);
};

/**
 * redirectIfAuth – Prevents logged-in users from seeing
 * login / register pages.
 */
const redirectIfAuth = (req, res, next) => {
  if (req.session && req.session.userId) return res.redirect('/dashboard');
  next();
};

module.exports = { requireAuth, redirectIfAuth };
