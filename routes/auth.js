// routes/auth.js
// ──────────────────────────────────────────────────────────────────────────────
// Handles:
//   GET  /               → home (redirect to dashboard or login)
//   GET  /register       → show registration form
//   POST /register       → create user with optional password
//   GET  /login          → show login form
//   POST /login/password → authenticate with email + password
//   POST /logout         → destroy session
// ──────────────────────────────────────────────────────────────────────────────
'use strict';

const express  = require('express');
const crypto   = require('crypto');
const User     = require('../models/User');
const { redirectIfAuth, requireAuth } = require('../middleware/auth');

const router = express.Router();

// ── Home ──────────────────────────────────────────────────────
router.get('/', (req, res) => {
  if (req.session.userId) return res.redirect('/dashboard');
  res.redirect('/login');
});

// ── Register form ─────────────────────────────────────────────
router.get('/register', redirectIfAuth, (_req, res) => {
  res.render('register', { error: null });
});

// ── Register: create account ──────────────────────────────────
router.post('/register', redirectIfAuth, async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email) {
    return res.render('register', { error: 'Username and email are required.' });
  }

  try {
    // Check for duplicates
    const normalizedEmail = email.trim().toLowerCase();
    const normalizedUsername = username.trim();
    const exists = await User.findByEmailOrUsername(normalizedEmail, normalizedUsername);
    if (exists) {
      return res.render('register', { error: 'Username or email already taken.' });
    }

    // Generate a random 64-byte WebAuthn user handle (hex)
    const webAuthnUserID = crypto.randomBytes(32).toString('hex');

    const user = await User.create({
      username: normalizedUsername,
      email: normalizedEmail,
      password: password || null,
      webAuthnUserID,
    });

    // Auto-login after registration
    req.session.userId   = user.id;
    req.session.username = user.username;

    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    if (err.code === '23505') {
      return res.render('register', { error: 'Username or email already taken.' });
    }
    res.render('register', { error: 'Something went wrong. Please try again.' });
  }
});

// ── Login form ────────────────────────────────────────────────
router.get('/login', redirectIfAuth, (_req, res) => {
  res.render('login', { error: null });
});

// ── Login: password fallback ──────────────────────────────────
router.post('/login/password', redirectIfAuth, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render('login', { error: 'Email and password are required.' });
  }

  try {
    const user = await User.findByEmail(email.trim().toLowerCase());
    if (!user || !(await user.comparePassword(password))) {
      return res.render('login', { error: 'Invalid email or password.' });
    }

    req.session.userId   = user.id;
    req.session.username = user.username;

    const next = req.query.next || '/dashboard';
    res.redirect(decodeURIComponent(next));
  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Something went wrong. Please try again.' });
  }
});

// ── Logout ────────────────────────────────────────────────────
router.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});

module.exports = router;
