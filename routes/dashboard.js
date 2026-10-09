// routes/dashboard.js – Protected dashboard and passkey management page
'use strict';

const express = require('express');
const User    = require('../models/User');
const Passkey = require('../models/Passkey');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// ── Dashboard ─────────────────────────────────────────────────
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const user = await User.findById(req.session.userId);

    if (!user) {
      return req.session.destroy((err) => {
        if (err) return next(err);
        res.redirect('/login');
      });
    }

    const passkeys = await Passkey.listForUser(user.id);
    res.render('dashboard', { user, passkeys });
  } catch (err) {
    console.error(err);
    res.status(500).render('error', { message: err.message });
  }
});

module.exports = router;
