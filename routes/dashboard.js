// routes/dashboard.js – Protected dashboard and passkey management page
'use strict';

const express = require('express');
const User    = require('../models/User');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// ── Dashboard ─────────────────────────────────────────────────
router.get('/', requireAuth, async (req, res) => {
  try {
    const user = await User
      .findById(req.session.userId)
      .populate('passkeys')
      .lean();

    if (!user) {
      req.session.destroy();
      return res.redirect('/login');
    }

    res.render('dashboard', { user, passkeys: user.passkeys });
  } catch (err) {
    console.error(err);
    res.status(500).render('error', { message: err.message });
  }
});

module.exports = router;
