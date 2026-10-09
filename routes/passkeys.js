// routes/passkeys.js
// ──────────────────────────────────────────────────────────────────────────────
//  All WebAuthn / Passkey API endpoints:
//
//  REGISTRATION
//    POST /passkeys/register/options   → generate registration options (challenge)
//    POST /passkeys/register/verify    → verify attestation & save credential
//
//  AUTHENTICATION
//    POST /passkeys/login/options      → generate authentication options (challenge)
//    POST /passkeys/login/verify       → verify assertion & create session
//
//  MANAGEMENT  (requires session)
//    DELETE /passkeys/:id              → remove a passkey from the account
//    PATCH  /passkeys/:id/rename       → rename a passkey
// ──────────────────────────────────────────────────────────────────────────────
'use strict';

const express = require('express');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const User    = require('../models/User');
const Passkey = require('../models/Passkey');
const { rpName, rpID, origin } = require('../config/webauthn');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

// ══════════════════════════════════════════════════════════════
//  REGISTRATION
// ══════════════════════════════════════════════════════════════

/**
 * POST /passkeys/register/options
 * ─────────────────────────────────────────────────────────────
 * Returns a PublicKeyCredentialCreationOptions JSON that the
 * browser's navigator.credentials.create() call needs.
 *
 * Requires: active session (user must already be logged in).
 */
router.post('/register/options', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).populate('passkeys');
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Exclude credentials the user already registered so the
    // browser won't offer a device the user has already added.
    const excludeCredentials = user.passkeys.map((pk) => ({
      id:         pk.credentialID,
      type:       'public-key',
      transports: pk.transports,
    }));

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID:               Buffer.from(user.webAuthnUserID, 'hex'),
      userName:             user.username,
      userDisplayName:      user.username,
      attestationType:      'none',          // 'none' = no hardware attestation
      excludeCredentials,
      authenticatorSelection: {
        // 'platform'  → device-native (Touch ID, Face ID, Windows Hello)
        // 'cross-platform' → roaming keys (YubiKey, phone via QR)
        // '' → let the browser decide (recommended for widest support)
        authenticatorAttachment: undefined,
        residentKey:   'required',   // passkeys MUST be discoverable
        userVerification: 'required', // biometric / PIN always required
      },
      supportedAlgorithmIDs: [-7, -257],    // ES256, RS256
    });

    // Store challenge in session for verification
    req.session.registrationChallenge = options.challenge;

    res.json(options);
  } catch (err) {
    console.error('[register/options]', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /passkeys/register/verify
 * ─────────────────────────────────────────────────────────────
 * Receives the attestation from the browser, verifies it, and
 * saves the new credential to the database.
 *
 * Body: { credential: PublicKeyCredential (JSON), deviceName?: string }
 */
router.post('/register/verify', requireAuth, async (req, res) => {
  const { credential, deviceName } = req.body;
  const expectedChallenge = req.session.registrationChallenge;

  if (!expectedChallenge) {
    return res.status(400).json({ error: 'No challenge found. Start registration first.' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response:          credential,
      expectedChallenge,
      expectedOrigin:    origin,
      expectedRPID:      rpID,
      requireUserVerification: true,
    });

    const { verified, registrationInfo } = verification;

    if (!verified || !registrationInfo) {
      return res.status(400).json({ error: 'Verification failed.' });
    }

    const {
      credential: cred,
      credentialDeviceType,
      credentialBackedUp,
    } = registrationInfo;

    // Save the new passkey
    const passkey = new Passkey({
      user:               req.session.userId,
      credentialID:       cred.id,
      credentialPublicKey: Buffer.from(cred.publicKey).toString('base64url'),
      credentialAlgorithm: cred.algorithm,
      counter:            cred.counter,
      transports:         credential.response?.transports || [],
      deviceName:         deviceName || 'My Passkey',
    });

    await passkey.save();

    // Link passkey to the user document
    await User.findByIdAndUpdate(req.session.userId, {
      $push: { passkeys: passkey._id },
    });

    // Clear challenge from session
    delete req.session.registrationChallenge;

    res.json({
      success: true,
      passkey: {
        id:         passkey._id,
        deviceName: passkey.deviceName,
        createdAt:  passkey.createdAt,
      },
    });
  } catch (err) {
    console.error('[register/verify]', err);
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════
//  AUTHENTICATION
// ══════════════════════════════════════════════════════════════

/**
 * POST /passkeys/login/options
 * ─────────────────────────────────────────────────────────────
 * Returns a PublicKeyCredentialRequestOptions JSON.
 *
 * Body: { username?: string }  – optional; omit for "conditional UI"
 * (the browser's auto-fill passkey prompt).
 */
router.post('/login/options', async (req, res) => {
  try {
    const { username } = req.body;

    let allowCredentials = [];

    if (username) {
      // Lookup passkeys for a specific user (username-first flow)
      const user = await User.findOne({ username: username.trim() }).populate('passkeys');
      if (user) {
        allowCredentials = user.passkeys.map((pk) => ({
          id:         pk.credentialID,
          type:       'public-key',
          transports: pk.transports,
        }));
      }
    }
    // If no username → empty allowCredentials → browser shows all
    // stored passkeys for this rpID (discoverable credential flow)

    const options = await generateAuthenticationOptions({
      rpID,
      timeout:              60000,
      allowCredentials,
      userVerification:     'required',
    });

    // Store challenge in session for verification
    req.session.authChallenge = options.challenge;

    res.json(options);
  } catch (err) {
    console.error('[login/options]', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /passkeys/login/verify
 * ─────────────────────────────────────────────────────────────
 * Receives the assertion from the browser, verifies it, and
 * creates an authenticated session.
 *
 * Body: { credential: PublicKeyCredential (JSON) }
 */
router.post('/login/verify', async (req, res) => {
  const { credential } = req.body;
  const expectedChallenge = req.session.authChallenge;

  if (!expectedChallenge) {
    return res.status(400).json({ error: 'No challenge found. Start authentication first.' });
  }

  try {
    // Find the passkey by credential ID
    const passkey = await Passkey.findOne({ credentialID: credential.id }).populate('user');
    if (!passkey) {
      return res.status(400).json({ error: 'Passkey not found.' });
    }

    const verification = await verifyAuthenticationResponse({
      response:              credential,
      expectedChallenge,
      expectedOrigin:        origin,
      expectedRPID:          rpID,
      requireUserVerification: true,
      credential: {
        id:         passkey.credentialID,
        publicKey:  Buffer.from(passkey.credentialPublicKey, 'base64url'),
        counter:    passkey.counter,
        transports: passkey.transports,
      },
    });

    const { verified, authenticationInfo } = verification;

    if (!verified) {
      return res.status(400).json({ error: 'Authentication failed.' });
    }

    // Update counter (replay-attack protection)
    passkey.counter    = authenticationInfo.newCounter;
    passkey.lastUsedAt = new Date();
    await passkey.save();

    // Create authenticated session
    const user = passkey.user;
    req.session.userId   = user._id.toString();
    req.session.username = user.username;

    delete req.session.authChallenge;

    res.json({ success: true, redirect: '/dashboard' });
  } catch (err) {
    console.error('[login/verify]', err);
    res.status(500).json({ error: err.message });
  }
});

// ══════════════════════════════════════════════════════════════
//  MANAGEMENT  (authenticated users only)
// ══════════════════════════════════════════════════════════════

/**
 * PATCH /passkeys/:id/rename
 * Rename a passkey (must belong to the current user)
 */
router.patch('/:id/rename', requireAuth, async (req, res) => {
  try {
    const { deviceName } = req.body;
    if (!deviceName || !deviceName.trim()) {
      return res.status(400).json({ error: 'Device name is required.' });
    }

    const passkey = await Passkey.findOneAndUpdate(
      { _id: req.params.id, user: req.session.userId },
      { deviceName: deviceName.trim() },
      { new: true }
    );

    if (!passkey) return res.status(404).json({ error: 'Passkey not found.' });
    res.json({ success: true, deviceName: passkey.deviceName });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /passkeys/:id
 * Remove a passkey from the account.
 * Prevents removing the last passkey if the user has no password.
 */
router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).populate('passkeys');
    if (!user) return res.status(404).json({ error: 'User not found.' });

    // Safety: don't let users lock themselves out
    if (user.passkeys.length <= 1 && !user.password) {
      return res.status(400).json({
        error: 'Cannot remove your last passkey when you have no password set.',
      });
    }

    const passkey = await Passkey.findOneAndDelete({
      _id: req.params.id,
      user: req.session.userId,
    });

    if (!passkey) return res.status(404).json({ error: 'Passkey not found.' });

    await User.findByIdAndUpdate(req.session.userId, {
      $pull: { passkeys: passkey._id },
    });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
