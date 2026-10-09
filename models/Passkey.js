// models/Passkey.js – Registered authenticator credential schema
//
// Each row corresponds to ONE passkey (one device / platform authenticator).
// A single user can have many passkeys (phone, laptop, YubiKey, etc.)
'use strict';

const mongoose = require('mongoose');

const passkeySchema = new mongoose.Schema(
  {
    // ── Owner ─────────────────────────────────────────────────
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },

    // ── WebAuthn fields ───────────────────────────────────────

    // Credential ID returned by the authenticator (base64url string)
    credentialID: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },

    // Public key in COSE format (base64url encoded)
    credentialPublicKey: {
      type: String,
      required: true,
    },

    // Algorithm used (e.g. -7 = ES256, -257 = RS256)
    credentialAlgorithm: {
      type: Number,
      required: true,
    },

    // Signature counter – incremented on each use.
    // Used to detect authenticator cloning attacks.
    counter: {
      type: Number,
      required: true,
      default: 0,
    },

    // Transports reported by the authenticator (e.g. ['internal', 'hybrid'])
    transports: {
      type: [String],
      default: [],
    },

    // ── UX metadata ───────────────────────────────────────────

    // Friendly name the user can give this passkey
    deviceName: {
      type: String,
      default: 'My Passkey',
      maxlength: 64,
    },

    // Last time this passkey was used to sign in
    lastUsedAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('Passkey', passkeySchema);
