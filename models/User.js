// models/User.js – User document schema
'use strict';

const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    // ── Identity ──────────────────────────────────────────────
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 64,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },

    // ── Optional password (fallback login) ────────────────────
    // Users who register via passkey only will have no password.
    password: {
      type: String,
      default: null,
    },

    // ── WebAuthn user handle ──────────────────────────────────
    // A random, unique, opaque byte-string used by the authenticator.
    // Stored as a hex string. Must never be re-used across accounts.
    webAuthnUserID: {
      type: String,   // hex-encoded Uint8Array
      required: true,
      unique: true,
    },

    // ── Passkeys (one user can register multiple devices) ─────
    // Each element is a Passkey subdocument (see models/Passkey.js)
    // We embed them here for fast lookup during authentication.
    passkeys: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Passkey' }],
  },
  { timestamps: true }
);

// ── Hash password before save ─────────────────────────────────
userSchema.pre('save', async function (next) {
  if (!this.isModified('password') || !this.password) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// ── Instance method: compare plaintext to hash ────────────────
userSchema.methods.comparePassword = function (plain) {
  if (!this.password) return Promise.resolve(false);
  return bcrypt.compare(plain, this.password);
};

module.exports = mongoose.model('User', userSchema);
