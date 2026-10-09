// config/webauthn.js – Shared WebAuthn / Relying Party configuration
'use strict';

module.exports = {
  // Human-readable name shown in the browser's passkey dialog
  rpName: process.env.RP_NAME || 'PasskeyDemo',

  // The effective domain – must match the browser's hostname exactly.
  // No scheme, no port.
  rpID: process.env.RP_ID || 'localhost',

  // The full public URL your app is reachable at.
  // During development this is typically http://localhost:3000
  origin: process.env.RP_ORIGIN || 'http://localhost:3000',
};
