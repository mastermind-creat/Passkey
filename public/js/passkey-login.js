import {
  decodeBase64Url,
  requestJson,
  requireWebAuthn,
  serializeCredential,
} from './webauthn.js';

const button = document.getElementById('btn-passkey-login');

if (button) {
  button.addEventListener('click', async () => {
    const originalText = button.textContent.trim();
    button.disabled = true;
    button.textContent = 'Waiting for passkey…';

    try {
      requireWebAuthn();

      const options = await requestJson('/passkeys/login/options', {});
      const credential = await navigator.credentials.get({
        publicKey: {
          ...options,
          challenge: decodeBase64Url(options.challenge),
          allowCredentials: (options.allowCredentials || []).map((entry) => ({
            ...entry,
            id: decodeBase64Url(entry.id),
          })),
        },
      });

      if (!credential) throw new Error('No passkey was selected.');

      const result = await requestJson('/passkeys/login/verify', {
        credential: serializeCredential(credential),
      });
      window.location.assign(result.redirect || '/dashboard');
    } catch (error) {
      if (error.name !== 'NotAllowedError') {
        window.alert(error.message || 'Passkey sign-in failed. Please try again.');
      }
    } finally {
      button.disabled = false;
      button.textContent = originalText;
    }
  });
}
