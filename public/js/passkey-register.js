import {
  decodeBase64Url,
  requestJson,
  requireWebAuthn,
  serializeCredential,
} from './webauthn.js';

const overlay = document.getElementById('modal-overlay');
const openButton = document.getElementById('btn-add-passkey');
const closeButton = document.getElementById('btn-modal-close');
const cancelButton = document.getElementById('btn-cancel-passkey');
const confirmButton = document.getElementById('btn-confirm-passkey');
const nameInput = document.getElementById('device-name');
const alertArea = document.getElementById('alert-area');
const modalAlert = document.getElementById('modal-alert');

const showMessage = (message, type = 'error', target = alertArea) => {
  if (!target) return;
  target.replaceChildren();
  const alert = document.createElement('div');
  alert.className = `alert alert-${type}`;
  alert.setAttribute('role', 'alert');
  alert.textContent = message;
  target.append(alert);
};

const setModalOpen = (open) => {
  if (!overlay) return;
  overlay.classList.toggle('hidden', !open);
  if (open) {
    nameInput?.focus();
  } else {
    if (nameInput) nameInput.value = '';
  }
};

openButton?.addEventListener('click', () => {
  alertArea?.replaceChildren();
  modalAlert?.replaceChildren();
  setModalOpen(true);
});
closeButton?.addEventListener('click', () => setModalOpen(false));
cancelButton?.addEventListener('click', () => setModalOpen(false));
overlay?.addEventListener('click', (event) => {
  if (event.target === overlay) setModalOpen(false);
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && overlay && !overlay.classList.contains('hidden')) {
    setModalOpen(false);
  }
});

confirmButton?.addEventListener('click', async () => {
  const deviceName = nameInput?.value.trim() || 'My Passkey';
  if (deviceName.length > 64) {
    showMessage('Device name must be 64 characters or fewer.', 'error', modalAlert);
    return;
  }

  const originalText = confirmButton.textContent.trim();
  confirmButton.disabled = true;
  confirmButton.textContent = 'Registering…';

  try {
    requireWebAuthn();

    const options = await requestJson('/passkeys/register/options', {});
    const credential = await navigator.credentials.create({
      publicKey: {
        ...options,
        challenge: decodeBase64Url(options.challenge),
        user: {
          ...options.user,
          id: decodeBase64Url(options.user.id),
        },
        excludeCredentials: (options.excludeCredentials || []).map((entry) => ({
          ...entry,
          id: decodeBase64Url(entry.id),
        })),
      },
    });

    if (!credential) throw new Error('Passkey registration was cancelled.');

    await requestJson('/passkeys/register/verify', {
      credential: serializeCredential(credential),
      deviceName,
    });
    window.location.reload();
  } catch (error) {
    if (error.name !== 'NotAllowedError') {
      showMessage(
        error.message || 'Passkey registration failed. Please try again.',
        'error',
        modalAlert
      );
    }
  } finally {
    confirmButton.disabled = false;
    confirmButton.textContent = originalText;
  }
});

document.querySelectorAll('[data-passkey-action]').forEach((button) => {
  button.addEventListener('click', async () => {
    const { passkeyAction, passkeyId } = button.dataset;
    const item = button.closest('.passkey-item');
    const name = item?.querySelector('.passkey-name')?.textContent || 'passkey';

    try {
      if (passkeyAction === 'rename') {
        const deviceName = window.prompt('Enter a new name for this passkey:', name);
        if (deviceName === null) return;
        const trimmedName = deviceName.trim();
        if (!trimmedName || trimmedName.length > 64) {
          showMessage('Device name must be between 1 and 64 characters.');
          return;
        }

        await requestJson(`/passkeys/${encodeURIComponent(passkeyId)}/rename`, {
          deviceName: trimmedName,
        });
      } else if (passkeyAction === 'delete') {
        if (!window.confirm(`Remove "${name}"? You may not be able to sign in with it again.`)) {
          return;
        }
        const response = await fetch(`/passkeys/${encodeURIComponent(passkeyId)}`, {
          method: 'DELETE',
          credentials: 'same-origin',
        });
        const payload = await response.json();
        if (!response.ok) {
          throw new Error(payload.error || `Request failed (${response.status}).`);
        }
      }

      window.location.reload();
    } catch (error) {
      showMessage(error.message || 'Could not update this passkey.');
    }
  });
});
