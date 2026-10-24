// Web app de login en dos pasos (Step-Up Auth).
// Los tokens viven solo en memoria: al recargar la página se vuelve a empezar.
let preAuthToken = null;
let accessToken = null;

const $ = (id) => document.getElementById(id);
const views = ['login', 'setup', 'verify', 'vault'];

function show(view, step) {
  for (const v of views) $(`view-${v}`).hidden = v !== view && !(view === 'setup' && v === 'verify');
  document.querySelectorAll('.steps span').forEach((s) => s.classList.toggle('active', s.dataset.step === String(step)));
}

function alertMsg(text, kind = 'error') {
  const el = $('alert');
  el.textContent = text;
  el.className = `alert ${kind}`;
  el.hidden = !text;
}

async function api(path, { body, token, method = 'POST' } = {}) {
  const res = await fetch(path, {
    method,
    headers: {
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join(', ') : data.detail;
    throw new Error(detail || `Error ${res.status}`);
  }
  return data;
}

function decodeJwt(token) {
  const payload = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(atob(payload));
}

async function withBusy(form, fn) {
  const buttons = form.querySelectorAll('button');
  buttons.forEach((b) => (b.disabled = true));
  try {
    await fn();
  } catch (e) {
    alertMsg(e.message);
  } finally {
    buttons.forEach((b) => (b.disabled = false));
  }
}

// --- Paso 1: contraseña ---------------------------------------------------------
$('login-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const form = e.target;
  withBusy(form, async () => {
    alertMsg('');
    const creds = { username: form.username.value, password: form.password.value };
    const res = await api('/auth/login', { body: creds });
    preAuthToken = res.pre_auth_token;

    if (res.mfa_status === 'ACTIVE') {
      show('verify', 2);
      $('code').focus();
    } else {
      await startSetup();
    }
  });
});

$('register-btn').addEventListener('click', () => {
  const form = $('login-form');
  if (!form.reportValidity()) return;
  withBusy(form, async () => {
    await api('/auth/register', { body: { username: form.username.value, password: form.password.value } });
    alertMsg('Cuenta creada. Ahora inicia sesión.', 'ok');
  });
});

// --- Aprovisionamiento ----------------------------------------------------------
async function startSetup() {
  const res = await api('/auth/2fa/setup', { token: preAuthToken });
  $('setup-status').textContent = res.status;
  $('qr').src = res.qr_png;
  $('secret').textContent = res.secret;
  $('backup-codes').innerHTML = res.backup_codes.map((c) => `<li>${c}</li>`).join('');
  $('use-backup').checked = false;
  $('use-backup').parentElement.hidden = true; // en PENDING_VERIFICATION solo vale TOTP
  setCodeMode(false);
  show('setup', 2);
}

// --- Paso 2: segundo factor -----------------------------------------------------
function setCodeMode(backup) {
  $('code-label').firstChild.textContent = backup ? 'Código de respaldo (XXXX-XXXX)' : 'Código de 6 dígitos';
  $('code').inputMode = backup ? 'text' : 'numeric';
  $('code').value = '';
}
$('use-backup').addEventListener('change', (e) => setCodeMode(e.target.checked));

$('verify-form').addEventListener('submit', (e) => {
  e.preventDefault();
  withBusy(e.target, async () => {
    alertMsg('');
    const method = $('use-backup').checked ? 'backup' : 'totp';
    const res = await api('/auth/verify-2fa', {
      token: preAuthToken,
      body: { code: $('code').value.trim(), method },
    });
    accessToken = res.access_token;
    const extra = res.mfa_activated_now ? ' Tu 2FA pasó a ACTIVE.' : '';
    const window = res.window ? ` (ventana ${res.window})` : '';
    alertMsg(`Segundo factor correcto${window}.${extra}`, 'ok');
    await openVault();
  });
});

// --- Paso 3: bóveda -------------------------------------------------------------
async function openVault() {
  const data = await api('/api/boveda-secreta', { method: 'GET', token: accessToken });
  $('vault').textContent = JSON.stringify(data, null, 2);
  $('claims').textContent = JSON.stringify(decodeJwt(accessToken), null, 2);
  show('vault', 3);
}

document.querySelectorAll('.logout').forEach((b) =>
  b.addEventListener('click', () => {
    preAuthToken = accessToken = null;
    $('use-backup').parentElement.hidden = false;
    $('use-backup').checked = false;
    setCodeMode(false);
    alertMsg('');
    show('login', 1);
  })
);

show('login', 1);
