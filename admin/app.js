const loginView = document.getElementById('login-view');
const editorView = document.getElementById('editor-view');
const loginForm = document.getElementById('login-form');
const passwordInput = document.getElementById('password');
const loginError = document.getElementById('login-error');
const loginBtn = document.getElementById('login-btn');
const tradeForm = document.getElementById('trade-form');
const paymentMethod = document.getElementById('paymentMethod');
const tradeId = document.getElementById('tradeId');
const amount = document.getElementById('amount');
const statusEl = document.getElementById('status');
const saveBtn = document.getElementById('save-btn');
const saveError = document.getElementById('save-error');
const saveStatus = document.getElementById('save-status');
const lastSaved = document.getElementById('last-saved');
const logoutBtn = document.getElementById('logout-btn');

const pvMethod = document.getElementById('pv-method');
const pvTrade = document.getElementById('pv-trade');
const pvAmount = document.getElementById('pv-amount');
const pvStatus = document.getElementById('pv-status');

let dirty = false;

async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...(options.headers || {}) },
    ...options,
  });
  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { error: text || `Request failed (${res.status})` };
  }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function showError(el, msg) {
  el.textContent = msg;
  el.classList.remove('hidden');
}

function clearError(el) {
  el.classList.add('hidden');
  el.textContent = '';
}

function statusLabel(value) {
  return value === 'complete' ? 'Transfer complete' : 'Waiting confirmation';
}

function fillForm(trade) {
  paymentMethod.value = trade.paymentMethod || '';
  tradeId.value = trade.tradeId || '';
  amount.value = trade.amount || '';
  statusEl.value = trade.status === 'complete' ? 'complete' : 'waiting';
  updatePreview();
  dirty = false;
}

function updatePreview() {
  pvMethod.textContent = paymentMethod.value || '—';
  pvTrade.textContent = tradeId.value || '—';
  pvAmount.textContent = amount.value || '—';
  pvStatus.textContent = statusLabel(statusEl.value);
}

async function init() {
  try {
    const { authed } = await api('/admin/api/session');
    if (authed) {
      await showEditor();
    } else {
      loginView.classList.remove('hidden');
      passwordInput.focus();
    }
  } catch {
    showError(loginError, 'Cannot reach the server.');
    loginView.classList.remove('hidden');
  }
}

async function showEditor() {
  loginView.classList.add('hidden');
  editorView.classList.remove('hidden');
  const data = await api('/admin/api/trade');
  fillForm(data.trade || {});
  if (data.savedAt) {
    lastSaved.textContent = `Last saved: ${new Date(data.savedAt).toLocaleString()}`;
  }
}

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearError(loginError);
  loginBtn.disabled = true;
  loginBtn.textContent = 'Signing in…';
  try {
    await api('/admin/api/login', {
      method: 'POST',
      body: JSON.stringify({ password: passwordInput.value }),
    });
    passwordInput.value = '';
    await showEditor();
  } catch (err) {
    showError(loginError, err.message);
  } finally {
    loginBtn.disabled = false;
    loginBtn.textContent = 'Sign in';
  }
});

tradeForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearError(saveError);
  saveStatus.textContent = '';
  saveBtn.disabled = true;
  saveBtn.textContent = 'Saving…';
  try {
    const data = await api('/admin/api/trade', {
      method: 'POST',
      body: JSON.stringify({
        paymentMethod: paymentMethod.value.trim(),
        tradeId: tradeId.value.trim(),
        amount: amount.value.trim(),
        status: statusEl.value,
      }),
    });
    fillForm(data.trade);
    dirty = false;
    const via = data.savedVia ? ` via ${data.savedVia}` : '';
    saveStatus.textContent = `Saved at ${new Date(data.savedAt).toLocaleTimeString()}${via}`;
    lastSaved.textContent = `Last saved: ${new Date(data.savedAt).toLocaleString()}`;
    if (data.savedVia === 'github' || (data.savedVia || '').includes('github')) {
      saveStatus.textContent += ' (permanent in repo; site auto-redeploys)';
    } else if (data.warn) {
      saveStatus.textContent += ` ⚠ ${data.warn}`;
    } else if (data.savedVia === 'memory') {
      saveStatus.textContent += ' ⚠ Temporary only — set GITHUB_TOKEN in Vercel env for permanent saves';
    }
  } catch (err) {
    showError(saveError, err.message);
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = 'Save changes';
  }
});

for (const el of [paymentMethod, tradeId, amount, statusEl]) {
  el.addEventListener('input', () => {
    dirty = true;
    saveStatus.textContent = 'Unsaved changes';
    updatePreview();
  });
  el.addEventListener('change', () => {
    dirty = true;
    saveStatus.textContent = 'Unsaved changes';
    updatePreview();
  });
}

logoutBtn.addEventListener('click', async () => {
  try {
    await api('/admin/api/logout', { method: 'POST' });
  } catch {
    /* ignore */
  }
  location.reload();
});

window.addEventListener('beforeunload', (e) => {
  if (dirty) {
    e.preventDefault();
    e.returnValue = '';
  }
});

init();
