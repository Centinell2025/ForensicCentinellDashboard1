/* Copyright © 2026 Beacon of the Eagle LLC. All Rights Reserved. Proprietary software. */
(function () {
  'use strict';
  const staticPreview = window.location.hostname.endsWith('github.io');
  const api = async (path, options = {}) => {
    const response = await fetch(path, { credentials: 'same-origin', headers: { 'content-type': 'application/json', ...(options.headers || {}) }, ...options });
    if (response.status === 204) return null;
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.title || 'Request failed');
    return data;
  };
  const escapeHtml = value => String(value).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
  const auth = document.createElement('div');
  auth.id = 'authGate';
  auth.innerHTML = `<div class="auth-card"><div class="auth-logo">C</div><h1>Centinell Forensics Enterprise</h1><p>Secure organizational access</p><div class="auth-tabs"><button data-mode="login" class="active">Sign in</button><button data-mode="register">Create account</button></div><form id="authForm"><div id="registerFields" hidden><label>Organization<input name="organization" autocomplete="organization" minlength="2"></label><label>Full name<input name="fullName" autocomplete="name" minlength="2"></label></div><label>Business email<input name="email" type="email" autocomplete="email" required></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button class="btn primary" type="submit">Continue</button><div id="authError" role="alert"></div></form><small>Protected access · Tenant isolation · Audit logging</small></div>`;
  document.body.appendChild(auth);
  let mode = 'login';
  const form = document.getElementById('authForm');
  auth.querySelectorAll('[data-mode]').forEach(button => button.addEventListener('click', () => {
    mode = button.dataset.mode;
    auth.querySelectorAll('[data-mode]').forEach(b => b.classList.toggle('active', b === button));
    document.getElementById('registerFields').hidden = mode !== 'register';
    form.password.autocomplete = mode === 'register' ? 'new-password' : 'current-password';
  }));
  function enter(user) {
    auth.classList.add('authenticated');
    const userButton = document.querySelector('.actions .btn');
    if (userButton) userButton.textContent = `${user.fullName} · ${user.role}`;
    const org = document.getElementById('orgName'); if (org) org.value = user.organization;
  }
  if (staticPreview) {
    enter({ fullName: 'Market Preview', role: 'demo', organization: 'Beacon of the Eagle LLC' });
    const notice = document.createElement('div');
    notice.className = 'info';
    notice.style.cssText = 'position:sticky;top:0;z-index:100;text-align:center;border-left:0;border-bottom:1px solid #71e4ff';
    notice.textContent = 'Secure market preview · Synthetic demonstration data · Live accounts and database run on the Railway deployment';
    document.body.prepend(notice);
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const error = document.getElementById('authError'); error.textContent = '';
    const body = Object.fromEntries(new FormData(form));
    try { const data = await api(`/api/v1/auth/${mode}`, { method:'POST', body:JSON.stringify(body) }); enter(data.user); }
    catch (e) { error.textContent = e.message; }
  });
  if (!staticPreview) api('/api/v1/auth/me').then(data => enter(data.user)).catch(() => {});

  const oldInfo = document.querySelector('#ai .info');
  if (oldInfo) oldInfo.textContent = 'Centinell AI is securely connected through the server. Provider credentials are never exposed to the browser or customer.';
  const connectionPanel = document.querySelector('#ai .info + .panel'); if (connectionPanel) connectionPanel.hidden = true;
  const send = async () => {
    const input = document.getElementById('aiInput'); const messages = document.getElementById('aiMessages');
    const message = input && input.value.trim(); if (!message) return;
    messages.insertAdjacentHTML('beforeend', `<div class="msg user">${escapeHtml(message)}</div>`); input.value = '';
    try { const data = await api('/api/v1/ai/chat', { method:'POST', body:JSON.stringify({ message }) }); messages.insertAdjacentHTML('beforeend', `<div class="msg bot">${escapeHtml(data.reply)}</div>`); }
    catch (e) { messages.insertAdjacentHTML('beforeend', `<div class="msg bot">${escapeHtml(e.message)}</div>`); }
    messages.scrollTop = messages.scrollHeight;
  };
  const sendButton = document.getElementById('aiSendBtn'); if (sendButton) sendButton.addEventListener('click', e => { e.stopImmediatePropagation(); send(); }, true);
  const aiInput = document.getElementById('aiInput'); if (aiInput) aiInput.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); e.stopImmediatePropagation(); send(); } }, true);

  const caseForm = document.getElementById('newCaseForm');
  if (caseForm) caseForm.addEventListener('submit', async event => {
    event.preventDefault(); event.stopImmediatePropagation();
    try {
      const data = await api('/api/v1/cases', { method:'POST', body:JSON.stringify({ title:document.getElementById('ncTitle').value, caseType:document.getElementById('ncType').value, priority:document.getElementById('ncPriority').value, description:document.getElementById('ncDesc').value }) });
      document.getElementById('caseModal').classList.remove('show'); caseForm.reset();
      if (window.showToast) window.showToast('Case created', `${data.case.caseNumber} was saved securely.`, 'success'); else alert(`${data.case.caseNumber} created`);
    } catch (e) { alert(e.message); }
  }, true);
})();
