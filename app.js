/* Copyright © 2026 Beacon of the Eagle LLC. All Rights Reserved. Proprietary software. */
(function () {
  'use strict';
  const staticPreview = window.location.hostname.endsWith('github.io');
  const api = (path, options = {}) => window.CentinellAPI.request(path, options);
  const auth = document.createElement('div');
  auth.id = 'authGate';
  auth.innerHTML = `<div class="auth-card"><div class="auth-logo">C</div><h1>Centinell Forensics Enterprise</h1><p>Secure organizational access</p><div class="auth-tabs"><button data-mode="login" class="active">Sign in</button><button data-mode="register">Create account</button></div><a id="buyAccess" class="btn primary" href="#" target="_blank" rel="noopener" hidden>Buy secure access</a><form id="authForm"><div id="registerFields" hidden><label>Organization<input name="organization" autocomplete="organization" minlength="2"></label><label>Full name<input name="fullName" autocomplete="name" minlength="2"></label><p class="muted">Purchase first, then use the same business email to create your organization.</p></div><label>Business email<input name="email" type="email" autocomplete="email" required></label><label>Password<input name="password" type="password" autocomplete="current-password" minlength="12" required></label><label id="confirmPasswordField" hidden>Confirm password<input name="confirmPassword" type="password" autocomplete="new-password" minlength="12"></label><button class="btn primary" type="submit">Continue</button><div id="authError" role="alert"></div></form><small>Paid access · Tenant isolation · Audit logging</small></div>`;
  document.body.appendChild(auth);
  let mode = 'login';
  const form = document.getElementById('authForm');
  auth.querySelectorAll('[data-mode]').forEach(button => button.addEventListener('click', () => {
    mode = button.dataset.mode;
    auth.querySelectorAll('[data-mode]').forEach(b => b.classList.toggle('active', b === button));
    const registering = mode === 'register';
    document.getElementById('registerFields').hidden = !registering;
    document.getElementById('confirmPasswordField').hidden = !registering;
    form.confirmPassword.required = registering;
    form.password.autocomplete = registering ? 'new-password' : 'current-password';
  }));
  function enter(user) {
    auth.classList.add('authenticated');
    let userBadge = document.getElementById('userBadge');
    if (!userBadge) { userBadge = document.createElement('span'); userBadge.id = 'userBadge'; userBadge.className = 'chip medium'; document.querySelector('.actions')?.appendChild(userBadge); }
    userBadge.textContent = `${user.fullName} · ${user.role}`;
    const org = document.getElementById('orgName'); if (org) org.value = user.organization;
    window.dispatchEvent(new CustomEvent('centinell:authenticated', { detail: { user } }));
  }
  if (staticPreview) {
    auth.remove();
    enter({ fullName: 'Authorized Web Operator', role: 'viewer', organization: 'Beacon of the Eagle LLC' });
    const notice = document.createElement('div');
    notice.className = 'info';
    notice.style.cssText = 'position:sticky;top:0;z-index:100;text-align:center;border-left:0;border-bottom:1px solid #71e4ff';
    notice.textContent = 'Live product demonstration · synthetic data for evaluation';
    document.body.prepend(notice);
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const error = document.getElementById('authError'); error.textContent = '';
    const body = Object.fromEntries(new FormData(form));
    if (mode === 'register' && body.password !== body.confirmPassword) {
      error.textContent = 'Passwords do not match.';
      return;
    }
    delete body.confirmPassword;
    try { const data = await api(`/api/v1/auth/${mode}`, { method:'POST', body:JSON.stringify(body) }); enter(data.user); }
    catch (e) { error.textContent = e.message; }
  });
  if (!staticPreview) {
    api('/api/v1/auth/me').then(data => enter(data.user)).catch(() => {});
    api('/api/v1/billing/checkout').then(data => {
      const buy = document.getElementById('buyAccess');
      if (data.available && data.url) { buy.href = data.url; buy.hidden = false; }
    }).catch(() => {});
  }

  const caseForm = document.getElementById('newCaseForm');
  if (caseForm) caseForm.addEventListener('submit', async event => {
    if (staticPreview) return;
    event.preventDefault(); event.stopImmediatePropagation();
    try {
      const data = await api('/api/v1/cases', { method:'POST', body:JSON.stringify({ title:document.getElementById('ncTitle').value, caseType:document.getElementById('ncType').value, priority:document.getElementById('ncPriority').value, description:document.getElementById('ncDesc').value }) });
      document.getElementById('caseModal').classList.remove('show'); caseForm.reset();
      if (window.showToast) window.showToast('Case created', `${data.case.caseNumber} was saved securely.`, 'success'); else alert(`${data.case.caseNumber} created`);
    } catch (e) { alert(e.message); }
  }, true);

  const saveSettings = async () => {
    const switches = Array.from(document.querySelectorAll('#settings .switch input'));
    const payload = { name:document.getElementById('orgName').value.trim(), timezone:document.getElementById('orgTz').value, evidenceRetentionDays:Number(document.getElementById('orgRetention').value), notifications:{ criticalEmail:!!switches[0]?.checked,p1Sms:!!switches[1]?.checked,executiveDigest:!!switches[2]?.checked,complianceReminders:!!switches[3]?.checked } };
    if (staticPreview) { localStorage.setItem('centinell:organization-settings', JSON.stringify(payload)); return payload; }
    return (await api('/api/v1/settings/organization',{method:'PUT',body:JSON.stringify(payload)})).settings;
  };
  const saveOrgButton=document.getElementById('saveOrgBtn');if(saveOrgButton)saveOrgButton.addEventListener('click',async event=>{event.preventDefault();event.stopImmediatePropagation();saveOrgButton.disabled=true;try{await saveSettings();window.mostrarAlertaSOC?.('Organization settings saved.','success');}catch(error){window.mostrarAlertaSOC?.(error.message,'danger');}finally{saveOrgButton.disabled=false;}},true);
})();
