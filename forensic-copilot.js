/* Centinell AI forensic copilot: BYOK browser client and evidence-aware workspace. */
(function (global) {
  'use strict';

  var contract = global.CentinellForensicAdvisor;
  var aiPage = document.getElementById('ai');
  if (!contract || !aiPage) return;

  var staticPreview = global.location.hostname.endsWith('github.io');
  var escapeHtml = function (value) {
    return String(value == null ? '' : value).replace(/[&<>'"]/g, function (character) {
      return {'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[character];
    });
  };
  var text = function (value) { return String(value == null ? '' : value).trim(); };
  var api = function (path, options) { return global.CentinellAPI.request(path, options || {}); };
  var state = {
    authenticated: staticPreview,
    caseId: null,
    cases: [],
    findings: [],
    selectedFindingIds: new Set(),
    directive: contract.DEFAULT_ADVISOR_DIRECTIVE,
    directiveIsDefault: true,
    conversation: [],
    lastReply: '',
    apiKey: ''
  };

  function installStyles() {
    if (document.getElementById('forensic-copilot-styles')) return;
    var style = document.createElement('style');
    style.id = 'forensic-copilot-styles';
    style.textContent = `.ai-copilot-shell{background:transparent;border:0;box-shadow:none;padding:0}.ai-copilot-grid{display:grid;grid-template-columns:minmax(280px,.78fr) minmax(0,1.22fr);gap:13px;align-items:stretch}.ai-copilot-zone{min-width:0}.ai-directive-zone{grid-column:1;grid-row:1}.ai-write-zone{grid-column:2;grid-row:1;display:flex;flex-direction:column}.ai-copilot-zone h2{margin:0;font-size:16px}.ai-directive-textarea{width:100%;min-height:310px;resize:vertical;line-height:1.55;background:#09264a;border:1px solid var(--line);border-radius:9px;color:#fff;padding:12px}.ai-copilot-actions{display:flex;justify-content:flex-end;gap:8px;flex-wrap:wrap;margin-top:10px}.ai-copilot-status{min-height:18px;margin:9px 0 0}.ai-context-controls{display:grid;grid-template-columns:minmax(180px,1fr) auto;gap:9px;align-items:end;margin-bottom:10px}.ai-context-controls select{width:100%;padding:9px;border-radius:8px;border:1px solid var(--line);background:#09294f;color:#fff}.ai-context-toggle{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:12px;min-height:38px}.ai-finding-list{display:grid;gap:8px;max-height:210px;overflow:auto;padding-right:3px}.ai-finding{display:grid;grid-template-columns:auto 1fr;gap:9px;align-items:start;padding:10px;border:1px solid var(--line);border-radius:9px;background:#09264a;cursor:pointer}.ai-finding:hover{border-color:var(--cyan)}.ai-finding.verified{border-left:3px solid var(--good)}.ai-finding.pending{border-left:3px solid var(--warn)}.ai-finding input{margin-top:3px;accent-color:var(--cyan)}.ai-finding-title{font-size:12px;font-weight:700}.ai-finding-meta{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:5px}.ai-finding-meta small{color:var(--muted);font-size:10px}.ai-context-note{margin:10px 0 0;color:var(--muted);font-size:11px;line-height:1.45}.ai-byok{padding:11px;margin-bottom:12px;border:1px solid var(--line);border-radius:10px;background:#09264a}.ai-byok .field{margin:0}.ai-byok input{width:100%;padding:10px;border-radius:8px;border:1px solid var(--line);background:#061b38;color:#fff}.ai-byok-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:9px}.ai-byok-notice{margin:8px 0 0;color:var(--muted);font-size:11px;line-height:1.45}.ai-copilot-suggestions{margin-bottom:10px}.ai-copilot-suggestions button{border:1px solid var(--line);background:#0e3562;color:#cfe6ff;border-radius:999px;padding:7px 12px;font-size:12px}.ai-copilot-suggestions button:hover{background:#134680;color:#fff}.ai-copilot-write-label{margin:9px 0 5px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}.ai-copilot-input{width:100%;min-height:68px;resize:vertical;background:#09294f;border:1px solid var(--line);border-radius:9px;color:#fff;padding:11px;outline:0;line-height:1.45}.ai-copilot-actions .btn:disabled{opacity:.55;cursor:not-allowed}.ai-draft-row{background:#ffc15a0d}.ai-draft-row td{border-bottom-color:#ffc15a55}.ai-draft-row .chip{white-space:nowrap}@media(max-width:900px){.ai-copilot-grid{grid-template-columns:1fr}.ai-directive-zone,.ai-write-zone{grid-column:1;grid-row:auto}.ai-directive-textarea{min-height:230px}}@media(max-width:560px){.ai-context-controls{grid-template-columns:1fr}.ai-copilot-actions,.ai-byok-actions{justify-content:stretch}.ai-copilot-actions .btn,.ai-byok-actions .btn{flex:1}}
`
    document.head.appendChild(style);
  }

  function renderMarkup() {
    var panel = aiPage.querySelector('.panel');
    if (!panel) return false;
    panel.classList.add('ai-copilot-shell');
    panel.innerHTML = '<div class="ai-copilot-grid">'
      + '<section class="panel ai-copilot-zone ai-directive-zone" aria-labelledby="advisorDirectiveTitle">'
      + '<div class="head"><div><h2 id="advisorDirectiveTitle">Advisor Directive</h2><p class="muted">The forensic rules sent as the Centinell AI system instruction.</p></div><span class="chip medium">Audited</span></div>'
      + '<label class="field" for="advisorDirective"><span>Advisor Directive</span><textarea id="advisorDirective" class="ai-directive-textarea" rows="14" spellcheck="true"></textarea></label>'
      + '<div class="ai-copilot-actions"><button type="button" class="btn" id="restoreDirectiveBtn" data-copilot-action="restore-directive">Restore directive</button><button type="button" class="btn primary" id="saveDirectiveBtn" data-copilot-action="save-directive">Save directive</button></div>'
      + '<p class="ai-copilot-status muted" id="advisorDirectiveStatus" role="status"></p>'
      + '</section>'
      + '<section class="panel ai-copilot-zone ai-write-zone" aria-labelledby="copilotWriteTitle">'
      + '<div class="head"><div><h2 id="copilotWriteTitle">Write</h2><p class="muted">Ask the forensic advisor about tenant-authorized evidence.</p></div><span class="chip warning">Human sign-off required</span></div>'
      + '<div class="ai-byok"><label class="field" for="byokKeyInput"><span>Anthropic API key (BYOK)</span><input id="byokKeyInput" type="password" autocomplete="new-password" spellcheck="false" placeholder="Paste your key for this browser session"></label><div class="ai-byok-actions"><button type="button" class="btn" id="saveByokBtn" data-copilot-action="save-byok">Use key in this session</button><span class="chip warning" id="byokStatus">Not connected</span></div><p class="ai-byok-notice" id="byokNotice">Configure your Anthropic API key (BYOK) to use Centinell AI. The key stays in this browser session and is never sent to Centinell services.</p></div>'
      + '<div class="panel" style="padding:12px;margin-bottom:12px"><div class="head"><div><h2>Evidence context</h2><p class="muted">Attach normalized findings returned for the current tenant and case.</p></div><span class="chip medium" id="selectedFindingCount">0 selected</span></div><div class="ai-context-controls"><label class="field" for="advisorCaseSelect"><span>Case context</span><select id="advisorCaseSelect"><option value="">Current workspace</option></select></label><label class="ai-context-toggle"><input id="advisorIncludeContext" type="checkbox" checked><span>Include selected findings</span></label></div><div id="advisorFindings" class="ai-finding-list" role="list"></div><p class="ai-context-note" id="advisorContextStatus">Verified findings are confirmed; pending findings are injected as explicitly unverified context.</p></div>'
      + '<div class="ai-copilot-suggestions suggest"><button type="button" data-copilot-prompt="Summarize the verified findings for the selected case and list the evidence citations.">Summarize verified findings</button><button type="button" data-copilot-prompt="Separate confirmed facts from hypotheses in the selected evidence context.">Separate facts from hypotheses</button><button type="button" data-copilot-prompt="Draft analyst next steps using only the cited evidence and identify what still requires verification.">Draft next steps</button></div>'
      + '<div class="ai-messages" id="aiMessages" aria-live="polite"></div><label class="ai-copilot-write-label" for="aiInput">Write your forensic question</label><textarea id="aiInput" class="ai-copilot-input" rows="3" aria-label="Centinell AI message" placeholder="Ask about the selected findings, a case, or a report draft..."></textarea><div class="ai-copilot-actions"><button type="button" class="btn primary" id="aiSendBtn" data-copilot-action="send-question">Send</button><button type="button" class="btn" id="aiDraftBtn" data-copilot-action="send-report-draft" disabled>Send to Reports (draft)</button></div><p class="ai-copilot-status muted" id="aiDraftStatus" role="status"></p>'
      + '</section></div>';
    return true;
  }

  function updateHeader() {
    var chip = aiPage.querySelector('.heading .chip');
    var info = aiPage.querySelector('.info');
    if (chip) chip.textContent = 'BYOK · Analyst controlled';
    if (info) info.textContent = 'Centinell AI uses your own Anthropic API key (BYOK). The key stays in this browser session; tenant evidence context is fetched only from the authenticated production workspace.';
  }

  function setStatus(id, message, tone) {
    var node = document.getElementById(id);
    if (!node) return;
    node.textContent = message || '';
    node.className = 'ai-copilot-status ' + (tone === 'error' ? 'critical' : tone === 'success' ? 'good' : 'muted');
  }

  function directiveStorageKey() {
    return 'centinell:advisor-directive:demo:' + (state.caseId || 'workspace');
  }

  function renderDirective() {
    var input = document.getElementById('advisorDirective');
    if (input) input.value = state.directive || contract.DEFAULT_ADVISOR_DIRECTIVE;
    setStatus('advisorDirectiveStatus', state.directiveIsDefault ? 'Default forensic directive loaded.' : 'Directive loaded from the tenant workspace.', state.directiveIsDefault ? 'success' : '');
  }

  function renderCaseOptions() {
    var select = document.getElementById('advisorCaseSelect');
    if (!select) return;
    var selected = state.caseId || '';
    select.innerHTML = '<option value="">Current workspace</option>' + state.cases.map(function (item) {
      return '<option value="' + escapeHtml(item.id) + '">' + escapeHtml(item.caseNumber || item.title || item.id) + '</option>';
    }).join('');
    select.value = selected;
  }

  function renderFindings() {
    var list = document.getElementById('advisorFindings');
    if (!list) return;
    if (!state.findings.length) {
      list.innerHTML = '<p class="muted">No tenant-authorized forensic findings are available for this context.</p>';
      updateSelectedCount();
      return;
    }
    list.innerHTML = state.findings.map(function (raw) {
      var finding = contract.normalizeFinding(raw);
      var verified = finding.status === 'verified';
      return '<label class="ai-finding ' + (verified ? 'verified' : 'pending') + '" role="listitem"><input type="checkbox" data-finding-id="' + escapeHtml(finding.id) + '"' + (state.selectedFindingIds.has(finding.id) ? ' checked' : '') + '><span><span class="ai-finding-title">' + escapeHtml(finding.title) + '</span><span class="ai-finding-meta"><span class="chip ' + (verified ? 'good' : 'warning') + '">' + (verified ? 'Verified' : 'Pending verification') + '</span><small>' + escapeHtml(finding.source) + (finding.toolVersion ? ' · ' + finding.toolVersion : '') + '</small>' + (finding.artifactId ? '<small>Artifact: ' + escapeHtml(finding.artifactId) + '</small>' : '') + '</span></span></label>';
    }).join('');
    list.querySelectorAll('[data-finding-id]').forEach(function (checkbox) {
      checkbox.addEventListener('change', function () {
        if (checkbox.checked) state.selectedFindingIds.add(checkbox.dataset.findingId);
        else state.selectedFindingIds.delete(checkbox.dataset.findingId);
        updateSelectedCount();
      });
    });
    updateSelectedCount();
  }

  function updateSelectedCount() {
    var count = document.getElementById('selectedFindingCount');
    var include = document.getElementById('advisorIncludeContext');
    if (count) count.textContent = (include && include.checked ? state.selectedFindingIds.size : 0) + ' selected';
  }

  function selectedFindings() {
    var include = document.getElementById('advisorIncludeContext');
    if (!include || !include.checked) return [];
    return state.findings.filter(function (finding) { return state.selectedFindingIds.has(finding.id); }).map(contract.normalizeFinding);
  }

  function errorMessage(error, fallback) {
    var message = text(error && error.message);
    if (state.apiKey && message) message = message.split(state.apiKey).join('[redacted]');
    return message && message.length < 260 ? message : fallback;
  }

  async function loadCases() {
    if (staticPreview || !state.authenticated) return;
    try {
      var response = await api('/api/v1/cases');
      state.cases = Array.isArray(response.cases) ? response.cases : [];
      renderCaseOptions();
    } catch (error) {
      state.cases = [];
      renderCaseOptions();
      setStatus('advisorDirectiveStatus', errorMessage(error, 'Cases could not be loaded from the production workspace.'), 'error');
    }
  }

  async function loadContext() {
    if (staticPreview) {
      try {
        var saved = localStorage.getItem(directiveStorageKey());
        state.directive = saved || contract.DEFAULT_ADVISOR_DIRECTIVE;
        state.directiveIsDefault = !saved;
      } catch (_) {
        state.directive = contract.DEFAULT_ADVISOR_DIRECTIVE;
        state.directiveIsDefault = true;
      }
      state.findings = [];
      state.selectedFindingIds = new Set();
      renderDirective();
      renderFindings();
      var staticStatus = document.getElementById('advisorContextStatus');
      if (staticStatus) staticStatus.textContent = 'Static GitHub Pages demonstration: no tenant-authorized findings are attached.';
      return;
    }
    if (!state.authenticated) {
      setStatus('advisorDirectiveStatus', 'Sign in to load the tenant directive and evidence context.', '');
      var unauthenticated = document.getElementById('advisorContextStatus');
      if (unauthenticated) unauthenticated.textContent = 'Sign in to load tenant-authorized forensic findings.';
      return;
    }
    var query = state.caseId ? '?caseId=' + encodeURIComponent(state.caseId) : '';
    var list = document.getElementById('advisorFindings');
    if (list) list.innerHTML = '<p class="muted">Loading tenant-authorized findings…</p>';
    try {
      var responses = await Promise.all([api('/api/v1/advisor-directive' + query), api('/api/v1/forensic-findings' + query)]);
      state.directive = responses[0].directive || contract.DEFAULT_ADVISOR_DIRECTIVE;
      state.directiveIsDefault = !!responses[0].isDefault;
      state.findings = Array.isArray(responses[1].findings) ? responses[1].findings.map(contract.normalizeFinding) : [];
      state.selectedFindingIds = new Set(state.findings.map(function (finding) { return finding.id; }));
      renderDirective();
      renderFindings();
      var status = document.getElementById('advisorContextStatus');
      if (status) status.textContent = state.findings.length ? 'Verified findings are confirmed; pending findings are injected as explicitly unverified context.' : 'No tenant-authorized findings are available for this context.';
    } catch (error) {
      state.findings = [];
      state.selectedFindingIds = new Set();
      renderFindings();
      setStatus('advisorDirectiveStatus', errorMessage(error, 'The tenant directive or evidence context could not be loaded.'), 'error');
      var failedStatus = document.getElementById('advisorContextStatus');
      if (failedStatus) failedStatus.textContent = 'Evidence context unavailable. Verify the authenticated backend connection.';
    }
  }

  async function saveDirective() {
    var input = document.getElementById('advisorDirective');
    var value = text(input && input.value);
    if (!value) return setStatus('advisorDirectiveStatus', 'The directive cannot be empty.', 'error');
    if (value.length > 12000) return setStatus('advisorDirectiveStatus', 'The directive is limited to 12,000 characters.', 'error');
    var button = document.getElementById('saveDirectiveBtn');
    if (button) button.disabled = true;
    try {
      if (staticPreview) {
        localStorage.setItem(directiveStorageKey(), value);
        state.directive = value;
        state.directiveIsDefault = value === contract.DEFAULT_ADVISOR_DIRECTIVE;
      } else {
        var data = await api('/api/v1/advisor-directive', { method: 'PUT', body: JSON.stringify({ directive: value, caseId: state.caseId }) });
        state.directive = data.directive || value;
        state.directiveIsDefault = false;
      }
      setStatus('advisorDirectiveStatus', staticPreview ? 'Directive saved for this demonstration browser.' : 'Directive saved and recorded in the tenant audit chain.', 'success');
    } catch (error) {
      setStatus('advisorDirectiveStatus', errorMessage(error, 'The directive could not be saved.'), 'error');
    } finally {
      if (button) button.disabled = false;
    }
  }

  function restoreDirective() {
    var input = document.getElementById('advisorDirective');
    if (input) input.value = contract.DEFAULT_ADVISOR_DIRECTIVE;
    saveDirective();
  }

  function updateByokStatus(connected) {
    var status = document.getElementById('byokStatus');
    var notice = document.getElementById('byokNotice');
    if (status) { status.textContent = connected ? 'Connected' : 'Not connected'; status.className = 'chip ' + (connected ? 'good' : 'warning'); }
    if (notice) notice.textContent = connected ? 'Your key is held in memory for this browser session and is sent only to Anthropic for the request you start.' : 'Configure your Anthropic API key (BYOK) to use Centinell AI. The key stays in this browser session and is never sent to Centinell services.';
  }

  function saveByok() {
    var input = document.getElementById('byokKeyInput');
    var value = text(input && input.value);
    if (!value) {
      state.apiKey = '';
      updateByokStatus(false);
      return setStatus('aiDraftStatus', 'Configure your Anthropic API key (BYOK) above before asking Centinell AI.', 'error');
    }
    state.apiKey = value;
    if (input) { input.value = ''; input.placeholder = 'Key loaded for this browser session'; }
    updateByokStatus(true);
    setStatus('aiDraftStatus', 'BYOK key loaded in memory. It is not stored by Centinell.', 'success');
  }

  function appendMessage(role, message) {
    var messages = document.getElementById('aiMessages');
    if (!messages) return;
    var node = document.createElement('div');
    node.className = 'msg ' + (role === 'user' ? 'user' : 'bot');
    node.textContent = message;
    messages.appendChild(node);
    messages.scrollTop = messages.scrollHeight;
  }

  function setInitialMessage() {
    var messages = document.getElementById('aiMessages');
    if (!messages) return;
    messages.textContent = '';
    appendMessage('assistant', 'Hello — I am Centinell AI. I can summarize cited forensic findings, separate confirmed facts from hypotheses, and prepare report drafts. Configure your Anthropic API key (BYOK) above to start.');
  }

  async function providerError(response) {
    var data = await response.json().catch(function () { return null; });
    var providerMessage = data && data.error && data.error.message;
    return providerMessage && providerMessage.length < 220 ? providerMessage : 'The Anthropic request failed with HTTP ' + response.status + '.';
  }

  async function requestAdvisor(question) {
    if (!state.apiKey) throw new Error('Configure your Anthropic API key (BYOK) above before asking Centinell AI.');
    var content = contract.buildAdvisorUserMessage(question, selectedFindings());
    var messages = state.conversation.slice(-8).concat([{ role: 'user', content: content }]);
    var response = await global.fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': state.apiKey,
        'anthropic-version': '2023-06-01',
        'anthropic-dangerous-direct-browser-access': 'true'
      },
      body: JSON.stringify({ model: contract.CENTINELL_AI_MODEL, max_tokens: 1600, system: state.directive || contract.DEFAULT_ADVISOR_DIRECTIVE, messages: messages })
    });
    if (!response.ok) throw new Error(await providerError(response));
    var data = await response.json();
    var reply = (data.content || []).filter(function (item) { return item.type === 'text'; }).map(function (item) { return item.text; }).join('\n').trim();
    if (!reply) throw new Error('The AI provider returned no text response.');
    state.conversation = messages.concat([{ role: 'assistant', content: reply }]);
    return reply;
  }

  async function sendQuestion() {
    var input = document.getElementById('aiInput');
    var button = document.getElementById('aiSendBtn');
    var question = text(input && input.value);
    if (!question) return;
    appendMessage('user', question);
    if (input) input.value = '';
    if (!state.apiKey) {
      appendMessage('assistant', 'Configure your Anthropic API key (BYOK) above before asking Centinell AI.');
      return;
    }
    if (button) button.disabled = true;
    try {
      var reply = await requestAdvisor(question);
      state.lastReply = reply;
      appendMessage('assistant', reply);
      var draftButton = document.getElementById('aiDraftBtn');
      if (draftButton) draftButton.disabled = false;
      setStatus('aiDraftStatus', 'Response ready. It remains an analyst draft until you send it to Reports.', '');
    } catch (error) {
      appendMessage('assistant', errorMessage(error, 'The AI provider request failed. Check the BYOK key and try again.'));
      setStatus('aiDraftStatus', errorMessage(error, 'The AI provider request failed. Check the BYOK key and try again.'), 'error');
    } finally {
      if (button) button.disabled = false;
    }
  }

  function caseNumberForCurrentContext() {
    var item = state.cases.find(function (candidate) { return candidate.id === state.caseId; });
    return item ? (item.caseNumber || item.title || item.id) : 'Current workspace';
  }

  function storeLocalDraft(draft) {
    var key = 'centinell:ai-report-drafts:demo';
    var drafts = [];
    try { drafts = JSON.parse(localStorage.getItem(key) || '[]'); } catch (_) { drafts = []; }
    drafts = Array.isArray(drafts) ? drafts.filter(function (item) { return item.id !== draft.id; }) : [];
    drafts.unshift(draft);
    localStorage.setItem(key, JSON.stringify(drafts.slice(0, 50)));
  }

  function reportCell(value) {
    var cell = document.createElement('td');
    cell.textContent = value == null ? '' : String(value);
    return cell;
  }

  function insertDraftRow(draft) {
    var body = document.querySelector('#reportsTable tbody');
    if (!body || !draft) return;
    var existing = Array.from(body.querySelectorAll('[data-ai-draft-id]')).find(function (row) { return row.dataset.aiDraftId === String(draft.id); });
    if (existing) existing.remove();
    var row = document.createElement('tr');
    row.className = 'ai-draft-row';
    row.dataset.aiDraftId = draft.id;
    row.appendChild(reportCell(draft.title || 'Centinell AI Forensic Draft'));
    row.appendChild(reportCell('Forensic/Legal'));
    row.appendChild(reportCell(draft.caseNumber || 'Current workspace'));
    row.appendChild(reportCell('Centinell AI'));
    row.appendChild(reportCell(draft.createdAt ? new Date(draft.createdAt).toLocaleDateString('en-US') : new Date().toLocaleDateString('en-US')));
    var status = document.createElement('td');
    status.innerHTML = '<span class="chip warning">Pending verification</span>';
    row.appendChild(status);
    row.appendChild(reportCell('Human review required'));
    body.insertBefore(row, body.firstChild);
  }

  function loadLocalDrafts() {
    var drafts = [];
    try { drafts = JSON.parse(localStorage.getItem('centinell:ai-report-drafts:demo') || '[]'); } catch (_) { drafts = []; }
    if (Array.isArray(drafts)) drafts.slice().reverse().forEach(insertDraftRow);
  }

  async function loadServerDrafts() {
    if (staticPreview || !state.authenticated) return;
    try {
      var response = await api('/api/v1/reports/drafts');
      (Array.isArray(response.drafts) ? response.drafts : []).slice().reverse().forEach(insertDraftRow);
    } catch (_) {
      setStatus('aiDraftStatus', 'Existing report drafts could not be loaded. The current AI conversation remains available.', 'error');
    }
  }

  async function sendReportDraft() {
    if (!state.lastReply) return setStatus('aiDraftStatus', 'Generate an advisor response before sending a report draft.', 'error');
    var button = document.getElementById('aiDraftBtn');
    if (button) button.disabled = true;
    var selected = selectedFindings();
    var payload = { title: 'Centinell AI Forensic Draft — ' + caseNumberForCurrentContext(), body: state.lastReply, caseId: state.caseId, citedFindingIds: selected.map(function (finding) { return finding.id; }) };
    try {
      var draft;
      if (staticPreview) {
        draft = { id: 'demo-draft-' + Date.now(), title: payload.title, body: payload.body, source: 'centinell_ai', status: 'pending_verification', caseId: payload.caseId, caseNumber: caseNumberForCurrentContext(), citedFindingIds: payload.citedFindingIds, contextSnapshot: selected, createdAt: new Date().toISOString() };
        storeLocalDraft(draft);
      } else {
        var response = await api('/api/v1/reports/drafts', { method: 'POST', body: JSON.stringify(payload) });
        draft = response.draft;
      }
      insertDraftRow(draft);
      setStatus('aiDraftStatus', 'Draft sent to Reports as pending verification. Human sign-off is required.', 'success');
      if (global.CentinellRouter) global.CentinellRouter.navigate('reports');
    } catch (error) {
      setStatus('aiDraftStatus', errorMessage(error, 'The report draft could not be saved.'), 'error');
      if (button) button.disabled = false;
    }
  }

  function wireEvents() {
    document.getElementById('restoreDirectiveBtn').addEventListener('click', restoreDirective);
    document.getElementById('saveDirectiveBtn').addEventListener('click', saveDirective);
    document.getElementById('saveByokBtn').addEventListener('click', saveByok);
    document.getElementById('advisorIncludeContext').addEventListener('change', updateSelectedCount);
    document.getElementById('advisorCaseSelect').addEventListener('change', function (event) {
      state.caseId = event.target.value || null;
      loadContext();
    });
    document.getElementById('aiSendBtn').addEventListener('click', sendQuestion);
    document.getElementById('aiDraftBtn').addEventListener('click', sendReportDraft);
    document.getElementById('aiInput').addEventListener('keydown', function (event) {
      if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); sendQuestion(); }
    });
    aiPage.querySelectorAll('[data-copilot-prompt]').forEach(function (button) {
      button.addEventListener('click', function () {
        var input = document.getElementById('aiInput');
        if (input) { input.value = button.dataset.copilotPrompt || ''; input.focus(); }
      });
    });
  }

  installStyles();
  updateHeader();
  if (!renderMarkup()) return;
  wireEvents();
  updateByokStatus(false);
  setInitialMessage();
  renderCaseOptions();
  renderDirective();
  if (staticPreview) { loadContext(); loadLocalDrafts(); }
  else setStatus('advisorDirectiveStatus', 'Sign in to load the tenant directive and evidence context.', '');
  global.addEventListener('centinell:authenticated', function () {
    state.authenticated = true;
    Promise.all([loadCases(), loadContext(), loadServerDrafts()]);
  });
}(window));
