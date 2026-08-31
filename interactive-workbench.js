/*
 * Centinell Forensics Enterprise v1.1.0
 * Copyright © 2026 Beacon of the Eagle LLC. All Rights Reserved.
 *
 * Interactive KPI workbench. The browser never rewrites evidence or custody
 * records: production actions are tenant-scoped API requests that append an
 * auditable intent, while the GitHub Pages preview remains explicitly local.
 */
(function (global) {
  'use strict';

  var VERSION = '1.1.0';
  var STATIC_PREVIEW = global.location.protocol === 'file:' || /github\.io$/i.test(global.location.hostname);
  var FRE_URL = 'https://www.uscourts.gov/sites/default/files/document/federal-rules-of-evidence.pdf';
  var FRCP_URL = 'https://www.uscourts.gov/sites/default/files/document/federal-rules-of-civil-procedure.pdf';
  var SCA_URL = 'https://uscode.house.gov/view.xhtml?edition=prelim&num=0&req=granuleid%3AUSC-prelim-title18-section2701';
  var HIPAA_URL = 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html';
  var SOX_URL = 'https://www.sec.gov/rules-regulations/2003/03/managements-report-internal-control-over-financial-reporting-certification-disclosure-exchange-act';
  var RETRY_KEY = 'centinell:interactive:retry:EVD-4438';
  var state = {
    initialized: false,
    drawer: null,
    backdrop: null,
    active: null,
    previousFocus: null,
    snapshot: null,
    refreshTimer: null,
    previewTimer: null,
    stream: null,
    observer: null,
    enhancementTimer: null,
    requestController: null,
    reducedMotion: !!(global.matchMedia && global.matchMedia('(prefers-reduced-motion: reduce)').matches)
  };

  var LEGAL_REFERENCES = [
    {
      title: 'FRE Rules 902(13) & 902(14)',
      tag: 'Electronic-record authentication',
      body: 'SHA-256 records support digital identification and integrity analysis. They do not replace qualified certification, notice, or the court’s authenticity determination.',
      href: FRE_URL
    },
    {
      title: 'FRCP Rules 34 & 37',
      tag: 'ESI production and preservation',
      body: 'The workflow supports defensible collection, production, and preservation of electronically stored information. Counsel must issue and scope any litigation hold.',
      href: FRCP_URL
    },
    {
      title: 'Stored Communications Act · 18 U.S.C. § 2701 et seq.',
      tag: 'Cloud-access boundary',
      body: 'Stored-communications access must be authorized, documented, and handled under applicable law, consent, provider terms, and legal process.',
      href: SCA_URL
    },
    {
      title: 'HIPAA Security Rule',
      tag: 'ePHI safeguards',
      body: 'When ePHI is in scope, confidentiality, integrity, availability, access controls, and audit controls require an applicability and risk assessment.',
      href: HIPAA_URL
    },
    {
      title: 'Sarbanes-Oxley (SOX)',
      tag: 'Financial-control evidence',
      body: 'For covered issuers, evidence and logs can support internal-control and financial-reporting review. This interface is not a SOX certification.',
      href: SOX_URL
    }
  ];

  function escapeHtml(value) {
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function cleanText(node) {
    return node ? String(node.textContent || '').replace(/\s+/g, ' ').trim() : '';
  }

  function normalizedUtc(value) {
    if (!value) return 'Not recorded';
    var date = new Date(value);
    if (isNaN(date.getTime())) return String(value);
    return date.toISOString().replace('.000Z', 'Z') + ' UTC';
  }

  function nowUtc() {
    return new Date().toISOString().replace('.000Z', 'Z') + ' UTC';
  }

  function pageName(target) {
    var page = target && target.closest ? target.closest('.page') : null;
    if (!page) return 'Platform';
    var heading = page.querySelector('.page-title h1, h1');
    return cleanText(heading) || page.id || 'Platform';
  }

  function metricLabel(target) {
    if (!target) return 'Metric detail';
    if (target.tagName === 'TR') {
      var cells = Array.prototype.slice.call(target.querySelectorAll('td'));
      return cleanText(cells[2]) || cleanText(cells[0]) || 'Record detail';
    }
    return cleanText(target.querySelector('.sub, .metric-label, h3, h4')) || pageName(target);
  }

  function metricValue(target) {
    if (!target) return 'Not available';
    if (target.tagName === 'TR') {
      var cells = Array.prototype.slice.call(target.querySelectorAll('td'));
      var chip = target.querySelector('.chip');
      return cleanText(chip) || cleanText(cells[cells.length - 1]) || 'Not available';
    }
    return cleanText(target.querySelector('.metric, .value, strong')) || 'Not available';
  }

  function securityState(text) {
    var value = String(text || '');
    if (/(critical|compromised|blocked|shadow it|gap identified|failed)/i.test(value)) return 'critical';
    if (/(high|overdue|escalated|at risk)/i.test(value)) return 'high';
    if (/(pending|awaiting|warning|review|open|degraded|due)/i.test(value)) return 'warning';
    if (/(verified|healthy|compliant|resolved|complete|success|good)/i.test(value)) return 'good';
    return 'neutral';
  }

  function securityLabel(status) {
    return ({
      critical: 'Critical',
      high: 'High',
      warning: 'Attention',
      good: 'Verified',
      neutral: 'Observed'
    })[status] || 'Observed';
  }

  function recordKey(target) {
    if (!target || target.tagName !== 'TR') {
      return metricLabel(target).toLowerCase() === 'pending intake' ? 'EVD-4438' : '';
    }
    return cleanText(target.querySelector('td:first-child')) || '';
  }

  function metadataFor(target) {
    var label = metricLabel(target);
    var value = metricValue(target);
    var text = cleanText(target);
    var key = recordKey(target);
    var status = securityState(label + ' ' + value + ' ' + text);
    var pending = /pending|awaiting|hash.*missing|not verified/i.test(label + ' ' + value + ' ' + text);
    return {
      target: target,
      kind: target && target.tagName === 'TR' ? 'record' : 'kpi',
      label: label,
      value: value,
      text: text,
      recordKey: key,
      pending: pending,
      status: status,
      statusLabel: securityLabel(status),
      module: pageName(target)
    };
  }

  function displayStatus(status) {
    return securityLabel(status || 'neutral');
  }

  function formatMetric(value) {
    if (value === undefined || value === null || value === '') return 'Not available';
    return String(value);
  }

  function localRetryStatus() {
    try {
      return global.localStorage.getItem(RETRY_KEY);
    } catch (error) {
      return '';
    }
  }

  function storeLocalRetry() {
    var timestamp = new Date().toISOString();
    try {
      global.localStorage.setItem(RETRY_KEY, timestamp);
    } catch (error) {
      return timestamp;
    }
    return timestamp;
  }

  function custodyStorageKey(evidenceKey) {
    return 'centinell:interactive:custody:' + (evidenceKey || 'unknown');
  }

  function localCustodyStatus(evidenceKey) {
    try {
      return global.localStorage.getItem(custodyStorageKey(evidenceKey)) || '';
    } catch (error) {
      return '';
    }
  }

  function storeLocalCustody(evidenceKey, status) {
    var timestamp = new Date().toISOString();
    try {
      global.localStorage.setItem(custodyStorageKey(evidenceKey), status + '|' + timestamp);
    } catch (error) {
      return timestamp;
    }
    return timestamp;
  }

  function storedCustodyState(evidenceKey) {
    var stored = localCustodyStatus(evidenceKey);
    return stored.split('|')[0] || 'in_review';
  }

  function apiRequest(path, options) {
    if (global.CentinellAPI && typeof global.CentinellAPI.request === 'function') {
      return global.CentinellAPI.request(path, options || {});
    }
    options = options || {};
    return global.fetch(path, Object.assign({}, options, {
      credentials: 'same-origin',
      headers: Object.assign({ 'content-type': 'application/json', 'x-centinell-client': 'interactive-workbench' }, options.headers || {})
    })).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (data) {
        if (!response.ok) {
          var error = new Error(data.title || ('Request failed (' + response.status + ')'));
          error.status = response.status;
          error.details = data;
          throw error;
        }
        return data;
      });
    });
  }

  function notify(title, message, type) {
    if (typeof global.showToast === 'function') {
      global.showToast(title, message, type || 'success');
      return;
    }
    if (typeof global.mostrarAlertaSOC === 'function') {
      global.mostrarAlertaSOC(title + ': ' + message, type || 'success');
    }
  }

  function installStyles() {
    if (document.getElementById('interactive-workbench-styles')) return;
    var style = document.createElement('style');
    style.id = 'interactive-workbench-styles';
    style.textContent = [
      '.corporate-legal-strip{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:8px 18px;border-bottom:1px solid #22517f;background:linear-gradient(90deg,#082342,#0c2b54);color:#b9d3ec;font-size:10px;line-height:1.45}.corporate-legal-strip strong{color:#ffc75f;letter-spacing:.03em}.corporate-legal-strip span:last-child{text-align:right;color:#8fb0d1}.interactive-kpi{cursor:pointer;position:relative;transition:transform .18s,border-color .18s,box-shadow .18s}.interactive-kpi:hover,.interactive-kpi:focus-visible{transform:translateY(-3px);border-color:var(--cyan);box-shadow:0 18px 45px #0008,0 0 0 1px #71e4ff44;outline:none}.interactive-kpi[data-live-state="connected"]{border-color:#2d9b79}.interactive-kpi[data-live-state="warning"]{border-color:#9f7229}.interactive-kpi[data-live-state="error"]{border-color:#994555}.kpi-live-state{display:inline-flex;align-items:center;gap:5px;margin-top:8px;color:#9bb8d7;font-size:10px}.kpi-live-state:before{content:"";width:6px;height:6px;border-radius:50%;background:#40d69a;box-shadow:0 0 0 3px #40d69a22}.kpi-live-state[data-state="warning"]:before{background:#ffc15a;box-shadow:0 0 0 3px #ffc15a22}.kpi-live-state[data-state="error"]:before{background:#ff6980;box-shadow:0 0 0 3px #ff698022}.kpi-live-state[data-state="preview"]:before{background:#71e4ff;box-shadow:0 0 0 3px #71e4ff22}.kpi-security-signal{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;margin-left:6px;border:1px solid currentColor;border-radius:50%;font-size:9px;line-height:1;color:#9bb8d7;vertical-align:middle;cursor:help}.kpi-security-signal[data-security="critical"]{color:#ff6980}.kpi-security-signal[data-security="high"]{color:#ff9b6a}.kpi-security-signal[data-security="warning"]{color:#ffc15a}.kpi-security-signal[data-security="good"]{color:#40d69a}.kpi-security-signal[data-tooltip]{position:relative}.kpi-security-signal[data-tooltip]:hover:after,.kpi-security-signal[data-tooltip]:focus-visible:after{content:attr(data-tooltip);position:absolute;z-index:10010;left:20px;top:22px;width:220px;padding:8px;border:1px solid #3979ad;border-radius:8px;background:#03142b;color:#eef7ff;font-size:10px;font-weight:400;line-height:1.4;text-align:left;box-shadow:0 12px 30px #000a}.kpi-enhanced-row{cursor:pointer}.kpi-enhanced-row:hover,.kpi-enhanced-row:focus-visible{background:#2da9ff12;outline:2px solid #71e4ff55;outline-offset:-2px}.kpi-filter-pills{display:flex;flex-wrap:wrap;gap:7px;margin:0 0 10px}.kpi-filter-pill{border:1px solid #22517f;border-radius:999px;padding:6px 10px;background:#061d3a;color:#b9d3ec;font:700 10px/1.1 inherit;cursor:pointer;transition:background .18s,border-color .18s,color .18s}.kpi-filter-pill:hover,.kpi-filter-pill:focus-visible,.kpi-filter-pill[aria-pressed="true"]{border-color:var(--cyan);background:#2da9ff20;color:#eef7ff;outline:none}.kpi-pill-hidden{display:none!important}.kpi-drawer-backdrop{position:fixed;inset:0;z-index:9600;background:#010917aa;opacity:0;pointer-events:none;transition:opacity .2s}.kpi-drawer-backdrop.is-open{opacity:1;pointer-events:auto}.kpi-drawer{position:fixed;top:0;right:0;z-index:9650;display:flex;width:min(560px,100vw);height:100vh;flex-direction:column;background:linear-gradient(160deg,#103a6b,#061b37 66%,#041225);border-left:1px solid #3979ad;box-shadow:-24px 0 70px #000b;transform:translateX(102%);transition:transform .24s ease;visibility:hidden}.kpi-drawer.is-open{transform:translateX(0);visibility:visible}.kpi-drawer-head{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;padding:20px;border-bottom:1px solid var(--line)}.kpi-drawer-head small{color:var(--cyan);font-size:9px;font-weight:800;letter-spacing:.16em}.kpi-drawer-head h2{margin:5px 0 4px;font-size:21px}.kpi-drawer-head p{margin:0;color:var(--muted);font-size:11px}.kpi-drawer-close{flex:0 0 auto}.kpi-drawer-body{flex:1;overflow:auto;padding:18px 20px}.kpi-drawer-footer{display:flex;justify-content:space-between;align-items:center;gap:9px;padding:14px 20px;border-top:1px solid var(--line);background:#04172f}.kpi-drawer-footer a{color:var(--cyan);font-size:11px;text-decoration:none}.kpi-drawer-footer a:hover{text-decoration:underline}.kpi-drawer-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px;margin:0 0 16px}.kpi-drawer-card{min-width:0;padding:11px;border:1px solid var(--line);border-radius:10px;background:#061d3a}.kpi-drawer-card small{display:block;color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.07em}.kpi-drawer-card strong{display:block;margin-top:6px;color:#eef7ff;font-size:14px;overflow-wrap:anywhere}.kpi-drawer-section{margin:18px 0}.kpi-drawer-section h3{margin:0 0 9px;font-size:13px}.kpi-metadata{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.kpi-metadata div{padding:9px;border-bottom:1px solid #22517f44}.kpi-metadata dt{color:var(--muted);font-size:9px;text-transform:uppercase}.kpi-metadata dd{margin:4px 0 0;color:#eef7ff;font-size:11px;overflow-wrap:anywhere}.kpi-process{display:grid;gap:7px}.kpi-process-step{display:flex;align-items:flex-start;gap:9px;padding:9px;border:1px solid #22517f;border-radius:9px;background:#061d3a}.kpi-process-step i{display:grid;place-items:center;width:19px;height:19px;flex:0 0 19px;border-radius:50%;background:#2da9ff22;color:var(--cyan);font-size:10px;font-style:normal;font-weight:800}.kpi-history{width:100%;border-collapse:collapse;font-size:10px}.kpi-history th,.kpi-history td{padding:8px 5px;border-bottom:1px solid #22517f66;text-align:left;vertical-align:top}.kpi-history th{color:var(--muted);font-size:9px;text-transform:uppercase}.kpi-history td:first-child{white-space:nowrap;color:#b9d3ec}.kpi-history .good{color:var(--good)}.kpi-history .warning{color:var(--warn)}.kpi-history .critical{color:var(--bad)}.kpi-action-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:12px;border:1px solid #a56e2e;border-radius:10px;background:#3b290922}.kpi-action-row p{flex:1 1 100%;margin:0;color:#ffd79a;font-size:10px;line-height:1.45}.kpi-drawer-notice{padding:11px;border-left:3px solid var(--cyan);background:#2da9ff12;color:#b9d3ec;font-size:10px;line-height:1.5}.kpi-drawer-notice strong{color:#eef7ff}.kpi-drawer-loading{display:grid;gap:10px}.kpi-skeleton{height:46px;border-radius:9px;background:linear-gradient(90deg,#061d3a,#153f68,#061d3a);background-size:200% 100%;animation:kpi-skeleton 1.2s linear infinite}@keyframes kpi-skeleton{to{background-position:-200% 0}}.kpi-legal-panel{margin-top:16px}.kpi-legal-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}.kpi-legal-head h2{margin:0;font-size:18px}.kpi-legal-head p{margin:5px 0 0;color:var(--muted);font-size:11px;line-height:1.5}.kpi-legal-ref-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px;margin-top:14px}.kpi-legal-ref{display:flex;min-height:120px;flex-direction:column;padding:11px;border:1px solid var(--line);border-radius:10px;background:#061d3a}.kpi-legal-ref h3{margin:0 0 4px;font-size:12px}.kpi-legal-ref p{margin:0;color:var(--muted);font-size:10px;line-height:1.45}.kpi-legal-ref span{margin-bottom:7px;color:var(--cyan);font-size:9px;text-transform:uppercase;letter-spacing:.06em}.kpi-legal-ref a{margin-top:auto;padding-top:9px;color:var(--cyan);font-size:10px;text-decoration:none}.kpi-legal-ref a:hover{text-decoration:underline}.kpi-legal-notice{margin-top:13px;padding:11px;border:1px solid #a56e2e;border-radius:9px;background:#3b290922;color:#ffd79a;font-size:10px;line-height:1.5}.kpi-legal-notice strong{color:#fff}.kpi-legal-export{margin-top:12px}.drawer-open{overflow:hidden}@media(max-width:700px){.corporate-legal-strip{display:block;padding:9px 14px}.corporate-legal-strip span{display:block}.corporate-legal-strip span:last-child{margin-top:4px;text-align:left}.kpi-drawer-grid,.kpi-metadata,.kpi-legal-ref-grid{grid-template-columns:1fr}.kpi-drawer-footer{align-items:flex-start;flex-direction:column}.kpi-drawer-head{padding:16px}.kpi-drawer-body{padding:15px 16px}}@media(prefers-reduced-motion:reduce){.interactive-kpi,.kpi-filter-pill,.kpi-drawer,.kpi-drawer-backdrop{transition:none}.kpi-skeleton{animation:none}.interactive-kpi:hover,.interactive-kpi:focus-visible{transform:none}}'];
    document.head.appendChild(style);
  }

  function installHeaderSeal() {
    if (document.querySelector('[data-corporate-legal-seal]')) return;
    var strip = document.createElement('div');
    strip.className = 'corporate-legal-strip';
    strip.setAttribute('data-corporate-legal-seal', 'true');
    strip.setAttribute('role', 'note');
    strip.innerHTML = '<span><strong>Beacon of the Eagle LLC</strong> · Copyright © 2026 Beacon of the Eagle LLC. All Rights Reserved. · Centinell Forensics Enterprise v' + VERSION + '</span><span>Proprietary software · <strong>DFIR limitation notice:</strong> outputs require qualified human/legal review; no guarantee of admissibility or outcome.</span>';
    var top = document.querySelector('.top');
    if (top && top.parentNode) top.parentNode.insertBefore(strip, top);
    else document.body.insertBefore(strip, document.body.firstChild);
  }

  function legalMarkup(scope) {
    var cards = LEGAL_REFERENCES.map(function (reference) {
      return '<article class="kpi-legal-ref"><span>' + escapeHtml(reference.tag) + '</span><h3>' + escapeHtml(reference.title) + '</h3><p>' + escapeHtml(reference.body) + '</p><a href="' + reference.href + '" target="_blank" rel="noopener noreferrer">Read official source ↗</a></article>';
    }).join('');
    return '<section class="panel kpi-legal-panel" data-legal-framework="' + escapeHtml(scope) + '"><div class="kpi-legal-head"><div><h2>Federal Digital Evidence &amp; Compliance Framework</h2><p>Operational controls for evidence handling, acquisition, preservation, and audit review · v' + VERSION + '</p></div><span class="chip medium">Reference · not legal advice</span></div><div class="kpi-legal-ref-grid">' + cards + '</div><div class="kpi-legal-notice"><strong>DFIR limitation notice:</strong> Beacon of the Eagle LLC provides technical workflow controls, not legal advice or a representation that any artifact will be admitted. Qualified counsel and the court determine legal sufficiency, preservation scope, authentication, and admissibility under the facts and the applicable written agreement.</div>' + (scope === 'reports' ? '<button type="button" class="btn kpi-legal-export" data-kpi-export-legal>Export legal basis</button>' : '') + '</section>';
  }

  function installLegalPanels() {
    var risk = document.getElementById('risk');
    var reports = document.getElementById('reports');
    if (risk && !risk.querySelector('[data-legal-framework="risk"]')) risk.insertAdjacentHTML('beforeend', legalMarkup('risk'));
    if (reports && !reports.querySelector('[data-legal-framework="reports"]')) reports.insertAdjacentHTML('beforeend', legalMarkup('reports'));
  }

  function installDrawer() {
    if (state.drawer) return;
    state.backdrop = document.createElement('div');
    state.backdrop.className = 'kpi-drawer-backdrop';
    state.backdrop.id = 'kpiDrawerBackdrop';
    state.backdrop.setAttribute('aria-label', 'Close metric details');
    state.backdrop.setAttribute('role', 'button');
    state.backdrop.setAttribute('tabindex', '0');
    state.drawer = document.createElement('aside');
    state.drawer.className = 'kpi-drawer';
    state.drawer.id = 'kpiDrawer';
    state.drawer.setAttribute('role', 'dialog');
    state.drawer.setAttribute('aria-modal', 'true');
    state.drawer.setAttribute('aria-hidden', 'true');
    state.drawer.setAttribute('aria-labelledby', 'kpiDrawerTitle');
    state.drawer.innerHTML = '<header class="kpi-drawer-head"><div><small>LIVE KPI WORKSPACE · v' + VERSION + '</small><h2 id="kpiDrawerTitle">Metric details</h2><p id="kpiDrawerContext">Tenant-authorized technical analysis</p></div><button type="button" class="btn kpi-drawer-close" data-kpi-close aria-label="Close metric details">Close</button></header><div class="kpi-drawer-body" id="kpiDrawerBody"></div><footer class="kpi-drawer-footer"><button type="button" class="btn" data-kpi-refresh>Refresh live data</button><a id="kpiFullAnalysis" href="technical-analysis.html">Open full technical analysis →</a></footer>';
    document.body.appendChild(state.backdrop);
    document.body.appendChild(state.drawer);
    state.backdrop.addEventListener('click', closeDrawer);
    state.backdrop.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        closeDrawer();
      }
    });
  }

  function processSteps(meta) {
    var text = (meta.label + ' ' + meta.text).toLowerCase();
    if (/pending intake|hash/.test(text)) return ['Intake record located', 'SHA-256 computation queued', 'Integrity comparison and verification', 'Analyst or custodian sign-off'];
    if (/storage/.test(text)) return ['Envelope-encrypted write', 'Protected storage placement', 'Capacity and retention check', 'Audit event recorded'];
    if (/call|review/.test(text)) return ['Interaction captured', 'Quality or supervisor review', 'Outcome recorded', 'Audit trail update'];
    if (/alert|risk|vulnerab/.test(text)) return ['Signal correlated', 'Severity and asset scope evaluated', 'Analyst triage', 'Remediation or exception recorded'];
    return ['Source record collected', 'Tenant context correlated', 'Analyst review', 'Audit trail update'];
  }

  function baseHistory(meta) {
    if (meta.recordKey === 'EVD-4438') {
      var retry = localRetryStatus();
      return [
        { timestamp: '2026-08-12T00:00:00Z', event: 'EVD-4438 · Mobile Extraction (UFED) intake', status: 'Pending', reference: 'CASE-2029' },
        { timestamp: '', event: 'SHA-256 computation', status: retry ? 'Retry intent recorded locally' : 'Awaiting processing', reference: retry ? normalizedUtc(retry) : 'No verified digest asserted' }
      ];
    }
    return [{ timestamp: '', event: meta.label + ' selected', status: displayStatus(meta.status), reference: meta.module }];
  }

  function shortValue(value) {
    var text = formatMetric(value);
    if (text.length <= 84) return text;
    return text.slice(0, 78) + '…';
  }

  function historyMarkup(history) {
    if (!history || !history.length) return '<p class="muted">No history was returned for this tenant-authorized view.</p>';
    return '<div style="overflow:auto"><table class="kpi-history"><thead><tr><th>UTC</th><th>Event</th><th>Status</th><th>Reference</th></tr></thead><tbody>' + history.map(function (entry) {
      var status = securityState(entry.status || entry.event);
      return '<tr><td>' + escapeHtml(normalizedUtc(entry.timestamp || entry.createdAt)) + '</td><td>' + escapeHtml(entry.event || entry.action || 'Audit event') + '</td><td class="' + status + '">' + escapeHtml(entry.status || displayStatus(status)) + '</td><td class="mono">' + escapeHtml(shortValue(entry.reference || entry.entityId || '—')) + '</td></tr>';
    }).join('') + '</tbody></table></div>';
  }

  function processMarkup(meta, processing) {
    var steps = processSteps(meta);
    var current = processing && processing.status ? String(processing.status).replace(/_/g, ' ') : '';
    return '<div class="kpi-process">' + steps.map(function (step, index) {
      var active = index === 0 || (current && index === 1 && /pending|queued|retry/.test(current));
      return '<div class="kpi-process-step"><i>' + (active ? '•' : '✓') + '</i><span>' + escapeHtml(step) + (active && current ? ' · ' + escapeHtml(current) : '') + '</span></div>';
    }).join('') + '</div>';
  }

  function evidenceMetadata(meta, payload) {
    var evidence = payload && payload.evidence ? payload.evidence : {};
    var acquisition = payload && payload.acquisitionMetadata ? payload.acquisitionMetadata : {};
    var snapshot = payload && payload.kpis ? payload.kpis : {};
    var sha = acquisition.sha256 || evidence.sha256 || (meta.recordKey === 'EVD-4438' ? '— pending —' : 'Not returned');
    var caseName = acquisition.caseNumber || evidence.caseNumber || (meta.recordKey === 'EVD-4438' ? 'CASE-2029' : 'Not returned');
    return [
      ['Artifact / record', acquisition.objectKey || evidence.objectKey || meta.recordKey || meta.label],
      ['Case', caseName + (acquisition.caseTitle || evidence.caseTitle ? ' · ' + (acquisition.caseTitle || evidence.caseTitle) : '')],
      ['SHA-256', sha],
      ['Cipher / key reference', acquisition.cipher || evidence.cipher || 'Envelope-encrypted at rest'],
      ['Size', acquisition.sizeBytes || evidence.sizeBytes || (snapshot.storageUsedLabel ? snapshot.storageUsedLabel + ' aggregate' : 'Not returned')],
      ['Created / acquired', normalizedUtc(acquisition.createdAt || evidence.createdAt)],
      ['Created by', acquisition.createdByName || evidence.createdByName || 'Tenant-authorized identity'],
      ['KMS key reference', acquisition.kmsKeyId || evidence.kmsKeyId || 'Protected reference']
    ];
  }

  function historyFromPayload(meta, payload) {
    if (payload && Array.isArray(payload.history)) return payload.history;
    if (payload && payload.audit && Array.isArray(payload.audit.events)) return payload.audit.events;
    if (payload && payload.analysis && Array.isArray(payload.analysis.auditEvents)) return payload.analysis.auditEvents;
    return baseHistory(meta);
  }

  function renderLoading(meta) {
    if (!state.drawer) return;
    state.drawer.querySelector('#kpiDrawerTitle').textContent = meta.label;
    state.drawer.querySelector('#kpiDrawerContext').textContent = (STATIC_PREVIEW ? 'Preview dataset · local interaction only' : 'Tenant-authorized technical analysis · loading live source');
    state.drawer.querySelector('#kpiDrawerBody').innerHTML = '<div class="kpi-drawer-loading" aria-live="polite"><div class="kpi-skeleton"></div><div class="kpi-skeleton"></div><div class="kpi-skeleton"></div><p class="muted">Loading tenant-scoped metadata…</p></div>';
    state.drawer.querySelector('#kpiFullAnalysis').href = fullAnalysisHref(meta);
  }

  function renderDrawer(meta, payload, message) {
    if (!state.drawer || !state.active || state.active.meta !== meta) return;
    var evidence = payload && payload.evidence ? payload.evidence : {};
    var processing = payload && payload.processing ? payload.processing : {};
    var audit = payload && payload.audit ? payload.audit : {};
    var refreshed = payload && payload.generatedAt ? normalizedUtc(payload.generatedAt) : nowUtc();
    var status = securityState(meta.status + ' ' + (processing.status || '') + ' ' + (evidence.sha256 || ''));
    if (processing.status === 'verified') status = 'good';
    var body = state.drawer.querySelector('#kpiDrawerBody');
    var stats = [
      ['Observed value', payload && payload.kpis && payload.kpis[metricDataKey(meta.label)] !== undefined ? formatMetric(payload.kpis[metricDataKey(meta.label)]) : meta.value],
      ['Security state', processing.status ? processing.status.replace(/_/g, ' ') : meta.statusLabel],
      ['Data source', STATIC_PREVIEW ? 'GitHub Pages preview' : 'Tenant database API'],
      ['Refreshed UTC', refreshed]
    ];
    var metadata = evidenceMetadata(meta, payload);
    var action = '';
    var retryAvailable = !!(meta.pending || meta.recordKey === 'EVD-4438') && (!processing || processing.retryAvailable !== false);
    if (retryAvailable) {
      action = '<div class="kpi-action-row"><p>Quick action is tenant-scoped and append-only: it requests processing and preserves the evidence object, custody ledger, RLS policies, and existing hash-chain entries.</p><button type="button" class="btn primary" data-kpi-retry data-evidence-key="' + escapeHtml(meta.recordKey || 'EVD-4438') + '">Retry SHA-256 processing</button></div>';
    }
    if (meta.recordKey && /evidence|custody|hash|intake|acquisition/i.test(meta.module + ' ' + meta.label)) {
      var custody = storedCustodyState(meta.recordKey);
      action += '<div class="kpi-action-row" style="margin-top:10px"><p>Record a custody state transition as an append-only audit event. The evidence object and existing custody history remain unchanged.</p><label style="display:flex;align-items:center;gap:8px;color:#eef7ff;font-size:10px"><span>Custody state</span><select data-custody-state><option value="in_review"' + (custody === 'in_review' ? ' selected' : '') + '>In review</option><option value="legal_hold"' + (custody === 'legal_hold' ? ' selected' : '') + '>Legal hold</option><option value="released"' + (custody === 'released' ? ' selected' : '') + '>Released</option></select></label><button type="button" class="btn" data-custody-submit data-evidence-key="' + escapeHtml(meta.recordKey) + '">Record custody state</button></div>';
    }
    if (message) action += '<div class="kpi-drawer-notice" style="margin-top:10px"><strong>Action status:</strong> ' + escapeHtml(message) + '</div>';
    var chain = audit.chainValid === false ? 'Chain verification requires attention' : (audit.chainValid === true ? 'Audit chain verified' : 'Audit chain status returned by service');
    body.innerHTML = '<div class="kpi-drawer-grid">' + stats.map(function (stat) {
      return '<div class="kpi-drawer-card"><small>' + escapeHtml(stat[0]) + '</small><strong>' + escapeHtml(shortValue(stat[1])) + '</strong></div>';
    }).join('') + '</div><div class="kpi-drawer-notice"><strong>' + escapeHtml(meta.module) + ' / ' + escapeHtml(meta.label) + '</strong><br>UTC timestamps are normalized for this analytical view. ' + escapeHtml(STATIC_PREVIEW ? 'The public preview does not claim a server-side state change.' : 'The response is tenant-scoped and preserves acquisition metadata.') + '</div>' + action + '<section class="kpi-drawer-section"><h3>Acquisition &amp; custody metadata</h3><dl class="kpi-metadata">' + metadata.map(function (item) {
      return '<div><dt>' + escapeHtml(item[0]) + '</dt><dd class="' + (item[0] === 'SHA-256' || item[0] === 'Artifact / record' ? 'mono' : '') + '">' + escapeHtml(shortValue(item[1])) + '</dd></div>';
    }).join('') + '</dl></section><section class="kpi-drawer-section"><h3>Technical process</h3>' + processMarkup(meta, processing) + '</section><section class="kpi-drawer-section"><h3>Audit history</h3>' + historyMarkup(historyFromPayload(meta, payload)) + '</section><div class="kpi-drawer-notice"><strong>' + escapeHtml(chain) + '.</strong> A drawer view is analytical only; it does not rewrite forensic evidence, acquisition metadata, custody records, database tables, or RLS functions.</div>';
    state.drawer.querySelector('#kpiDrawerTitle').textContent = meta.label;
    state.drawer.querySelector('#kpiDrawerContext').textContent = displayStatus(status) + ' · refreshed ' + refreshed;
  }

  function metricDataKey(label) {
    var text = String(label || '').toLowerCase();
    if (/active cases|open cases/.test(text)) return 'activeCases';
    if (/critical alerts/.test(text)) return 'criticalAlerts';
    if (/assets at risk/.test(text)) return 'assetsAtRisk';
    if (/evidence integrity/.test(text)) return 'evidenceIntegrity';
    if (/total evidence/.test(text)) return 'totalEvidenceItems';
    if (/verified hashes/.test(text)) return 'verifiedHashes';
    if (/pending intake/.test(text)) return 'pendingIntake';
    if (/storage used/.test(text)) return 'storageUsedLabel';
    if (/in review|review/.test(text)) return 'casesInReview';
    return '';
  }

  function fullAnalysisHref(meta) {
    var params = new URLSearchParams();
    params.set('version', VERSION);
    params.set('module', meta.module);
    params.set('metric', meta.label);
    params.set('value', meta.value);
    if (meta.recordKey) params.set('record', meta.recordKey);
    return 'technical-analysis.html?' + params.toString();
  }

  function setLiveState(card, text, stateName) {
    var indicator = card.querySelector('.kpi-live-state');
    if (!indicator) {
      indicator = document.createElement('span');
      indicator.className = 'kpi-live-state';
      card.appendChild(indicator);
    }
    indicator.textContent = text;
    indicator.setAttribute('data-state', stateName || 'connected');
    card.setAttribute('data-live-state', stateName || 'connected');
  }

  function enhanceCards() {
    Array.prototype.slice.call(document.querySelectorAll('.page .card')).forEach(function (card) {
      if (card.classList.contains('kpi-enhanced')) return;
      var meta = metadataFor(card);
      card.classList.add('interactive-kpi', 'kpi-enhanced');
      card.setAttribute('role', 'button');
      card.setAttribute('tabindex', '0');
      card.setAttribute('aria-controls', 'kpiDrawer');
      card.setAttribute('aria-expanded', 'false');
      card.setAttribute('data-kpi-label', meta.label);
      card.setAttribute('data-kpi-module', meta.module);
      setLiveState(card, STATIC_PREVIEW ? 'Preview · local dataset' : 'Live · connecting', STATIC_PREVIEW ? 'preview' : 'warning');
    });
  }

  function tableForRow(row) {
    return row && row.closest ? row.closest('table') : null;
  }

  function filterRows(table, value) {
    if (!table) return;
    table.setAttribute('data-kpi-filter', value || 'all');
    Array.prototype.slice.call(table.querySelectorAll('tbody tr')).forEach(function (row) {
      var rowValue = row.getAttribute('data-kpi-filter-values') || '';
      var visible = !value || value === 'all' || rowValue.split('|').indexOf(value.toLowerCase()) >= 0;
      row.classList.toggle('kpi-pill-hidden', !visible);
    });
    var bar = table.parentElement && table.parentElement.querySelector('[data-kpi-filter-bar]');
    if (bar) Array.prototype.slice.call(bar.querySelectorAll('[data-kpi-filter]')).forEach(function (button) {
      button.setAttribute('aria-pressed', String((button.getAttribute('data-kpi-filter') || 'all') === (value || 'all')));
    });
  }

  function enhanceTable(table) {
    if (!table || !table.tBodies || !table.tBodies[0]) return;
    var rows = Array.prototype.slice.call(table.tBodies[0].querySelectorAll('tr'));
    if (!rows.length) return;
    var statuses = [];
    rows.forEach(function (row) {
      var meta = metadataFor(row);
      row.classList.add('kpi-enhanced-row');
      row.setAttribute('tabindex', '0');
      row.setAttribute('role', 'button');
      row.setAttribute('aria-controls', 'kpiDrawer');
      row.setAttribute('aria-expanded', 'false');
      row.setAttribute('data-security-state', meta.status);
      row.setAttribute('data-security-label', meta.statusLabel);
      row.setAttribute('data-kpi-filter-values', (meta.statusLabel + '|' + meta.status + '|' + metricValue(row)).toLowerCase());
      if (statuses.indexOf(meta.statusLabel) === -1) statuses.push(meta.statusLabel);
      var firstCell = row.querySelector('td:first-child');
      if (firstCell && !firstCell.querySelector('.kpi-security-signal')) {
        var signal = document.createElement('span');
        signal.className = 'kpi-security-signal';
        signal.textContent = '•';
        signal.tabIndex = 0;
        signal.setAttribute('data-security', meta.status);
        signal.setAttribute('data-tooltip', 'Security state: ' + meta.statusLabel + ' · Click row for technical details');
        signal.setAttribute('aria-label', 'Security state: ' + meta.statusLabel + '. Open technical details.');
        firstCell.appendChild(signal);
      }
    });
    var host = table.closest('.table-wrap') || table.parentElement;
    if (!host) return;
    var bar = host.querySelector('[data-kpi-filter-bar]');
    if (!bar) {
      bar = document.createElement('div');
      bar.className = 'kpi-filter-pills';
      bar.setAttribute('data-kpi-filter-bar', 'true');
      bar.setAttribute('role', 'toolbar');
      bar.setAttribute('aria-label', 'Live table filters');
      host.insertBefore(bar, table);
    }
    var existing = ['all'];
    Array.prototype.slice.call(bar.querySelectorAll('[data-kpi-filter]')).forEach(function (button) {
      existing.push(button.getAttribute('data-kpi-filter'));
    });
    if (!bar.querySelector('[data-kpi-filter="all"]')) {
      var all = document.createElement('button');
      all.type = 'button';
      all.className = 'kpi-filter-pill';
      all.setAttribute('data-kpi-filter', 'all');
      all.setAttribute('aria-pressed', 'true');
      all.textContent = 'All';
      bar.appendChild(all);
    }
    statuses.forEach(function (status) {
      var value = status.toLowerCase();
      if (existing.indexOf(value) >= 0 || bar.querySelector('[data-kpi-filter="' + value + '"]')) return;
      var button = document.createElement('button');
      button.type = 'button';
      button.className = 'kpi-filter-pill';
      button.setAttribute('data-kpi-filter', value);
      button.setAttribute('aria-pressed', 'false');
      button.textContent = status;
      bar.appendChild(button);
    });
    var selected = table.getAttribute('data-kpi-filter') || 'all';
    filterRows(table, selected === 'all' ? '' : selected);
  }

  function enhanceTables() {
    Array.prototype.slice.call(document.querySelectorAll('.page table')).forEach(enhanceTable);
  }

  function scheduleEnhancement() {
    if (state.enhancementTimer) return;
    state.enhancementTimer = global.setTimeout(function () {
      state.enhancementTimer = null;
      enhanceCards();
      enhanceTables();
      installLegalPanels();
    }, 80);
  }

  function applySnapshot(snapshot) {
    if (!snapshot || !snapshot.kpis) return;
    state.snapshot = snapshot;
    var kpis = snapshot.kpis;
    Array.prototype.slice.call(document.querySelectorAll('.page .interactive-kpi')).forEach(function (card) {
      var label = card.getAttribute('data-kpi-label') || metricLabel(card);
      var key = metricDataKey(label);
      var value = key === 'evidenceIntegrity' && snapshot.evidenceIntegrity ? snapshot.evidenceIntegrity.percentage + '%' : kpis[key];
      if (!key || value === undefined) return;
      var metric = card.querySelector('.metric');
      if (metric) metric.textContent = formatMetric(value);
      card.setAttribute('data-live-value', formatMetric(value));
      var nextState = 'connected';
      if (/critical alerts/i.test(label) && Number(value) > 0) nextState = 'warning';
      if (/pending intake/i.test(label) && Number(value) > 0) nextState = 'warning';
      if (/storage used/i.test(label) && kpis.storageCapacityBytes && Number(kpis.storageUsedBytes) / Number(kpis.storageCapacityBytes) > .85) nextState = 'warning';
      setLiveState(card, 'Live · ' + normalizedUtc(snapshot.generatedAt), nextState);
    });
    var updated = document.getElementById('dashboardUpdateDate');
    if (updated && snapshot.generatedAt) updated.textContent = 'Live update: ' + normalizedUtc(snapshot.generatedAt);
  }

  function setConnectionState(text, stateName) {
    Array.prototype.slice.call(document.querySelectorAll('.page .interactive-kpi')).forEach(function (card) {
      setLiveState(card, text, stateName);
    });
  }

  async function fetchSnapshot() {
    if (STATIC_PREVIEW) return null;
    if (state.requestController) state.requestController.abort();
    state.requestController = new AbortController();
    try {
      var snapshot = await apiRequest('/api/v1/dashboard/kpis', { signal: state.requestController.signal });
      applySnapshot(snapshot);
      setConnectionState('Live · tenant API', 'connected');
      return snapshot;
    } catch (error) {
      if (error && error.name === 'AbortError') return null;
      setConnectionState('Live · reconnecting', 'warning');
      return null;
    }
  }

  function startLiveFeed() {
    if (STATIC_PREVIEW) {
      state.previewTimer = global.setInterval(function () {
        setConnectionState('Preview · checked ' + nowUtc(), 'preview');
      }, 30000);
      return;
    }
    fetchSnapshot();
    state.refreshTimer = global.setInterval(fetchSnapshot, 30000);
    if (!global.EventSource) return;
    try {
      state.stream = new global.EventSource('/api/v1/dashboard/kpis/stream');
      state.stream.addEventListener('kpi.snapshot', function (event) {
        try { applySnapshot(JSON.parse(event.data)); setConnectionState('Live · stream connected', 'connected'); } catch (error) { setConnectionState('Live · parse warning', 'warning'); }
      });
      state.stream.addEventListener('kpi.event', function () {
        setConnectionState('Live · event received', 'connected');
        fetchSnapshot();
      });
      state.stream.onerror = function () {
        setConnectionState('Live · stream reconnecting', 'warning');
      };
    } catch (error) {
      setConnectionState('Live · polling fallback', 'warning');
    }
  }

  async function loadDrawerData(meta) {
    if (STATIC_PREVIEW) {
      renderDrawer(meta, { generatedAt: new Date().toISOString(), kpis: state.snapshot ? state.snapshot.kpis : {} });
      return;
    }
    try {
      if (state.requestController) state.requestController.abort();
      state.requestController = new AbortController();
      var payload;
      if (meta.recordKey && /evidence|custody|hash|intake|acquisition/i.test(meta.module + ' ' + meta.label)) {
        payload = await apiRequest('/api/v1/evidence/' + encodeURIComponent(meta.recordKey), { signal: state.requestController.signal });
      } else {
        payload = await apiRequest('/api/v1/analysis?module=command&metric=' + encodeURIComponent(meta.label), { signal: state.requestController.signal });
      }
      if (state.active && state.active.meta === meta) renderDrawer(meta, payload);
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      var detail = error && error.status === 401 ? 'Authentication is required for tenant-scoped metadata.' : 'The live source could not be read; no local record was changed.';
      renderDrawer(meta, { generatedAt: new Date().toISOString(), kpis: state.snapshot ? state.snapshot.kpis : {} }, detail);
      setConnectionState('Live · detail unavailable', 'warning');
    }
  }

  function openDrawer(target) {
    if (!target) return;
    installDrawer();
    var meta = metadataFor(target);
    state.previousFocus = target;
    state.active = { meta: meta, target: target };
    target.setAttribute('aria-expanded', 'true');
    renderLoading(meta);
    state.backdrop.classList.add('is-open');
    state.drawer.classList.add('is-open');
    state.drawer.setAttribute('aria-hidden', 'false');
    document.body.classList.add('drawer-open');
    var close = state.drawer.querySelector('[data-kpi-close]');
    if (close) close.focus();
    loadDrawerData(meta);
  }

  function closeDrawer() {
    if (!state.drawer) return;
    if (state.requestController) state.requestController.abort();
    if (state.active && state.active.target) state.active.target.setAttribute('aria-expanded', 'false');
    state.drawer.classList.remove('is-open');
    state.backdrop.classList.remove('is-open');
    state.drawer.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('drawer-open');
    var focus = state.previousFocus;
    state.active = null;
    if (focus && document.body.contains(focus) && typeof focus.focus === 'function') focus.focus();
  }

  async function retryHash(button) {
    if (!state.active || !state.active.meta) return;
    var meta = state.active.meta;
    var evidenceKey = button.getAttribute('data-evidence-key') || meta.recordKey || 'EVD-4438';
    button.disabled = true;
    button.textContent = 'Submitting…';
    if (STATIC_PREVIEW) {
      var timestamp = storeLocalRetry();
      renderDrawer(meta, { generatedAt: timestamp, processing: { status: 'retry_requested', retryAvailable: true } }, 'Preview only: retry intent recorded locally at ' + normalizedUtc(timestamp) + '; no server processing or hash mutation occurred.');
      button.disabled = false;
      button.textContent = 'Retry SHA-256 processing';
      notify('Preview action recorded', 'No backend or evidence record was changed.', 'warning');
      return;
    }
    try {
      var response = await apiRequest('/api/v1/evidence/' + encodeURIComponent(evidenceKey) + '/retry', {
        method: 'POST',
        body: JSON.stringify({ reason: 'KPI drawer retry action', version: VERSION }),
        headers: { 'content-type': 'application/json', 'x-centinell-action': 'evidence-hash-retry' }
      });
      if (state.active && state.active.meta === meta) renderDrawer(meta, response, 'Retry request accepted and appended to the audit chain. The evidence hash remains unchanged until the processing worker completes.');
      notify('SHA-256 retry queued', 'The tenant-scoped request was audited; the evidence object was not rewritten.', 'success');
      fetchSnapshot();
    } catch (error) {
      var message = error && error.status === 409 ? 'No retry was queued because the evidence already has a verified digest.' : (error && error.message ? error.message : 'The retry request was not accepted.');
      if (state.active && state.active.meta === meta) renderDrawer(meta, { generatedAt: new Date().toISOString(), processing: { status: 'retry_not_accepted' } }, message);
      notify('Retry not accepted', message, 'error');
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = 'Retry SHA-256 processing';
      }
    }
  }

  async function recordCustodyState(button) {
    if (!state.active || !state.active.meta) return;
    var meta = state.active.meta;
    var select = state.drawer && state.drawer.querySelector('[data-custody-state]');
    var status = select ? select.value : 'in_review';
    var evidenceKey = button.getAttribute('data-evidence-key') || meta.recordKey;
    button.disabled = true;
    button.textContent = 'Recording…';
    if (STATIC_PREVIEW) {
      var timestamp = storeLocalCustody(evidenceKey, status);
      renderDrawer(meta, { generatedAt: timestamp, processing: { status: status }, history: [{ timestamp: timestamp, event: 'Custody state transition', status: status, reference: evidenceKey }] }, 'Preview only: custody state intent recorded locally at ' + normalizedUtc(timestamp) + '; no backend, evidence, or ledger record was changed.');
      button.disabled = false;
      button.textContent = 'Record custody state';
      notify('Preview action recorded', 'No backend or forensic record was changed.', 'warning');
      return;
    }
    try {
      var response = await apiRequest('/api/v1/evidence/' + encodeURIComponent(evidenceKey) + '/custody-state', {
        method: 'POST',
        body: JSON.stringify({ status: status, reason: 'KPI drawer custody action', version: VERSION }),
        headers: { 'content-type': 'application/json', 'x-centinell-action': 'custody-state-record' }
      });
      if (state.active && state.active.meta === meta) renderDrawer(meta, response, 'Custody state event appended to the audit chain. The evidence object and existing custody records were not rewritten.');
      notify('Custody state recorded', 'The tenant-scoped transition was appended to the audit chain.', 'success');
    } catch (error) {
      var message = error && error.message ? error.message : 'The custody state was not recorded.';
      if (state.active && state.active.meta === meta) renderDrawer(meta, { generatedAt: new Date().toISOString(), processing: { status: 'custody_state_not_recorded' } }, message);
      notify('Custody action not accepted', message, 'error');
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = 'Record custody state';
      }
    }
  }

  function exportLegalBasis() {
    var lines = [
      'Centinell Forensics Enterprise v' + VERSION,
      'Copyright © 2026 Beacon of the Eagle LLC. All Rights Reserved.',
      '',
      'Federal Digital Evidence & Compliance Framework',
      ''
    ];
    LEGAL_REFERENCES.forEach(function (reference) {
      lines.push(reference.title + ' — ' + reference.tag);
      lines.push(reference.body);
      lines.push('Official source: ' + reference.href);
      lines.push('');
    });
    lines.push('DFIR limitation notice: This operational reference is not legal advice and does not represent that an artifact will be admitted. Qualified counsel and the court determine legal sufficiency, preservation scope, authentication, and admissibility under the applicable facts and written agreement.');
    var blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' });
    var url = global.URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.href = url;
    link.download = 'centinell-v1.1.0-legal-framework.txt';
    document.body.appendChild(link);
    link.click();
    link.remove();
    global.setTimeout(function () { global.URL.revokeObjectURL(url); }, 1000);
  }

  function isControl(target) {
    return !!(target && target.closest && target.closest('button,a,input,select,textarea,label,[data-no-kpi-drawer]'));
  }

  function targetFromEvent(target) {
    if (!target || !target.closest) return null;
    var row = target.closest('.page table tbody tr');
    if (row) return row;
    return target.closest('.page .card');
  }

  function bindEvents() {
    document.addEventListener('click', function (event) {
      var target = event.target;
      var close = target && target.closest ? target.closest('[data-kpi-close]') : null;
      if (close) {
        event.preventDefault();
        closeDrawer();
        return;
      }
      var refresh = target && target.closest ? target.closest('[data-kpi-refresh]') : null;
      if (refresh) {
        event.preventDefault();
        if (state.active) {
          renderLoading(state.active.meta);
          loadDrawerData(state.active.meta);
        } else fetchSnapshot();
        return;
      }
      var retry = target && target.closest ? target.closest('[data-kpi-retry]') : null;
      if (retry) {
        event.preventDefault();
        retryHash(retry);
        return;
      }
      var custody = target && target.closest ? target.closest('[data-custody-submit]') : null;
      if (custody) {
        event.preventDefault();
        recordCustodyState(custody);
        return;
      }
      var filter = target && target.closest ? target.closest('[data-kpi-filter]') : null;
      if (filter) {
        event.preventDefault();
        var table = filter.closest('[data-kpi-filter-bar]') && filter.closest('[data-kpi-filter-bar]').parentElement.querySelector('table');
        filterRows(table, filter.getAttribute('data-kpi-filter') === 'all' ? '' : filter.getAttribute('data-kpi-filter'));
        return;
      }
      var legalExport = target && target.closest ? target.closest('[data-kpi-export-legal]') : null;
      if (legalExport) {
        event.preventDefault();
        exportLegalBasis();
        return;
      }
      if (isControl(target)) return;
      var interactive = targetFromEvent(target);
      if (!interactive) return;
      event.preventDefault();
      event.stopPropagation();
      openDrawer(interactive);
    }, true);

    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && state.drawer && state.drawer.classList.contains('is-open')) {
        event.preventDefault();
        event.stopPropagation();
        closeDrawer();
        return;
      }
      if (event.key !== 'Enter' && event.key !== ' ') return;
      if (isControl(event.target)) return;
      var interactive = targetFromEvent(event.target);
      if (!interactive) return;
      event.preventDefault();
      event.stopPropagation();
      openDrawer(interactive);
    }, true);
  }

  function observeDynamicModules() {
    if (!global.MutationObserver || !document.body) return;
    state.observer = new global.MutationObserver(function () { scheduleEnhancement(); });
    state.observer.observe(document.body, { childList: true, subtree: true });
  }

  function init() {
    if (state.initialized) return;
    state.initialized = true;
    installStyles();
    installHeaderSeal();
    installDrawer();
    installLegalPanels();
    enhanceCards();
    enhanceTables();
    bindEvents();
    observeDynamicModules();
    startLiveFeed();
    global.setTimeout(scheduleEnhancement, 400);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();

  global.CentinellInteractive = Object.freeze({
    version: VERSION,
    openDrawer: openDrawer,
    closeDrawer: closeDrawer,
    refresh: fetchSnapshot
  });
})(window);
