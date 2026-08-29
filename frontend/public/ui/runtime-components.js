/* High-performance runtime UI: preferences, RBAC, SOC alerts, chart, CSV/PDF exports. */
(function (global) {
  'use strict';
  var lifecycle = global.CentinellLifecycle.create('runtime-components');
  var preferencesKey = 'centinell:preferences:v1';
  function loadPreferences() { try { return Object.assign({ theme: 'dark', filters: {} }, JSON.parse(localStorage.getItem(preferencesKey) || '{}')); } catch (_) { return { theme: 'dark', filters: {} }; } }
  var preferences = loadPreferences();
  function setTheme(theme) { preferences.theme = theme === 'light' ? 'light' : 'dark'; document.documentElement.dataset.theme = preferences.theme; localStorage.setItem(preferencesKey, JSON.stringify(preferences)); }
  setTheme(preferences.theme);

  function toast(message, type) {
    var container = document.getElementById('toast-container');
    if (!container) { container = document.createElement('div'); container.id = 'toast-container'; document.body.appendChild(container); }
    var item = document.createElement('div'); item.className = 'soc-toast ' + (type || 'danger'); item.textContent = '[SOC] ' + message; container.appendChild(item);
    global.CentinellLocalData.putEvent({ message: message, severity: type || 'danger' });
    lifecycle.timeout(function () { item.remove(); }, 4000);
  }
  global.mostrarAlertaSOC = toast;
  lifecycle.listen(global, 'offline', function () { toast('Connection lost. Operating in offline mode.', 'warning'); });
  lifecycle.listen(global, 'online', function () { toast('Connection restored.', 'success'); });

  var actions = document.querySelector('.top .actions');
  if (actions) { var themeButton = document.createElement('button'); themeButton.className = 'btn'; themeButton.id = 'themeToggle'; themeButton.textContent = preferences.theme === 'dark' ? '☀ Light' : '◐ Dark'; actions.insertBefore(themeButton, actions.firstChild); lifecycle.listen(themeButton, 'click', function () { setTheme(preferences.theme === 'dark' ? 'light' : 'dark'); themeButton.textContent = preferences.theme === 'dark' ? '☀ Light' : '◐ Dark'; }); }

  var roleAccess = { admin: null, analyst: ['settings'], auditor: ['settings','ai-operations'], viewer: ['settings','investigation','ai-operations'] };
  function applyRBAC(user) {
    var denied = roleAccess[user.role];
    document.querySelectorAll('.nav button[data-page]').forEach(function (button) { var blocked = Array.isArray(denied) && denied.includes(button.dataset.page); button.hidden = blocked; button.setAttribute('aria-hidden', blocked ? 'true' : 'false'); });
    var canWrite = user.role === 'admin' || user.role === 'analyst' || user.role === 'demo';
    document.querySelectorAll('.corporate-entry-form button[type="submit"],[data-delete-record]').forEach(function (button) { button.disabled = !canWrite; button.title = canWrite ? '' : 'Write access requires administrator or analyst role'; });
    document.documentElement.dataset.role = user.role;
  }
  lifecycle.listen(global, 'centinell:authenticated', function (event) { applyRBAC(event.detail.user); });

  function csvEscape(value) { var text = String(value == null ? '' : value); return /[",\n]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text; }
  function exportCommandCsv() { var rows = [['Metric','Value','Context']]; document.querySelectorAll('#command .card').forEach(function (card) { rows.push([(card.querySelector('.sub') || {}).textContent || '', (card.querySelector('.metric') || {}).textContent || '', (card.querySelector('.metric + span') || {}).textContent || '']); }); var csv = rows.map(function (row) { return row.map(csvEscape).join(','); }).join('\n'), link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' })); link.download = 'centinell-command-center.csv'; link.click(); setTimeout(function () { URL.revokeObjectURL(link.href); }, 0); }

  var command = document.getElementById('command');
  if (command) {
    var tools = document.createElement('div'); tools.className = 'panel runtime-tools'; tools.innerHTML = '<div class="head"><div><h2>Real-Time Operations</h2><p class="muted">Lightweight browser rendering; no external chart dependency.</p></div><div><button class="btn" data-export-csv>Export CSV</button> <button class="btn" data-export-pdf>Print / PDF</button></div></div><canvas id="runtimeChart" height="130" aria-label="Real-time SOC operations chart"></canvas>';
    command.appendChild(tools);
    lifecycle.listen(tools, 'click', function (event) { if (event.target.closest('[data-export-csv]')) exportCommandCsv(); if (event.target.closest('[data-export-pdf]')) global.print(); });
    var canvas = tools.querySelector('canvas'), context = canvas.getContext('2d'), points = [18,24,21,35,29,42,38,47,43,52,49,58];
    function draw() { var width = canvas.clientWidth || 700, height = 130, ratio = global.devicePixelRatio || 1; canvas.width = width * ratio; canvas.height = height * ratio; context.setTransform(ratio,0,0,ratio,0,0); context.clearRect(0,0,width,height); context.strokeStyle='#71e4ff';context.lineWidth=2;context.beginPath();points.forEach(function (point,index) { var x=index*(width/(points.length-1)),y=height-12-(point/70)*(height-24);if(index===0)context.moveTo(x,y);else context.lineTo(x,y); });context.stroke(); }
    draw(); var throttledDraw = global.CentinellPerformance.throttle(draw, 200); lifecycle.listen(global, 'resize', throttledDraw); lifecycle.interval(function () { points.push(Math.max(8,Math.min(68,points[points.length-1]+Math.round(Math.random()*12-6))));points.shift();draw(); }, 5000); lifecycle.add(throttledDraw.cancel);
  }
})(window);
