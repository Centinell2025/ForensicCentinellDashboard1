/* GitHub Pages-safe hash router with deep routes and query parameters. */
(function (global) {
  'use strict';
  var subscribers = new Set(), started = false;
  function parse(hash) {
    var raw = String(hash || global.location.hash || '#/command').replace(/^#\/?/, ''), parts = raw.split('?'), path = (parts[0] || 'command').replace(/^\/+|\/+$/g, ''), params = {};
    new URLSearchParams(parts[1] || '').forEach(function (value, key) { params[key] = value; });
    return { path: path || 'command', segments: (path || 'command').split('/').filter(Boolean), params: params, hash: '#/' + (path || 'command') + (parts[1] ? '?' + parts[1] : '') };
  }
  function emit() { var route = parse(); subscribers.forEach(function (subscriber) { subscriber(route); }); }
  function start() { if (started) return; started = true; global.addEventListener('hashchange', emit); global.addEventListener('popstate', emit); }
  function navigate(path, options) { options = options || {}; var query = new URLSearchParams(options.params || {}).toString(), next = '#/' + String(path).replace(/^#?\/?/, '') + (query ? '?' + query : ''); if (global.location.hash === next) { emit(); return; } global.history[options.replace ? 'replaceState' : 'pushState']({ route: path, params: options.params || {} }, '', next); emit(); }
  function subscribe(handler) { start(); subscribers.add(handler); return function () { subscribers.delete(handler); }; }
  global.CentinellRouter = Object.freeze({ parse: parse, navigate: navigate, subscribe: subscribe, current: function () { return parse(); } });
})(window);
