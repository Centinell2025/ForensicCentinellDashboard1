/* Scoped cleanup for listeners, timers, and in-flight requests. */
(function (global) {
  'use strict';
  var scopes = new Map();
  function create(scopeName) {
    destroy(scopeName);
    var cleanups = [], controller = new AbortController();
    var scope = {
      signal: controller.signal,
      listen: function (target, type, handler, options) {
        target.addEventListener(type, handler, options);
        cleanups.push(function () { target.removeEventListener(type, handler, options); });
        return handler;
      },
      interval: function (handler, milliseconds) {
        var id = setInterval(handler, milliseconds); cleanups.push(function () { clearInterval(id); }); return id;
      },
      timeout: function (handler, milliseconds) {
        var id = setTimeout(handler, milliseconds); cleanups.push(function () { clearTimeout(id); }); return id;
      },
      add: function (cleanup) { if (typeof cleanup === 'function') cleanups.push(cleanup); },
      destroy: function () { controller.abort(); cleanups.splice(0).reverse().forEach(function (cleanup) { try { cleanup(); } catch (_) {} }); scopes.delete(scopeName); }
    };
    scopes.set(scopeName, scope); return scope;
  }
  function destroy(scopeName) { var scope = scopes.get(scopeName); if (scope) scope.destroy(); }
  global.CentinellLifecycle = Object.freeze({ create: create, destroy: destroy, destroyAll: function () { Array.from(scopes.keys()).forEach(destroy); } });
})(window);
