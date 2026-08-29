/* Central immutable-style application store with durable selected state. */
(function (global) {
  'use strict';
  var storageKey = 'centinell:spa-state:v2', listeners = new Set();
  function defaults() { return { version: 2, activeRoute: 'command', routeParams: {}, telemetry: {}, network: { online: navigator.onLine }, updatedAt: new Date().toISOString() }; }
  function load() { try { var saved = JSON.parse(localStorage.getItem(storageKey) || 'null'); return saved && saved.version === 2 ? Object.assign(defaults(), saved) : defaults(); } catch (_) { return defaults(); } }
  var state = load();
  function persist() { state.updatedAt = new Date().toISOString(); try { localStorage.setItem(storageKey, JSON.stringify(state)); } catch (_) {} }
  function notify() { listeners.forEach(function (listener) { listener(state); }); }
  function update(mutator) { var next = typeof mutator === 'function' ? mutator(state) : Object.assign({}, state, mutator); if (next) state = next; persist(); global.CentinellState = state; notify(); return state; }
  function record(moduleName, eventName) { update(function (current) { var item = current.telemetry[moduleName] || { views: 0, events: 0, lastEvent: null, lastVisitedAt: null }; item = Object.assign({}, item); if (eventName === 'view') { item.views += 1; item.lastVisitedAt = new Date().toISOString(); } else { item.events += 1; item.lastEvent = eventName; } return Object.assign({}, current, { telemetry: Object.assign({}, current.telemetry, { [moduleName]: item }) }); }); }
  function subscribe(listener) { listeners.add(listener); return function () { listeners.delete(listener); }; }
  global.CentinellStore = Object.freeze({ getState: function () { return state; }, update: update, recordTelemetry: record, subscribe: subscribe });
  global.CentinellState = state;
  global.addEventListener('online', function () { update(function (s) { return Object.assign({}, s, { network: { online: true } }); }); });
  global.addEventListener('offline', function () { update(function (s) { return Object.assign({}, s, { network: { online: false } }); }); });
})(window);
