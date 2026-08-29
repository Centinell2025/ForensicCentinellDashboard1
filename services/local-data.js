/* IndexedDB-backed SOC event cache with bounded in-memory fallback. */
(function (global) {
  'use strict';
  var memory = [], databasePromise;
  function database() {
    if (!('indexedDB' in global)) return Promise.reject(new Error('IndexedDB unavailable'));
    if (!databasePromise) databasePromise = new Promise(function (resolve, reject) {
      var request = indexedDB.open('centinell-dashboard', 1);
      request.onupgradeneeded = function () { var db = request.result; if (!db.objectStoreNames.contains('soc_events')) { var store = db.createObjectStore('soc_events', { keyPath: 'id' }); store.createIndex('createdAt', 'createdAt'); } };
      request.onsuccess = function () { resolve(request.result); }; request.onerror = function () { reject(request.error); };
    });
    return databasePromise;
  }
  async function put(event) {
    var item = Object.assign({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), severity: 'info' }, event);
    try { var db = await database(); await new Promise(function (resolve, reject) { var tx = db.transaction('soc_events', 'readwrite'); tx.objectStore('soc_events').put(item); tx.oncomplete = resolve; tx.onerror = function () { reject(tx.error); }; }); }
    catch (_) { memory.unshift(item); memory = memory.slice(0, 500); }
    return item;
  }
  async function list(limit) {
    limit = Math.min(Math.max(Number(limit) || 100, 1), 500);
    try { var db = await database(); return await new Promise(function (resolve, reject) { var request = db.transaction('soc_events').objectStore('soc_events').getAll(); request.onsuccess = function () { resolve(request.result.sort(function (a, b) { return b.createdAt.localeCompare(a.createdAt); }).slice(0, limit)); }; request.onerror = function () { reject(request.error); }; }); }
    catch (_) { return memory.slice(0, limit); }
  }
  global.CentinellLocalData = Object.freeze({ putEvent: put, listEvents: list });
})(window);
