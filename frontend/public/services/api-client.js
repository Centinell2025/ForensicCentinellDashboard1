/* Fetch service with timeout, cancellation, normalized errors, and offline signaling. */
(function (global) {
  'use strict';
  async function request(path, options) {
    options = options || {};
    var timeout = options.timeout || 15000, controller = new AbortController(), timer = setTimeout(function () { controller.abort('timeout'); }, timeout);
    if (options.signal) {
      if (options.signal.aborted) controller.abort();
      else options.signal.addEventListener('abort', function () { controller.abort(); }, { once: true });
    }
    try {
      var response = await fetch(path, Object.assign({}, options, { credentials: 'same-origin', signal: controller.signal, headers: Object.assign({ 'content-type': 'application/json' }, options.headers || {}) }));
      if (response.status === 204) return null;
      var data = await response.json().catch(function () { return {}; });
      if (!response.ok) { var error = new Error(data.title || ('Request failed (' + response.status + ')')); error.status = response.status; error.details = data; throw error; }
      return data;
    } catch (error) {
      if (!navigator.onLine) error.message = 'Network unavailable. Preview data remains accessible offline.';
      else if (error.name === 'AbortError') error.message = 'Request cancelled or timed out.';
      throw error;
    } finally { clearTimeout(timer); }
  }
  global.CentinellAPI = Object.freeze({ request: request, get: function (path, options) { return request(path, options); }, post: function (path, body, options) { return request(path, Object.assign({}, options, { method: 'POST', body: JSON.stringify(body) })); }, delete: function (path, options) { return request(path, Object.assign({}, options, { method: 'DELETE' })); } });
})(window);
