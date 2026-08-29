/* Copyright © 2026 Beacon of the Eagle LLC. */
(function (global) {
  'use strict';
  function debounce(fn, wait) {
    var timer;
    function wrapped() {
      var context = this, args = arguments;
      clearTimeout(timer);
      timer = setTimeout(function () { fn.apply(context, args); }, wait);
    }
    wrapped.cancel = function () { clearTimeout(timer); };
    return wrapped;
  }
  function throttle(fn, wait) {
    var last = 0, timer;
    function wrapped() {
      var now = Date.now(), remaining = wait - (now - last), context = this, args = arguments;
      if (remaining <= 0) { clearTimeout(timer); last = now; fn.apply(context, args); }
      else if (!timer) timer = setTimeout(function () { timer = null; last = Date.now(); fn.apply(context, args); }, remaining);
    }
    wrapped.cancel = function () { clearTimeout(timer); timer = null; };
    return wrapped;
  }
  global.CentinellPerformance = Object.freeze({ debounce: debounce, throttle: throttle });
})(window);
