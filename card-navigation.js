(function () {
  'use strict';

  var requestedModule = window.location.hash.replace('#', '');
  if (requestedModule) {
    var requestedButton = document.querySelector('.nav button[data-page="' + requestedModule + '"]');
    var welcome = document.getElementById('welcomeScreen');
    if (requestedButton) {
      if (welcome) welcome.remove();
      requestedButton.click();
    }
  }

  function analysisUrl(card) {
    var page = card.closest('.page');
    var title = card.querySelector('.sub');
    var value = card.querySelector('.metric');
    var context = card.querySelector('.metric + span');
    var params = new URLSearchParams({
      module: page ? page.id : 'command',
      metric: title ? title.textContent.trim() : 'Security metric',
      value: value ? value.textContent.trim() : '—',
      context: context ? context.textContent.trim() : 'Technical review requested'
    });
    return 'technical-analysis.html?' + params.toString();
  }

  document.querySelectorAll('.page .card').forEach(function (card) {
    card.classList.add('navigable-card');
    card.setAttribute('role', 'link');
    card.setAttribute('tabindex', '0');
    card.setAttribute('aria-label', 'Open technical analysis for ' + (card.querySelector('.sub') || {}).textContent);
    var cue = document.createElement('span');
    cue.className = 'analysis-cue';
    cue.textContent = 'Open technical analysis →';
    card.appendChild(cue);
    function openAnalysis() {
      var detail = { card: card, url: analysisUrl(card), module: (card.closest('.page') || {}).id || 'command' };
      var event = new CustomEvent('centinell:metric-selected', { detail: detail, cancelable: true });
      if (window.dispatchEvent(event)) window.location.href = detail.url;
    }
    card.addEventListener('click', openAnalysis);
    card.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        openAnalysis();
      }
    });
  });
})();
