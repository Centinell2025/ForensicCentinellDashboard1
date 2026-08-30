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

  /* Command Center architecture panels use one delegated action registry. */
  var panelRoutes = {
    'Security Operations Volume': 'soc',
    'Priority Activity': 'soc',
    'Open Cases Snapshot': 'cases',
    'Compliance Posture': 'risk',
    'Real-Time Operations': 'soc'
  };
  function panelTitle(panel) { var heading = panel.querySelector(':scope > .head h2, :scope > h2'); return heading ? heading.textContent.trim() : ''; }
  function executePanel(panel) {
    var route = panel.dataset.actionRoute;
    if (window.CentinellRouter) window.CentinellRouter.navigate(route);
    else window.location.hash = '#/' + route;
    window.dispatchEvent(new CustomEvent('centinell:action-executed', { detail: { route:route, label:panelTitle(panel) } }));
  }
  document.querySelectorAll('#command .panel').forEach(function (panel) {
    var title = panelTitle(panel), route = panelRoutes[title]; if (!route) return;
    panel.dataset.actionRoute = route; panel.classList.add('investigative-panel'); panel.setAttribute('role','link'); panel.setAttribute('tabindex','0');
    panel.setAttribute('aria-label','Open '+title+' investigation workspace');
    var cue=document.createElement('span');cue.className='panel-action-cue';cue.textContent='Open investigation workspace →';panel.appendChild(cue);
  });
  document.addEventListener('click', function (event) {
    var panel=event.target.closest('[data-action-route]'); if(!panel)return;
    if(event.target.closest('button,a,input,select,textarea'))return; executePanel(panel);
  });
  document.addEventListener('keydown', function (event) {
    if(event.key!=='Enter'&&event.key!==' ')return;var panel=event.target.closest('[data-action-route]');if(!panel||event.target!==panel)return;
    event.preventDefault();executePanel(panel);
  });
  var style=document.createElement('style');style.textContent='.investigative-panel{cursor:pointer;transition:transform .18s,border-color .18s,box-shadow .18s}.investigative-panel:hover,.investigative-panel:focus-visible{transform:translateY(-2px);border-color:var(--cyan);box-shadow:0 18px 44px #0007;outline:none}.panel-action-cue{display:block;margin-top:14px;padding-top:10px;border-top:1px solid var(--line);color:var(--cyan);font-size:11px;font-weight:700}';document.head.appendChild(style);
})();

/* Forensic support diagnostic sequence: 2 → 2 → 3 → 2 → 1. */
(function(){
  var sequence=[2,2,3,2,1], key='centinell:forensic-sequence:v1', index=Number(sessionStorage.getItem(key)||0);
  function targetDepth(){return sequence[index]}
  function announce(){
    var text='Forensic diagnostic step '+Math.min(index+1,sequence.length)+'/'+sequence.length+' · depth '+targetDepth();
    var el=document.getElementById('forensicSequenceStatus');
    if(!el){el=document.createElement('div');el.id='forensicSequenceStatus';el.setAttribute('role','status');el.style.cssText='position:fixed;left:18px;bottom:18px;z-index:9800;padding:9px 13px;border:1px solid #71e4ff;border-radius:9px;background:#082342;color:#dff8ff;font:12px Inter,sans-serif';document.body.appendChild(el)}
    el.textContent=text;
  }
  window.triggerModuleDepth=function(depth){
    var route=depth>=3?'evidence':depth===2?'soc':'command';
    if(window.CentinellRouter) window.CentinellRouter.navigate(route); else window.location.hash='#/'+route;
    window.dispatchEvent(new CustomEvent('centinell:forensic-depth',{detail:{depth:depth,route:route,step:index+1}}));
    announce();
  };
  window.executeForensicStepSequence=function(){
    var depth=targetDepth(); triggerModuleDepth(depth); index=(index+1)%sequence.length; sessionStorage.setItem(key,String(index));
  };
  document.addEventListener('click',function(e){
    var el=e.target.closest('[data-forensic-sequence],#command [data-support-step]');
    if(el) window.executeForensicStepSequence();
  });
  document.addEventListener('keydown',function(e){
    if((e.key==='Enter'||e.key===' ')&&e.target.closest('[data-forensic-sequence],#command [data-support-step]')){e.preventDefault();window.executeForensicStepSequence();}
  });
  if(location.hash.indexOf('/command/support-center')===0){if(window.CentinellRouter)window.CentinellRouter.navigate('command');announce();}
})();
