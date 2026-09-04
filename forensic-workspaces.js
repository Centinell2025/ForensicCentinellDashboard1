(function(){
'use strict';
var pages=[
 ['intake','Intake & Triage','Receive URLs, documents, emails, images and logs; register source, scope and collection authority.'],
 ['case-workspace','Case Workspace','Assign work, manage tasks, analyst notes, deadlines and supervisory review.'],
 ['evidence-lab','Evidence & Analysis Lab','Calculate SHA-256 fingerprints, record metadata and document URL or file-analysis findings.'],
 ['team-assignments','Team & Assignments','Maintain authorized workers, roles, assigned cases and review responsibilities.'],
 ['work-record','Work Record & Approval','Generate a time-stamped work record, peer review and final approval trail.']
];
function route(id){return 'forensic/'+id}
function page(id){return document.getElementById(id)}
function show(id){
 var target=page(id); if(!target)return;
 document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active')});
 target.classList.add('active');
 document.querySelectorAll('[data-page]').forEach(function(b){b.classList.toggle('active',b.dataset.page===id)});
 history.replaceState(null,'','#/'+route(id));
}
function renderTable(kind){
 var rows=JSON.parse(localStorage.getItem('centinell:'+kind)||'[]');
 return rows.length?rows.map(function(r){return '<tr><td>'+r.when+'</td><td>'+r.text+'</td><td>'+r.owner+'</td></tr>'}).join(''):'<tr><td colspan="3" class="muted">No records yet. Add the first authorized work record.</td></tr>';
}
function install(){
 var main=document.querySelector('main.main'), side=document.querySelector('aside.side'), health=side&&side.querySelector('.health');
 if(!main||!side||!health||document.getElementById('intake'))return;
 var label=document.createElement('div');label.className='label';label.textContent='FORENSIC WORKFLOW';side.insertBefore(label,health);
 var nav=document.createElement('nav');nav.className='nav';side.insertBefore(nav,health);
 pages.forEach(function(item){
  var id=item[0], button=document.createElement('button'); button.dataset.page=id;button.innerHTML='<span>'+item[1]+'</span>';nav.appendChild(button);
  var section=document.createElement('section');section.className='page';section.id=id;
  section.innerHTML='<div class="heading"><div><h1>'+item[1]+'</h1><p>'+item[2]+'</p></div><button class="btn" data-go="command">← Command Center</button></div><div class="panel"><div class="head"><h2>Authorized work record</h2><span class="chip good">UTC · audit-ready</span></div><div class="form"><div class="field"><label>Record / finding</label><textarea data-record rows="5" placeholder="Describe the authorized action, source reference, scope, result, uncertainty and next review step."></textarea></div><div class="formactions"><button class="btn primary" data-save-record>Save work record</button><button class="btn" data-export-record>Export record</button></div></div></div><div class="panel" style="margin-top:13px"><div class="head"><h2>Review trail</h2><span class="muted">Browser preview; production records are tenant-scoped.</span></div><div class="tablewrap"><table class="table"><thead><tr><th>UTC</th><th>Record</th><th>Worker</th></tr></thead><tbody data-record-list>'+renderTable(id)+'</tbody></table></div></div>';
  main.appendChild(section);
 });
 document.addEventListener('click',function(e){
  var b=e.target.closest('[data-page]');if(b&&page(b.dataset.page)){show(b.dataset.page);return;}
  var go=e.target.closest('[data-go="command"]');if(go&&typeof window.showPage==='function'){window.showPage('command');history.replaceState(null,'','#/command');return;}
  var save=e.target.closest('[data-save-record]');if(save){var s=save.closest('.page'),t=s.querySelector('[data-record]');if(!t.value.trim())return;var k='centinell:'+s.id,rows=JSON.parse(localStorage.getItem(k)||'[]');rows.unshift({when:new Date().toISOString(),text:t.value.trim(),owner:'Authorized Web Operator'});localStorage.setItem(k,JSON.stringify(rows));s.querySelector('[data-record-list]').innerHTML=renderTable(s.id);t.value='';window.showToast&&window.showToast('Work record saved','UTC record added to the preview trail.','success');}
  var ex=e.target.closest('[data-export-record]');if(ex){var s=ex.closest('.page'),blob=new Blob([JSON.stringify(JSON.parse(localStorage.getItem('centinell:'+s.id)||'[]'),null,2)],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=s.id+'-work-record.json';a.click();URL.revokeObjectURL(a.href);}
 });
 var current=(location.hash||'').replace(/^#\//,'');var match=pages.find(function(x){return route(x[0])===current});if(match)show(match[0]);
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',install);else install();
})();