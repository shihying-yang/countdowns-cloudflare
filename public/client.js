const $ = (s, r=document)=>r.querySelector(s); const $$=(s,r=document)=>Array.from(r.querySelectorAll(s));
const fmtDT = new Intl.DateTimeFormat(undefined,{weekday:'short',year:'numeric',month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'});
const fmtD  = new Intl.DateTimeFormat(undefined,{weekday:'short',year:'numeric',month:'short',day:'2-digit'});

function pad2(n){ return String(n).padStart(2,'0'); }
function toInputsFromStamp(stamp){ const parts = stamp.split('T'); return { date: parts[0], time: parts[1] || '00:00:00' }; }

function etaHTML(target, dateOnly){
  const now = new Date(); const diff = target-now; if (diff<=0) return '<span class="expired">Time’s up!</span>';
  if(dateOnly){ const d = Math.ceil(diff/86400000); return d+'d'; }
  const t = Math.floor(diff/1000); const dd=Math.floor(t/86400);
  const hh=String(Math.floor((t%86400)/3600)).padStart(2,'0'); const mm=String(Math.floor((t%3600)/60)).padStart(2,'0'); const ss=String(t%60).padStart(2,'0');
  return (dd>0?dd+'d ':'')+hh+'h '+mm+'m '+ss+'s';
}

async function api(path, opts={}){
  const res = await fetch(path, {headers:{'content-type':'application/json'}, credentials:'same-origin', ...opts});
  const text = await res.text(); let data; try{ data = text? JSON.parse(text):{} }catch{ data={raw:text} }
  if(!res.ok) throw Object.assign(new Error('HTTP '+res.status), {status:res.status, data});
  return data;
}

function makeShareBox(url, onCopy, onRevoke){
  const box = document.createElement('div'); box.className='share-box';
  const inp = document.createElement('input'); inp.type='text'; inp.readOnly = true; inp.value = url;
  const copy = document.createElement('button'); copy.className='btn'; copy.textContent='Copy';
  const revoke = document.createElement('button'); revoke.className='btn danger'; revoke.textContent='Revoke';
  copy.addEventListener('click', async ()=>{
    try{ await navigator.clipboard.writeText(inp.value); copy.textContent='Copied'; setTimeout(()=>copy.textContent='Copy',800); }
    catch{ inp.select(); document.execCommand && document.execCommand('copy'); }
    if (onCopy) onCopy();
  });
  revoke.addEventListener('click', ()=>{ if (onRevoke) onRevoke(); });
  box.appendChild(inp); box.appendChild(copy); box.appendChild(revoke);
  return box;
}

async function checkMe(){
  try{
    const {user} = await api('/api/me');
    $('#auth-card').classList.add('hidden'); $('#app-card').classList.remove('hidden');
    $('#who').textContent = user.email;
    await refreshList();
  }catch(e){
    $('#app-card').classList.add('hidden'); $('#auth-card').classList.remove('hidden');
  }
}

async function refreshList(){
  const root = $('#list'); root.innerHTML='';
  const {items} = await api('/api/countdowns');

  for (const it of items) {
    const row = document.createElement('div'); row.className='item'; row.dataset.id = it.id;

    const cb = document.createElement('input'); cb.type='checkbox';

    const middle = document.createElement('div');
    middle.innerHTML = ''
      + '<strong class="name-view"></strong>'
      + '<div class="muted when-view"></div>'
      + '<div class="edit-fields hidden" style="margin-top:6px">'
      + '  <div class="row" style="gap:6px;flex-wrap:wrap">'
      + '    <input class="edit-name" type="text" style="min-width:220px">'
      + '    <input class="edit-date" type="date">'
      + '    <input class="edit-time" type="time" step="1">'
      + '    <button class="btn primary btn-save">Save</button>'
      + '    <button class="btn btn-cancel">Cancel</button>'
      + '  </div>'
      + '</div>';

    const right = document.createElement('div'); right.className='right';
    const eta = document.createElement('span'); eta.className='eta';
    const badge = document.createElement('span'); badge.className='badge'; badge.textContent='date-only'; badge.hidden=!it.date_only;
    const editBtn = document.createElement('button'); editBtn.className='btn'; editBtn.textContent='Edit';
    right.appendChild(eta); right.appendChild(badge); right.appendChild(editBtn);

    row.appendChild(cb); row.appendChild(middle); row.appendChild(right);
    root.appendChild(row);

    // Fill view values
    $('.name-view', row).textContent = it.name;
    $('.when-view', row).textContent = it.date_only ? fmtD.format(new Date(it.stamp)) : fmtDT.format(new Date(it.stamp));

    // Prepare edit defaults
    const ins = toInputsFromStamp(it.stamp);
    $('.edit-name', row).value = it.name;
    $('.edit-date', row).value = ins.date;
    $('.edit-time', row).value = ins.time || '00:00:00';

    function setEdit(on){
      // Show/hide the edit fields
      $('.edit-fields', row).classList.toggle('hidden', !on);
      // Hide only the view elements (not the whole container!)
      $('.name-view', row).classList.toggle('hidden', on);
      $('.when-view', row).classList.toggle('hidden', on);

      editBtn.textContent = on ? 'Editing…' : 'Edit';
      editBtn.disabled = on;

      if (on) {
        // optional: focus first input
        const en = $('.edit-name', row);
        if (en) { en.focus(); en.select && en.select(); }
      }
    }

    editBtn.addEventListener('click', ()=> setEdit(true));
    $('.name-view', row).addEventListener('click', ()=> setEdit(true));
    $('.when-view', row).addEventListener('click', ()=> setEdit(true));
    $('.btn-cancel', row).addEventListener('click', (e)=>{ e.preventDefault();
      $('.edit-name', row).value = it.name;
      $('.edit-date', row).value = ins.date;
      $('.edit-time', row).value = ins.time || '00:00:00';
      setEdit(false);
    });

    $('.btn-save', row).addEventListener('click', async (e)=>{
      e.preventDefault();
      const newName = $('.edit-name', row).value.trim();
      const d = $('.edit-date', row).value;
      const t = $('.edit-time', row).value || '00:00:00';
      if (!newName || !d) { alert('Name and date are required'); return; }
      const parts = (t || '00:00:00').split(':');
      const hh = parts[0] || '00', mm = parts[1] || '00', ss = parts[2] || '00';
      const stamp = d + "T" + pad2(hh) + ":" + pad2(mm) + ":" + pad2(ss);
      const date_only = (t === '' || t === '00:00:00');

      try{
        const res = await api('/api/countdowns/' + it.id, {
          method:'PATCH',
          body: JSON.stringify({ name:newName, stamp, date_only })
        });
        it.name = res.item.name;
        it.stamp = res.item.stamp;
        it.date_only = !!res.item.date_only;
        $('.name-view', row).textContent = it.name;
        $('.when-view', row).textContent = it.date_only ? fmtD.format(new Date(it.stamp)) : fmtDT.format(new Date(it.stamp));
        badge.hidden = !it.date_only;
        setEdit(false);
        tick();
      }catch(err){
        alert((err && err.data && err.data.error) || 'Save failed');
      }
    });
  }

  tick();
  if(window._timer) clearInterval(window._timer);
  window._timer=setInterval(tick,1000);
  function tick(){ $$('.item', root).forEach(node=>{
    const id = node.dataset.id; const it = items.find(x=>x.id===id); if(!it) return;
    const html = etaHTML(new Date(it.stamp), !!it.date_only); $('.eta', node).innerHTML = html;
  });}
}

function toRFC3339Local(date){
  const p=n=>String(n).padStart(2,'0');
  return date.getFullYear()+'-'+p(date.getMonth()+1)+'-'+p(date.getDate())+'T'+p(date.getHours())+':'+p(date.getMinutes())+':'+p(date.getSeconds());
}

// The original code used DOMContentLoaded, but since we are using `defer` on the script tag,
// the DOM is guaranteed to be ready when this script executes.

const today = new Date(); $('#date').value = today.toISOString().slice(0,10);

const pageShareBtn  = document.getElementById('btnPageShare');
const pageShareZone = document.getElementById('pageShareZone');

if (pageShareBtn) {
  pageShareBtn.addEventListener('click', async function(e){
    e.preventDefault();
    try {
      const res = await api('/api/page-share', { method:'POST', body: JSON.stringify({}) });
      const token = res.token;
      const url = window.location.origin + '/p/' + token;
      pageShareZone.innerHTML = '';
      pageShareZone.appendChild(makeShareBox(url, null, async function(){
        try {
          await api('/api/page-share', { method:'DELETE' });
          pageShareZone.innerHTML = '<span class="muted">Page share revoked</span>';
        } catch (err) {
          alert('Revoke failed');
        }
      }));
    } catch (err) {
      alert('Page share failed');
    }
  });
}

$('#login').onclick = async ()=>{
  const email=$('#email').value.trim().toLowerCase(), password=$('#password').value;
  try{ await api('/api/login',{method:'POST', body:JSON.stringify({email,password})}); $('#auth-msg').textContent=''; await checkMe(); }
  catch(e){ $('#auth-msg').textContent = (e && e.data && e.data.error) || 'Login failed'; }
};
$('#signup').onclick = async ()=>{
  const email=$('#email').value.trim().toLowerCase(), password=$('#password').value;
  try{ await api('/api/signup',{method:'POST', body:JSON.stringify({email,password})}); $('#auth-msg').textContent=''; await checkMe(); }
  catch(e){ $('#auth-msg').textContent = (e && e.data && e.data.error) || 'Signup failed'; }
};
$('#logout').onclick = async () => {
	await api('/api/logout', { method: 'POST' });
	await checkMe();
	// Clear the input fields after logout for security
	$('#email').value = '';
	$('#password').value = '';
};

$('#create').addEventListener('submit', async (e)=>{
  e.preventDefault();

  const name = $('#name').value.trim();
  const d = $('#date').value;
  const t = $('#time').value; // may be empty
  if (!name || !d) return;

  let stamp, dateOnly;
  if (!t) {
    // Send a plain date; server will normalize to midnight and set date_only=true
    stamp = d;
    dateOnly = true;
  } else {
    const parts = t.split(':');
    const hh = parts[0] || '00', mm = parts[1] || '00', ss = parts[2] || '00';
    stamp = d + "T" + pad2(hh) + ":" + pad2(mm) + ":" + pad2(ss);
    dateOnly = (t === '00:00:00');
  }

  try{ await api('/api/countdowns',{method:'POST', body:JSON.stringify({name, stamp, date_only: dateOnly})}); e.target.reset(); $('#date').value=d; await refreshList(); }
  catch(e){ alert((e && e.data && e.data.error) || 'Failed to add'); }
});

$('#deleteSelected').onclick = async ()=>{
  const ids = $$('.item').filter(n=>$('input[type=checkbox]',n).checked).map(n=>n.dataset.id);
  if(ids.length===0) return; try{ await api('/api/countdowns',{method:'DELETE', body:JSON.stringify({ids})}); await refreshList(); }
  catch(e){ alert((e && e.data && e.data.error) || 'Delete failed'); }
};

checkMe();
