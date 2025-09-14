// src/index.js (no unescaped template literals inside APP_HTML)

const JSON_HEADERS = { 'content-type': 'application/json' };

// === Utilities ===
function json(data, status = 200, headers = {}) {
	return new Response(JSON.stringify(data), {
		status,
		headers: { ...JSON_HEADERS, ...headers },
	});
}
async function readJson(req) {
	try {
		return await req.json();
	} catch {
		throw new Error('INVALID_JSON');
	}
}
function badRequest(msg = 'Bad Request') {
	return json({ error: msg }, 400);
}
function unauthorized(msg = 'Unauthorized') {
	return json({ error: msg }, 401);
}
function conflict(msg = 'Conflict') {
	return json({ error: msg }, 409);
}
function notFound(msg = 'Not Found') {
	return json({ error: msg }, 404);
}
function nowEpoch() {
	return Math.floor(Date.now() / 1000);
}

// === Cookie helpers ===
const COOKIE_NAME = 'sid';
const COOKIE_MAX_AGE_IDLE = 60 * 60 * 24 * 7; // 7 days idle
const COOKIE_MAX_AGE_ABS = 60 * 60 * 24 * 30; // 30 days absolute cap
function buildCookie(name, value, { maxAge, path = '/', httpOnly = true, secure = true, sameSite = 'Lax' } = {}) {
	let c = `${name}=${value}; Path=${path}; SameSite=${sameSite}`;
	if (httpOnly) c += '; HttpOnly';
	if (secure) c += '; Secure';
	if (typeof maxAge === 'number') c += `; Max-Age=${maxAge}`;
	return c;
}
function parseCookies(request) {
	const header = request.headers.get('cookie') || '';
	const out = {};
	header.split(/;\s*/).forEach((kv) => {
		const [k, v] = kv.split('=');
		if (k) out[k] = v ?? '';
	});
	return out;
}

// === Crypto: PBKDF2-SHA256 ===
async function pbkdf2(password, saltBytes, iterations = 100_000, keyLen = 32) {
	const enc = new TextEncoder();
	const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
	const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations }, keyMaterial, keyLen * 8);
	return new Uint8Array(bits);
}
function b64encode(bytes) {
	let s = '';
	for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
	return btoa(s);
}
function b64decode(str) {
	const bin = atob(str);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}
async function hashPassword(password, saltB64) {
	const salt = saltB64 ? b64decode(saltB64) : crypto.getRandomValues(new Uint8Array(16));
	const hashBytes = await pbkdf2(password, salt, 100_000, 32);
	return { saltB64: b64encode(salt), hashB64: b64encode(hashBytes), algo: 'pbkdf2-sha256' };
}
async function verifyPassword(password, saltB64, expectedHashB64) {
	const { hashB64 } = await hashPassword(password, saltB64);
	if (hashB64.length !== expectedHashB64.length) return false;
	let diff = 0;
	for (let i = 0; i < hashB64.length; i++) diff |= hashB64.charCodeAt(i) ^ expectedHashB64.charCodeAt(i);
	return diff === 0;
}

// === Rate limiting (D1-backed) ===
const RL_WINDOW_SECONDS = 10 * 60; // 10 minutes
const RL_LIMITS = {
	'login:ip': 10,
	'login:email': 5,
	'signup:ip': 10,
	'signup:email': 5,
};
function getClientIp(request) {
	return request.headers.get('cf-connecting-ip') || '';
}
async function rlCountInWindow(DB, key, nowSec) {
	const since = nowSec - RL_WINDOW_SECONDS;
	const row = await DB.prepare('SELECT COUNT(1) AS c FROM rl_attempts WHERE key = ? AND ts >= ?').bind(key, since).first();
	return Number(row?.c || 0);
}
async function rlAdd(DB, key, nowSec) {
	await DB.prepare('INSERT INTO rl_attempts (key, ts) VALUES (?, ?)').bind(key, nowSec).run();
	if (Math.random() < 0.1) {
		const cutoff = nowSec - RL_WINDOW_SECONDS * 2;
		await DB.prepare('DELETE FROM rl_attempts WHERE ts < ?').bind(cutoff).run();
	}
}
async function rlCheckAndRecord(DB, route, request, emailLower) {
	const nowSec = nowEpoch();
	const ip = getClientIp(request);
	const keys = [];
	if (ip) keys.push(`${route}:ip:${ip}`);
	if (emailLower) keys.push(`${route}:email:${emailLower}`);
	for (const key of keys) {
		const limitType = key.split(':').slice(0, 2).join(':');
		const limit = RL_LIMITS[limitType] ?? 10;
		const count = await rlCountInWindow(DB, key, nowSec);
		if (count >= limit) {
			const resetIn = RL_WINDOW_SECONDS;
			const msg = `RATE_LIMITED (${limitType} limit ${limit}/10m)`;
			return { ok: false, status: 429, body: { error: msg, retry_after_sec: resetIn } };
		}
	}
	for (const key of keys) await rlAdd(DB, key, nowSec);
	return { ok: true };
}

// === Login lockouts & jitter ===
const FAIL_WINDOW_SECONDS = 10 * 60; // 10 minutes (uses RL window)
const LOCKOUT_AFTER_FAILS = 5; // threshold within window
const LOCKOUT_SECONDS = 15 * 60; // 15 minutes
function sleep(ms) {
	return new Promise((r) => setTimeout(r, ms));
}
async function isLockedOut(DB, emailLower) {
	const row = await DB.prepare('SELECT until FROM login_lockouts WHERE email = ?').bind(emailLower).first();
	const now = nowEpoch();
	return row && Number(row.until) > now;
}
async function setLockout(DB, emailLower, secondsFromNow) {
	const until = nowEpoch() + secondsFromNow;
	await DB.prepare(
		`
    INSERT INTO login_lockouts (email, until) VALUES (?, ?)
    ON CONFLICT(email) DO UPDATE SET until = excluded.until
  `
	)
		.bind(emailLower, until)
		.run();
}
async function clearLockout(DB, emailLower) {
	await DB.prepare('DELETE FROM login_lockouts WHERE email = ?').bind(emailLower).run();
}
async function loginFailAdd(DB, emailLower) {
	const key = `fail:login:email:${emailLower}`;
	await rlAdd(DB, key, nowEpoch());
}
async function loginFailCount(DB, emailLower) {
	const key = `fail:login:email:${emailLower}`;
	return rlCountInWindow(DB, key, nowEpoch());
}
async function jitter() {
	const ms = 150 + Math.floor(Math.random() * 200);
	await sleep(ms);
}

// === DB helpers (auth) ===
async function getUserByEmail(DB, email) {
	return (await DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first()) || null;
}
async function createUser(DB, email, password) {
	const existing = await getUserByEmail(DB, email);
	if (existing) return { error: 'EMAIL_IN_USE' };
	const id = crypto.randomUUID();
	const { saltB64, hashB64, algo } = await hashPassword(password);
	await DB.prepare(
		`INSERT INTO users (id, email, email_verified, password_hash, password_salt, password_algo)
     VALUES (?, ?, 0, ?, ?, ?)`
	)
		.bind(id, email, hashB64, saltB64, algo)
		.run();
	return { id, email };
}
async function createSession(DB, userId) {
	const sid = crypto.randomUUID();
	const now = nowEpoch();
	const idleExpires = now + COOKIE_MAX_AGE_IDLE;
	const activeExpires = now + COOKIE_MAX_AGE_ABS;
	await DB.prepare(
		`INSERT INTO sessions (id, user_id, created_at, idle_expires, active_expires)
     VALUES (?, ?, ?, ?, ?)`
	)
		.bind(sid, userId, now, idleExpires, activeExpires)
		.run();
	return { sid, idleExpires, activeExpires };
}
async function deleteSession(DB, sid) {
	await DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sid).run();
}
async function getSession(DB, sid) {
	return (await DB.prepare('SELECT * FROM sessions WHERE id = ?').bind(sid).first()) || null;
}
async function refreshSessionIfEligible(DB, session) {
	const now = nowEpoch();
	if (now >= session.active_expires) {
		await DB.prepare('DELETE FROM sessions WHERE id = ?').bind(session.id).run();
		return null;
	}
	if (now + 60 < session.idle_expires) return session;
	const newIdle = now + COOKIE_MAX_AGE_IDLE;
	await DB.prepare('UPDATE sessions SET idle_expires = ? WHERE id = ?').bind(newIdle, session.id).run();
	session.idle_expires = newIdle;
	return session;
}
async function currentUser(env, request) {
	const cookies = parseCookies(request);
	const sid = cookies[COOKIE_NAME];
	if (!sid) return { user: null, session: null };
	const session = await getSession(env.DB, sid);
	if (!session) return { user: null, session: null };
	const now = nowEpoch();
	if (now >= session.idle_expires || now >= session.active_expires) {
		await deleteSession(env.DB, sid);
		return { user: null, session: null };
	}
	const refreshed = await refreshSessionIfEligible(env.DB, session);
	const user = await env.DB.prepare('SELECT id, email FROM users WHERE id = ?').bind(session.user_id).first();
	return { user, session: refreshed || session };
}

// === DB helpers (countdowns) ===
// function isRFC3339Timestamp(s) { return typeof s === "string" && /^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}$/.test(s); }
function isISODate(s) {
	return typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
}
function isISODateTime(s) {
	return typeof s === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(s);
}
function normalizeStampAndDateOnly(stamp, dateOnlyFlag) {
	if (isISODate(stamp)) {
		return { stamp: stamp + 'T00:00:00', date_only: true };
	}
	if (isISODateTime(stamp)) {
		// honor the explicit flag if provided, otherwise default false
		return { stamp, date_only: !!dateOnlyFlag };
	}
	throw new Error('INVALID_STAMP (expected YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)');
}
function toBoolInt(v) {
	return v ? 1 : 0;
}
async function listCountdowns(DB, userId) {
	const { results } = await DB.prepare(
		`SELECT id, name, stamp, date_only, created_at, updated_at
     FROM countdowns WHERE user_id = ? ORDER BY stamp ASC`
	)
		.bind(userId)
		.all();
	return results.map((r) => ({ ...r, date_only: !!r.date_only }));
}
async function createCountdown(DB, userId, name, stamp, dateOnly) {
	const id = crypto.randomUUID();
	await DB.prepare(
		`INSERT INTO countdowns (id, user_id, name, stamp, date_only)
     VALUES (?, ?, ?, ?, ?)`
	)
		.bind(id, userId, name, stamp, toBoolInt(dateOnly))
		.run();
	return { id, name, stamp, date_only: !!dateOnly };
}
async function deleteCountdowns(DB, userId, ids) {
	if (!Array.isArray(ids) || ids.length === 0) return 0;
	const qs = ids.map(() => '?').join(',');
	const sql = `DELETE FROM countdowns WHERE user_id = ? AND id IN (${qs})`;
	const bindVals = [userId, ...ids];
	const res = await DB.prepare(sql)
		.bind(...bindVals)
		.run();
	return res.meta.changes || 0;
}
function isUUID(v) {
	return typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v);
}
async function getCountdown(DB, userId, id) {
	return await DB.prepare(
		`SELECT id, user_id, name, stamp, date_only, created_at, updated_at
     FROM countdowns WHERE id = ? AND user_id = ?`
	)
		.bind(id, userId)
		.first();
}
async function updateCountdown(DB, userId, id, patch) {
	const sets = [];
	const args = [];

	if (typeof patch.name === 'string') {
		const n = patch.name.trim();
		if (!n || n.length > 200) throw new Error('INVALID_NAME');
		sets.push('name = ?');
		args.push(n);
	}
	if (typeof patch.stamp === 'string') {
		if (!isISODateTime(patch.stamp)) throw new Error('INVALID_STAMP (expected YYYY-MM-DDTHH:MM:SS)');
		sets.push('stamp = ?');
		args.push(patch.stamp);
	}
	if (typeof patch.date_only !== 'undefined') {
		sets.push('date_only = ?');
		args.push(toBoolInt(!!patch.date_only));
	}

	if (sets.length === 0) return 0;

	const sql = `UPDATE countdowns SET ${sets.join(', ')} WHERE id = ? AND user_id = ?`;
	args.push(id, userId);
	const res = await DB.prepare(sql)
		.bind(...args)
		.run();
	return res.meta.changes || 0;
}

// === Page shares helpers ===
async function createOrGetPageShare(DB, userId, expiresDays) {
	const reuse = await DB.prepare(
		'SELECT token FROM shares_pages WHERE user_id = ? AND revoked_at IS NULL ' + 'AND (expires_at IS NULL OR expires_at > unixepoch())'
	)
		.bind(userId)
		.first();
	if (reuse) return { token: reuse.token, created: false };

	const token = crypto.randomUUID();
	let expires_at = null;
	if (typeof expiresDays === 'number' && expiresDays > 0) {
		expires_at = Math.floor(Date.now() / 1000) + Math.floor(expiresDays * 86400);
	}
	await DB.prepare('INSERT INTO shares_pages (token, user_id, expires_at) VALUES (?, ?, ?)').bind(token, userId, expires_at).run();
	return { token, created: true };
}

async function getActivePageShare(DB, token) {
	return await DB.prepare(
		'SELECT token, user_id, created_at, expires_at ' +
			'FROM shares_pages WHERE token = ? AND revoked_at IS NULL ' +
			'AND (expires_at IS NULL OR expires_at > unixepoch())'
	)
		.bind(token)
		.first();
}

async function revokePageShare(DB, userId) {
	const res = await DB.prepare('UPDATE shares_pages SET revoked_at = unixepoch() WHERE user_id = ? AND revoked_at IS NULL')
		.bind(userId)
		.run();
	return res.meta.changes || 0;
}

// --- Minimal inlined UI (served at "/") ---
const APP_HTML = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Countdowns</title>
<style>
  :root{--bg:#0b0c10;--fg:#e5e7eb;--muted:#9ca3af;--border:#1f2430;--card:#111217;--accent:#4f46e5;--danger:#ef4444}
  body{margin:0;background:var(--bg);color:var(--fg);font:16px system-ui,Segoe UI,Roboto,Helvetica,Arial}
  .wrap{max-width:900px;margin:32px auto;padding:0 16px}
  .card{background:var(--card);border:1px solid var(--border);border-radius:14px;box-shadow:0 8px 24px rgba(0,0,0,.25);margin-bottom:16px}
  .pad{padding:18px}
  h1{margin:0 0 8px 0} p{margin:0;color:var(--muted)}
  label{font-size:12px;color:var(--muted)} input,button{font:inherit}
  input[type=text],input[type=email],input[type=password],input[type=date],input[type=time]{width:100%;box-sizing:border-box;background:#0f1117;color:var(--fg);border:1px solid var(--border);border-radius:10px;padding:10px 12px}
  .grid{display:grid;gap:10px}
  @media(min-width:640px){.grid-4{grid-template-columns:1.2fr .8fr .8fr auto}}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .btn{background:#0f1117;border:1px solid var(--border);color:var(--fg);padding:10px 14px;border-radius:10px;cursor:pointer}
  .btn.primary{background:var(--accent);border-color:transparent}
  .btn.danger{background:#231012;border-color:#3d2025;color:#fca5a5}
  .muted{color:var(--muted)}
  .list .item{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;border-top:1px solid var(--border);padding:12px 14px}
  .list .item:first-child{border-top:0}
  .eta{font-variant-numeric:tabular-nums;font-weight:700}
  .expired{color:var(--danger);font-weight:800}
  .badge{font-size:11px;background:#10b981;color:#06291f;padding:2px 8px;border-radius:999px;margin-left:6px}
  .right{margin-left:auto}
  .hidden{display:none}
</style>
</head><body><div class="wrap">
  <header class="card pad">
    <h1>Countdowns</h1>
    <p>Sign in to manage your personal countdowns. Date-only shows days; date+time shows d hh mm ss.</p>
  </header>

  <section id="auth-card" class="card pad">
    <div class="row" style="justify-content:space-between;align-items:flex-end">
      <div style="max-width:480px;flex:1">
        <div class="grid" style="grid-template-columns:1fr 1fr;gap:8px">
          <div>
            <label for="email">Email</label>
            <input id="email" type="email" placeholder="you@example.com" autocomplete="username">
          </div>
          <div>
            <label for="password">Password</label>
            <input id="password" type="password" placeholder="min 8 chars" autocomplete="current-password">
          </div>
        </div>
      </div>
      <div class="row">
        <button id="login" class="btn primary">Log in</button>
        <button id="signup" class="btn">Sign up</button>
      </div>
    </div>
    <div id="auth-msg" class="muted" style="margin-top:8px"></div>
  </section>

  <section id="app-card" class="card pad hidden">
    <div class="row" style="justify-content:space-between;align-items:center;margin-bottom:8px">
      <div class="muted">Signed in as <span id="who"></span></div>
      <div class="row">
        <button id="logout" class="btn">Log out</button>
      </div>
    </div>

    <div class="row" style="margin-top:10px">
      <button id="btnPageShare" class="btn">Share Page</button>
      <div id="pageShareZone" style="margin-left:12px"></div>
    </div>

    <form id="create" class="grid grid-4" autocomplete="off">
      <div>
        <label for="name">Name</label>
        <input id="name" type="text" placeholder="Project launch" required>
      </div>
      <div>
        <label for="date">Date</label>
        <input id="date" type="date" required>
      </div>
      <div>
        <label for="time">Time (optional)</label>
        <input id="time" type="time" step="1" placeholder="00:00:00">
      </div>
      <div style="display:flex;align-items:flex-end">
        <button class="btn primary" type="submit">Add</button>
      </div>
    </form>

    <div class="row" style="justify-content:space-between;margin-top:10px">
      <div></div>
      <div class="row">
        <button id="deleteSelected" class="btn danger">Delete Selected</button>
      </div>
    </div>

    <div id="list" class="list" style="margin-top:10px"></div>
  </section>
</div>
<script>
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

window.addEventListener('DOMContentLoaded', ()=>{
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
  $('#logout').onclick = async ()=>{ await api('/api/logout',{method:'POST'}); await checkMe(); };

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
});
</script>
</body></html>`;

// === Router ===
export default {
	async fetch(request, env) {
		const url = new URL(request.url);

		// Serve UI
		if (url.pathname === '/') {
			return new Response(APP_HTML, { headers: { 'content-type': 'text/html; charset=utf-8' } });
		}

		// Version marker for deploy checks
		if (url.pathname === '/version') return json({ v: 'data-3' });

		// Health
		if (url.pathname === '/health') return json({ ok: true });

		// DB schema debug
		if (url.pathname === '/debug/schema') {
			try {
				const { results } = await env.DB.prepare(
					`
          SELECT name, type FROM sqlite_schema
          WHERE type IN ('table','index','trigger')
          ORDER BY type, name
        `
				).all();
				return new Response(JSON.stringify(results, null, 2), { headers: JSON_HEADERS });
			} catch (err) {
				return json({ error: String(err) }, 500);
			}
		}

		// --- Public read-only page: /p/:token ---
		if (url.pathname.startsWith('/p/') && request.method === 'GET') {
			const token = url.pathname.split('/').pop();
			const share = await getActivePageShare(env.DB, token);
			if (!share) {
				return new Response('Page share not found or expired.', {
					status: 404,
					headers: { 'content-type': 'text/plain; charset=utf-8' },
				});
			}

			// Fetch all countdowns of that user
			const { results } = await env.DB.prepare('SELECT id, name, stamp, date_only FROM countdowns WHERE user_id = ? ORDER BY stamp ASC')
				.bind(share.user_id)
				.all();

			const html =
				"<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>" +
				'<title>Shared Countdowns</title>' +
				'<style>body{background:#0b0c10;color:#e5e7eb;font:16px system-ui;margin:0;padding:32px}' +
				'.card{max-width:720px;margin:0 auto;background:#111217;border:1px solid #1f2430;border-radius:14px;padding:20px}' +
				'.item{margin:12px 0;padding:12px;border:1px solid #1f2430;border-radius:10px}' +
				'h1{margin-top:0}.eta{font-variant-numeric:tabular-nums;font-weight:700;font-size:20px}.muted{color:#9ca3af}' +
				"</style></head><body><div class='card'><h1>Shared Countdowns</h1>" +
				"<div id='list'></div></div>" +
				'<script>' +
				'const items=' +
				JSON.stringify(results) +
				';' +
				"function etaHTML(target,dateOnly){var now=new Date();var diff=target-now;if(diff<=0)return 'Time\\u2019s up!';" +
				"if(dateOnly){var d=Math.ceil(diff/86400000);return d+'d';}" +
				'var t=Math.floor(diff/1000);var dd=Math.floor(t/86400);' +
				"var hh=String(Math.floor((t%86400)/3600)).padStart(2,'0');" +
				"var mm=String(Math.floor((t%3600)/60)).padStart(2,'0');" +
				"var ss=String(t%60).padStart(2,'0');" +
				"return (dd>0?dd+'d ':'')+hh+'h '+mm+'m '+ss+'s';}" +
				"function render(){const root=document.getElementById('list');root.innerHTML='';items.forEach(function(it){" +
				"const div=document.createElement('div');div.className='item';" +
				"div.innerHTML='<div><strong>'+it.name+'</strong></div>'+" +
				"'<div class=muted>'+it.stamp+'</div>'+" +
				"'<div class=eta id=eta-'+it.id+'></div>';root.appendChild(div);});tick();}" +
				"function tick(){items.forEach(function(it){var el=document.getElementById('eta-'+it.id);if(el) el.textContent=etaHTML(new Date(it.stamp),!!it.date_only);});}" +
				'render();setInterval(tick,1000);' +
				'</script></body></html>';

			return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8' } });
		}

		// --- Auth: Signup ---
		if (request.method === 'POST' && url.pathname === '/api/signup') {
			let body;
			try {
				body = await readJson(request);
			} catch {
				return badRequest('INVALID_JSON');
			}
			const email = String(body?.email || '')
				.trim()
				.toLowerCase();
			const password = String(body?.password || '');
			if (!email || !password || password.length < 8) return badRequest('EMAIL_AND_PASSWORD_REQUIRED (min 8 chars)');

			// Rate limit: signup
			const rl = await rlCheckAndRecord(env.DB, 'signup', request, email);
			if (!rl.ok) return json(rl.body, rl.status);

			const user = await createUser(env.DB, email, password);
			if (user?.error === 'EMAIL_IN_USE') return conflict('EMAIL_IN_USE');
			const { sid } = await createSession(env.DB, user.id);
			const setCookie = buildCookie(COOKIE_NAME, sid, { maxAge: COOKIE_MAX_AGE_IDLE });
			return json({ user }, 201, { 'set-cookie': setCookie });
		}

		// --- Auth: Login ---
		if (request.method === 'POST' && url.pathname === '/api/login') {
			let body;
			try {
				body = await readJson(request);
			} catch {
				return badRequest('INVALID_JSON');
			}
			const email = String(body?.email || '')
				.trim()
				.toLowerCase();
			const password = String(body?.password || '');
			if (!email || !password) {
				await jitter();
				return badRequest('EMAIL_AND_PASSWORD_REQUIRED');
			}

			// Lockout first
			if (await isLockedOut(env.DB, email)) {
				await jitter();
				return unauthorized('ACCOUNT_LOCKED_TRY_LATER');
			}

			// Then rate-limit
			const rl = await rlCheckAndRecord(env.DB, 'login', request, email);
			if (!rl.ok) {
				await jitter();
				return json(rl.body, rl.status);
			}

			const user = await getUserByEmail(env.DB, email);
			if (!user || !user.password_hash || !user.password_salt) {
				await loginFailAdd(env.DB, email);
				const fails = await loginFailCount(env.DB, email);
				if (fails >= LOCKOUT_AFTER_FAILS) await setLockout(env.DB, email, LOCKOUT_SECONDS);
				await jitter();
				return unauthorized('INVALID_CREDENTIALS');
			}
			const ok = await verifyPassword(password, user.password_salt, user.password_hash);
			if (!ok) {
				await loginFailAdd(env.DB, email);
				const fails = await loginFailCount(env.DB, email);
				if (fails >= LOCKOUT_AFTER_FAILS) await setLockout(env.DB, email, LOCKOUT_SECONDS);
				await jitter();
				return unauthorized('INVALID_CREDENTIALS');
			}

			await clearLockout(env.DB, email);
			const { sid } = await createSession(env.DB, user.id);
			const setCookie = buildCookie(COOKIE_NAME, sid, { maxAge: COOKIE_MAX_AGE_IDLE });
			await jitter();
			return json({ user: { id: user.id, email: user.email } }, 200, { 'set-cookie': setCookie });
		}

		// --- Auth: Logout ---
		if (request.method === 'POST' && url.pathname === '/api/logout') {
			const cookies = parseCookies(request);
			const sid = cookies[COOKIE_NAME];
			if (sid) await deleteSession(env.DB, sid);
			const setCookie = buildCookie(COOKIE_NAME, '', { maxAge: 0 });
			return json({ ok: true }, 200, { 'set-cookie': setCookie });
		}

		// --- Auth: Me ---
		if (request.method === 'GET' && url.pathname === '/api/me') {
			const { user } = await currentUser(env, request);
			if (!user) return unauthorized('NO_SESSION');
			return json({ user });
		}

		// --- Page Shares API ---
		// Create/reuse a page share link: returns { token }
		if (url.pathname === '/api/page-share' && request.method === 'POST') {
			const { user } = await currentUser(env, request);
			if (!user) return unauthorized('NO_SESSION');
			let body;
			try {
				body = await readJson(request);
			} catch {
				body = {};
			}
			const expiresDays = body && typeof body.expires_days === 'number' ? body.expires_days : undefined;
			const res = await createOrGetPageShare(env.DB, user.id, expiresDays);
			return json({ token: res.token, created: !!res.created });
		}

		// Revoke my page share link
		if (url.pathname === '/api/page-share' && request.method === 'DELETE') {
			const { user } = await currentUser(env, request);
			if (!user) return unauthorized('NO_SESSION');
			const n = await revokePageShare(env.DB, user.id);
			if (n === 0) return notFound('NOT_FOUND');
			return json({ revoked: true });
		}

		// --- Countdown: PATCH /api/countdowns/:id (partial update) ---
		if (url.pathname.startsWith('/api/countdowns/') && request.method === 'PATCH') {
			const { user } = await currentUser(env, request);
			if (!user) return unauthorized('NO_SESSION');

			const id = url.pathname.split('/').pop();
			if (!isUUID(id)) return badRequest('INVALID_ID');

			const existing = await getCountdown(env.DB, user.id, id);
			if (!existing) return json({ error: 'NOT_FOUND' }, 404);

			let body;
			try {
				body = await readJson(request);
			} catch {
				return badRequest('INVALID_JSON');
			}

			try {
				let patchObj = { name: body?.name };

				if (typeof body?.stamp === 'string') {
					// If caller didn’t send date_only, keep the existing setting
					const keepDateOnly = typeof body?.date_only === 'undefined' ? !!existing.date_only : !!body.date_only;
					const norm = normalizeStampAndDateOnly(body.stamp, keepDateOnly);
					patchObj.stamp = norm.stamp;
					patchObj.date_only = norm.date_only;
				} else if (typeof body?.date_only !== 'undefined') {
					patchObj.date_only = !!body.date_only;
				}

				const changed = await updateCountdown(env.DB, user.id, id, patchObj);

				if (changed === 0) return json({ item: existing, changed: 0 });
				const fresh = await getCountdown(env.DB, user.id, id);
				fresh.date_only = !!fresh.date_only;
				return json({ item: fresh, changed });
			} catch (e) {
				return badRequest(String(e.message || e));
			}
		}

		// --- Countdown APIs (require session) ---
		if (url.pathname === '/api/countdowns') {
			const { user } = await currentUser(env, request);
			if (!user) return unauthorized('NO_SESSION');

			// GET: list user's countdowns
			if (request.method === 'GET') {
				const rows = await listCountdowns(env.DB, user.id);
				return json({ items: rows });
			}

			// POST: create a countdown
			if (request.method === 'POST') {
				let body;
				try {
					body = await readJson(request);
				} catch {
					return badRequest('INVALID_JSON');
				}
				const name = String(body?.name || '').trim();
				const rawStamp = String(body?.stamp || '');
				const explicitDateOnly = typeof body?.date_only !== 'undefined' ? !!body.date_only : undefined;

				if (!name || name.length > 200) return badRequest('INVALID_NAME');
				let norm;
				try {
					norm = normalizeStampAndDateOnly(rawStamp, explicitDateOnly);
				} catch (e) {
					return badRequest(String(e.message || e));
				}

				const item = await createCountdown(env.DB, user.id, name, norm.stamp, norm.date_only);
				return json({ item }, 201);
			}

			// DELETE: bulk delete by ids
			if (request.method === 'DELETE') {
				let body;
				try {
					body = await readJson(request);
				} catch {
					return badRequest('INVALID_JSON');
				}
				const ids = Array.isArray(body?.ids) ? body.ids.map((x) => String(x)) : [];
				if (ids.length === 0) return badRequest('NO_IDS');
				const deleted = await deleteCountdowns(env.DB, user.id, ids);
				return json({ deleted });
			}

			return badRequest('METHOD_NOT_ALLOWED');
		}

		// Default
		return new Response('up', { status: 200 });
	},
};
