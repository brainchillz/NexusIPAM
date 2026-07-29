// Shared plumbing: API client, navigation, modal, formatting helpers.
// Ported from DNSMAQ-MGR core.js so both apps behave identically; the IPAM
// additions are the sub-page router (a page can carry an argument, e.g. one
// network's detail view) and the shared form/table builders.

function onUnauthorized() { showLogin(); throw new Error('Session expired — please sign in'); }

const API = {
  async get(path) {
    const r = await fetch(path);
    if (r.status === 401) onUnauthorized();
    if (!r.ok) {
      let j = null; try { j = await r.json(); } catch (e) {}
      throw new Error((j && j.error) || ('HTTP ' + r.status));
    }
    return r.json();
  },
  async post(path, data) {
    const r = await fetch(path, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(data)
    });
    if (r.status === 401) onUnauthorized();
    const j = await r.json();
    if (!r.ok && !j.success) {
      const e = new Error(j.error || JSON.stringify(j));
      e.body = j;
      throw e;
    }
    return j;
  },
  async delete(path) {
    const r = await fetch(path, { method: 'DELETE' });
    if (r.status === 401) onUnauthorized();
    const j = await r.json();
    if (!j.success) throw new Error(j.error || 'Command failed');
    return j;
  }
};

function $(id) { return document.getElementById(id); }
function escapeHtml(s) { const d = document.createElement('div'); d.textContent = (s == null ? '' : s); return d.innerHTML; }
// Escape a value for safe use as a single-quoted JS string inside a
// double-quoted HTML attribute (e.g. onclick="fn('VALUE')").
function jsArg(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;')
    .replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

let isAuthed = false;
let currentUser = '';
let currentRole = 'admin';
let currentFqdn = '';

// Sidebar title: the operator-set banner wins; otherwise the host FQDN.
function applyBanner(banner) {
  $('sidebar-title').textContent = banner || currentFqdn || 'Nexus IPAM';
}
let currentPage = 'overview';
let currentArg = null;

function canWrite() { return currentRole === 'admin'; }

// ─── Modal ──────────────────────────────────────────────
function openModal(title, html, opts) {
  $('modal-title').textContent = title;
  $('modal-body').innerHTML = html;
  $('modal-content').classList.toggle('wide', !!(opts && opts.wide));
  $('modal-overlay').style.display = 'flex';
  const first = $('modal-body').querySelector('input,select,textarea');
  if (first) first.focus();
}
let modalLocked = false;  // forced modals (first-run password change) can't be dismissed
function closeModal() {
  if (modalLocked) return;
  $('modal-overlay').style.display = 'none';
}
$('modal-overlay').addEventListener('click', e => { if (e.target === $('modal-overlay')) closeModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

// ─── Navigation ─────────────────────────────────────────
// A page may take one argument (an object id), so "networks" and
// "networks/7" are the same handler with different state. Keeping it in one
// router means the breadcrumb links are plain showPage() calls.
function showPage(id, arg) {
  currentPage = id;
  currentArg = arg == null ? null : arg;
  document.querySelectorAll('.nav-list a').forEach(a => a.classList.toggle('active', a.dataset.page === id));
  renderPage(id, currentArg);
}
function reloadPage() { renderPage(currentPage, currentArg); }

document.querySelectorAll('.nav-list a').forEach(a => {
  a.addEventListener('click', e => { e.preventDefault(); showPage(a.dataset.page); });
});

function toggleNavGroup(el) {
  const group = el.closest('.nav-group');
  group.classList.toggle('collapsed');
  try {
    const collapsed = JSON.parse(localStorage.getItem('navCollapsed') || '[]');
    const key = group.dataset.group;
    const next = group.classList.contains('collapsed')
      ? [...new Set([...collapsed, key])] : collapsed.filter(k => k !== key);
    localStorage.setItem('navCollapsed', JSON.stringify(next));
  } catch (e) {}
}
function restoreNavGroups() {
  try {
    const collapsed = JSON.parse(localStorage.getItem('navCollapsed') || '[]');
    document.querySelectorAll('.nav-group').forEach(g => {
      if (collapsed.includes(g.dataset.group)) g.classList.add('collapsed');
    });
  } catch (e) {}
}

async function renderPage(page, arg) {
  $('page-content').innerHTML = '<div class="loading">Loading...</div>';
  const content = document.querySelector('.content');
  if (content) content.scrollTop = 0;
  window.scrollTo(0, 0);
  try {
    if (typeof window['page_' + page] === 'function') await window['page_' + page](arg);
    else $('page-content').innerHTML = '<h2>Page not found</h2>';
  } catch (e) {
    $('page-content').innerHTML = `<div class="error">Error: ${escapeHtml(e.message)}</div>`;
  }
}

// ─── Theme (light / dark) ───────────────────────────────
function applyThemeLabel() {
  const light = document.documentElement.classList.contains('theme-light');
  const el = $('theme-label');
  if (el) el.textContent = light ? 'Dark theme' : 'Light theme';
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', light ? '#ffffff' : '#1c1e22');
}
function toggleTheme(e) {
  if (e) e.preventDefault();
  const light = document.documentElement.classList.toggle('theme-light');
  try { localStorage.setItem('theme', light ? 'light' : 'dark'); } catch (err) {}
  applyThemeLabel();
}

// ─── Formatting helpers ─────────────────────────────────
function fmtTs(sec) {
  if (!sec) return '-';
  try { return new Date(sec * 1000).toLocaleString(); } catch (e) { return '-'; }
}

function fmtAgo(sec) {
  if (!sec) return 'never';
  const d = Math.max(0, Math.floor(Date.now() / 1000) - sec);
  if (d < 60) return d + 's ago';
  if (d < 3600) return Math.floor(d / 60) + 'm ago';
  if (d < 86400) return Math.floor(d / 3600) + 'h ago';
  return Math.floor(d / 86400) + 'd ago';
}

function fmtNum(n) {
  if (n == null) return '-';
  return Number(n).toLocaleString();
}

// Colour shifts green -> yellow -> red as a network fills.
function usageBar(pct, small) {
  pct = Math.max(0, Math.min(100, Math.round(pct || 0)));
  const cls = pct >= 90 ? 'red' : pct >= 70 ? 'yellow' : 'green';
  return `<div class="usage-bar${small ? ' sm' : ''}"><div class="usage-bar-fill ${cls}" style="width:${pct}%"></div><span class="usage-bar-label">${pct}%</span></div>`;
}

function statusBadge(status) {
  const map = {active: 'green', reserved: 'yellow', dhcp: 'gray', deprecated: 'gray',
               planned: 'yellow', staged: 'yellow', offline: 'red', decommissioned: 'gray'};
  return `<span class="status-badge ${map[status] || 'gray'}">${escapeHtml(status || '-')}</span>`;
}

// Inline stroke icon from the symbol set in index.html. currentColor means
// it inherits whatever text colour surrounds it.
function icon(name) {
  return `<svg class="ico" aria-hidden="true"><use href="#i-${name}"/></svg>`;
}

function typeBadge(text) {
  return text ? `<span class="badge-type">${escapeHtml(text)}</span>` : '';
}

// Link to an inventory object's detail page.
function objLink(kind, id, name) {
  if (!kind || !id) return '<span class="muted">—</span>';
  return `<a onclick="showPage('${jsArg(kind)}s', ${Number(id)})">${escapeHtml(name || kind + ' ' + id)}</a>`;
}

function breadcrumb(parts) {
  return '<div class="crumb">' + parts.map((p, i) =>
    (i ? '<span class="sep">/</span>' : '') +
    (p.page ? `<a onclick="showPage('${jsArg(p.page)}'${p.arg != null ? ', ' + Number(p.arg) : ''})">${escapeHtml(p.label)}</a>`
            : escapeHtml(p.label))).join('') + '</div>';
}

// ─── Form builders ──────────────────────────────────────
// Modals are built from a field spec rather than hand-written HTML: every
// resource form then looks the same, and readFields() below returns the body
// to POST without each page repeating a list of $('...').value lookups.

function field(f, value) {
  const id = 'f-' + f.name;
  const v = value == null ? (f.def == null ? '' : f.def) : value;
  const help = f.help ? `<p class="help">${escapeHtml(f.help)}</p>` : '';
  if (f.type === 'select') {
    const opts = (f.options || []).map(o => {
      const [ov, ol] = Array.isArray(o) ? o : [o, o];
      return `<option value="${escapeHtml(ov)}" ${String(v) === String(ov) ? 'selected' : ''}>${escapeHtml(ol)}</option>`;
    }).join('');
    return `<div class="form-group"><label>${escapeHtml(f.label)}</label>
      <select id="${id}" class="form-control">${opts}</select>${help}</div>`;
  }
  if (f.type === 'checkbox') {
    return `<label class="checkitem" style="padding-left:0"><input id="${id}" type="checkbox" ${v ? 'checked' : ''}> ${escapeHtml(f.label)}</label>${help}`;
  }
  if (f.type === 'textarea') {
    return `<div class="form-group"><label>${escapeHtml(f.label)}</label>
      <textarea id="${id}" class="form-control" rows="${f.rows || 4}" placeholder="${escapeHtml(f.placeholder || '')}">${escapeHtml(v)}</textarea>${help}</div>`;
  }
  return `<div class="form-group"><label>${escapeHtml(f.label)}</label>
    <input id="${id}" class="form-control" type="${f.type || 'text'}" value="${escapeHtml(v)}" placeholder="${escapeHtml(f.placeholder || '')}">${help}</div>`;
}

function buildForm(fields, record) {
  return fields.map(f => field(f, record ? record[f.name] : undefined)).join('');
}

function readFields(fields) {
  const out = {};
  fields.forEach(f => {
    const el = $('f-' + f.name);
    if (!el) return;
    if (f.type === 'checkbox') out[f.name] = el.checked;
    else if (f.type === 'number') out[f.name] = el.value.trim() === '' ? null : Number(el.value);
    else out[f.name] = el.value.trim();
  });
  return out;
}

// One save path for every resource modal: POST to the collection (create) or
// to the record (update), then re-render whatever page is open.
async function saveResource(path, id, fields, after) {
  const body = readFields(fields);
  try {
    await API.post(path + (id ? '/' + encodeURIComponent(id) : ''), body);
    closeModal();
    if (after) await after(); else reloadPage();
  } catch (e) { alert(e.message); }
}

async function deleteResource(path, id, label, after) {
  if (!confirm(`Delete "${label}"?`)) return;
  try {
    await API.delete(path + '/' + encodeURIComponent(id));
    if (after) await after(); else reloadPage();
  } catch (e) { alert(e.message); }
}

// ─── Option loaders (shared by several forms) ───────────
let _hostCache = null;
async function hostOptions(includeBlank) {
  if (!_hostCache) _hostCache = (await API.get('/api/hosts')).hosts;
  const opts = includeBlank ? [['', '— none —']] : [];
  return opts.concat(_hostCache.map(h => [`${h.kind}:${h.id}`, `${h.name} (${h.kind})`]));
}
function invalidateHostCache() { _hostCache = null; }

async function selectOptions(url, key, labelFn, includeBlank) {
  const data = await API.get(url);
  const opts = includeBlank === false ? [] : [['', '— none —']];
  return opts.concat((data[key] || []).map(r => [r.id, labelFn(r)]));
}

// ─── Table helper ───────────────────────────────────────
// Renders a <table class="table"> from column specs. `cols` entries are
// {label, get(row) -> html, cls}. Keeps every listing page consistent and
// removes the repeated `.map(r => '<tr>...').join('')` boilerplate.
function dataTable(cols, rows, emptyMessage) {
  const head = cols.map(c => `<th class="${c.cls || ''}">${escapeHtml(c.label)}</th>`).join('');
  if (!rows.length) {
    return `<table class="table"><thead><tr>${head}</tr></thead><tbody>
      <tr><td colspan="${cols.length}">${escapeHtml(emptyMessage || 'Nothing here yet')}</td></tr></tbody></table>`;
  }
  const body = rows.map(r => '<tr>' + cols.map(c =>
    `<td class="${c.cls || ''}">${c.get(r)}</td>`).join('') + '</tr>').join('');
  return `<table class="table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

// ─── Global search ──────────────────────────────────────
async function globalSearch(e) {
  if (e) e.preventDefault();
  const q = $('global-q').value.trim();
  if (!q) return;
  let r;
  try { r = await API.get('/api/search?q=' + encodeURIComponent(q)); }
  catch (err) { alert(err.message); return; }

  // An unambiguous hit skips the results list entirely.
  if (r.exact && r.exact.kind === 'network') { closeModal(); showPage('networks', r.exact.id); return; }
  if (r.exact && r.exact.kind === 'free-address') { closeModal(); showPage('networks', r.exact.id); return; }

  const hits = [];
  r.networks.forEach(n => hits.push({kind: 'network', label: `${n.cidr} ${n.name || ''}`, page: 'networks', arg: n.id}));
  r.addresses.forEach(a => hits.push({kind: 'address', label: `${a.address} ${a.dns_name || ''}`, page: 'addresses', arg: a.id}));
  r.objects.forEach(o => hits.push({kind: o.kind, label: o.name, page: o.kind + 's', arg: o.id}));

  openModal('Search: ' + q, hits.length ? hits.map(h =>
    `<div class="search-hit" onclick="closeModal();showPage('${jsArg(h.page)}', ${Number(h.arg)})">
       <span class="kind">${escapeHtml(h.kind)}</span>${escapeHtml(h.label)}</div>`).join('')
    : '<p class="help">No matches.</p>');
}

function searchBar() {
  return `<form class="filters" onsubmit="globalSearch(event)" style="margin-bottom:18px">
    <div class="form-group grow"><input id="global-q" class="form-control"
      placeholder="Search an IP, CIDR, hostname, device, VM…"></div>
    <button class="btn" type="submit">Search</button></form>`;
}

// ─── Authentication ─────────────────────────────────────
function showLogin() {
  isAuthed = false;
  document.querySelector('.sidebar').style.display = 'none';
  document.querySelector('.content').style.display = 'none';
  modalLocked = false;
  closeModal();
  $('login-screen').style.display = 'flex';
  $('login-pass').value = '';
  $('login-user').focus();
}

async function showApp(user, fqdn, role, mustChange, banner) {
  isAuthed = true;
  currentRole = role || 'admin';
  $('login-screen').style.display = 'none';
  document.querySelector('.sidebar').style.display = '';
  document.querySelector('.content').style.display = '';
  document.body.classList.toggle('readonly', currentRole !== 'admin');
  currentUser = user || '';
  currentFqdn = fqdn || '';
  applyBanner(banner);
  $('account-user').textContent = user ? `Signed in as ${user}${currentRole !== 'admin' ? ' · read-only' : ''}` : '';
  restoreNavGroups();
  showPage('overview');
  if (mustChange) forcePasswordChange();
}

// First-run: force the bootstrap admin to set a real password before anything else.
function forcePasswordChange() {
  modalLocked = true;
  openModal('Set a new password to continue', `
    <div class="alert alert-warning">This account is still using its initial setup password. Choose a new one to continue.</div>
    <div class="form-group"><label>Current password</label><input id="cp-old" type="password" class="form-control" autocomplete="current-password"></div>
    <div class="form-group"><label>New password</label><input id="cp-new" type="password" class="form-control" autocomplete="new-password"></div>
    <div class="form-group"><label>Confirm new password</label><input id="cp-confirm" type="password" class="form-control" autocomplete="new-password"></div>
    <p class="help">Must be at least 8 characters.</p>
    <button class="btn" onclick="doChangePassword(true)">Set Password</button>`);
}

async function doLogin(e) {
  e.preventDefault();
  const errEl = $('login-error');
  errEl.style.display = 'none';
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ username: $('login-user').value.trim(), password: $('login-pass').value })
    });
    const j = await r.json();
    if (!r.ok || !j.success) {
      errEl.textContent = j.error || 'Login failed';
      errEl.style.display = 'block';
      return;
    }
    showApp(j.user, j.fqdn, j.role, j.must_change, j.banner);
  } catch (err) {
    errEl.textContent = 'Login failed';
    errEl.style.display = 'block';
  }
}

async function doLogout(e) {
  if (e) e.preventDefault();
  try { await fetch('/api/logout', { method: 'POST' }); } catch (err) {}
  showLogin();
}

function changePassword(e) {
  if (e) e.preventDefault();
  openModal('Change Password', `
    <div class="form-group"><label>Current password</label><input id="cp-old" type="password" class="form-control" autocomplete="current-password"></div>
    <div class="form-group"><label>New password</label><input id="cp-new" type="password" class="form-control" autocomplete="new-password"></div>
    <div class="form-group"><label>Confirm new password</label><input id="cp-confirm" type="password" class="form-control" autocomplete="new-password"></div>
    <p class="help">Must be at least 8 characters.</p>
    <button class="btn" onclick="doChangePassword()">Update Password</button>`);
}

async function doChangePassword(forced) {
  const oldp = $('cp-old').value, newp = $('cp-new').value, confirmp = $('cp-confirm').value;
  if (newp !== confirmp) { alert('New passwords do not match'); return; }
  try {
    await API.post('/api/account/password', { old_password: oldp, new_password: newp });
    modalLocked = false;
    closeModal();
    alert('Password updated.');
    if (forced) showPage('overview');
  } catch (err) { alert(err.message); }
}

async function checkAuth() {
  try {
    const r = await fetch('/api/me');
    if (!r.ok) { showLogin(); return; }
    const j = await r.json();
    showApp(j.user, j.fqdn, j.role, j.must_change, j.banner);
  } catch (err) { showLogin(); }
}

applyThemeLabel();
checkAuth();
