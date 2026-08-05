// Settings: sidebar banner, users, API tokens, TLS, backup/restore, health
// and the audit log.

async function page_settings() {
  const [users, tokens, tls, health, version, banner, sync] = await Promise.all([
    API.get('/api/users').catch(() => []),
    API.get('/api/tokens').catch(() => []),
    API.get('/api/tls/info').catch(() => ({present: false})),
    API.get('/api/health').catch(() => ({ok: true, issues: []})),
    API.get('/api/version').catch(() => ({})),
    API.get('/api/settings/banner').catch(() => ({banner: ''})),
    API.get('/api/sync').catch(() => null),
  ]);

  $('page-content').innerHTML = `
    <div class="page-header"><h2>Settings</h2></div>

    <h3>Data health</h3>
    ${health.issues.length ? health.issues.map(i => `
      <div class="alert alert-${i.level === 'error' ? 'danger' : i.level === 'warning' ? 'warning' : 'info'}">
        <strong>${escapeHtml(String(i.count))}</strong> ${escapeHtml(i.message)}
        ${i.examples && i.examples.length ? `<br><span class="muted">${escapeHtml(i.examples.join(', '))}</span>` : ''}
      </div>`).join('')
      : '<div class="health-ok">No consistency problems found.</div>'}

    ${sync ? `
    <h3 style="margin-top:24px">External sources</h3>
    <p class="help">What each importer owns (derived live from the records' <code>source</code> field)
      and when its last run finished. Importers report here after every run; the cron wrapper
      reports failures too, so a silently broken sync shows up as a red row.</p>
    ${dataTable([
      {label: 'Source', get: ([s]) => `<code>${escapeHtml(s)}</code>`},
      {label: 'Records', get: ([, v]) => String(v.total)},
      {label: 'Breakdown', get: ([, v]) => escapeHtml(Object.entries(v.tables).map(([t, n]) => `${t}: ${n}`).join(' · '))},
      {label: 'Last change', get: ([, v]) => v.latest ? fmtTs(v.latest) : '—'},
    ], Object.entries(sync.sources || {}), 'No externally sourced records')}
    ${(sync.runs || []).length ? `
    <h4 style="margin-top:14px">Recent importer runs</h4>
    ${dataTable([
      {label: 'When', get: r => fmtTs(r.ts)},
      {label: 'Source', get: r => `<code>${escapeHtml(r.source)}</code>`},
      {label: '', get: r => r.ok ? '<span class="status-badge green">ok</span>' : '<span class="status-badge red">FAILED</span>'},
      {label: 'Detail', get: r => escapeHtml(r.detail || '')},
    ], sync.runs.slice(0, 10), '')}` : ''}` : ''}

    <h3 style="margin-top:24px">Sidebar banner</h3>
    <p class="help">Shown in the top-left corner in place of the host name.
      Leave empty to show this host's FQDN (${escapeHtml(version.fqdn || '')}).</p>
    <form class="filters" onsubmit="saveBanner(event)">
      <div class="form-group grow"><input id="banner-text" class="form-control" maxlength="64"
        placeholder="e.g. Homelab HQ — production"></div>
      <button class="btn btn-sm" type="submit">Save</button>
    </form>

    <h3 style="margin-top:24px">Users</h3>
    <div class="toolbar"><button class="btn btn-sm" onclick="userModal()">+ Add user</button></div>
    ${dataTable([
      {label: 'Username', get: u => escapeHtml(u.username)},
      {label: 'Role', get: u => `<span class="status-badge ${u.role === 'admin' ? 'green' : 'gray'}">${escapeHtml(u.role)}</span>`},
      {label: '', cls: 'row-actions', get: u => `
        <button class="btn btn-sm btn-outline" onclick="setUserPassword('${jsArg(u.username)}')">Password</button>
        <button class="btn btn-sm btn-outline" onclick="setUserRole('${jsArg(u.username)}','${u.role === 'admin' ? 'readonly' : 'admin'}')">Make ${u.role === 'admin' ? 'read-only' : 'admin'}</button>
        <button class="btn btn-sm btn-danger" onclick="deleteUser('${jsArg(u.username)}')">Delete</button>`},
    ], users, 'No users')}

    <h3 style="margin-top:24px">API tokens</h3>
    <p class="help">Bearer tokens for automation. A <strong>read-only</strong> token can query everything
      but change nothing — that is the read-only API. An <strong>admin</strong> token can also create
      records and allocate addresses, which is what a deployment tool needs.
      Send it as <code>Authorization: Bearer &lt;token&gt;</code> or <code>X-API-Token</code>.</p>
    <div class="toolbar"><button class="btn btn-sm" onclick="tokenModal()">+ Create token</button></div>
    ${dataTable([
      {label: 'Name', get: t => escapeHtml(t.name)},
      {label: 'Role', get: t => `<span class="status-badge ${t.role === 'admin' ? 'green' : 'gray'}">${escapeHtml(t.role)}</span>`},
      {label: 'Created', get: t => escapeHtml(t.created || '')},
      {label: 'Last used', get: t => escapeHtml(t.last_used || 'never')},
      {label: '', cls: 'row-actions', get: t =>
        `<button class="btn btn-sm btn-danger" onclick="deleteToken('${jsArg(t.id)}','${jsArg(t.name)}')">Revoke</button>`},
    ], tokens, 'No API tokens')}

    <h3 style="margin-top:24px">Backup &amp; restore</h3>
    <p class="help">The whole database is a single SQLite file, so a JSON dump here and a copy of
      <code>ipam.db</code> are equivalent backups. Restore merges by default — existing records win —
      or replaces everything.</p>
    <div class="toolbar">
      <a class="btn btn-sm btn-outline" href="/api/export/json" target="_blank">Download JSON backup</a>
      <a class="btn btn-sm btn-outline" href="/api/export/csv" target="_blank">Download CSV</a>
      <button class="btn btn-sm btn-outline" onclick="restoreModal()">Restore from JSON</button>
    </div>

    <h3 style="margin-top:24px">TLS certificate</h3>
    ${tls.present ? `
      <dl class="detail-grid">
        <div><dt>Subject</dt><dd>${escapeHtml(tls.subject || '—')}</dd></div>
        <div><dt>Issuer</dt><dd>${escapeHtml(tls.issuer || '—')}</dd></div>
        <div><dt>Expires</dt><dd>${escapeHtml(tls.expires || '—')}</dd></div>
        <div><dt>Type</dt><dd>${tls.self_signed ? 'self-signed' : 'CA-issued'}</dd></div>
      </dl>` : '<div class="alert alert-info">No certificate on disk (HTTPS is disabled).</div>'}
    <div class="toolbar">
      <button class="btn btn-sm btn-outline" onclick="regenerateCert()">Regenerate self-signed</button>
      <button class="btn btn-sm btn-outline" onclick="uploadCertModal()">Upload certificate</button>
    </div>

    <h3 style="margin-top:24px">Audit log</h3>
    <div id="audit-info" class="help">Loading…</div>
    <div class="toolbar">
      <button class="btn btn-sm btn-outline" onclick="showAudit()">View recent changes</button>
      <button class="btn btn-sm btn-outline" onclick="pruneAuditModal()">Prune…</button>
    </div>

    <p class="help" style="margin-top:24px">Nexus IPAM ${escapeHtml(version.version || '')}
      ${version.fqdn ? '&middot; ' + escapeHtml(version.fqdn) : ''}</p>`;

  // Set via .value, not the HTML attribute — the banner is free text.
  $('banner-text').value = banner.banner || '';
  fillAuditInfo();
}

async function saveBanner(e) {
  if (e) e.preventDefault();
  try {
    const r = await API.post('/api/settings/banner', {banner: $('banner-text').value.trim()});
    applyBanner(r.banner);   // take effect immediately, no reload needed
  } catch (err) { alert(err.message); }
}

// ─── Users ────────────────────────────────────────────────

function userModal() {
  openModal('Add user', `
    <div class="form-group"><label>Username</label><input id="u-name" class="form-control"></div>
    <div class="form-group"><label>Password</label><input id="u-pass" type="password" class="form-control" autocomplete="new-password"></div>
    <div class="form-group"><label>Role</label>
      <select id="u-role" class="form-control">
        <option value="readonly">Read-only — can view everything, change nothing</option>
        <option value="admin">Administrator</option>
      </select></div>
    <p class="help">Passwords must be at least 8 characters.</p>
    <button class="btn" onclick="createUser()">Add user</button>`);
}

async function createUser() {
  try {
    await API.post('/api/users', {username: $('u-name').value.trim(),
                                  password: $('u-pass').value, role: $('u-role').value});
    closeModal();
    page_settings();
  } catch (e) { alert(e.message); }
}

function setUserPassword(username) {
  openModal('Set password for ' + username, `
    <div class="form-group"><label>New password</label><input id="up-pass" type="password" class="form-control" autocomplete="new-password"></div>
    <button class="btn" onclick="doSetUserPassword('${jsArg(username)}')">Set password</button>`);
}

async function doSetUserPassword(username) {
  try {
    await API.post(`/api/users/${encodeURIComponent(username)}/password`, {password: $('up-pass').value});
    closeModal();
    alert('Password updated.');
  } catch (e) { alert(e.message); }
}

async function setUserRole(username, role) {
  try {
    await API.post(`/api/users/${encodeURIComponent(username)}/role`, {role});
    page_settings();
  } catch (e) { alert(e.message); }
}

async function deleteUser(username) {
  if (!confirm(`Delete user "${username}"?`)) return;
  try {
    await API.delete('/api/users/' + encodeURIComponent(username));
    page_settings();
  } catch (e) { alert(e.message); }
}

// ─── Tokens ───────────────────────────────────────────────

function tokenModal() {
  openModal('Create API token', `
    <div class="form-group"><label>Name</label><input id="t-name" class="form-control" placeholder="vc-deployer"></div>
    <div class="form-group"><label>Role</label>
      <select id="t-role" class="form-control">
        <option value="readonly">Read-only — queries only</option>
        <option value="admin">Admin — can create records and allocate addresses</option>
      </select></div>
    <button class="btn" onclick="createToken()">Create</button>`);
}

async function createToken() {
  try {
    const r = await API.post('/api/tokens', {name: $('t-name').value.trim(), role: $('t-role').value});
    // Shown exactly once — only its SHA-256 is stored.
    openModal('Token created', `
      <div class="alert alert-warning">Copy this now — it is shown once and cannot be retrieved again.</div>
      <div class="raw-output">${escapeHtml(r.token)}</div>
      <p class="help" style="margin-top:12px">Example:</p>
      <div class="raw-output">curl -sk -H "Authorization: Bearer ${escapeHtml(r.token)}" \\
  https://${escapeHtml(location.host)}/api/next-free?cidr=10.0.0.0/24</div>
      <button class="btn" style="margin-top:12px" onclick="closeModal();page_settings()">Done</button>`, {wide: true});
  } catch (e) { alert(e.message); }
}

async function deleteToken(id, name) {
  if (!confirm(`Revoke token "${name}"? Anything using it stops working immediately.`)) return;
  try {
    await API.delete('/api/tokens/' + encodeURIComponent(id));
    page_settings();
  } catch (e) { alert(e.message); }
}

// ─── Backup / restore ─────────────────────────────────────

function restoreModal() {
  openModal('Restore from JSON', `
    <div class="alert alert-warning">Replace mode deletes every existing record first. Take a backup before you use it.</div>
    <div class="form-group"><label>Backup file</label>
      <input id="rs-file" type="file" class="form-control" accept="application/json,.json"></div>
    <div class="form-group"><label>Mode</label>
      <select id="rs-mode" class="form-control">
        <option value="merge">Merge — add records that are missing, keep existing ones</option>
        <option value="replace">Replace — wipe everything, then restore</option>
      </select></div>
    <button class="btn" onclick="doRestore()">Restore</button>`);
}

async function doRestore() {
  const file = $('rs-file').files[0];
  if (!file) { alert('Choose a backup file'); return; }
  const mode = $('rs-mode').value;
  if (mode === 'replace' && !confirm('This deletes every existing record. Continue?')) return;
  let data;
  try { data = JSON.parse(await file.text()); }
  catch (e) { alert('That file is not valid JSON'); return; }
  try {
    const r = await API.post('/api/import/json?mode=' + mode, data);
    closeModal();
    alert('Restored: ' + Object.entries(r.imported).map(([k, v]) => `${k} ${v}`).join(', '));
    page_settings();
  } catch (e) { alert(e.message); }
}

// ─── TLS ──────────────────────────────────────────────────

async function regenerateCert() {
  if (!confirm('Generate a new self-signed certificate? It takes effect after a restart.')) return;
  try {
    await API.post('/api/tls/regenerate', {});
    alert('New certificate generated — restart Nexus IPAM to use it.');
    page_settings();
  } catch (e) { alert(e.message); }
}

function uploadCertModal() {
  openModal('Upload certificate', `
    <p class="help">Both are validated with openssl and checked to be a matching pair before
      anything on disk is replaced. Takes effect after a restart.</p>
    <div class="form-group"><label>Certificate (PEM)</label>
      <textarea id="tc-cert" class="form-control" rows="8" placeholder="-----BEGIN CERTIFICATE-----"></textarea></div>
    <div class="form-group"><label>Private key (PEM)</label>
      <textarea id="tc-key" class="form-control" rows="8" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></div>
    <button class="btn" onclick="doUploadCert()">Upload</button>`);
}

async function doUploadCert() {
  try {
    await API.post('/api/tls/cert', {cert: $('tc-cert').value, key: $('tc-key').value});
    closeModal();
    alert('Certificate installed — restart Nexus IPAM to use it.');
    page_settings();
  } catch (e) { alert(e.message); }
}

// ─── Audit ────────────────────────────────────────────────

// Populated after the page renders; failures leave the static text.
async function fillAuditInfo() {
  const el = $('audit-info');
  if (!el) return;
  try {
    const a = await API.get('/api/audit?limit=1');
    el.innerHTML = `${fmtNum(a.total)} entr${a.total === 1 ? 'y' : 'ies'}` +
      (a.oldest ? `, oldest ${escapeHtml(fmtTs(a.oldest))}` : '') +
      (a.retention_days > 0
        ? ` &middot; auto-pruned after ${a.retention_days} days`
        : ' &middot; <strong>automatic pruning disabled</strong> (NEXUSIPAM_AUDIT_DAYS=0)');
  } catch (e) { el.textContent = ''; }
}

function pruneAuditModal() {
  openModal('Prune audit log', `
    <p class="help">Entries older than the retention window are removed automatically by the
      daily maintenance task. This is the manual version — for clearing more, sooner.</p>
    <div class="form-group"><label>Keep the last</label>
      <select id="pa-days" class="form-control">
        <option value="365">1 year</option>
        <option value="180">6 months</option>
        <option value="90">90 days</option>
        <option value="30">30 days</option>
        <option value="all">Nothing — empty the log</option>
      </select></div>
    <p class="help">The prune itself is recorded, so an emptied log still says why it is empty.</p>
    <button class="btn btn-danger" onclick="doPruneAudit()">Prune</button>`);
}

async function doPruneAudit() {
  const v = $('pa-days').value;
  const body = v === 'all' ? {all: true} : {days: Number(v)};
  if (v === 'all' && !confirm('Delete every audit entry?')) return;
  try {
    const r = await API.post('/api/audit/prune', body);
    closeModal();
    alert(`Removed ${fmtNum(r.deleted)} entr${r.deleted === 1 ? 'y' : 'ies'}; ${fmtNum(r.total)} remain.`);
    fillAuditInfo();
  } catch (e) { alert(e.message); }
}

async function showAudit() {
  const d = await API.get('/api/audit?limit=300');
  openModal('Audit log', dataTable([
    {label: 'When', get: a => escapeHtml(fmtTs(a.ts))},
    {label: 'Who', get: a => escapeHtml(a.actor)},
    {label: 'Action', get: a => typeBadge(a.action)},
    {label: 'Object', get: a => escapeHtml(a.object_kind)},
    {label: 'Detail', get: a => escapeHtml(a.detail)},
  ], d.audit, 'Nothing recorded yet'), {wide: true});
}
