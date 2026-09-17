// Settings: sidebar banner, users, API tokens, TLS, backup/restore, health
// and the audit log.
// Appearance (the light/dark switch) is client-side and shown to every role;
// the server-configuration sections stay admin-only.
function appearanceSection() {
  const light = document.documentElement.classList.contains('theme-light');
  return `
    <h3 style="margin-top:24px">Appearance</h3>
    <label class="checkitem" style="max-width:280px">
      <input type="checkbox" ${light ? 'checked' : ''}
             onchange="toggleTheme(); page_settings();"> Light theme
    </label>
    <p class="help">Stored in this browser only — each browser keeps its own choice.</p>`;
}

async function page_settings() {
  if (currentRole !== 'admin') {
    $('page-content').innerHTML = '<h2>Settings</h2>' + appearanceSection() +
      '<div class="alert alert-warning" style="margin-top:16px">Server settings require administrator access.</div>';
    return;
  }
  const [users, tokens, tls, health, version, banner, sync, push] = await Promise.all([
    API.get('/api/users').catch(() => []),
    API.get('/api/tokens').catch(() => []),
    API.get('/api/tls/info').catch(() => ({present: false})),
    API.get('/api/health').catch(() => ({ok: true, issues: []})),
    API.get('/api/version').catch(() => ({})),
    API.get('/api/settings/banner').catch(() => ({banner: ''})),
    API.get('/api/sync').catch(() => null),
    API.get('/api/push').catch(() => null),
  ]);
  // The target modals are opened from onclicks and have no access to the
  // response, so stash what they need. Sections come from the server rather
  // than a hardcoded list: a section exists once something can render it.
  pushSections = (push && push.sections) || ['hosts'];
  pushTargets = (push && push.targets) || [];

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

    ${push ? `
    <h3 style="margin-top:24px">Push targets</h3>
    <p class="help">Pushes the address plan to its enforcement points, one section at a time:
      <code>hosts</code> (DNS records) and <code>dhcp</code> (scopes, options, reservations).
      DNSMAQ-MGR nodes receive a mirror payload and lock the pushed section read-only; a UniFi
      gateway is reconciled object by object. Every target is pushed independently, so none goes
      stale because another is down. Each section carries its own serial:
      ${pushSectionSummary(push)}.</p>
    <div class="toolbar">
      <button class="btn btn-sm" onclick="pushTargetModal()">+ Add target</button>
      ${(push.targets || []).length ? `<button class="btn btn-sm" onclick="pushRunNow(this)">Push now</button>` : ''}
      ${(push.sections || []).map(s => `<a class="btn btn-sm btn-outline"
        href="/api/push/preview?sections=${encodeURIComponent(s)}" target="_blank">Preview ${escapeHtml(s)}</a>`).join('')}
    </div>
    ${dataTable([
      {label: 'Target', get: t => `<strong>${escapeHtml(t.name)}</strong><br><span class="muted">${escapeHtml(t.url || '')}</span>`},
      {label: 'Type', get: t => {
        if (t.kind === 'unifi') {
          return `<span class="status-badge">UniFi gateway</span><br><span class="muted">${t.unifi_delete_extra ? 'authoritative' : 'additive'}</span>`;
        }
        if (t.kind === 'pihole') {
          return `<span class="status-badge">Pi-hole</span><br><span class="muted">${t.pihole_delete_extra ? 'authoritative' : 'additive'}</span>`;
        }
        if (t.kind === 'technitium') {
          return `<span class="status-badge">Technitium</span><br><span class="muted">${escapeHtml(t.technitium_zones || '')}</span>`;
        }
        return '<span class="status-badge">DNSMAQ-MGR</span>';
      }},
      {label: 'Sections held', get: t => sectionBadges(t, push)},
      {label: 'Enabled', get: t => t.enabled ? '<span class="status-badge green">yes</span>' : '<span class="status-badge gray">no</span>'},
      {label: 'Last push', get: t => t.last
        ? `${t.last.ok ? '<span class="status-badge green">ok</span>' : '<span class="status-badge red">FAILED</span>'}
           <span class="muted">${fmtTs(t.last.ts)} · ${escapeHtml(lastSerials(t.last))} · ${escapeHtml(t.last.detail || '')}</span>`
        : '<span class="muted">never</span>'},
      {label: 'Drift', get: driftCell},
      {label: '', cls: 'row-actions', get: t => `
        <button class="btn btn-sm btn-outline" onclick="pushRunNow(this,'${jsArg(t.name)}')">Push</button>
        <button class="btn btn-sm btn-outline" onclick="pushTargetModal('${jsArg(t.name)}')">Edit</button>
        ${t.kind !== 'dnsmaq' || t.has_read_token ? `<button class="btn btn-sm btn-outline"
          title="${t.kind !== 'dnsmaq' ? 'Read this server back and diff it against the plan — read-only' : 'Read the node\'s mirror status back: still locked to this IPAM, still at the serial we sent?'}"
          onclick="driftCheck('${jsArg(t.name)}', this)">Drift</button>` : ''}
        ${t.kind === 'unifi' || (t.kind === 'dnsmaq' && t.has_read_token) ? `<button class="btn btn-sm btn-outline"
          title="Read this server's networks, DHCP scopes, options and reservations into the plan"
          onclick="pullTargetModal('${jsArg(t.name)}')">Adopt…</button>` : ''}
        <button class="btn btn-sm btn-danger" onclick="pushTargetDelete('${jsArg(t.name)}','${jsArg(t.kind || 'dnsmaq')}')">Remove</button>`},
    ], push.targets || [], 'No push targets — this IPAM is not yet writing DNS anywhere')}` : ''}

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

    ${appearanceSection()}

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

// ─── Push targets ───────────────────────────────────────
let pushSections = ['hosts'];
let pushTargets = [];

// Per-section serial summary for the panel header, e.g.
// "hosts: 61 record(s), serial 14 · dhcp: 12 record(s), serial 3".
// Targets stored before per-section serials existed only carry the legacy
// scalar, so it is the fallback everywhere a per-section number is missing.
function pushSectionSummary(push) {
  const serials = push.serials || {};
  return (push.sections || []).map(s => {
    const serial = serials[s] != null ? serials[s] : push.serial;
    const extra = s === 'hosts' ? ` across ${push.address_count} address(es)` : '';
    return `<strong>${escapeHtml(s)}</strong>: ${fmtNum((push.counts || {})[s])} record(s)${extra}, serial ${serial}`;
  }).join(' · ');
}

// One badge per subscribed section: the serial this target holds, coloured by
// whether that is the current one — the at-a-glance answer to "is this target
// current for DHCP?".
function sectionBadges(t, push) {
  const current = push.serials || {};
  const held = t.serials || (t.serial ? {hosts: t.serial} : {});
  const out = (t.sections || []).map(s => {
    const h = held[s];
    if (h == null) {
      return `<span class="status-badge gray" title="This target has never received ${escapeHtml(s)}">${escapeHtml(s)} · never</span>`;
    }
    if (current[s] != null && h < current[s]) {
      return `<span class="status-badge yellow" title="Holds serial ${h}; the current ${escapeHtml(s)} serial is ${current[s]} — push to catch it up">${escapeHtml(s)} · ${h} (behind, now ${current[s]})</span>`;
    }
    return `<span class="status-badge green" title="Holds the current ${escapeHtml(s)} serial">${escapeHtml(s)} · ${h}</span>`;
  });
  return out.join(' ') || '<span class="muted">none</span>';
}

function lastSerials(last) {
  if (last.serials) {
    return Object.entries(last.serials).map(([s, n]) => `${s} ${n}`).join(' · ');
  }
  return 'serial ' + last.serial;
}

// Serials say whether a target ACKED the current content; drift says whether
// it still HOLDS it. A reconciled target (gateway, Pi-hole, Technitium) is
// read back and diffed; a DNSMAQ-MGR node is asked for its mirror status —
// its locks stop edits, but a detach, rollback or restore would not show up
// in the serial column, and that is exactly what this cell catches.
function driftCell(t) {
  const d = t.drift;
  if (!d) {
    return (t.kind || 'dnsmaq') === 'dnsmaq' && !t.has_read_token
      ? '<span class="muted" title="Add the node\'s read-only API token to this target to check its mirror status">no read token</span>'
      : '<span class="muted">unchecked</span>';
  }
  if (!d.ok) {
    return `<span class="status-badge red" title="${escapeHtml(d.error || '')}">check failed</span>
      <span class="muted">${escapeHtml(fmtAgo(d.ts))}</span>`;
  }
  const bad = Object.entries(d.sections || {}).filter(([, v]) => v.drifted);
  if (!bad.length) {
    return `<span class="status-badge green">in sync</span> <span class="muted">${escapeHtml(fmtAgo(d.ts))}</span>`;
  }
  return bad.map(([s, v]) => {
    const n = Object.values(v.counts || {}).reduce((a, b) => a + b, 0);
    return `<span class="status-badge red" title="${escapeHtml((v.examples || []).join(' · '))}">${escapeHtml(s)}: ${n} difference(s)</span>`;
  }).join(' ') + ` <span class="muted">${escapeHtml(fmtAgo(d.ts))}</span>`;
}

async function driftCheck(name, btn) {
  btn.disabled = true; btn.textContent = 'Checking…';
  try {
    const r = await API.post('/api/push/targets/' + encodeURIComponent(name) + '/drift', {});
    const lines = Object.entries(r.drift.sections || {}).map(([s, v]) => v.drifted
      ? `${s}: DRIFTED — ${(v.examples || []).join('; ')}`
      : `${s}: in sync${v.in_step > 1 ? ` (${v.in_step} setting(s) verified unchanged)` : ''}`);
    alert(`${name} read back:\n\n${lines.join('\n')}\n\nRead-only — nothing was written.`);
  } catch (e) { alert(e.message); }
  page_settings();
}

function pushTargetModal(name) {
  const cur = name ? pushTargets.find(t => t.name === name) : null;
  const kind = (cur && cur.kind) || 'dnsmaq';
  const subs = cur ? (cur.sections || []) : ['hosts'];
  openModal(cur ? 'Edit push target' : 'Add push target', `
    <div class="form-group"><label>Type</label>
      <select id="pt-kind" class="form-control" onchange="pushTargetKind()" ${cur ? 'disabled' : ''}>
        <option value="dnsmaq" ${kind === 'dnsmaq' ? 'selected' : ''}>DNSMAQ-MGR node (mirror push)</option>
        <option value="unifi" ${kind === 'unifi' ? 'selected' : ''}>UniFi Cloud Gateway (direct reconcile)</option>
        <option value="pihole" ${kind === 'pihole' ? 'selected' : ''}>Pi-hole (v6 API, direct reconcile)</option>
        <option value="technitium" ${kind === 'technitium' ? 'selected' : ''}>Technitium DNS Server (zones + DHCP scopes)</option>
      </select></div>
    <div class="form-group"><label>Name</label>
      <input id="pt-name" class="form-control" placeholder="ns1" autocomplete="off"
        value="${cur ? escapeHtml(cur.name) : ''}" ${cur ? 'readonly' : ''}></div>
    <div class="form-group"><label>URL</label>
      <input id="pt-url" class="form-control" placeholder="https://dns-node:8443" spellcheck="false"
        value="${cur ? escapeHtml(cur.url || '') : ''}"></div>
    <div class="form-group"><label>Sections to push</label>
      ${pushSections.map(s => `
        <label class="checkitem" style="padding-left:0"><input class="pt-section" type="checkbox"
          value="${escapeHtml(s)}" ${subs.includes(s) ? 'checked' : ''}> ${escapeHtml(s)}</label>`).join('')}
      <p class="help">What this target receives. A target only gets what it subscribes to,
        so a DNS-only node is never handed DHCP.</p></div>
    <div class="form-group"><label>TLS verification</label>
      <input id="pt-verify" class="form-control" placeholder="insecure" spellcheck="false"
        value="${cur ? escapeHtml(cur.verify || 'insecure') : ''}">
      <p class="help"><code>insecure</code>, or <code>fingerprint:&lt;sha256-hex&gt;</code> to pin the
        target's certificate — worth setting on anything that carries credentials, since the push
        then refuses to talk to an impostor.</p></div>

    <div id="pt-dnsmaq">
      <div class="form-group"><label>Mirror token (generate on the node: Mirroring → receive token)</label>
        <input id="pt-token" class="form-control" spellcheck="false"
          placeholder="${cur && cur.has_token ? '(unchanged — leave empty to keep the stored token)' : 'dmm_…'}"></div>
      <p class="help">The node must have "accept mirrored config" enabled. Each pushed section
        becomes read-only there; "Detach" on its Mirroring page hands control back at any time.</p>
      <div class="form-group"><label>Read token (optional — a READ-ONLY API token minted on the node)</label>
        <input id="pt-read" class="form-control" spellcheck="false"
          placeholder="${cur && cur.has_read_token ? '(unchanged — leave empty to keep the stored token)' : 'dm_…'}"></div>
      <p class="help">The mirror token is write-only by design. A read-only token additionally lets
        this IPAM poll the node's DHCP leases into the overlay, and adopt its existing DHCP state.
        Mint it on the node: Settings → API tokens, role read-only.</p>
    </div>

    <div id="pt-unifi" style="display:none">
      <div class="form-group"><label>Gateway username</label>
        <input id="pt-user" class="form-control" placeholder="admin" autocomplete="off"
          value="${cur ? escapeHtml(cur.unifi_username || '') : ''}"></div>
      <div class="form-group"><label>Gateway password</label>
        <input id="pt-pass" class="form-control" type="password" autocomplete="new-password"
          placeholder="${cur && cur.has_password ? '(unchanged — leave empty to keep the stored password)' : ''}"></div>
      <div class="form-group"><label>Site</label>
        <input id="pt-site" class="form-control" spellcheck="false"
          value="${cur ? escapeHtml(cur.unifi_site || 'default') : 'default'}"></div>

      <h4 style="margin-top:12px">hosts section (Static DNS)</h4>
      <label class="checkitem" style="padding-left:0"><input id="pt-delextra" type="checkbox"
        ${cur && cur.unifi_delete_extra ? 'checked' : ''}>
        Delete Static DNS entries this IPAM did not create</label>
      <label class="checkitem" style="padding-left:0"><input id="pt-claim" type="checkbox"
        ${cur && cur.unifi_claim_client_dns ? 'checked' : ''}>
        Take names held by a client's own Local DNS Record</label>
      <p class="help">Use a local admin with MFA disabled — the gateway API refuses a 2FA login.
        The first option makes this IPAM authoritative over the gateway's whole A/AAAA table;
        leave it off and the sync only adds and updates. The second unticks a client's Local DNS
        Record (its DHCP reservation is left alone) so a static entry for that name is accepted.</p>

      <h4 style="margin-top:12px">dhcp section (scopes &amp; reservations)</h4>
      <label class="checkitem" style="padding-left:0"><input id="pt-dhcp-delextra" type="checkbox"
        ${cur && cur.unifi_dhcp_delete_extra ? 'checked' : ''}>
        Withdraw DHCP reservations the plan does not list</label>
      <label class="checkitem" style="padding-left:0"><input id="pt-scope-state" type="checkbox"
        ${cur && cur.unifi_manage_scope_state ? 'checked' : ''}>
        Manage scope on/off state (dhcpd_enabled)</label>
      <p class="help"><strong>Both have a large blast radius; leave them off unless you are
        certain.</strong> The first clears every fixed-IP binding on the gateway that this plan does
        not list — machines relying on those reservations lose their addresses at their next
        renewal. The second lets a range that is disabled in the plan turn a VLAN's DHCP server
        <em>off</em>, which is an outage, not a config tweak. They apply only when this target
        receives the <code>dhcp</code> section.</p>
    </div>
    <div id="pt-pihole" style="display:none">
      <div class="form-group"><label>Pi-hole password (web interface password, or an app password)</label>
        <input id="pt-ph-pass" class="form-control" type="password" autocomplete="new-password"
          placeholder="${cur && cur.has_password && kind === 'pihole' ? '(unchanged — leave empty to keep the stored password)' : ''}"></div>
      <label class="checkitem" style="padding-left:0"><input id="pt-ph-delextra" type="checkbox"
        ${cur && cur.pihole_delete_extra ? 'checked' : ''}>
        Delete local DNS records this IPAM did not create</label>
      <label class="checkitem" style="padding-left:0"><input id="pt-ph-dhcp-delextra" type="checkbox"
        ${cur && cur.pihole_dhcp_delete_extra ? 'checked' : ''}>
        Withdraw DHCP reservations the plan does not list</label>
      <label class="checkitem" style="padding-left:0"><input id="pt-ph-scope-state" type="checkbox"
        ${cur && cur.pihole_manage_scope_state ? 'checked' : ''}>
        Manage the DHCP server's on/off state</label>
      <p class="help">A Pi-hole serves <strong>one</strong> DHCP scope — the subnet it lives on;
        the plan's other scopes are reported as skipped, and options it cannot express (DNS handed
        out, NTP, PXE, …) are reported as conflicts rather than silently dropped. All three flags
        default off: the first two make this IPAM authoritative over its local records and
        reservations, and the third can turn its DHCP server on or off — with the plan's
        <code>enabled</code> flag deciding which.</p>
    </div>
    <div id="pt-technitium" style="display:none">
      <div class="form-group"><label>API token (create a permanent one there: Administration → Sessions → Create Token)</label>
        <input id="pt-tn-token" class="form-control" spellcheck="false"
          placeholder="${cur && cur.has_token && kind === 'technitium' ? '(unchanged — leave empty to keep the stored token)' : ''}"></div>
      <div class="form-group"><label>Managed zones (comma or space separated)</label>
        <input id="pt-tn-zones" class="form-control" spellcheck="false" placeholder="example.net"
          value="${cur ? escapeHtml(cur.technitium_zones || '') : ''}">
        <p class="help">The zones this IPAM authors — created as Primary if missing. Records this
          IPAM writes are tagged by comment, and reconcile only ever touches tagged records;
          names outside every managed zone are counted as skipped. NS/SOA are never touched.</p></div>
      <label class="checkitem" style="padding-left:0"><input id="pt-tn-reverse" type="checkbox"
        ${cur && cur.technitium_manage_reverse ? 'checked' : ''}>
        Manage reverse (PTR) zones — one PTR per address, from its canonical name</label>
      <label class="checkitem" style="padding-left:0"><input id="pt-tn-delextra" type="checkbox"
        ${cur && cur.technitium_delete_extra ? 'checked' : ''}>
        Delete untagged A/AAAA (and PTR) records in the managed zones</label>
      <label class="checkitem" style="padding-left:0"><input id="pt-tn-dhcp-delextra" type="checkbox"
        ${cur && cur.technitium_dhcp_delete_extra ? 'checked' : ''}>
        Delete DHCP scopes the plan does not define</label>
      <label class="checkitem" style="padding-left:0"><input id="pt-tn-scope-state" type="checkbox"
        ${cur && cur.technitium_manage_scope_state ? 'checked' : ''}>
        Manage scope enable/disable state</label>
      <p class="help">Scopes this IPAM creates start <strong>disabled</strong> and are named after
        the plan's scope tags; scopes with other names are foreign and kept unless the delete flag
        says otherwise. Authored scopes set <code>dnsUpdates: false</code> — in an IPAM-managed
        zone, the server auto-registering lease names would be a second writer.</p>
    </div>
    <button class="btn" onclick="pushTargetSave()">${cur ? 'Save' : 'Add target'}</button>`);
  pushTargetKind();
}

function pushTargetKind() {
  const kind = $('pt-kind').value;
  $('pt-unifi').style.display = kind === 'unifi' ? '' : 'none';
  $('pt-pihole').style.display = kind === 'pihole' ? '' : 'none';
  $('pt-technitium').style.display = kind === 'technitium' ? '' : 'none';
  $('pt-dnsmaq').style.display = kind === 'dnsmaq' ? '' : 'none';
  $('pt-url').placeholder = {unifi: 'https://192.168.1.1',
                             pihole: 'https://pihole-host:443',
                             technitium: 'https://technitium-host:53443'}[kind] || 'https://dns-node:8443';
}

async function pushTargetSave() {
  const kind = $('pt-kind').value;
  const body = {
    kind,
    name: $('pt-name').value.trim(),
    url: $('pt-url').value.trim(),
    sections: [...document.querySelectorAll('.pt-section:checked')].map(el => el.value),
    verify: $('pt-verify').value.trim() || 'insecure',
  };
  if (kind === 'unifi') {
    body.unifi_username = $('pt-user').value.trim();
    // Empty means "keep the stored secret" on an existing target — the API
    // only replaces a password/token that is actually sent.
    if ($('pt-pass').value) body.unifi_password = $('pt-pass').value;
    body.unifi_site = $('pt-site').value.trim() || 'default';
    body.unifi_delete_extra = $('pt-delextra').checked;
    body.unifi_claim_client_dns = $('pt-claim').checked;
    body.unifi_dhcp_delete_extra = $('pt-dhcp-delextra').checked;
    body.unifi_manage_scope_state = $('pt-scope-state').checked;
  } else if (kind === 'pihole') {
    if ($('pt-ph-pass').value) body.pihole_password = $('pt-ph-pass').value;
    body.pihole_delete_extra = $('pt-ph-delextra').checked;
    body.pihole_dhcp_delete_extra = $('pt-ph-dhcp-delextra').checked;
    body.pihole_manage_scope_state = $('pt-ph-scope-state').checked;
  } else if (kind === 'technitium') {
    if ($('pt-tn-token').value.trim()) body.technitium_token = $('pt-tn-token').value.trim();
    body.technitium_zones = $('pt-tn-zones').value.trim();
    body.technitium_manage_reverse = $('pt-tn-reverse').checked;
    body.technitium_delete_extra = $('pt-tn-delextra').checked;
    body.technitium_dhcp_delete_extra = $('pt-tn-dhcp-delextra').checked;
    body.technitium_manage_scope_state = $('pt-tn-scope-state').checked;
  } else {
    if ($('pt-token').value.trim()) body.token = $('pt-token').value.trim();
    if ($('pt-read').value.trim()) body.read_token = $('pt-read').value.trim();
  }
  try {
    await API.post('/api/push/targets', body);
    closeModal(); page_settings();
  } catch (e) { alert(e.message); }
}

async function pushTargetDelete(name, kind) {
  const tail = kind === 'unifi'
    ? 'The gateway keeps the Static DNS entries it has but stops receiving updates.'
    : 'The node keeps its current records but stops receiving updates (detach the section there to unlock local editing).';
  if (!confirm(`Remove push target "${name}"? ${tail}`)) return;
  try { await API.delete('/api/push/targets/' + encodeURIComponent(name)); page_settings(); }
  catch (e) { alert(e.message); }
}

async function pushRunNow(btn, target) {
  btn.disabled = true; btn.textContent = 'Pushing…';
  try {
    const r = await API.post('/api/push/run' + (target ? '?target=' + encodeURIComponent(target) : ''), {});
    alert(r.results.map(x => `${x.name}: ${x.ok ? 'ok — ' : 'FAILED — '}${x.detail}`).join('\n')
          + '\n\n' + r.sections.map(s =>
            `${s}: ${r.counts[s]} record(s), serial ${r.serials[s]}`).join('\n'));
  } catch (e) { alert(e.message); }
  page_settings();
}

// ─── Adopt from a gateway (pull) ────────────────────────
// Reads a UniFi target's DHCP state into the plan. Deliberately presented as
// ADOPTION, not sync: one explicit "take what is there", gap-filling only,
// after a read-only preview of what the gateway holds.

async function pullTargetModal(name) {
  openModal('Adopt from ' + name, `
    <p class="help">Reads this gateway's networks, DHCP scopes, options and fixed reservations
      into the address plan. Adoption <strong>fills gaps and never overwrites</strong>: anything
      already recorded here keeps its value (reported as kept), and a scope that overlaps a
      recorded range is refused rather than added alongside it. Re-running is safe.</p>
    <div id="pull-body"><p class="loading">Reading ${escapeHtml(name)}…</p></div>`, {wide: true});
  let r;
  try {
    r = await API.post('/api/push/targets/' + encodeURIComponent(name) + '/pull?dry_run=1', {});
  } catch (e) {
    const el = $('pull-body');
    if (el) el.innerHTML = `<div class="alert alert-danger">${escapeHtml(e.message)}</div>`;
    return;
  }
  const el = $('pull-body');
  if (!el) return;   // modal closed while reading
  const nets = (r.state || {}).networks || [];
  const res = (r.state || {}).reservations || [];
  el.innerHTML = `
    <h4>The gateway holds</h4>
    ${dataTable([
      {label: 'Network', get: n => `<span class="cidr">${escapeHtml(n.cidr)}</span>${n.name ? '<br><span class="muted">' + escapeHtml(n.name) + '</span>' : ''}`},
      {label: 'VLAN', get: n => n.vlan != null ? escapeHtml(String(n.vlan)) : '<span class="muted">—</span>'},
      {label: 'Gateway', get: n => escapeHtml(n.gateway || '') || '<span class="muted">—</span>'},
      {label: 'DNS', get: n => escapeHtml((n.dns || []).join(', ')) || '<span class="muted">gateway</span>'},
      {label: 'Domain', get: n => escapeHtml(n.domain || '') || '<span class="muted">—</span>'},
      {label: 'Scope', get: n => n.range
        ? `<span class="cidr">${escapeHtml(n.range.start)} – ${escapeHtml(n.range.end)}</span>` +
          (n.range.enabled ? '' : ' <span class="status-badge gray">disabled</span>')
        : '<span class="muted">none</span>'},
      {label: 'Options', get: n => escapeHtml(Object.keys(n.options || {}).join(', ')) || '<span class="muted">—</span>'},
    ], nets, 'No networks readable on this gateway')}
    <h4 style="margin-top:14px">Fixed reservations <span class="help">(${res.length})</span></h4>
    ${dataTable([
      {label: 'Address', get: x => `<span class="cidr">${escapeHtml(x.ip)}</span>`},
      {label: 'MAC', get: x => escapeHtml(x.mac || '')},
      {label: 'Gateway name', get: x => escapeHtml(x.hostname || '') || '<span class="muted">—</span>'},
    ], res, 'No fixed-IP reservations on this gateway')}
    <div class="toolbar" style="margin-top:14px">
      <button class="btn" onclick="pullTargetGo('${jsArg(name)}', this)">Adopt into the plan</button>
    </div>
    <p class="help">Nothing has been written yet — this preview is read-only.</p>`;
}

async function pullTargetGo(name, btn) {
  btn.disabled = true; btn.textContent = 'Adopting…';
  let r;
  try {
    r = await API.post('/api/push/targets/' + encodeURIComponent(name) + '/pull', {});
  } catch (e) {
    alert(e.message);
    btn.disabled = false; btn.textContent = 'Adopt into the plan';
    return;
  }
  const el = $('pull-body');
  if (!el) return;
  const groups = [['networks', 'Networks'], ['ranges', 'DHCP ranges'],
                  ['options', 'DHCP options'], ['reservations', 'Reservations']];
  const cells = groups.map(([key, label]) => {
    const bits = ['created', 'updated', 'kept'].map(verb => {
      const items = r[key + '_' + verb] || [];
      if (!items.length) return '';
      const detail = verb === 'kept' ? '' :
        `<br><span class="muted">${escapeHtml(items.slice(0, 12).join(', '))}${items.length > 12 ? ` +${items.length - 12} more` : ''}</span>`;
      return `${items.length} ${verb}${detail}`;
    }).filter(Boolean);
    return `<div><dt>${escapeHtml(label)}</dt><dd>${bits.join('<br>') || 'nothing to take'}</dd></div>`;
  });
  el.innerHTML = `
    ${(r.errors || []).map(e => `<div class="alert alert-danger">${escapeHtml(e)}</div>`).join('')}
    <h4>Adopted from ${escapeHtml(name)}</h4>
    <dl class="detail-grid">${cells.join('')}</dl>
    <p class="help">Kept = already recorded here with a value, left untouched. Errors above (if any)
      are disagreements to resolve by hand — nothing was forced.</p>
    <div class="toolbar" style="margin-top:12px">
      <button class="btn btn-sm" onclick="closeModal(); page_settings()">Done</button>
    </div>`;
}
