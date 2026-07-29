// Scan & Verify: ping sweeps, and reconciling the address plan against what
// actually answers on the wire.

let _scanPoll = null;

async function page_scan() {
  stopScanPoll();
  const [nets, jobs, rec] = await Promise.all([
    API.get('/api/networks'),
    API.get('/api/scan/jobs'),
    API.get('/api/scan/reconcile'),
  ]);

  const netOpts = nets.networks.filter(n => n.role !== 'container')
    .map(n => `<option value="${n.id}">${escapeHtml(n.cidr)}${n.name ? ' — ' + escapeHtml(n.name) : ''}</option>`).join('');

  $('page-content').innerHTML = `
    <div class="page-header"><h2>Scan &amp; Verify</h2></div>
    <p class="help">A record saying an address is free is a claim; a silent ping is evidence.
      Sweeps use ICMP via the system <code>ping</code>, so no extra privileges are needed.</p>

    ${canWrite() ? `
    <div class="filters">
      <div class="form-group"><label>Network</label>
        <select id="sc-net" class="form-control">${netOpts || '<option value="">No networks defined</option>'}</select></div>
      <div class="form-group"><label>Scope</label>
        <select id="sc-scope" class="form-control">
          <option value="all">Every address in the network</option>
          <option value="free">Only addresses we believe are free</option>
        </select></div>
      <button class="btn btn-sm" onclick="startScan()">Start sweep</button>
      <button class="btn btn-sm btn-outline" onclick="adHocScanModal()">Scan a specific list</button>
    </div>` : ''}

    <div id="scan-progress"></div>

    <h3>Recent sweeps</h3>
    <div id="scan-jobs">${renderJobs(jobs.jobs)}</div>

    <h3 style="margin-top:24px">Unmanaged hosts <span class="help">(${rec.unmanaged_count})</span></h3>
    <p class="help">These answered a ping, have no address record, and are <strong>outside</strong>
      every DHCP pool — so someone assigned an address without recording it. This is the conflict
      an address plan is meant to prevent. DHCP leases are listed separately below.</p>
    ${canWrite() && rec.unmanaged.length ? `<div class="toolbar">
      <button class="btn btn-sm" onclick="adoptAll()">Adopt all into the address plan</button></div>` : ''}
    ${dataTable([
      {label: 'Address', get: u => `<a class="cidr" onclick="addressPeek('${jsArg(u.address)}')">${escapeHtml(u.address)}</a>`},
      {label: 'Network', get: u => u.network_id
        ? `<a class="cidr" onclick="showPage('networks', ${u.network_id})">${escapeHtml(u.network_cidr)}</a>`
        : '<span class="muted">outside every network</span>'},
      {label: 'Hostname', get: u => escapeHtml(u.hostname || '') || '<span class="muted">—</span>'},
      {label: 'MAC', get: u => escapeHtml(u.mac || '') || '<span class="muted">—</span>'},
      {label: 'RTT', cls: 'num', get: u => u.rtt_ms != null ? u.rtt_ms + ' ms' : '—'},
      {label: 'Seen', get: u => escapeHtml(fmtAgo(u.last_alive))},
      {label: '', cls: 'row-actions', get: u => canWrite()
        ? `<button class="btn btn-sm" onclick="adoptOne('${jsArg(u.address)}')">Adopt</button>` : ''},
    ], rec.unmanaged, 'None — everything answering a ping is recorded')}

    <h3 style="margin-top:24px">DHCP leases seen <span class="help">(${rec.dhcp_lease_count})</span></h3>
    <p class="help">Answered a ping from inside a DHCP pool. Expected — these are leases, not
      anomalies, which is why they are kept out of the list above. Adopting one records it with
      status <code>dhcp</code>; usually you only want to do that for a host you intend to
      convert to a reservation.</p>
    ${dataTable([
      {label: 'Address', get: u => `<a class="cidr" onclick="addressPeek('${jsArg(u.address)}')">${escapeHtml(u.address)}</a>`},
      {label: 'Pool', get: u => typeBadge(u.dhcp_range || '')},
      {label: 'Hostname', get: u => escapeHtml(u.hostname || '') || '<span class="muted">—</span>'},
      {label: 'MAC', get: u => escapeHtml(u.mac || '') || '<span class="muted">—</span>'},
      {label: 'Seen', get: u => escapeHtml(fmtAgo(u.last_alive))},
      {label: '', cls: 'row-actions', get: u => canWrite()
        ? `<button class="btn btn-sm btn-outline" onclick="adoptOne('${jsArg(u.address)}', true)">Record as DHCP</button>` : ''},
    ], rec.dhcp_leases || [], 'None seen')}

    <h3 style="margin-top:24px">Silent records <span class="help">(${rec.stale_count})</span></h3>
    <p class="help">Recorded as active but did not answer the last probe. Could be powered off,
      firewalled, or a record for a machine that no longer exists.</p>
    ${dataTable([
      {label: 'Address', get: s => `<a class="cidr" onclick="addressPeek('${jsArg(s.address)}')">${escapeHtml(s.address)}</a>`},
      {label: 'Network', get: s => escapeHtml(s.network_cidr || '')},
      {label: 'DNS name', get: s => escapeHtml(s.dns_name || '') || '<span class="muted">—</span>'},
      {label: 'Assigned to', get: s => s.assigned_kind
        ? objLink(s.assigned_kind, s.assigned_id, s.assigned_name) : '<span class="muted">—</span>'},
      {label: 'Last probe', get: s => escapeHtml(fmtAgo(s.last_scan))},
      {label: 'Last seen up', get: s => s.last_alive ? escapeHtml(fmtAgo(s.last_alive)) : 'never'},
      {label: '', cls: 'row-actions', get: s => canWrite() ? `
        <button class="btn btn-sm btn-outline" onclick="verifyOne('${jsArg(s.address)}')">Re-check</button>
        <button class="btn btn-sm btn-danger" onclick="deleteResource('/api/addresses', ${s.id}, '${jsArg(s.address)}')">Delete record</button>` : ''},
    ], rec.stale, 'None — every active record answered its last probe')}`;
}

function renderJobs(jobs) {
  return dataTable([
    {label: 'Target', get: j => escapeHtml(j.label)},
    {label: 'State', get: j => `<span class="status-badge ${j.state === 'done' ? 'green' : j.state === 'error' ? 'red' : 'yellow'}">${escapeHtml(j.state)}</span>`},
    {label: 'Progress', cls: 'util-cell', get: j => usageBar(j.total ? j.done / j.total * 100 : 0, true)},
    {label: 'Probed', cls: 'num', get: j => `${fmtNum(j.done)} / ${fmtNum(j.total)}`},
    {label: 'Responded', cls: 'num', get: j => fmtNum(j.alive)},
    {label: 'Started', get: j => escapeHtml(fmtAgo(j.started))},
    {label: 'Error', get: j => escapeHtml(j.error || '')},
  ], jobs, 'No sweeps run yet');
}

async function startScan() {
  const netId = $('sc-net').value;
  if (!netId) { alert('Define a network first'); return; }
  const body = {network_id: Number(netId)};
  if ($('sc-scope').value === 'free') body.free_only = true;
  try {
    const r = await API.post('/api/scan', body);
    watchScan(r.job);
  } catch (e) { alert(e.message); }
}

// Poll a running job. The scan writes results as they land, so the page is
// refreshed once at the end rather than continuously re-rendering tables.
function watchScan(jobId) {
  stopScanPoll();
  _scanPoll = setInterval(async () => {
    let j;
    try { j = await API.get('/api/scan/jobs/' + encodeURIComponent(jobId)); }
    catch (e) { stopScanPoll(); return; }
    const el = $('scan-progress');
    if (!el) { stopScanPoll(); return; }
    el.innerHTML = `
      <div class="pool-card">
        <div class="pool-header"><span class="pool-name">Sweeping ${escapeHtml(j.label)}</span>
          <span class="pool-stats">${fmtNum(j.done)} / ${fmtNum(j.total)} probed &middot; ${fmtNum(j.alive)} responded</span></div>
        ${usageBar(j.total ? j.done / j.total * 100 : 0)}
      </div>`;
    if (j.state !== 'running') {
      stopScanPoll();
      el.innerHTML = `<div class="alert alert-${j.state === 'error' ? 'danger' : 'info'}">
        Sweep of <strong>${escapeHtml(j.label)}</strong> ${escapeHtml(j.state)} —
        ${fmtNum(j.alive)} of ${fmtNum(j.total)} address(es) responded.
        ${j.error ? escapeHtml(j.error) : ''}</div>`;
      setTimeout(() => { if (currentPage === 'scan') page_scan(); }, 1200);
    }
  }, 1000);
}

function stopScanPoll() {
  if (_scanPoll) { clearInterval(_scanPoll); _scanPoll = null; }
}

function adHocScanModal() {
  openModal('Scan a specific list', `
    <p class="help">One address per line. Useful for spot-checking a handful of addresses
      without sweeping a whole subnet.</p>
    <div class="form-group"><label>Addresses</label>
      <textarea id="ah-list" class="form-control" rows="10" placeholder="10.0.0.5&#10;10.0.0.6"></textarea></div>
    <button class="btn" onclick="doAdHocScan()">Probe</button>`);
}

async function doAdHocScan() {
  const addrs = $('ah-list').value.split('\n').map(a => a.trim()).filter(Boolean);
  if (!addrs.length) return;
  if (addrs.length > 256) { alert('Use a network sweep for more than 256 addresses'); return; }
  $('modal-body').innerHTML = '<p class="loading">Probing ' + addrs.length + ' addresses…</p>';
  try {
    const r = await API.post('/api/scan/verify', {addresses: addrs});
    openModal('Probe results', `
      <p class="help">${r.alive.length} responded, ${r.free.length} silent.</p>
      <div class="raw-output">${addrs.map(a => {
        const res = r.results[a];
        return res && res.alive
          ? `<span style="color:var(--red)">${escapeHtml(a)}  IN USE${res.hostname ? ' — ' + escapeHtml(res.hostname) : ''}</span>`
          : `${escapeHtml(a)}  free`;
      }).join('\n')}</div>`);
  } catch (e) { openModal('Probe results', `<div class="error">${escapeHtml(e.message)}</div>`); }
}

async function adoptOne(address, includeDhcp) {
  try {
    await API.post('/api/scan/adopt', {addresses: [address], include_dhcp: !!includeDhcp});
    page_scan();
  } catch (e) { alert(e.message); }
}

async function adoptAll() {
  const rec = await API.get('/api/scan/reconcile');
  const addrs = rec.unmanaged.map(u => u.address);
  if (!addrs.length) return;
  if (!confirm(`Create address records for ${addrs.length} discovered host(s)?`)) return;
  try {
    const r = await API.post('/api/scan/adopt', {addresses: addrs});
    alert(`Created ${r.created} record(s)${r.skipped ? `, skipped ${r.skipped} already recorded` : ''}` +
          `${r.skipped_dhcp ? `, skipped ${r.skipped_dhcp} inside DHCP pools` : ''}.`);
    page_scan();
  } catch (e) { alert(e.message); }
}
