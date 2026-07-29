// Networks: the prefix tree, one network's detail page, and the IP map.

const NETWORK_FIELDS = [
  {name: 'cidr', label: 'CIDR', placeholder: '10.0.0.0/24 or 2001:db8::/64',
   help: 'Accepts a host address too — 10.0.0.5/24 is normalized to 10.0.0.0/24.'},
  {name: 'name', label: 'Name', placeholder: 'lab-servers'},
  {name: 'role', label: 'Role', type: 'select', def: 'subnet',
   options: [['subnet', 'Subnet — hosts live here'],
             ['container', 'Container — a supernet you carve up'],
             ['pool', 'Pool — reserved for dynamic use']]},
  {name: 'vlan_id', label: 'VLAN', type: 'select', options: [['', '— none —']]},
  {name: 'gateway', label: 'Gateway', placeholder: '10.0.0.1',
   help: 'Excluded from the free list so it is never handed out.'},
  {name: 'dns_servers', label: 'DNS servers', placeholder: '10.0.0.53, 1.1.1.1'},
  {name: 'domain', label: 'Domain', placeholder: 'lab.lan',
   help: 'Qualifies bare hostnames in the DNS exports.'},
  {name: 'site', label: 'Site', placeholder: 'rack-1'},
  {name: 'status', label: 'Status', type: 'select', def: 'active',
   options: ['active', 'planned', 'staged', 'offline', 'decommissioned']},
  {name: 'description', label: 'Description'},
];

async function page_networks(id) {
  if (id) return networkDetail(id);

  const data = await API.get('/api/networks/tree');
  const rows = data.networks.map(n => {
    const indent = `<span class="tree-indent" style="width:${n.depth * 18}px"></span>` +
      (n.depth ? '<span class="tree-branch">&#9492;</span>' : '');
    return {...n, _indent: indent};
  });

  const cols = [
      {label: 'Network', get: n => n._indent +
        `<a class="cidr" onclick="showPage('networks', ${n.id})">${escapeHtml(n.cidr)}</a>` +
        (n.role === 'container' ? ' ' + typeBadge('supernet') : '')},
      {label: 'Name', get: n => escapeHtml(n.name || '')},
      {label: 'VLAN', get: n => n.vlan_vid ? `<a onclick="showPage('vlans')">${escapeHtml(n.vlan_vid)}${n.vlan_name ? ' ' + escapeHtml(n.vlan_name) : ''}</a>` : '<span class="muted">—</span>'},
      {label: 'Gateway', get: n => escapeHtml(n.gateway || '') || '<span class="muted">—</span>'},
      {label: 'Used', cls: 'num', get: n => `${fmtNum(n.utilization.used)} / ${fmtNum(n.utilization.capacity)}`},
      {label: 'Utilization', cls: 'util-cell', get: n =>
        n.role === 'container' ? '<span class="muted">supernet</span>' : usageBar(n.utilization.pct, true)},
      {label: 'Free', cls: 'num', get: n => fmtNum(n.utilization.free)},
      {label: 'Site', get: n => escapeHtml(n.site || '')},
      {label: '', cls: 'row-actions', get: n => canWrite() ? `
        <button class="btn btn-sm btn-outline" onclick="networkModal(${n.id})">Edit</button>
        <button class="btn btn-sm btn-danger" onclick="deleteResource('/api/networks', ${n.id}, '${jsArg(n.cidr)}')">Delete</button>` : ''},
  ];
  if (canWrite()) cols.unshift(bulkCol('/api/networks', n => n.cidr));

  $('page-content').innerHTML = `
    <div class="page-header"><h2>Networks</h2></div>
    ${searchBar()}
    ${canWrite() ? `<div class="toolbar">
      <button class="btn btn-sm" onclick="networkModal()">+ Add network</button>
      <button class="btn btn-sm btn-outline" onclick="showPage('vlans')">Manage VLANs</button>
      ${bulkBtn()}
    </div>` : ''}
    ${dataTable(cols, rows, 'No networks yet — add one to start tracking addresses')}`;
}

async function networkModal(id) {
  const fields = NETWORK_FIELDS.map(f => ({...f}));
  fields.find(f => f.name === 'vlan_id').options =
    await selectOptions('/api/vlans', 'vlans', v => `${v.vid}${v.name ? ' — ' + v.name : ''}${v.site ? ' (' + v.site + ')' : ''}`);
  const rec = id ? await API.get('/api/networks/' + id) : null;
  openModal(id ? 'Edit network' : 'Add network',
    buildForm(fields, rec) +
    `<button class="btn" onclick="saveResource('/api/networks', ${id || 0}, NETWORK_FORM)">${id ? 'Save' : 'Add'}</button>`);
  window.NETWORK_FORM = fields;
}

// ─── Detail ───────────────────────────────────────────────

async function networkDetail(id) {
  const d = await API.get('/api/networks/' + id + '/detail');
  const n = d.network, u = d.utilization;

  const facts = `
    <dl class="detail-grid">
      <div><dt>CIDR</dt><dd class="cidr">${escapeHtml(n.cidr)}</dd></div>
      <div><dt>Name</dt><dd>${escapeHtml(n.name || '—')}</dd></div>
      <div><dt>Role</dt><dd>${escapeHtml(n.role)}</dd></div>
      <div><dt>VLAN</dt><dd>${n.vlan_vid ? escapeHtml(n.vlan_vid + (n.vlan_name ? ' — ' + n.vlan_name : '')) : '—'}</dd></div>
      <div><dt>Gateway</dt><dd>${escapeHtml(n.gateway || '—')}</dd></div>
      <div><dt>Netmask</dt><dd>${escapeHtml(d.deploy.netmask || '—')}</dd></div>
      <div><dt>DNS</dt><dd>${escapeHtml((d.deploy.dns || []).join(', ') || '—')}</dd></div>
      <div><dt>Domain</dt><dd>${escapeHtml(n.domain || '—')}</dd></div>
      <div><dt>Site</dt><dd>${escapeHtml(n.site || '—')}</dd></div>
      <div><dt>Status</dt><dd>${statusBadge(n.status)}</dd></div>
      <div><dt>Capacity</dt><dd>${fmtNum(u.capacity)} usable</dd></div>
      <div><dt>Free</dt><dd>${fmtNum(u.free)}</dd></div>
    </dl>`;

  const children = d.children.length ? `
    <h3>Contained networks</h3>
    ${dataTable([
      {label: 'Network', get: c => `<a class="cidr" onclick="showPage('networks', ${c.id})">${escapeHtml(c.cidr)}</a>`},
      {label: 'Name', get: c => escapeHtml(c.name || '')},
      {label: 'Role', get: c => escapeHtml(c.role)},
    ], d.children)}` : '';

  const ranges = `
    <h3 style="margin-top:24px">DHCP ranges</h3>
    ${canWrite() ? `<div class="toolbar"><button class="btn btn-sm" onclick="dhcpRangeModal(null, ${n.id})">+ Add range</button></div>` : ''}
    ${dataTable([
      {label: 'Range', get: r => `<span class="cidr">${escapeHtml(r.start_addr)} – ${escapeHtml(r.end_addr)}</span>`},
      {label: 'Name', get: r => escapeHtml(r.name || '')},
      {label: 'Server', get: r => escapeHtml(r.server_name || '—')},
      {label: 'Lease', get: r => escapeHtml(r.lease_time)},
      {label: 'State', get: r => `<span class="status-badge ${r.enabled ? 'green' : 'gray'}">${r.enabled ? 'enabled' : 'disabled'}</span>`},
      {label: '', cls: 'row-actions', get: r => canWrite() ? `
        <button class="btn btn-sm btn-outline" onclick="dhcpRangeModal(${r.id}, ${n.id})">Edit</button>
        <button class="btn btn-sm btn-danger" onclick="deleteResource('/api/dhcp/ranges', ${r.id}, '${jsArg(r.start_addr)}')">Delete</button>` : ''},
    ], d.dhcp_ranges, 'No DHCP ranges in this network')}`;

  const addresses = `
    <h3 style="margin-top:24px">Address records <span class="help">(${d.addresses.length})</span></h3>
    ${canWrite() ? `<div class="toolbar">
      <button class="btn btn-sm" onclick="addressModal(null, ${n.id})">+ Add address</button>
      <button class="btn btn-sm btn-outline" onclick="allocateModal(${n.id})">Allocate next free</button>
      <button class="btn btn-sm btn-outline" onclick="reserveSpanModal(${n.id})">Reserve a span</button>
    </div>` : ''}
    ${dataTable(addressColumns(), d.addresses, 'No addresses recorded in this network')}`;

  $('page-content').innerHTML = `
    ${breadcrumb([{label: 'Networks', page: 'networks'}, {label: n.cidr}])}
    <div class="page-header">
      <h2>${escapeHtml(n.cidr)}${n.name ? ' — ' + escapeHtml(n.name) : ''}</h2>
      <div class="toolbar" style="margin:0">
        ${canWrite() ? `<button class="btn btn-sm btn-outline" onclick="networkModal(${n.id})">Edit</button>` : ''}
        <button class="btn btn-sm btn-outline" onclick="showFreeList(${n.id})">Free addresses</button>
        ${canWrite() ? `<button class="btn btn-sm btn-outline" onclick="scanNetwork(${n.id})">Ping sweep</button>` : ''}
      </div>
    </div>
    ${d.parent ? `<p class="crumb">Inside <a onclick="showPage('networks', ${d.parent.id})" class="cidr">${escapeHtml(d.parent.cidr)}</a></p>` : ''}
    ${facts}
    <h3>Utilization</h3>
    ${usageBar(u.pct)}
    <p class="help">${fmtNum(u.records)} record(s) &middot; ${fmtNum(u.dhcp)} address(es) inside DHCP pools &middot; ${fmtNum(u.free)} free</p>
    ${d.enumerable ? `<div id="ipmap"><p class="loading">Loading address map…</p></div>` : `
      <div class="alert alert-info">This prefix has ${fmtNum(u.capacity)} addresses — too many to draw an address map.
        Browse its contained networks instead.</div>`}
    ${children}
    ${ranges}
    ${addresses}`;

  if (d.enumerable) renderIpMap(n.id);
}

// ─── IP map ───────────────────────────────────────────────

async function renderIpMap(id) {
  let data;
  try { data = await API.get('/api/networks/' + id + '/map'); }
  catch (e) { $('ipmap').innerHTML = `<div class="alert alert-warning">${escapeHtml(e.message)}</div>`; return; }

  const cells = data.addresses.map(a => {
    const tip = [a.address,
                 a.record ? (a.record.dns_name || a.record.assigned_name || a.record.status) : a.state,
                 a.hostname || '',
                 a.alive === true ? 'responds to ping' : (a.alive === false ? 'silent at last scan' : '')]
      .filter(Boolean).join(' · ');
    const last = a.address.includes(':') ? a.address.split(':').pop() : a.address.split('.').pop();
    return `<div class="ip-cell ${escapeHtml(a.state)}${a.gateway ? ' gw' : ''}"
      title="${escapeHtml(tip)}" onclick="addressPeek('${jsArg(a.address)}')">${escapeHtml(last)}</div>`;
  }).join('');

  $('ipmap').innerHTML = `
    <div class="ip-legend">
      <span><i style="background:var(--st-free)"></i> free</span>
      <span><i style="background:var(--st-active)"></i> assigned</span>
      <span><i style="background:var(--st-reserved)"></i> reserved</span>
      <span><i style="background:var(--st-pool)"></i> DHCP pool</span>
      <span><i style="background:var(--st-deprecated)"></i> deprecated</span>
      <span><i style="background:var(--st-unmanaged)"></i> unmanaged (answered a ping)</span>
      <span>&#9873; gateway</span>
    </div>
    <div class="ip-map">${cells}</div>`;
}

// Clicking a cell resolves the address through the API rather than reusing
// the map payload, so the popup is always current and works for free
// addresses the map has no record for.
async function addressPeek(address) {
  let r;
  try { r = await API.get('/api/addresses/lookup?address=' + encodeURIComponent(address)); }
  catch (e) { alert(e.message); return; }

  const rec = r.record;
  const rows = [
    ['State', r.state],
    ['Network', r.network ? r.network.cidr : '—'],
    ['VLAN', r.network && r.network.vlan_vid ? r.network.vlan_vid : '—'],
    ['DNS name', rec ? (rec.dns_name || '—') : '—'],
    ['Assigned to', rec && rec.assigned_name ? `${rec.assigned_name} (${rec.assigned_kind})` : '—'],
    ['MAC', rec ? (rec.mac || '—') : '—'],
    ['Interface', rec ? (rec.if_name || '—') : '—'],
    ['Source', rec ? rec.source : '—'],
    ['Description', rec ? (rec.description || '—') : '—'],
    ['DHCP pool', r.dhcp_range ? `${r.dhcp_range.start_addr} – ${r.dhcp_range.end_addr}` : '—'],
    ['Last ping', r.scan ? (r.scan.alive ? 'responded ' + fmtAgo(r.scan.last_scan)
                                         : 'silent ' + fmtAgo(r.scan.last_scan)) : 'never probed'],
  ];
  // Several addresses on one NIC is a normal way to run services that all want
  // the same port — shown as context, not as a problem.
  if ((r.siblings || []).length) {
    rows.push(['Also on this interface',
               r.siblings.map(s => s.address + (s.dns_name ? ' (' + s.dns_name + ')' : '')).join(', ')]);
  }

  const actions = canWrite() ? `<div class="toolbar" style="margin-top:14px">
    ${rec ? `<button class="btn btn-sm btn-outline" onclick="closeModal();addressModal(${rec.id})">Edit record</button>
             <button class="btn btn-sm btn-danger" onclick="closeModal();deleteResource('/api/addresses', ${rec.id}, '${jsArg(address)}')">Delete record</button>`
          : `<button class="btn btn-sm" onclick="closeModal();addressModal(null, ${r.network ? r.network.id : 'null'}, '${jsArg(address)}')">Record this address</button>`}
    <button class="btn btn-sm btn-outline" onclick="verifyOne('${jsArg(address)}')">Ping check</button>
  </div>` : '';

  openModal(address, `<dl class="detail-grid">${rows.map(([k, v]) =>
    `<div><dt>${escapeHtml(k)}</dt><dd>${escapeHtml(String(v))}</dd></div>`).join('')}</dl>${actions}`);
}

async function verifyOne(address) {
  try {
    const r = await API.post('/api/scan/verify', {addresses: [address]});
    const res = r.results[address];
    alert(res.alive
      ? `${address} ANSWERED (${res.rtt_ms != null ? res.rtt_ms + ' ms' : 'no timing'})${res.hostname ? ' — ' + res.hostname : ''}\n\nThis address is in use.`
      : `${address} did not answer — it looks free.`);
    reloadPage();
  } catch (e) { alert(e.message); }
}

// ─── Free list / allocation / reservation ─────────────────

async function showFreeList(id) {
  openModal('Free addresses', '<p class="loading">Finding free addresses…</p>', {wide: true});
  let r;
  try { r = await API.get(`/api/networks/${id}/free?limit=256`); }
  catch (e) { openModal('Free addresses', `<div class="error">${escapeHtml(e.message)}</div>`); return; }

  openModal(`Free addresses in ${r.network.cidr}`, `
    <p class="help">${fmtNum(r.utilization.free)} free in total; showing the first ${r.count}.
      Records, DHCP pools and the gateway are already excluded — a ping check catches
      anything using an address without a record.</p>
    <div class="toolbar">
      ${canWrite() ? `<button class="btn btn-sm" onclick="verifyFreeList(${id})">Ping-check these</button>` : ''}
      ${canWrite() ? `<button class="btn btn-sm btn-outline" onclick="closeModal();allocateModal(${id})">Allocate the next one</button>` : ''}
    </div>
    <div id="free-list" class="raw-output">${escapeHtml(r.free.join('\n')) || 'none'}</div>`, {wide: true});
}

async function verifyFreeList(id) {
  const el = $('free-list');
  const addrs = el.textContent.trim().split('\n').filter(Boolean).slice(0, 256);
  if (!addrs.length) return;
  el.textContent = 'Probing ' + addrs.length + ' addresses…';
  try {
    const r = await API.post('/api/scan/verify', {addresses: addrs});
    el.innerHTML = addrs.map(a => r.results[a] && r.results[a].alive
      ? `<span style="color:var(--red)">${escapeHtml(a)}  IN USE — answered a ping</span>`
      : escapeHtml(a) + '  free').join('\n');
  } catch (e) { el.textContent = 'Error: ' + e.message; }
}

async function allocateModal(networkId) {
  const hosts = await hostOptions(true);
  openModal('Allocate the next free address', `
    <div class="form-group"><label>Assign to</label>
      <select id="a-host" class="form-control">${hosts.map(([v, l]) =>
        `<option value="${escapeHtml(v)}">${escapeHtml(l)}</option>`).join('')}</select></div>
    <div class="form-group"><label>DNS name</label><input id="a-dns" class="form-control" placeholder="web01"></div>
    <div class="form-group"><label>Interface</label><input id="a-if" class="form-control" placeholder="eth0"></div>
    <div class="form-group"><label>MAC</label><input id="a-mac" class="form-control" placeholder="aa:bb:cc:dd:ee:ff"></div>
    <div class="form-group"><label>Description</label><input id="a-desc" class="form-control"></div>
    <label class="checkitem" style="padding-left:0"><input id="a-verify" type="checkbox" checked> Ping-check before allocating</label>
    <p class="help">With this on, a candidate that answers a ping is skipped and recorded as an unmanaged host.</p>
    <button class="btn" onclick="doAllocate(${networkId})">Allocate</button>`);
}

async function doAllocate(networkId) {
  const host = $('a-host').value;
  const body = {
    network_id: networkId,
    dns_name: $('a-dns').value.trim(),
    if_name: $('a-if').value.trim(),
    mac: $('a-mac').value.trim(),
    description: $('a-desc').value.trim(),
    verify: $('a-verify').checked,
  };
  if (host) {
    const [kind, id] = host.split(':');
    body.assigned_kind = kind;
    body.assigned_id = Number(id);
  }
  try {
    const r = await API.post('/api/allocate', body);
    closeModal();
    alert(`Allocated ${r.ip}\n\nnetmask ${r.netmask || '/' + r.prefixlen}\ngateway ${r.gateway || '—'}\nDNS ${(r.dns || []).join(', ') || '—'}`);
    reloadPage();
  } catch (e) { alert(e.message); }
}

function reserveSpanModal(networkId) {
  openModal('Reserve a span of addresses', `
    <p class="help">Creates a reserved record for every address in the range, keeping them
      out of the free list and out of allocation. Existing records are left alone.</p>
    <div class="form-group"><label>First address</label><input id="r-start" class="form-control" placeholder="10.0.0.1"></div>
    <div class="form-group"><label>Last address</label><input id="r-end" class="form-control" placeholder="10.0.0.20"></div>
    <div class="form-group"><label>Description</label><input id="r-desc" class="form-control" value="Reserved"></div>
    <button class="btn" onclick="doReserveSpan(${networkId})">Reserve</button>`);
}

async function doReserveSpan(networkId) {
  try {
    const r = await API.post(`/api/networks/${networkId}/reserve`, {
      start: $('r-start').value.trim(), end: $('r-end').value.trim(),
      description: $('r-desc').value.trim()});
    closeModal();
    alert(`Reserved ${r.created} address(es)${r.skipped ? `, skipped ${r.skipped} that already had records` : ''}.`);
    reloadPage();
  } catch (e) { alert(e.message); }
}

async function scanNetwork(id) {
  if (!confirm('Ping every address in this network?')) return;
  try {
    const r = await API.post('/api/scan', {network_id: id});
    showPage('scan');
    setTimeout(() => watchScan(r.job), 300);
  } catch (e) { alert(e.message); }
}
