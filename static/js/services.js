// DHCP and DNS: the servers on the network and the address space they own.

const DHCP_SERVER_FIELDS = [
  {name: 'name', label: 'Name', placeholder: 'dnsmasq-main'},
  {name: 'kind', label: 'Software', type: 'select', def: 'dnsmasq',
   options: [['dnsmasq', 'dnsmasq'], ['isc-dhcp', 'ISC DHCP'], ['kea', 'Kea'],
             ['windows', 'Windows Server'], ['unifi', 'UniFi'], ['other', 'Other']]},
  {name: 'address', label: 'Service address', placeholder: '10.0.0.1'},
  {name: 'host', label: 'Runs on', type: 'select', options: [['', '— none —']]},
  {name: 'url', label: 'Management URL', placeholder: 'https://dnsmasq.lab.lan:8443',
   help: 'Where this server is managed — e.g. its DNSMAQ-MGR instance.'},
  {name: 'status', label: 'Status', type: 'select', def: 'active',
   options: ['active', 'planned', 'staged', 'offline', 'decommissioned']},
  {name: 'description', label: 'Description'},
];

const DNS_SERVER_FIELDS = [
  {name: 'name', label: 'Name', placeholder: 'ns1'},
  {name: 'kind', label: 'Software', type: 'select', def: 'dnsmasq',
   options: [['dnsmasq', 'dnsmasq'], ['bind', 'BIND'], ['unbound', 'Unbound'],
             ['pihole', 'Pi-hole'], ['adguard', 'AdGuard Home'], ['powerdns', 'PowerDNS'],
             ['windows', 'Windows Server'], ['other', 'Other']]},
  {name: 'role', label: 'Role', type: 'select', def: 'recursive',
   options: [['recursive', 'Recursive resolver'], ['authoritative', 'Authoritative'],
             ['forwarder', 'Forwarder']]},
  {name: 'address', label: 'Service address', placeholder: '10.0.0.53'},
  {name: 'host', label: 'Runs on', type: 'select', options: [['', '— none —']]},
  {name: 'zones', label: 'Zones', placeholder: 'lab.lan, 0.0.10.in-addr.arpa'},
  {name: 'url', label: 'Management URL'},
  {name: 'status', label: 'Status', type: 'select', def: 'active',
   options: ['active', 'planned', 'staged', 'offline', 'decommissioned']},
  {name: 'description', label: 'Description'},
];

const DHCP_RANGE_FIELDS = [
  {name: 'network_id', label: 'Network', type: 'select', options: []},
  {name: 'name', label: 'Name', placeholder: 'main pool'},
  {name: 'start_addr', label: 'First address', placeholder: '10.0.0.100'},
  {name: 'end_addr', label: 'Last address', placeholder: '10.0.0.199'},
  {name: 'server_id', label: 'Served by', type: 'select', options: [['', '— unknown —']]},
  {name: 'lease_time', label: 'Lease time', def: '12h', placeholder: '12h / 90m / infinite'},
  {name: 'enabled', label: 'Enabled', type: 'checkbox', def: true,
   help: 'A disabled range keeps its definition but stops consuming address space.'},
  {name: 'description', label: 'Description'},
];

const DHCP_OPTION_FIELDS = [
  {name: 'network_id', label: 'Network', type: 'select', options: []},
  {name: 'option', label: 'Option', placeholder: 'option:ntp-server — or a bare code like 42',
   help: 'dnsmasq spelling, the canonical form every renderer translates from. Router, DNS ' +
         'servers and the domain are refused here on purpose: they live on the network itself, ' +
         'so the address plan and DHCP cannot disagree.'},
  {name: 'value', label: 'Value', placeholder: '10.0.0.5 (comma-separated for list options)'},
  {name: 'enabled', label: 'Enabled', type: 'checkbox', def: true,
   help: 'A disabled option keeps its definition but is left out of every rendered payload.'},
  {name: 'description', label: 'Description'},
];

async function dhcpOptionModal(id, presetNetworkId) {
  const fields = DHCP_OPTION_FIELDS.map(f => ({...f}));
  const nets = await API.get('/api/networks');
  fields.find(f => f.name === 'network_id').options =
    nets.networks.filter(n => n.role !== 'container').map(n => [n.id, n.cidr + (n.name ? ' — ' + n.name : '')]);

  let rec = id ? await API.get('/api/dhcp/options/' + id) : null;
  if (!rec && presetNetworkId) rec = {network_id: presetNetworkId, enabled: true};
  if (rec) rec.enabled = rec.enabled !== 0 && rec.enabled !== false;

  openModal(id ? 'Edit DHCP option' : 'Add DHCP option',
    buildForm(fields, rec) +
    `<button class="btn" onclick="saveResource('/api/dhcp/options', ${id || 0}, DHCP_OPTION_FORM)">${id ? 'Save' : 'Add'}</button>`);
  window.DHCP_OPTION_FORM = fields;
}

// Flip just the enabled flag; partial-update semantics keep everything else.
async function dhcpOptionToggle(id, to) {
  try {
    await API.post('/api/dhcp/options/' + id, {enabled: to});
    reloadPage();
  } catch (e) { alert(e.message); }
}

// ─── DHCP page ────────────────────────────────────────────

async function page_dhcp() {
  const d = await API.get('/api/dhcp/overview');

  $('page-content').innerHTML = `
    <div class="page-header"><h2>DHCP</h2></div>
    <p class="help">Ranges are tracked generically, whatever software serves them — every address
      inside an enabled range counts as consumed in its network's utilization.</p>

    <h3>Servers</h3>
    ${canWrite() ? `<div class="toolbar"><button class="btn btn-sm" onclick="dhcpServerModal()">+ Add DHCP server</button></div>` : ''}
    ${dataTable([
      {label: 'Name', get: s => escapeHtml(s.name)},
      {label: 'Software', get: s => typeBadge(s.kind)},
      {label: 'Address', get: s => escapeHtml(s.address || '') || '<span class="muted">—</span>'},
      {label: 'Ranges', cls: 'num', get: s => s.range_count},
      {label: 'Manage', get: s => s.url
        ? `<a href="${escapeHtml(s.url)}" target="_blank" rel="noopener">open &#8599;</a>` : '<span class="muted">—</span>'},
      {label: 'Status', get: s => statusBadge(s.status)},
      {label: '', cls: 'row-actions', get: s => canWrite() ? `
        <button class="btn btn-sm btn-outline" onclick="dhcpServerModal(${s.id})">Edit</button>
        <button class="btn btn-sm btn-danger" onclick="deleteResource('/api/dhcp/servers', ${s.id}, '${jsArg(s.name)}')">Delete</button>` : ''},
    ], d.servers, 'No DHCP servers recorded')}

    <h3 style="margin-top:24px">Ranges <span class="help">(${fmtNum(d.total_pool_addresses)} addresses in enabled pools)</span></h3>
    ${canWrite() ? `<div class="toolbar"><button class="btn btn-sm" onclick="dhcpRangeModal()">+ Add range</button></div>` : ''}
    ${dataTable([
      {label: 'Range', get: r => `<span class="cidr">${escapeHtml(r.start_addr)} – ${escapeHtml(r.end_addr)}</span>`},
      {label: 'Name', get: r => escapeHtml(r.name || '')},
      {label: 'Network', get: r => r.network_id
        ? `<a class="cidr" onclick="showPage('networks', ${r.network_id})">${escapeHtml(r.network_cidr)}</a>` : ''},
      {label: 'Server', get: r => escapeHtml(r.server_name || '') || '<span class="muted">—</span>'},
      {label: 'Size', cls: 'num', get: r => fmtNum(r.size)},
      {label: 'Static inside', cls: 'num', get: r => r.static_inside
        ? `${r.static_inside} <span class="muted">(${r.pct_static}%)</span>` : '0'},
      {label: 'Lease', get: r => escapeHtml(r.lease_time)},
      {label: 'State', get: r => `<span class="status-badge ${r.enabled ? 'green' : 'gray'}">${r.enabled ? 'enabled' : 'disabled'}</span>`},
      {label: '', cls: 'row-actions', get: r => canWrite() ? `
        <button class="btn btn-sm btn-outline" onclick="dhcpRangeModal(${r.id})">Edit</button>
        <button class="btn btn-sm btn-danger" onclick="deleteResource('/api/dhcp/ranges', ${r.id}, '${jsArg(r.start_addr)} – ${jsArg(r.end_addr)}')">Delete</button>` : ''},
    ], d.ranges, 'No DHCP ranges defined')}

    <h3 style="margin-top:24px">Export</h3>
    <p class="help">Reservations in the JSON body DNSMAQ-MGR's <code>/api/dhcp/static_leases</code> accepts —
      every IPv4 record that carries a MAC.</p>
    <div class="toolbar">
      <a class="btn btn-sm btn-outline" href="/api/export/dnsmasq/static-leases" target="_blank">Static leases (JSON)</a>
    </div>`;
}

async function dhcpServerModal(id) {
  const fields = DHCP_SERVER_FIELDS.map(f => ({...f}));
  fields.find(f => f.name === 'host').options = await hostOptions(true);
  let rec = id ? await API.get('/api/dhcp/servers/' + id) : null;
  if (rec && rec.host_kind) rec.host = `${rec.host_kind}:${rec.host_id}`;
  openModal(id ? 'Edit DHCP server' : 'Add DHCP server',
    buildForm(fields, rec) +
    `<button class="btn" onclick="saveServer('/api/dhcp/servers', ${id || 0}, DHCP_SERVER_FORM)">${id ? 'Save' : 'Add'}</button>`);
  window.DHCP_SERVER_FORM = fields;
}

async function dnsServerModal(id) {
  const fields = DNS_SERVER_FIELDS.map(f => ({...f}));
  fields.find(f => f.name === 'host').options = await hostOptions(true);
  let rec = id ? await API.get('/api/dns/servers/' + id) : null;
  if (rec && rec.host_kind) rec.host = `${rec.host_kind}:${rec.host_id}`;
  openModal(id ? 'Edit DNS server' : 'Add DNS server',
    buildForm(fields, rec) +
    `<button class="btn" onclick="saveServer('/api/dns/servers', ${id || 0}, DNS_SERVER_FORM)">${id ? 'Save' : 'Add'}</button>`);
  window.DNS_SERVER_FORM = fields;
}

// Both server forms use the merged "runs on" picker, so they share a save path.
async function saveServer(path, id, fields) {
  const body = readFields(fields);
  const picked = body.host || '';
  delete body.host;
  if (picked) {
    const [kind, hid] = picked.split(':');
    body.host_kind = kind;
    body.host_id = Number(hid);
  } else {
    body.host_kind = '';
    body.host_id = null;
  }
  try {
    await API.post(path + (id ? '/' + id : ''), body);
    closeModal();
    reloadPage();
  } catch (e) { alert(e.message); }
}

async function dhcpRangeModal(id, presetNetworkId) {
  const fields = DHCP_RANGE_FIELDS.map(f => ({...f}));
  const [nets, servers] = await Promise.all([
    API.get('/api/networks'),
    selectOptions('/api/dhcp/servers', 'dhcp_servers', s => s.name),
  ]);
  fields.find(f => f.name === 'network_id').options =
    nets.networks.filter(n => n.role !== 'container').map(n => [n.id, n.cidr + (n.name ? ' — ' + n.name : '')]);
  fields.find(f => f.name === 'server_id').options = servers;

  let rec = id ? await API.get('/api/dhcp/ranges/' + id) : null;
  if (!rec && presetNetworkId) rec = {network_id: presetNetworkId, lease_time: '12h', enabled: true};
  if (rec) rec.enabled = rec.enabled !== 0 && rec.enabled !== false;

  openModal(id ? 'Edit DHCP range' : 'Add DHCP range',
    buildForm(fields, rec) +
    `<button class="btn" onclick="saveResource('/api/dhcp/ranges', ${id || 0}, DHCP_RANGE_FORM)">${id ? 'Save' : 'Add'}</button>`);
  window.DHCP_RANGE_FORM = fields;
}

// ─── DNS page ─────────────────────────────────────────────

async function page_dns() {
  const d = await API.get('/api/dns/overview');
  const domains = [...new Set(d.servers.flatMap(s => s.zone_list || []))];

  $('page-content').innerHTML = `
    <div class="page-header"><h2>DNS</h2></div>
    <h3>Servers</h3>
    ${canWrite() ? `<div class="toolbar"><button class="btn btn-sm" onclick="dnsServerModal()">+ Add DNS server</button></div>` : ''}
    ${dataTable([
      {label: 'Name', get: s => escapeHtml(s.name)},
      {label: 'Software', get: s => typeBadge(s.kind)},
      {label: 'Role', get: s => typeBadge(s.role)},
      {label: 'Address', get: s => escapeHtml(s.address || '') || '<span class="muted">—</span>'},
      {label: 'Zones', get: s => (s.zone_list || []).map(z => typeBadge(z)).join(' ') || '<span class="muted">—</span>'},
      {label: 'Manage', get: s => s.url
        ? `<a href="${escapeHtml(s.url)}" target="_blank" rel="noopener">open &#8599;</a>` : '<span class="muted">—</span>'},
      {label: 'Status', get: s => statusBadge(s.status)},
      {label: '', cls: 'row-actions', get: s => canWrite() ? `
        <button class="btn btn-sm btn-outline" onclick="dnsServerModal(${s.id})">Edit</button>
        <button class="btn btn-sm btn-danger" onclick="deleteResource('/api/dns/servers', ${s.id}, '${jsArg(s.name)}')">Delete</button>` : ''},
    ], d.servers, 'No DNS servers recorded')}

    <h3 style="margin-top:24px">Name records</h3>
    <p class="help">${fmtNum(d.named_addresses)} address record(s) carry a DNS name. Bare hostnames are
      qualified with their network's domain on export.</p>
    <div class="toolbar">
      <a class="btn btn-sm btn-outline" href="/api/export/hosts" target="_blank">hosts file</a>
      <a class="btn btn-sm btn-outline" href="/api/export/dnsmasq/hosts" target="_blank">dnsmasq host records (JSON)</a>
      ${domains.map(z => `<a class="btn btn-sm btn-outline" href="/api/export/zone?domain=${encodeURIComponent(z)}" target="_blank">zone: ${escapeHtml(z)}</a>`).join('')}
    </div>
    <p class="help">The JSON export matches the body DNSMAQ-MGR's <code>/api/dns/hosts</code> endpoint accepts,
      so a sync script can fetch here and POST there without translating anything.</p>

    <h3 style="margin-top:24px">DHCP-side names</h3>
    <p class="help">Names the DHCP server resolves that this plan does not publish — a reservation's
      Local DNS Record, its UniFi label, or the hostname the device itself claimed. Adopting takes
      the name into the plan (canonical if the address has none, an alias otherwise); publishing it
      is then an ordinary push. <strong>Adopting a Local DNS Record is a handover</strong>: the next
      push unticks the client's own record and Static DNS takes over. Lease-derived names are
      listed but never adopted — a dynamic name in authoritative DNS goes stale on its own.</p>
    <div class="toolbar"><button class="btn btn-sm" onclick="loadNameCandidates(this)">Scan for candidates</button></div>
    <div id="name-candidates"></div>`;
}

// Reads every gateway target live, so it runs on demand rather than on page load.
async function loadNameCandidates(btn) {
  if (btn) { btn.disabled = true; btn.textContent = 'Scanning…'; }
  let r;
  try { r = await API.get('/api/names/candidates'); }
  catch (e) {
    $('name-candidates').innerHTML = `<div class="alert alert-danger">${escapeHtml(e.message)}</div>`;
    if (btn) { btn.disabled = false; btn.textContent = 'Scan for candidates'; }
    return;
  }
  if (btn) { btn.disabled = false; btn.textContent = 'Rescan'; }
  const conf = {high: 'green', medium: 'yellow', low: 'gray'};
  const flags = c => [
    c.dynamic ? '<span class="status-badge gray" title="From a lease, not a reservation — never adopted">dynamic</span>' : '',
    !c.valid ? '<span class="status-badge red" title="Not a valid DNS name — would be dropped, never mangled">invalid</span>' : '',
    c.conflict ? `<span class="status-badge red" title="Already points at ${escapeHtml(c.conflict)}">conflict</span>` : '',
    c.handover ? '<span class="status-badge yellow" title="Adopting unticks the client record on the next push">handover</span>' : '',
    !c.recorded ? '<span class="status-badge gray" title="Address has no plan record — pull the gateway first">unrecorded</span>' : '',
  ].filter(Boolean).join(' ');
  $('name-candidates').innerHTML = `
    ${(r.errors || []).map(e => `<div class="alert alert-warning">${escapeHtml(e)}</div>`).join('')}
    ${dataTable([
      {label: 'Address', sortKey: 'address', get: c => `<a class="cidr" onclick="addressPeek('${jsArg(c.address)}')">${escapeHtml(c.address)}</a>`},
      {label: 'DHCP-side name', get: c => escapeHtml(c.name)},
      {label: 'Would publish', get: c => `<code>${escapeHtml(c.fqdn)}</code>`},
      {label: 'Source', get: c => `${typeBadge(c.source)} <span class="status-badge ${conf[c.confidence] || 'gray'}">${escapeHtml(c.confidence)}</span>`},
      {label: '', get: flags},
      {label: '', cls: 'row-actions', get: c =>
        canWrite() && !c.dynamic && c.valid && !c.conflict && c.recorded
          ? `<button class="btn btn-sm" onclick="adoptCandidate('${jsArg(c.address)}')">Adopt</button>` : ''},
    ], r.candidates, 'Nothing — every DHCP-side name is already in the plan', {key: 'namecands'})}`;
}

async function adoptCandidate(address) {
  try {
    const r = await API.post('/api/names/adopt', {addresses: [address]});
    if (r.adopted.length) {
      const a = r.adopted[0];
      alert(`${a.fqdn} adopted as ${a.as} for ${a.address}.` +
            (a.handover ? '\n\nThe next push takes this name over from the client record.' : '') +
            '\n\nPublish with Push now (Settings → Push targets).');
    } else if (r.refused.length) {
      alert(r.refused[0].reason);
    }
  } catch (e) { alert(e.message); }
  loadNameCandidates();
}
