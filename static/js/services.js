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
      so a sync script can fetch here and POST there without translating anything.</p>`;
}
