// IP address records: the searchable master list and the edit form.

const ADDRESS_FIELDS = [
  {name: 'address', label: 'IP address', placeholder: '10.0.0.42'},
  {name: 'status', label: 'Status', type: 'select', def: 'active',
   options: [['active', 'Active — in use'],
             ['reserved', 'Reserved — held, never allocated'],
             ['dhcp', 'DHCP — handed out dynamically'],
             ['deprecated', 'Deprecated — retired, not reusable yet']]},
  {name: 'assigned', label: 'Assigned to', type: 'select', options: [['', '— none —']],
   help: 'A device, VM, container or cluster. The address follows whatever you pick.'},
  {name: 'dns_name', label: 'DNS name', placeholder: 'web01 or web01.lab.lan'},
  {name: 'if_name', label: 'Interface', placeholder: 'eth0'},
  {name: 'mac', label: 'MAC address', placeholder: 'aa:bb:cc:dd:ee:ff'},
  {name: 'is_primary', label: 'Primary address for this object', type: 'checkbox'},
  {name: 'description', label: 'Description'},
];

// Shared by the addresses page and the network detail page so a row looks the
// same wherever it appears.
function addressColumns(opts) {
  opts = opts || {};
  const cols = [
    {label: 'Address', sortKey: 'addr_hex', get: a => `<a class="cidr" onclick="addressPeek('${jsArg(a.address)}')">${escapeHtml(a.address)}</a>`},
    {label: 'Status', sortKey: 'status', get: a => statusBadge(a.status)},
    {label: 'DNS name', sortKey: 'dns_name', get: a => escapeHtml(a.dns_name || '') || '<span class="muted">—</span>'},
    {label: 'Assigned to', sortKey: 'assigned_name', get: a => a.assigned_kind
      ? objLink(a.assigned_kind, a.assigned_id, a.assigned_name) + ' ' + typeBadge(a.assigned_kind)
      : '<span class="muted">—</span>'},
    {label: 'MAC', sortKey: 'mac', get: a => escapeHtml(a.mac || '') || '<span class="muted">—</span>'},
    {label: 'Ping', sortKey: a => a.last_alive || 0, get: a => a.last_scan
      ? (a.last_alive ? '<span class="status-badge green">up</span>' : '<span class="status-badge gray">silent</span>')
      : '<span class="muted">—</span>'},
  ];
  if (opts.showNetwork !== false) {
    cols.splice(1, 0, {label: 'Network', sortKey: 'network_cidr', get: a => a.network_id
      ? `<a class="cidr" onclick="showPage('networks', ${a.network_id})">${escapeHtml(a.network_cidr)}</a>`
      : '<span class="muted">unmanaged</span>'});
  }
  cols.push({label: '', cls: 'row-actions', get: a => canWrite() ? `
    <button class="btn btn-sm btn-outline" onclick="addressModal(${a.id})">Edit</button>
    <button class="btn btn-sm btn-danger" onclick="deleteResource('/api/addresses', ${a.id}, '${jsArg(a.address)}')">Delete</button>` : ''});
  if (opts.bulk && canWrite()) cols.unshift(bulkCol('/api/addresses', a => a.address));
  return cols;
}

let _addrFilters = {q: '', network_id: '', status: '', assigned_kind: '', unassigned: false};

async function page_addresses(id) {
  // Arriving with an id (from a search hit) opens that record directly.
  if (id) {
    const rec = await API.get('/api/addresses/' + id).catch(() => null);
    if (rec) { showPage('addresses'); setTimeout(() => addressPeek(rec.address), 50); return; }
  }

  const [nets] = await Promise.all([API.get('/api/networks')]);
  const params = new URLSearchParams();
  Object.entries(_addrFilters).forEach(([k, v]) => { if (v) params.set(k, v === true ? '1' : v); });
  params.set('limit', '2000');   // client-side pagination handles the volume
  const data = await API.get('/api/addresses/search?' + params.toString());

  const netOpts = [['', 'All networks']].concat(
    nets.networks.map(n => [n.id, n.cidr + (n.name ? ' — ' + n.name : '')]));

  $('page-content').innerHTML = `
    <div class="page-header"><h2>IP Addresses</h2></div>
    ${canWrite() ? `<div class="toolbar"><button class="btn btn-sm" onclick="addressModal()">+ Add address</button>
      <button class="btn btn-sm" onclick="provisionModal()">Provision host</button>
      <button class="btn btn-sm btn-outline" onclick="importAddressesModal()">Import</button>
      <a class="btn btn-sm btn-outline" href="/api/export/csv">Export CSV</a>${bulkBtn()}</div>` : ''}
    <div class="filters">
      <div class="form-group grow"><label>Search</label>
        <input id="fl-q" class="form-control" value="${escapeHtml(_addrFilters.q)}"
          placeholder="address, hostname, MAC or description" onkeydown="if(event.key==='Enter')applyAddrFilters()"></div>
      <div class="form-group"><label>Network</label>
        <select id="fl-net" class="form-control" onchange="applyAddrFilters()">
          ${netOpts.map(([v, l]) => `<option value="${escapeHtml(v)}" ${String(_addrFilters.network_id) === String(v) ? 'selected' : ''}>${escapeHtml(l)}</option>`).join('')}
        </select></div>
      <div class="form-group"><label>Status</label>
        <select id="fl-status" class="form-control" onchange="applyAddrFilters()">
          ${[['', 'Any'], 'active', 'reserved', 'dhcp', 'deprecated'].map(o => {
            const [v, l] = Array.isArray(o) ? o : [o, o];
            return `<option value="${escapeHtml(v)}" ${_addrFilters.status === v ? 'selected' : ''}>${escapeHtml(l)}</option>`;
          }).join('')}
        </select></div>
      <div class="form-group"><label>Assigned to</label>
        <select id="fl-kind" class="form-control" onchange="applyAddrFilters()">
          ${[['', 'Anything'], 'device', 'vm', 'container', 'cluster'].map(o => {
            const [v, l] = Array.isArray(o) ? o : [o, o];
            return `<option value="${escapeHtml(v)}" ${_addrFilters.assigned_kind === v ? 'selected' : ''}>${escapeHtml(l)}</option>`;
          }).join('')}
        </select></div>
      <button class="btn btn-sm" onclick="applyAddrFilters()">Apply</button>
      <button class="btn btn-sm btn-outline" onclick="clearAddrFilters()">Clear</button>
    </div>
    <p class="help">${data.count} record(s)${data.count === data.limit ? ` — showing the first ${data.limit}; narrow the filters to see more` : ''}</p>
    ${dataTable(addressColumns({bulk: true}), data.addresses, 'No address records match these filters', {key: 'addresses'})}`;
}

function applyAddrFilters() {
  _addrFilters.q = $('fl-q').value.trim();
  _addrFilters.network_id = $('fl-net').value;
  _addrFilters.status = $('fl-status').value;
  _addrFilters.assigned_kind = $('fl-kind').value;
  page_addresses();
}

function clearAddrFilters() {
  _addrFilters = {q: '', network_id: '', status: '', assigned_kind: '', unassigned: false};
  page_addresses();
}

async function addressModal(id, networkId, presetAddress) {
  const fields = ADDRESS_FIELDS.map(f => ({...f}));
  fields.find(f => f.name === 'assigned').options = await hostOptions(true);

  let rec = null, names = null;
  if (id) {
    rec = await API.get('/api/addresses/' + id);
    rec.assigned = rec.assigned_kind ? `${rec.assigned_kind}:${rec.assigned_id}` : '';
    names = (await API.get('/api/addresses/' + id + '/names').catch(() => ({names: []}))).names;
  } else if (presetAddress) {
    rec = {address: presetAddress, status: 'active'};
  }

  // Multiple names on one IP are first-class (parallel A records). The list
  // is authoritative: first line is the canonical name (answers PTR); a
  // leading # disables a name without forgetting it.
  const namesBlock = id ? `
    <div class="form-group"><label>DNS names (one per line — first is canonical; prefix # to disable)</label>
      <textarea id="addr-names" class="form-control" rows="3" spellcheck="false">${
        escapeHtml((names || []).map(n => (n.enabled ? '' : '#') + n.name).join('\n'))}</textarea></div>` : '';

  openModal(id ? 'Edit address' : 'Add address',
    buildForm(fields, rec) + namesBlock +
    `<button class="btn" onclick="saveAddress(${id || 0})">${id ? 'Save' : 'Add'}</button>`);
  window.ADDRESS_FORM = fields;
  window.ADDRESS_NAMES_OLD = names || [];
}

async function saveAddress(id) {
  const body = readFields(window.ADDRESS_FORM);
  // The "assigned" select packs kind and id into one value; unpack it into
  // the two fields the API takes.
  const picked = body.assigned || '';
  delete body.assigned;
  if (picked) {
    const [kind, oid] = picked.split(':');
    body.assigned_kind = kind;
    body.assigned_id = Number(oid);
  } else {
    body.assigned_kind = '';
    body.assigned_id = null;
  }
  try {
    // The names list is authoritative when present — dns_name rides along for
    // the simple case but the textarea decides the full ordered set.
    if (id && $('addr-names')) {
      const old = Object.fromEntries((window.ADDRESS_NAMES_OLD || []).map(n => [n.name.toLowerCase(), n]));
      const list = $('addr-names').value.split('\n').map(x => x.trim()).filter(Boolean).map(line => {
        const enabled = !line.startsWith('#');
        const name = line.replace(/^#+\s*/, '');
        const prev = old[name.toLowerCase()] || {};
        return {name, enabled, rtype: prev.rtype || 'a',
                comment: prev.comment || '', ext_id: prev.ext_id || ''};
      });
      body.dns_name = list.find(n => n.enabled) ? list.find(n => n.enabled).name : '';
      await API.post('/api/addresses/' + id, body);
      await API.post('/api/addresses/' + id + '/names', {names: list});
    } else {
      await API.post('/api/addresses' + (id ? '/' + id : ''), body);
    }
    closeModal();
    reloadPage();
  } catch (e) { alert(e.message); }
}

// ─── Provision (allocate + names + DNS push, one action) ─────────────
async function provisionModal() {
  const nets = (await API.get('/api/networks')).networks;
  openModal('Provision host', `
    <p class="help">Next free address in the network, recorded with its name and pushed to the
      DNS nodes in one step. Deprovision from the address row menu reverses all of it.</p>
    <div class="form-group"><label>DNS name</label>
      <input id="pv-name" class="form-control" placeholder="newhost.example.net" spellcheck="false"></div>
    <div class="form-group"><label>Network</label>
      <select id="pv-net" class="form-control">
        ${nets.map(n => `<option value="${n.id}">${escapeHtml(n.cidr + (n.name ? ' — ' + n.name : ''))}</option>`).join('')}
      </select></div>
    <div class="form-group"><label>MAC (optional — recorded for the future DHCP reservation)</label>
      <input id="pv-mac" class="form-control" placeholder="aa:bb:cc:dd:ee:ff" spellcheck="false"></div>
    <button class="btn" onclick="provisionGo(this)">Provision</button>
    <div id="pv-result"></div>`);
}

async function provisionGo(btn) {
  btn.disabled = true;
  try {
    const r = await API.post('/api/provision', {
      name: $('pv-name').value.trim(),
      network_id: Number($('pv-net').value),
      mac: $('pv-mac').value.trim(),
    });
    const push = r.push ? r.push.results.map(x => `${x.name} ${x.ok ? 'ok' : 'FAILED'}`).join(', ') : 'no push targets';
    $('pv-result').innerHTML = `<div class="health-ok">✓ ${escapeHtml(r.names[0].name)} = ${escapeHtml(r.address)}
      · gateway ${escapeHtml(r.gateway || '-')} · DNS push: ${escapeHtml(push)}</div>
      <div class="toolbar" style="margin-top:8px"><button class="btn btn-sm" onclick="closeModal(); reloadPage();">Done</button></div>`;
  } catch (e) {
    $('pv-result').innerHTML = `<div class="alert alert-warning">${escapeHtml(e.message)}</div>`;
    btn.disabled = false;
  }
}

function importAddressesModal() {
  openModal('Import addresses', `
    <p class="help">One address per line: <code>IP [hostname] [MAC]</code>. Lines starting
      with # are ignored. Existing records are skipped unless you tick overwrite —
      so re-running an import is safe.</p>
    <div class="form-group"><label>Records</label>
      <textarea id="imp-text" class="form-control" rows="12"
        placeholder="10.0.0.10  nas01  aa:bb:cc:dd:ee:01&#10;10.0.0.11  printer"></textarea></div>
    <label class="checkitem" style="padding-left:0"><input id="imp-replace" type="checkbox"> Overwrite existing records</label>
    <button class="btn" onclick="doImportAddresses()">Import</button>`);
}

async function doImportAddresses() {
  const lines = $('imp-text').value.split('\n').map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
  const addresses = lines.map(line => {
    const parts = line.split(/[\s,]+/);
    const rec = {address: parts[0]};
    parts.slice(1).forEach(p => {
      if (/^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(p)) rec.mac = p;
      else if (!rec.dns_name) rec.dns_name = p;
    });
    return rec;
  });
  if (!addresses.length) { alert('Nothing to import'); return; }
  try {
    const r = await API.post('/api/addresses/bulk',
      {addresses, replace: $('imp-replace').checked, source: 'import'});
    closeModal();
    const errs = (r.errors || []).slice(0, 5).map(e => `  line ${e.index + 1}: ${e.error}`).join('\n');
    alert(`Created ${r.created}, updated ${r.updated}, skipped ${r.skipped}.` +
          (r.errors && r.errors.length ? `\n\n${r.errors.length} error(s):\n${errs}` : ''));
    reloadPage();
  } catch (e) { alert(e.message); }
}
