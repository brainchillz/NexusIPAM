// VLANs — layer-2 domains that networks attach to.

const VLAN_FIELDS = [
  {name: 'vid', label: 'VLAN ID', type: 'number', placeholder: '10',
   help: '1–4094. Unique per site, so the same VID may exist at two sites.'},
  {name: 'name', label: 'Name', placeholder: 'servers'},
  {name: 'site', label: 'Site', placeholder: 'main'},
  {name: 'status', label: 'Status', type: 'select', def: 'active',
   options: ['active', 'planned', 'staged', 'offline', 'decommissioned']},
  {name: 'description', label: 'Description'},
];

async function page_vlans() {
  const [data, nets] = await Promise.all([API.get('/api/vlans'), API.get('/api/networks')]);
  const netsByVlan = {};
  nets.networks.forEach(n => {
    if (n.vlan_id) (netsByVlan[n.vlan_id] = netsByVlan[n.vlan_id] || []).push(n);
  });

  const cols = [
      {label: 'VID', cls: 'num', get: v => `<span class="cidr">${escapeHtml(v.vid)}</span>`},
      {label: 'Name', get: v => escapeHtml(v.name || '')},
      {label: 'Site', get: v => escapeHtml(v.site || '') || '<span class="muted">—</span>'},
      {label: 'Status', get: v => statusBadge(v.status)},
      {label: 'Networks', get: v => (netsByVlan[v.id] || []).map(n =>
        `<a class="cidr" onclick="showPage('networks', ${n.id})">${escapeHtml(n.cidr)}</a>`).join(', ')
        || '<span class="muted">none</span>'},
      {label: 'Description', get: v => escapeHtml(v.description || '')},
      {label: '', cls: 'row-actions', get: v => canWrite() ? `
        <button class="btn btn-sm btn-outline" onclick="vlanModal(${v.id})">Edit</button>
        <button class="btn btn-sm btn-danger" onclick="deleteResource('/api/vlans', ${v.id}, 'VLAN ${jsArg(v.vid)}')">Delete</button>` : ''},
  ];
  if (canWrite()) cols.unshift(bulkCol('/api/vlans', v => 'VLAN ' + v.vid));

  $('page-content').innerHTML = `
    <div class="page-header"><h2>VLANs</h2></div>
    ${canWrite() ? `<div class="toolbar"><button class="btn btn-sm" onclick="vlanModal()">+ Add VLAN</button>${bulkBtn()}</div>` : ''}
    ${dataTable(cols, data.vlans, 'No VLANs defined')}
    <p class="help">Deleting a VLAN leaves its networks in place — they simply lose the VLAN link.</p>`;
}

async function vlanModal(id) {
  const rec = id ? await API.get('/api/vlans/' + id) : null;
  openModal(id ? 'Edit VLAN' : 'Add VLAN',
    buildForm(VLAN_FIELDS, rec) +
    `<button class="btn" onclick="saveResource('/api/vlans', ${id || 0}, VLAN_FIELDS)">${id ? 'Save' : 'Add'}</button>`);
}
