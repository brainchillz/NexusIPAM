// Inventory pages: devices, clusters, VMs, containers, and the topology tree.
// All four listings share one renderer — they differ only in their columns and
// their form spec.

const CLUSTER_FIELDS = [
  {name: 'name', label: 'Name', placeholder: 'pve-cluster'},
  {name: 'kind', label: 'Type', type: 'select', def: 'proxmox',
   options: [['proxmox', 'Proxmox VE'], ['vsphere', 'vSphere / vCenter'],
             ['kubernetes', 'Kubernetes'], ['nomad', 'Nomad'],
             ['ai', 'AI — Ray, RPC, distributed compute'],
             ['storage', 'Storage — Ceph, Gluster, …'], ['other', 'Other']]},
  {name: 'endpoint', label: 'Endpoint', placeholder: 'https://vcenter.lab.lan'},
  {name: 'site', label: 'Site'},
  {name: 'status', label: 'Status', type: 'select', def: 'active',
   options: ['active', 'planned', 'staged', 'offline', 'decommissioned']},
  {name: 'description', label: 'Description'},
];

const DEVICE_FIELDS = [
  {name: 'name', label: 'Name', placeholder: 'pve-node1'},
  {name: 'role', label: 'Role', type: 'select', def: 'server',
   options: [['server', 'Server'], ['ai', 'AI'], ['storage', 'Storage'],
             ['mixed', 'Mixed — several jobs at once'], ['switch', 'Switch'],
             ['router', 'Router'], ['firewall', 'Firewall'], ['ap', 'Access point'],
             ['appliance', 'Appliance'], ['pdu', 'PDU'], ['other', 'Other']],
   help: 'One primary job. Use tags below when a box does several.'},
  {name: 'tags', label: 'Tags', placeholder: '#AI #Storage #Container',
   help: 'Free-form, space or comma separated. Hashes optional; everything is ' +
         'lower-cased so #AI and ai are the same tag. Click a tag in the list to filter.'},
  {name: 'cluster_id', label: 'Cluster', type: 'select', options: [['', '— none —']]},
  {name: 'virt', label: 'Hypervisor', type: 'select', def: '',
   options: [['', '— none —'], ['vsphere', 'vSphere'], ['proxmox', 'Proxmox'],
             ['kvm', 'KVM'], ['xen', 'Xen'], ['hyperv', 'Hyper-V']],
   help: 'Set this if the device hosts VMs — it is what lets you place VMs on it.'},
  {name: 'engine', label: 'Container engine', type: 'select', def: '',
   options: [['', '— none —'], ['docker', 'Docker'], ['lxd', 'LXD'], ['incus', 'Incus'],
             ['podman', 'Podman'], ['kubernetes', 'Kubernetes'], ['other', 'Other']]},
  {name: 'manufacturer', label: 'Manufacturer'},
  {name: 'model', label: 'Model'},
  {name: 'serial', label: 'Serial'},
  {name: 'site', label: 'Site'},
  {name: 'rack', label: 'Rack'},
  {name: 'position', label: 'Position', placeholder: 'U12'},
  {name: 'status', label: 'Status', type: 'select', def: 'active',
   options: ['active', 'planned', 'staged', 'offline', 'decommissioned']},
  {name: 'description', label: 'Description'},
];

const VM_FIELDS = [
  {name: 'name', label: 'Name', placeholder: 'web01'},
  {name: 'platform', label: 'Hypervisor', type: 'select', def: 'kvm',
   options: [['vsphere', 'vSphere'], ['proxmox', 'Proxmox'], ['kvm', 'KVM'],
             ['xen', 'Xen'], ['hyperv', 'Hyper-V']],
   help: 'An LXD or Incus VM is KVM underneath — record those as KVM.'},
  {name: 'host_device_id', label: 'Host device', type: 'select', options: [['', '— none —']]},
  {name: 'cluster_id', label: 'Cluster', type: 'select', options: [['', '— none —']]},
  {name: 'vmid', label: 'Platform ID', placeholder: '101 or vm-1234',
   help: 'Proxmox VMID or vSphere managed-object reference.'},
  {name: 'vcpus', label: 'vCPUs', type: 'number'},
  {name: 'memory_mb', label: 'Memory (MB)', type: 'number'},
  {name: 'disk_gb', label: 'Disk (GB)', type: 'number'},
  {name: 'os', label: 'Operating system', placeholder: 'Ubuntu 24.04'},
  {name: 'status', label: 'Status', type: 'select', def: 'active',
   options: ['active', 'planned', 'staged', 'offline', 'decommissioned']},
  {name: 'description', label: 'Description'},
];

const CONTAINER_FIELDS = [
  {name: 'name', label: 'Name', placeholder: 'nginx'},
  {name: 'engine', label: 'Engine', type: 'select', def: 'docker',
   options: [['docker', 'Docker'], ['lxd', 'LXD'], ['incus', 'Incus'],
             ['podman', 'Podman'], ['kubernetes', 'Kubernetes'], ['other', 'Other']]},
  {name: 'parent', label: 'Runs on', type: 'select', options: [['', '— none —']],
   help: 'The physical device or VM running the container engine.'},
  {name: 'cluster_id', label: 'Cluster', type: 'select', options: [['', '— none —']]},
  {name: 'image', label: 'Image', placeholder: 'nginx:1.27'},
  {name: 'status', label: 'Status', type: 'select', def: 'active',
   options: ['active', 'planned', 'staged', 'offline', 'decommissioned']},
  {name: 'description', label: 'Description'},
];

// ─── Listing pages ────────────────────────────────────────

async function page_clusters(id) {
  if (id) return objectDetail('cluster', id);
  const d = await API.get('/api/clusters');
  renderInventory('Clusters', 'clusters', d.clusters, [
    {label: 'Name', get: c => `<a onclick="showPage('clusters', ${c.id})">${escapeHtml(c.name)}</a>`},
    {label: 'Type', get: c => typeBadge(c.kind)},
    {label: 'Endpoint', get: c => escapeHtml(c.endpoint || '') || '<span class="muted">—</span>'},
    {label: 'Devices', cls: 'num', get: c => c.device_count},
    {label: 'VMs', cls: 'num', get: c => c.vm_count},
    {label: 'IPs', cls: 'num', get: c => c.ip_count},
    {label: 'Site', get: c => escapeHtml(c.site || '')},
    {label: 'Status', get: c => statusBadge(c.status)},
  ], 'clusterModal', 'No clusters — add one if you run Proxmox, vCenter or Kubernetes');
}

let _deviceTag = '';

function filterDevicesByTag(tag) { _deviceTag = tag; page_devices(); }
function clearDeviceTag() { _deviceTag = ''; page_devices(); }

async function page_devices(id) {
  if (id) return objectDetail('device', id);
  const [d, tags] = await Promise.all([
    API.get('/api/devices' + (_deviceTag ? '?tag=' + encodeURIComponent(_deviceTag) : '')),
    API.get('/api/tags').catch(() => ({tags: []})),
  ]);
  window._deviceTagBar = `
    <div class="filters" style="margin-bottom:12px">
      <span class="help" style="margin:0">Filter by tag:</span>
      ${(tags.tags || []).map(t => `<a class="badge-type" style="cursor:pointer${t.tag === _deviceTag ? ';outline:1px solid var(--primary)' : ''}"
         onclick="filterDevicesByTag('${jsArg(t.tag)}')">${escapeHtml(t.tag)} <span class="muted">${t.count}</span></a>`).join(' ')
        || '<span class="muted">none yet — add tags on a device</span>'}
      ${_deviceTag ? `<button class="btn btn-sm btn-outline" onclick="clearDeviceTag()">Clear filter</button>` : ''}
    </div>`;
  renderInventory('Devices', 'devices', d.devices, [
    {label: 'Name', get: r => `<a onclick="showPage('devices', ${r.id})">${escapeHtml(r.name)}</a>`},
    // Classification comes from NexusController (AI / Storage / Virtualization
    // / DNS / External / Mixed) and is the axis the fleet is actually organised
    // by; role is IPAM's own coarser vocabulary.
    {label: 'Class', get: r => (r.meta && r.meta.classification)
      ? typeBadge(r.meta.classification) : '<span class="muted">—</span>'},
    {label: 'Role', get: r => typeBadge(r.role)},
    {label: 'Tags', get: r => (r.tags || '').split(',').map(t => t.trim()).filter(Boolean)
      .map(t => `<a class="badge-type" style="cursor:pointer" onclick="filterDevicesByTag('${jsArg(t)}')">${escapeHtml(t)}</a>`)
      .join(' ') || '<span class="muted">—</span>'},
    {label: 'Cluster', get: r => r.cluster_id ? objLink('cluster', r.cluster_id, r.cluster_name) : '<span class="muted">—</span>'},
    {label: 'Hosts', get: r => [r.virt ? 'VMs (' + r.virt + ')' : '', r.engine ? 'containers (' + r.engine + ')' : '']
      .filter(Boolean).map(t => typeBadge(t)).join(' ') || '<span class="muted">—</span>'},
    {label: 'VMs', cls: 'num', get: r => r.vm_count},
    {label: 'Containers', cls: 'num', get: r => r.container_count},
    {label: 'IPs', cls: 'num', get: r => r.ip_count},
    {label: 'Location', get: r => escapeHtml([r.site, r.rack, r.position].filter(Boolean).join(' / '))},
    {label: 'Status', get: r => statusBadge(r.status)},
  ], 'deviceModal', _deviceTag ? `No devices tagged "${_deviceTag}"`
                                : 'No devices — add your physical servers, switches and routers');
}

async function page_vms(id) {
  if (id) return objectDetail('vm', id);
  const d = await API.get('/api/vms');
  renderInventory('Virtual Machines', 'vms', d.vms, [
    {label: 'Name', get: r => `<a onclick="showPage('vms', ${r.id})">${escapeHtml(r.name)}</a>`},
    {label: 'Hypervisor', get: r => typeBadge(r.platform)},
    {label: 'Host', get: r => r.host_device_id ? objLink('device', r.host_device_id, r.host_name) : '<span class="muted">—</span>'},
    {label: 'Cluster', get: r => r.cluster_id ? objLink('cluster', r.cluster_id, r.cluster_name) : '<span class="muted">—</span>'},
    {label: 'Size', get: r => escapeHtml([r.vcpus ? r.vcpus + ' vCPU' : '',
      r.memory_mb ? Math.round(r.memory_mb / 1024) + ' GB' : '',
      r.disk_gb ? r.disk_gb + ' GB disk' : ''].filter(Boolean).join(' · ')) || '<span class="muted">—</span>'},
    {label: 'Containers', cls: 'num', get: r => r.container_count},
    {label: 'IPs', cls: 'num', get: r => r.ip_count},
    {label: 'Status', get: r => statusBadge(r.status)},
  ], 'vmModal', 'No virtual machines recorded');
}

async function page_containers(id) {
  if (id) return objectDetail('container', id);
  const d = await API.get('/api/containers');
  renderInventory('Containers', 'containers', d.containers, [
    {label: 'Name', get: r => `<a onclick="showPage('containers', ${r.id})">${escapeHtml(r.name)}</a>`},
    {label: 'Engine', get: r => typeBadge(r.engine)},
    {label: 'Runs on', get: r => r.parent_kind
      ? objLink(r.parent_kind, r.parent_id, r.parent_name) + ' ' + typeBadge(r.parent_kind)
      : '<span class="muted">—</span>'},
    {label: 'Image', get: r => escapeHtml(r.image || '') || '<span class="muted">—</span>'},
    {label: 'IPs', cls: 'num', get: r => r.ip_count},
    {label: 'Status', get: r => statusBadge(r.status)},
  ], 'containerModal', 'No containers recorded');
}

function renderInventory(title, path, rows, cols, modalFn, empty) {
  const withActions = cols.concat([{label: '', cls: 'row-actions', get: r => canWrite() ? `
    <button class="btn btn-sm btn-outline" onclick="${modalFn}(${r.id})">Edit</button>
    <button class="btn btn-sm btn-danger" onclick="deleteResource('/api/${path}', ${r.id}, '${jsArg(r.name)}')">Delete</button>` : ''}]);
  if (canWrite()) withActions.unshift(bulkCol('/api/' + path, r => r.name));
  const tagBar = path === 'devices' ? (window._deviceTagBar || '') : '';
  $('page-content').innerHTML = `
    <div class="page-header"><h2>${escapeHtml(title)}</h2></div>
    ${canWrite() ? `<div class="toolbar"><button class="btn btn-sm" onclick="${modalFn}()">+ Add</button>${bulkBtn()}</div>` : ''}
    ${tagBar}
    ${dataTable(withActions, rows, empty)}`;
}

// ─── Forms ────────────────────────────────────────────────

async function clusterModal(id) {
  const rec = id ? await API.get('/api/clusters/' + id) : null;
  openModal(id ? 'Edit cluster' : 'Add cluster',
    buildForm(CLUSTER_FIELDS, rec) +
    `<button class="btn" onclick="saveResource('/api/clusters', ${id || 0}, CLUSTER_FIELDS, afterInventorySave)">${id ? 'Save' : 'Add'}</button>`);
}

async function deviceModal(id) {
  const fields = DEVICE_FIELDS.map(f => ({...f}));
  fields.find(f => f.name === 'cluster_id').options =
    await selectOptions('/api/clusters', 'clusters', c => c.name);
  const rec = id ? await API.get('/api/devices/' + id) : null;
  openModal(id ? 'Edit device' : 'Add device',
    buildForm(fields, rec) +
    `<button class="btn" onclick="saveResource('/api/devices', ${id || 0}, DEVICE_FORM, afterInventorySave)">${id ? 'Save' : 'Add'}</button>`);
  window.DEVICE_FORM = fields;
}

async function vmModal(id) {
  const fields = VM_FIELDS.map(f => ({...f}));
  const [devices, clusters] = await Promise.all([
    selectOptions('/api/devices', 'devices', d => d.name + (d.virt ? ' (' + d.virt + ')' : '')),
    selectOptions('/api/clusters', 'clusters', c => c.name),
  ]);
  fields.find(f => f.name === 'host_device_id').options = devices;
  fields.find(f => f.name === 'cluster_id').options = clusters;
  const rec = id ? await API.get('/api/vms/' + id) : null;
  openModal(id ? 'Edit virtual machine' : 'Add virtual machine',
    buildForm(fields, rec) +
    `<button class="btn" onclick="saveResource('/api/vms', ${id || 0}, VM_FORM, afterInventorySave)">${id ? 'Save' : 'Add'}</button>`);
  window.VM_FORM = fields;
}

async function containerModal(id) {
  const fields = CONTAINER_FIELDS.map(f => ({...f}));
  const [devices, vms, clusters] = await Promise.all([
    API.get('/api/devices'), API.get('/api/vms'),
    selectOptions('/api/clusters', 'clusters', c => c.name),
  ]);
  // "Runs on" merges devices and VMs into one picker; the value carries the
  // kind so the API gets parent_kind + parent_id.
  fields.find(f => f.name === 'parent').options = [['', '— none —']]
    .concat(devices.devices.map(d => [`device:${d.id}`, `${d.name} (device)`]))
    .concat(vms.vms.map(v => [`vm:${v.id}`, `${v.name} (VM)`]));
  fields.find(f => f.name === 'cluster_id').options = clusters;

  let rec = id ? await API.get('/api/containers/' + id) : null;
  if (rec && rec.parent_kind) rec.parent = `${rec.parent_kind}:${rec.parent_id}`;
  openModal(id ? 'Edit container' : 'Add container',
    buildForm(fields, rec) +
    `<button class="btn" onclick="saveContainer(${id || 0})">${id ? 'Save' : 'Add'}</button>`);
  window.CONTAINER_FORM = fields;
}

async function saveContainer(id) {
  const body = readFields(window.CONTAINER_FORM);
  const picked = body.parent || '';
  delete body.parent;
  if (picked) {
    const [kind, pid] = picked.split(':');
    body.parent_kind = kind;
    body.parent_id = Number(pid);
  } else {
    body.parent_kind = '';
    body.parent_id = null;
  }
  try {
    await API.post('/api/containers' + (id ? '/' + id : ''), body);
    closeModal();
    afterInventorySave();
  } catch (e) { alert(e.message); }
}

// Any inventory change invalidates the shared host picker cache.
function afterInventorySave() {
  invalidateHostCache();
  reloadPage();
}

// ─── Object detail ────────────────────────────────────────

async function objectDetail(kind, id) {
  const d = await API.get(`/api/hosts/${kind}/${id}`);
  const o = d.object;
  const listPage = kind + 's';
  const modalFn = {device: 'deviceModal', vm: 'vmModal',
                   container: 'containerModal', cluster: 'clusterModal'}[kind];

  // Only show fields the object actually has — the four kinds share a
  // renderer but not a schema.
  const facts = [
    ['Name', o.name],
    ['Type', o.role || o.platform || o.engine || o.kind],
    ['Status', o.status],
    ['Cluster', o.cluster_name],
    ['Host', o.host_name],
    ['Runs on', o.parent_name],
    ['Hypervisor', o.virt],
    ['Container engine', kind === 'container' ? null : o.engine],
    ['Platform ID', o.vmid],
    ['vCPUs', o.vcpus],
    ['Memory', o.memory_mb ? o.memory_mb + ' MB' : null],
    ['Disk', o.disk_gb ? o.disk_gb + ' GB' : null],
    ['OS', o.os],
    ['Image', o.image],
    ['Manufacturer', o.manufacturer],
    ['Model', o.model],
    ['Serial', o.serial],
    ['Endpoint', o.endpoint],
    ['Location', [o.site, o.rack, o.position].filter(Boolean).join(' / ')],
    ['Classification', o.meta && o.meta.classification],
    ['Tags', o.tags],
    ['Capabilities', o.meta && (o.meta.capabilities || []).join(', ')],
    ['Also known as', o.meta && (o.meta.also_known_as || []).join(', ')],
    ['Agent version', o.meta && o.meta.agent_version],
    ['Source', o.source !== 'manual' ? `${o.source}${o.ext_id ? ' (' + o.ext_id + ')' : ''}` : null],
    ['Description', o.description],
  ].filter(([, v]) => v != null && v !== '');

  const childBlocks = Object.entries(d.children || {})
    .filter(([, list]) => list.length)
    .map(([name, list]) => `
      <h3 style="margin-top:24px">${escapeHtml(name.charAt(0).toUpperCase() + name.slice(1))}</h3>
      ${dataTable([
        {label: 'Name', get: c => objLink(name.replace(/s$/, ''), c.id, c.name)},
        {label: 'Type', get: c => typeBadge(c.role || c.platform || c.engine)},
        {label: 'Status', get: c => statusBadge(c.status)},
      ], list)}`).join('');

  $('page-content').innerHTML = `
    ${breadcrumb([{label: listPage.charAt(0).toUpperCase() + listPage.slice(1), page: listPage},
                  {label: o.name}])}
    <div class="page-header">
      <h2>${escapeHtml(o.name)}</h2>
      ${canWrite() ? `<div class="toolbar" style="margin:0">
        <button class="btn btn-sm btn-outline" onclick="${modalFn}(${o.id})">Edit</button>
        <button class="btn btn-sm" onclick="assignAddressModal('${jsArg(kind)}', ${o.id})">Assign an address</button>
      </div>` : ''}
    </div>
    <dl class="detail-grid">${facts.map(([k, v]) =>
      `<div><dt>${escapeHtml(k)}</dt><dd>${escapeHtml(String(v))}</dd></div>`).join('')}</dl>
    <h3>IP addresses</h3>
    ${dataTable(addressColumns(), d.addresses, 'No addresses assigned to this object')}
    ${childBlocks}`;
}

// Assign an address to an object: either allocate the next free one in a
// chosen network, or record a specific address.
async function assignAddressModal(kind, id) {
  const nets = await API.get('/api/networks');
  const opts = nets.networks.filter(n => n.role !== 'container')
    .map(n => `<option value="${n.id}">${escapeHtml(n.cidr)}${n.name ? ' — ' + escapeHtml(n.name) : ''}</option>`).join('');
  openModal('Assign an address', `
    <div class="form-group"><label>Network</label>
      <select id="as-net" class="form-control">${opts || '<option value="">No networks defined</option>'}</select></div>
    <div class="form-group"><label>Address</label>
      <input id="as-addr" class="form-control" placeholder="leave blank to take the next free one"></div>
    <div class="form-group"><label>DNS name</label><input id="as-dns" class="form-control"></div>
    <div class="form-group"><label>Interface</label><input id="as-if" class="form-control" placeholder="eth0"></div>
    <div class="form-group"><label>MAC</label><input id="as-mac" class="form-control"></div>
    <label class="checkitem" style="padding-left:0"><input id="as-verify" type="checkbox" checked> Ping-check first (auto-allocation only)</label>
    <button class="btn" onclick="doAssignAddress('${jsArg(kind)}', ${Number(id)})">Assign</button>`);
}

async function doAssignAddress(kind, id) {
  const addr = $('as-addr').value.trim();
  const common = {
    assigned_kind: kind, assigned_id: id,
    dns_name: $('as-dns').value.trim(),
    if_name: $('as-if').value.trim(),
    mac: $('as-mac').value.trim(),
  };
  try {
    if (addr) {
      await API.post('/api/addresses', {address: addr, status: 'active', ...common});
    } else {
      const r = await API.post('/api/allocate', {
        network_id: Number($('as-net').value), verify: $('as-verify').checked, ...common});
      alert('Allocated ' + r.ip);
    }
    closeModal();
    reloadPage();
  } catch (e) { alert(e.message); }
}

// ─── Topology ─────────────────────────────────────────────

async function page_topology() {
  const d = await API.get('/api/topology');

  const node = n => `
    <li>
      <div class="node">
        <a onclick="showPage('${jsArg(n.kind)}s', ${n.id})">${escapeHtml(n.name)}</a>
        ${typeBadge(n.kind)}
        ${typeBadge(n.role || n.platform || n.engine || n.kind)}
        ${n.ip_count ? `<span class="meta">${n.ip_count} IP${n.ip_count === 1 ? '' : 's'}</span>` : ''}
        ${n.status && n.status !== 'active' ? statusBadge(n.status) : ''}
      </div>
      ${n.children && n.children.length ? `<ul>${n.children.map(node).join('')}</ul>` : ''}
    </li>`;

  const unplaced = Object.entries(d.unplaced).filter(([, list]) => list.length);

  $('page-content').innerHTML = `
    <div class="page-header"><h2>Topology</h2></div>
    <p class="help">Clusters hold devices and VMs; devices host VMs and containers; VMs host containers.
      Objects with no parent are listed separately.</p>
    ${d.clusters.length ? `<ul class="topo">${d.clusters.map(node).join('')}</ul>`
      : '<div class="alert alert-info">No clusters defined.</div>'}
    ${unplaced.map(([name, list]) => `
      <h3 style="margin-top:24px">Unplaced ${escapeHtml(name)}</h3>
      <ul class="topo">${list.map(node).join('')}</ul>`).join('')}`;
}
