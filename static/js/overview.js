// Overview: address-space totals, inventory counts, busiest subnets, health.

async function page_overview() {
  const [ov, health] = await Promise.all([
    API.get('/api/overview'),
    API.get('/api/health').catch(() => ({ ok: true, issues: [] })),
  ]);
  const c = ov.counts, s = ov.space;

  const cards = `
    <div class="cards">
      <div class="card card-link" onclick="showPage('networks')">
        <div class="card-head">${icon('loc')} Address space</div>
        <div class="card-value">${s.pct}<span class="card-unit">% used</span></div>
        ${usageBar(s.pct)}
        <div class="card-sub">${fmtNum(s.used)} of ${fmtNum(s.capacity)} usable addresses</div>
      </div>
      <div class="card card-link" onclick="showPage('networks')">
        <div class="card-head">${icon('net')} Networks</div>
        <div class="card-value">${c.networks}<span class="card-unit">defined</span></div>
        <div class="card-sub">${c.containers_nets} supernet(s) &middot; ${c.vlans} VLAN(s)</div>
      </div>
      <div class="card card-link" onclick="showPage('addresses')">
        <div class="card-head">${icon('hash')} IP records</div>
        <div class="card-value">${fmtNum(c.addresses)}</div>
        <div class="card-sub">${fmtNum(c.assigned)} assigned &middot; ${fmtNum(c.reserved)} reserved</div>
      </div>
      <div class="card card-link" onclick="showPage('topology')">
        <div class="card-head">${icon('srv')} Inventory</div>
        <div class="card-value">${c.devices + c.vms + c.containers}<span class="card-unit">objects</span></div>
        <div class="card-sub">${c.devices} device(s) &middot; ${c.vms} VM(s) &middot; ${c.containers} container(s)</div>
      </div>
      <div class="card card-link" onclick="showPage('scan')">
        <div class="card-head">${icon('rad')} Last sweep</div>
        <div class="card-value" style="font-size:1.3em">${ov.scan.last ? fmtAgo(ov.scan.last) : 'never'}</div>
        <div class="card-sub">${fmtNum(ov.scan.known)} address(es) probed${ov.scan.unmanaged ? ` &middot; <strong style="color:var(--red)">${ov.scan.unmanaged} unmanaged</strong>` : ''}</div>
      </div>
      <div class="card card-link" onclick="showPage('dhcp')">
        <div class="card-head">${icon('swap')} Services</div>
        <div class="card-value">${c.dhcp_ranges}<span class="card-unit">DHCP pools</span></div>
        <div class="card-sub">${c.dhcp_servers} DHCP &middot; ${c.dns_servers} DNS server(s)</div>
      </div>
    </div>`;

  // Health issues are the one thing worth interrupting for — an address plan
  // that disagrees with reality is the failure this app exists to prevent.
  const issues = (health.issues || []).map(i => `
    <div class="alert alert-${i.level === 'error' ? 'danger' : i.level === 'warning' ? 'warning' : 'info'}">
      <strong>${escapeHtml(String(i.count))}</strong> ${escapeHtml(i.message)}
      ${i.examples && i.examples.length ? `<span class="muted"> — ${escapeHtml(i.examples.slice(0, 5).join(', '))}${i.count > 5 ? '…' : ''}</span>` : ''}
      ${i.kind === 'unmanaged-hosts' ? ' <a href="#" onclick="showPage(\'scan\');return false">Reconcile</a>' : ''}
    </div>`).join('');

  const busiest = ov.busiest.length ? `
    <h3>Busiest subnets</h3>
    ${dataTable([
      {label: 'Network', get: n => `<a class="cidr" onclick="showPage('networks', ${n.id})">${escapeHtml(n.cidr)}</a>`},
      {label: 'Name', get: n => escapeHtml(n.name || '')},
      {label: 'VLAN', get: n => n.vlan_vid ? typeBadge(n.vlan_vid) : '<span class="muted">—</span>'},
      {label: 'Used', cls: 'num', get: n => `${fmtNum(n.utilization.used)} / ${fmtNum(n.utilization.capacity)}`},
      {label: 'Utilization', cls: 'util-cell', get: n => usageBar(n.utilization.pct, true)},
      {label: 'Free', cls: 'num', get: n => fmtNum(n.utilization.free)},
    ], ov.busiest, 'No subnets defined yet')}` : `
    <div class="alert alert-info">No networks defined yet.
      <a href="#" onclick="showPage('networks');return false">Add your first network</a> to start tracking addresses.</div>`;

  const recent = ov.recent.length ? `
    <h3 style="margin-top:24px">Recent activity</h3>
    ${dataTable([
      {label: 'When', get: a => escapeHtml(fmtAgo(a.ts))},
      {label: 'Who', get: a => escapeHtml(a.actor)},
      {label: 'Action', get: a => typeBadge(a.action)},
      {label: 'Object', get: a => escapeHtml(a.object_kind)},
      {label: 'Detail', get: a => escapeHtml(a.detail)},
    ], ov.recent)}` : '';

  $('page-content').innerHTML = `
    <h2>Overview</h2>
    ${searchBar()}
    ${issues}
    ${cards}
    ${busiest}
    ${recent}`;
}
