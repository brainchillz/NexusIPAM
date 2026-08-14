"""End-to-end coverage of the address plan: CRUD, containment, utilization,
allocation and the guards that keep the data honest."""


def mknet(client, cidr, **kw):
    r = client.post('/api/networks', json={'cidr': cidr, **kw})
    assert r.status_code == 200, r.json
    return r.json['id']


# ─── Networks ─────────────────────────────────────────────────────────

def test_network_normalizes_and_rejects_junk(client):
    # A host address with a prefix is accepted and normalized to its network.
    r = client.post('/api/networks', json={'cidr': '10.0.0.55/24', 'name': 'lab'})
    assert r.json['network']['cidr'] == '10.0.0.0/24'
    assert r.json['network']['prefixlen'] == 24

    assert client.post('/api/networks', json={'cidr': 'not-a-network'}).status_code == 400
    # Duplicate CIDR is a conflict, not a crash.
    assert client.post('/api/networks', json={'cidr': '10.0.0.0/24'}).status_code == 409


def test_gateway_must_be_inside_the_network(client):
    assert client.post('/api/networks',
                       json={'cidr': '10.0.0.0/24', 'gateway': '192.168.1.1'}).status_code == 400
    assert client.post('/api/networks',
                       json={'cidr': '10.0.0.0/24', 'gateway': '10.0.0.1'}).status_code == 200


def test_containment_is_derived_not_stored(client):
    """A supernet added AFTER its subnets must immediately adopt them."""
    child = mknet(client, '10.1.2.0/24')
    parent = mknet(client, '10.0.0.0/8', role='container')
    detail = client.get(f'/api/networks/{child}/detail').json
    assert detail['parent']['id'] == parent
    kids = client.get(f'/api/networks/{parent}/detail').json['children']
    assert child in [k['id'] for k in kids]


def test_addresses_reparent_when_a_network_appears(client):
    client.post('/api/addresses', json={'address': '172.16.5.9'})
    rec = client.get('/api/addresses').json['addresses'][0]
    assert rec['network_id'] is None            # nothing contains it yet

    nid = mknet(client, '172.16.0.0/16')
    rec = client.get('/api/addresses').json['addresses'][0]
    assert rec['network_id'] == nid             # reindexed on network create

    client.delete(f'/api/networks/{nid}')
    rec = client.get('/api/addresses').json['addresses'][0]
    assert rec['network_id'] is None            # and again on delete


def test_ipv6_networks_work(client):
    nid = mknet(client, '2001:db8:abcd::/64', name='v6-lab')
    r = client.post('/api/addresses', json={'address': '2001:db8:abcd::5'})
    assert r.status_code == 200
    assert r.json['address']['network_id'] == nid
    assert r.json['address']['version'] == 6


# ─── Utilization / free space ─────────────────────────────────────────

def test_utilization_counts_records_and_pools_without_double_counting(client):
    nid = mknet(client, '10.0.0.0/24')
    u = client.get(f'/api/networks/{nid}/detail').json['utilization']
    assert u['capacity'] == 254 and u['used'] == 0

    client.post('/api/addresses', json={'address': '10.0.0.5'})
    u = client.get(f'/api/networks/{nid}/detail').json['utilization']
    assert u['used'] == 1

    # A 100-address pool, with one record already inside it.
    client.post('/api/addresses', json={'address': '10.0.0.150'})
    client.post('/api/dhcp/ranges', json={'network_id': nid, 'start_addr': '10.0.0.100',
                                          'end_addr': '10.0.0.199'})
    u = client.get(f'/api/networks/{nid}/detail').json['utilization']
    # 2 records + 100 pool addresses - 1 record inside the pool = 101
    assert u['used'] == 101
    assert u['free'] == 254 - 101


def test_slash31_and_slash32_are_fully_usable(client):
    """RFC 3021 point-to-point links have no wasted addresses."""
    p2p = mknet(client, '10.9.9.0/31')
    assert client.get(f'/api/networks/{p2p}/detail').json['utilization']['capacity'] == 2
    host = mknet(client, '10.9.9.4/32')
    assert client.get(f'/api/networks/{host}/detail').json['utilization']['capacity'] == 1


def test_free_list_skips_records_pools_and_gateway(client):
    nid = mknet(client, '10.2.0.0/29', gateway='10.2.0.1')   # .1-.6 usable
    client.post('/api/addresses', json={'address': '10.2.0.2'})
    client.post('/api/dhcp/ranges', json={'network_id': nid, 'start_addr': '10.2.0.5',
                                          'end_addr': '10.2.0.6'})
    free = client.get(f'/api/networks/{nid}/free').json['free']
    assert free == ['10.2.0.3', '10.2.0.4']   # .1 gateway, .2 record, .5-.6 pool


def test_reserved_addresses_stay_out_of_rotation(client):
    nid = mknet(client, '10.3.0.0/29')
    client.post('/api/addresses', json={'address': '10.3.0.1', 'status': 'reserved'})
    assert '10.3.0.1' not in client.get(f'/api/networks/{nid}/free').json['free']


def test_bulk_reserve_span(client):
    nid = mknet(client, '10.4.0.0/24')
    r = client.post(f'/api/networks/{nid}/reserve',
                    json={'start': '10.4.0.1', 'end': '10.4.0.20', 'description': 'infra'})
    assert r.json['created'] == 20
    # Re-running is idempotent: existing records are skipped, not duplicated.
    assert client.post(f'/api/networks/{nid}/reserve',
                       json={'start': '10.4.0.1', 'end': '10.4.0.20'}).json['skipped'] == 20
    assert client.get(f'/api/networks/{nid}/free').json['free'][0] == '10.4.0.21'


def test_reserve_span_must_be_inside_the_network(client):
    nid = mknet(client, '10.4.0.0/24')
    assert client.post(f'/api/networks/{nid}/reserve',
                       json={'start': '10.5.0.1', 'end': '10.5.0.5'}).status_code == 400


def test_huge_prefix_refuses_enumeration_but_still_allocates(client):
    """A /8 must not be enumerated for the UI, but next-free is a generator
    and still answers instantly."""
    nid = mknet(client, '10.0.0.0/8', role='container')
    assert client.get(f'/api/networks/{nid}/map').status_code == 413
    r = client.get('/api/next-free?cidr=10.0.0.0/8')
    assert r.json['addresses'] == ['10.0.0.1']


# ─── Allocation ───────────────────────────────────────────────────────

def test_allocate_returns_a_deploy_ready_payload(client):
    """The single call VC-Deployer needs before it can clone a VM."""
    nid = mknet(client, '10.10.0.0/24', gateway='10.10.0.1', domain='lab.lan',
                dns_servers='10.10.0.53, 1.1.1.1',
                meta={'vsphere_portgroup': 'VM Network'})
    vm = client.post('/api/vms', json={'name': 'web01', 'platform': 'vcenter'}).json['id']

    r = client.post('/api/allocate', json={'network_id': nid, 'assigned_kind': 'vm',
                                           'assigned_id': vm, 'dns_name': 'web01'})
    assert r.status_code == 200, r.json
    assert r.json['ip'] == '10.10.0.2'          # .1 is the gateway
    assert r.json['prefixlen'] == 24
    assert r.json['netmask'] == '255.255.255.0'
    assert r.json['gateway'] == '10.10.0.1'
    assert r.json['dns'] == ['10.10.0.53', '1.1.1.1']
    assert r.json['domain'] == 'lab.lan'
    assert r.json['meta']['vsphere_portgroup'] == 'VM Network'

    # The address is now attributed to the VM.
    detail = client.get(f'/api/hosts/vm/{vm}').json
    assert [a['address'] for a in detail['addresses']] == ['10.10.0.2']


def test_allocate_never_hands_out_the_same_address_twice(client):
    nid = mknet(client, '10.11.0.0/29')          # .1-.6
    got = [client.post('/api/allocate', json={'network_id': nid}).json['ip'] for _ in range(6)]
    assert sorted(got) == ['10.11.0.%d' % i for i in range(1, 7)]
    assert len(set(got)) == 6
    # Exhausted: a 409 with a clear message, not a silent duplicate.
    r = client.post('/api/allocate', json={'network_id': nid})
    assert r.status_code == 409 and 'free address' in r.json['error']


def test_allocate_by_name_and_cidr(client):
    mknet(client, '10.12.0.0/24', name='lab-servers')
    assert client.post('/api/allocate', json={'network': 'lab-servers'}).json['ip'] \
        == '10.12.0.1'
    assert client.post('/api/allocate', json={'cidr': '10.12.0.0/24'}).json['ip'] \
        == '10.12.0.2'


def test_allocate_dry_run_writes_nothing(client):
    nid = mknet(client, '10.13.0.0/24')
    r = client.post('/api/allocate', json={'network_id': nid, 'dry_run': True})
    assert r.json['dry_run'] and r.json['addresses'] == ['10.13.0.1']
    assert client.get('/api/addresses').json['addresses'] == []


def test_allocate_count_and_release(client):
    nid = mknet(client, '10.14.0.0/24')
    r = client.post('/api/allocate', json={'network_id': nid, 'count': 3})
    assert r.json['addresses'] == ['10.14.0.1', '10.14.0.2', '10.14.0.3']

    assert client.post('/api/release', json={'address': '10.14.0.2'}).json['action'] == 'released'
    assert client.get(f'/api/networks/{nid}/free').json['free'][0] == '10.14.0.2'

    # keep=1 retires the address instead of freeing it.
    client.post('/api/release', json={'address': '10.14.0.3', 'keep': True})
    assert '10.14.0.3' not in client.get(f'/api/networks/{nid}/free').json['free']


def test_next_free_reserves_nothing(client):
    nid = mknet(client, '10.15.0.0/24')
    assert client.get(f'/api/next-free?network_id={nid}').json['addresses'] == ['10.15.0.1']
    assert client.get(f'/api/next-free?network_id={nid}').json['addresses'] == ['10.15.0.1']
    assert client.get('/api/addresses').json['addresses'] == []


def test_allocate_rejects_a_bogus_assignment_target(client):
    nid = mknet(client, '10.16.0.0/24')
    r = client.post('/api/allocate', json={'network_id': nid, 'assigned_kind': 'vm',
                                           'assigned_id': 9999})
    assert r.status_code == 400 and 'No such vm' in r.json['error']


# ─── Addresses ────────────────────────────────────────────────────────

def test_address_validation(client):
    assert client.post('/api/addresses', json={'address': '10.0.0.999'}).status_code == 400
    assert client.post('/api/addresses',
                       json={'address': '10.0.0.1', 'mac': 'nope'}).status_code == 400
    assert client.post('/api/addresses',
                       json={'address': '10.0.0.1', 'status': 'invented'}).status_code == 400
    # Line breaks must never reach a rendered export.
    assert client.post('/api/addresses',
                       json={'address': '10.0.0.1',
                             'description': 'x\naddress=/evil/1.2.3.4'}).status_code == 400
    # MAC is normalized to lowercase colon form.
    r = client.post('/api/addresses', json={'address': '10.0.0.1', 'mac': 'AA-BB-CC-DD-EE-FF'})
    assert r.json['address']['mac'] == 'aa:bb:cc:dd:ee:ff'


def test_duplicate_address_is_a_conflict(client):
    client.post('/api/addresses', json={'address': '10.0.0.7'})
    assert client.post('/api/addresses', json={'address': '10.0.0.7'}).status_code == 409


def test_address_lookup_resolves_the_whole_picture(client):
    mknet(client, '10.20.0.0/24', name='core', gateway='10.20.0.1')
    dev = client.post('/api/devices', json={'name': 'nas01', 'role': 'storage'}).json['id']
    client.post('/api/addresses', json={'address': '10.20.0.10', 'assigned_kind': 'device',
                                        'assigned_id': dev, 'dns_name': 'nas01'})

    r = client.get('/api/addresses/lookup?address=10.20.0.10').json
    assert r['state'] == 'active'
    assert r['network']['name'] == 'core'
    assert r['record']['assigned_name'] == 'nas01'

    # An address with no record still resolves to its network.
    r = client.get('/api/addresses/lookup?address=10.20.0.99').json
    assert r['state'] == 'free' and r['record'] is None
    assert r['deploy']['gateway'] == '10.20.0.1'


def test_bulk_import(client):
    mknet(client, '10.21.0.0/24')
    body = {'addresses': [{'address': '10.21.0.%d' % i, 'dns_name': 'host%d' % i}
                          for i in range(1, 6)]}
    r = client.post('/api/addresses/bulk', json=body)
    assert r.json['created'] == 5

    # Default is skip-existing, so re-running an importer is safe.
    assert client.post('/api/addresses/bulk', json=body).json['skipped'] == 5
    assert client.post('/api/addresses/bulk?', json={**body, 'replace': True}).json['updated'] == 5

    bad = client.post('/api/addresses/bulk', json={'addresses': [{'address': 'junk'}]})
    assert bad.json['errors'][0]['error'] == 'Invalid IP address'


# ─── Inventory ────────────────────────────────────────────────────────

def test_full_containment_chain(client):
    cl = client.post('/api/clusters', json={'name': 'pve', 'kind': 'proxmox'}).json['id']
    dev = client.post('/api/devices', json={'name': 'pve-node1', 'cluster_id': cl,
                                            'virt': 'proxmox'}).json['id']
    vm = client.post('/api/vms', json={'name': 'docker01', 'host_device_id': dev,
                                       'cluster_id': cl, 'platform': 'proxmox',
                                       'engine': 'docker'}).json['id']
    ct = client.post('/api/containers', json={'name': 'nginx', 'engine': 'docker',
                                              'parent_kind': 'vm', 'parent_id': vm}).json['id']

    topo = client.get('/api/topology').json
    cluster = topo['clusters'][0]
    node = next(c for c in cluster['children'] if c['kind'] == 'device')
    guest = next(c for c in node['children'] if c['kind'] == 'vm')
    assert guest['children'][0]['name'] == 'nginx'
    assert topo['unplaced'] == {'devices': [], 'vms': [], 'containers': []}

    assert client.get(f'/api/hosts/container/{ct}').json['object']['parent_name'] == 'docker01'


def test_delete_guards_protect_the_address_plan(client):
    dev = client.post('/api/devices', json={'name': 'sw01', 'role': 'switch'}).json['id']
    client.post('/api/addresses', json={'address': '10.30.0.1',
                                        'assigned_kind': 'device', 'assigned_id': dev})
    r = client.delete(f'/api/devices/{dev}')
    assert r.status_code == 409 and 'IP address' in r.json['error']

    # A device hosting a VM cannot vanish either.
    host = client.post('/api/devices', json={'name': 'esxi01'}).json['id']
    client.post('/api/vms', json={'name': 'vm1', 'host_device_id': host})
    assert client.delete(f'/api/devices/{host}').status_code == 409


def test_container_parent_must_exist(client):
    r = client.post('/api/containers', json={'name': 'orphan', 'parent_kind': 'vm',
                                             'parent_id': 4242})
    assert r.status_code == 400 and 'No such vm' in r.json['error']


def test_duplicate_names_are_conflicts(client):
    client.post('/api/devices', json={'name': 'dup'})
    assert client.post('/api/devices', json={'name': 'dup'}).status_code == 409


# ─── DHCP / DNS ───────────────────────────────────────────────────────

def test_dhcp_range_must_fit_and_may_not_overlap(client):
    nid = mknet(client, '10.40.0.0/24')
    assert client.post('/api/dhcp/ranges',
                       json={'network_id': nid, 'start_addr': '10.41.0.1',
                             'end_addr': '10.41.0.9'}).status_code == 400
    assert client.post('/api/dhcp/ranges',
                       json={'network_id': nid, 'start_addr': '10.40.0.50',
                             'end_addr': '10.40.0.10'}).status_code == 400

    assert client.post('/api/dhcp/ranges',
                       json={'network_id': nid, 'start_addr': '10.40.0.100',
                             'end_addr': '10.40.0.150', 'name': 'main'}).status_code == 200
    r = client.post('/api/dhcp/ranges', json={'network_id': nid, 'start_addr': '10.40.0.140',
                                              'end_addr': '10.40.0.180'})
    assert r.status_code == 400 and 'overlaps' in r.json['error']


def test_deleting_a_network_takes_its_dhcp_ranges(client):
    nid = mknet(client, '10.42.0.0/24')
    client.post('/api/dhcp/ranges', json={'network_id': nid, 'start_addr': '10.42.0.10',
                                          'end_addr': '10.42.0.20'})
    client.delete(f'/api/networks/{nid}')
    assert client.get('/api/dhcp/ranges').json['dhcp_ranges'] == []


def test_dns_server_zone_validation(client):
    assert client.post('/api/dns/servers',
                       json={'name': 'ns1', 'zones': 'lan, example.com'}).status_code == 200
    assert client.post('/api/dns/servers',
                       json={'name': 'ns2', 'zones': 'not a domain!'}).status_code == 400


# ─── Integration surface ──────────────────────────────────────────────

def test_upsert_by_source_and_ext_id_is_idempotent(client):
    """Repeated syncs from an importer must update, not duplicate."""
    body = {'name': 'vm-from-vcenter', 'source': 'vcenter', 'ext_id': 'vm-1234',
            'platform': 'vcenter', 'vcpus': 2}
    first = client.post('/api/vms?upsert=1', json=body)
    assert first.status_code == 200

    body['vcpus'] = 4
    second = client.post('/api/vms?upsert=1', json=body)
    assert second.json['id'] == first.json['id']
    assert second.json['vm']['vcpus'] == 4
    assert len(client.get('/api/vms').json['vms']) == 1


def test_change_feed_returns_only_recent_edits(client):
    from nexusipam.core import db
    mknet(client, '10.50.0.0/24')
    cutoff = db.now() + 1
    r = client.get('/api/changes?since=%d' % cutoff)
    assert r.json['count'] == 0
    assert client.get('/api/changes?since=0').json['count'] >= 1
    assert client.get('/api/changes').status_code == 400   # since is required


def test_dnsmasq_exports_match_the_shape_dnsmaq_mgr_accepts(client):
    mknet(client, '10.60.0.0/24', domain='lab.lan')
    client.post('/api/addresses', json={'address': '10.60.0.5', 'dns_name': 'nas',
                                        'mac': 'aa:bb:cc:dd:ee:01'})
    client.post('/api/addresses', json={'address': '2001:db8::5', 'dns_name': 'nas.lab.lan'})

    hosts = client.get('/api/export/dnsmasq/hosts').json['hosts']
    entry = next(h for h in hosts if h['name'] == 'nas.lab.lan')
    assert entry['a'] == '10.60.0.5'            # qualified with the network's domain
    assert set(entry) == {'name', 'a', 'aaaa', 'comment'}

    leases = client.get('/api/export/dnsmasq/static-leases').json['static_leases']
    assert leases == [{'mac': 'aa:bb:cc:dd:ee:01', 'ip': '10.60.0.5',
                       'hostname': 'nas', 'comment': 'from Nexus IPAM'}]

    text = client.get('/api/export/hosts').get_data(as_text=True)
    assert '10.60.0.5' in text and 'nas.lab.lan' in text


def test_export_import_round_trip(client):
    nid = mknet(client, '10.70.0.0/24', name='keepme')
    client.post('/api/addresses', json={'address': '10.70.0.9', 'dns_name': 'keeper'})
    dump = client.get('/api/export/json').json

    from nexusipam.core import db
    for table in ('ip_addresses', 'networks'):
        db.connect().execute('DELETE FROM %s' % table)
    assert client.get('/api/networks').json['networks'] == []

    r = client.post('/api/import/json?mode=replace', json=dump)
    assert r.status_code == 200, r.json
    assert client.get('/api/networks').json['networks'][0]['name'] == 'keepme'
    # The restored address is reindexed onto its network.
    assert client.get('/api/addresses').json['addresses'][0]['network_id'] == nid


# ─── Scanning ─────────────────────────────────────────────────────────

def test_verify_marks_silent_addresses_free(client):
    """probe_one is stubbed to 'no answer', so everything reads as free."""
    mknet(client, '10.80.0.0/24')
    r = client.post('/api/scan/verify', json={'addresses': ['10.80.0.1', '10.80.0.2']})
    assert set(r.json['free']) == {'10.80.0.1', '10.80.0.2'} and r.json['alive'] == []


def test_reconcile_surfaces_unmanaged_responders(client, monkeypatch):
    from nexusipam import scan as scan_mod
    nid = mknet(client, '10.81.0.0/24')
    client.post('/api/addresses', json={'address': '10.81.0.1'})

    # .2 answers but has no record; .1 has a record but never answers.
    monkeypatch.setattr(scan_mod, 'probe_one',
                        lambda a, timeout=None: {'alive': a.endswith('.2'),
                                                 'rtt_ms': 0.4, 'method': 'icmp'})
    client.post('/api/scan/verify', json={'addresses': ['10.81.0.1', '10.81.0.2']})

    rec = client.get(f'/api/scan/reconcile?network_id={nid}').json
    assert [u['address'] for u in rec['unmanaged']] == ['10.81.0.2']
    assert [s['address'] for s in rec['stale']] == ['10.81.0.1']

    # Adopting turns the discovered host into a real record on the network.
    assert client.post('/api/scan/adopt', json={'addresses': ['10.81.0.2']}).json['created'] == 1
    adopted = client.get('/api/addresses/lookup?address=10.81.0.2').json
    assert adopted['record']['source'] == 'discovery'
    assert adopted['record']['network_id'] == nid


def test_scan_refuses_an_oversized_prefix(client):
    r = client.post('/api/scan', json={'cidr': '10.0.0.0/8'})
    assert r.status_code == 400 and 'scan limit' in r.json['error']


def test_map_marks_pool_gateway_and_free(client):
    nid = mknet(client, '10.82.0.0/29', gateway='10.82.0.1')
    client.post('/api/addresses', json={'address': '10.82.0.2', 'status': 'reserved'})
    client.post('/api/dhcp/ranges', json={'network_id': nid, 'start_addr': '10.82.0.5',
                                          'end_addr': '10.82.0.6'})
    states = {e['address']: e['state'] for e in client.get(f'/api/networks/{nid}/map').json['addresses']}
    assert states == {'10.82.0.1': 'free', '10.82.0.2': 'reserved', '10.82.0.3': 'free',
                      '10.82.0.4': 'free', '10.82.0.5': 'pool', '10.82.0.6': 'pool'}
    gw = [e for e in client.get(f'/api/networks/{nid}/map').json['addresses']
          if e.get('gateway')]
    assert [g['address'] for g in gw] == ['10.82.0.1']


# ─── Health / search ──────────────────────────────────────────────────

def test_health_flags_real_problems(client):
    client.post('/api/addresses', json={'address': '192.168.99.1'})   # outside every network
    kinds = {i['kind'] for i in client.get('/api/health').json['issues']}
    assert 'orphan-addresses' in kinds

    # A declared gateway with no separate address record is not a defect —
    # the allocator and free list already honour it.
    mknet(client, '10.90.0.0/24', gateway='10.90.0.1')
    kinds = {i['kind'] for i in client.get('/api/health').json['issues']}
    assert 'unrecorded-gateways' not in kinds


def test_search_routes_bare_ips_and_cidrs(client):
    nid = mknet(client, '10.91.0.0/24', name='searchme')
    client.post('/api/addresses', json={'address': '10.91.0.5', 'dns_name': 'findme'})

    assert client.get('/api/search?q=10.91.0.0/24').json['exact']['kind'] == 'network'
    assert client.get('/api/search?q=10.91.0.5').json['exact']['kind'] == 'address'
    # An unrecorded address inside a known network points at the network.
    free = client.get('/api/search?q=10.91.0.77').json['exact']
    assert free['kind'] == 'free-address' and free['id'] == nid
    assert client.get('/api/search?q=findme').json['addresses'][0]['dns_name'] == 'findme'


# ─── Access control ───────────────────────────────────────────────────

def test_readonly_identity_cannot_write(client, monkeypatch):
    from nexusipam.core import auth
    monkeypatch.setattr(auth, '_users', lambda: {'admin': {'password': 'x', 'role': 'readonly'}})
    assert client.get('/api/networks').status_code == 200
    assert client.post('/api/networks', json={'cidr': '10.99.0.0/24'}).status_code == 403
    assert client.post('/api/allocate', json={'cidr': '10.99.0.0/24'}).status_code == 403
    # next-free is a GET, so a monitoring token can still ask what is available.
    assert client.get('/api/next-free?cidr=10.99.0.0/24').status_code in (200, 404)


def test_editing_an_imported_record_keeps_its_sync_linkage(client):
    """A UI edit sends no source/ext_id. Those must survive, or the next
    importer run would create a duplicate instead of finding its own record."""
    r = client.post('/api/vms?upsert=1', json={'name': 'imported', 'source': 'vcenter',
                                               'ext_id': 'vm-77', 'vcpus': 2})
    vid = r.json['id']

    # Exactly what the edit form posts — no source, no ext_id.
    client.post(f'/api/vms/{vid}', json={'name': 'imported', 'platform': 'kvm', 'vcpus': 8})
    rec = client.get(f'/api/vms/{vid}').json
    assert rec['source'] == 'vcenter' and rec['ext_id'] == 'vm-77'
    assert rec['vcpus'] == 8

    # And the importer still matches its own record rather than duplicating.
    again = client.post('/api/vms?upsert=1', json={'name': 'imported', 'source': 'vcenter',
                                                   'ext_id': 'vm-77', 'vcpus': 4})
    assert again.json['id'] == vid
    assert len(client.get('/api/vms').json['vms']) == 1


def test_meta_survives_an_edit_that_omits_it(client):
    r = client.post('/api/networks', json={'cidr': '10.95.0.0/24',
                                           'meta': {'vsphere_portgroup': 'VM Network'}})
    nid = r.json['id']
    client.post(f'/api/networks/{nid}', json={'cidr': '10.95.0.0/24', 'name': 'renamed'})
    rec = client.get(f'/api/networks/{nid}').json
    assert rec['meta'] == {'vsphere_portgroup': 'VM Network'}
    assert rec['name'] == 'renamed'


def test_dhcp_leases_are_not_reported_as_unmanaged(client, monkeypatch):
    """A responder inside a DHCP pool is a lease doing its job. Reporting it as
    an unmanaged host would bury the real signal — an unrecorded static — under
    routine noise on any network that runs DHCP."""
    from nexusipam import scan as scan_mod
    nid = mknet(client, '10.85.0.0/24')
    client.post('/api/dhcp/ranges', json={'network_id': nid, 'name': 'pool',
                                          'start_addr': '10.85.0.100',
                                          'end_addr': '10.85.0.200'})
    # .150 is a DHCP client; .20 is someone squatting on a static address.
    monkeypatch.setattr(scan_mod, 'probe_one',
                        lambda a, timeout=None: {'alive': a in ('10.85.0.150', '10.85.0.20'),
                                                 'rtt_ms': 0.5, 'method': 'icmp'})
    client.post('/api/scan/verify', json={'addresses': ['10.85.0.20', '10.85.0.150',
                                                        '10.85.0.30']})

    rec = client.get(f'/api/scan/reconcile?network_id={nid}').json
    assert [u['address'] for u in rec['unmanaged']] == ['10.85.0.20']
    assert [u['address'] for u in rec['dhcp_leases']] == ['10.85.0.150']
    assert rec['dhcp_leases'][0]['dhcp_range'] == 'pool'

    # The Overview health banner must use the same definition.
    issues = {i['kind']: i for i in client.get('/api/health').json['issues']}
    assert issues['unmanaged-hosts']['count'] == 1


def test_adopt_skips_dhcp_pool_addresses_by_default(client, monkeypatch):
    """Recording a dynamic lease as a permanent entry writes down something
    that is only true until the lease expires."""
    from nexusipam import scan as scan_mod
    nid = mknet(client, '10.86.0.0/24')
    client.post('/api/dhcp/ranges', json={'network_id': nid, 'start_addr': '10.86.0.100',
                                          'end_addr': '10.86.0.200'})
    monkeypatch.setattr(scan_mod, 'probe_one',
                        lambda a, timeout=None: {'alive': True, 'rtt_ms': 0.5, 'method': 'icmp'})
    client.post('/api/scan/verify', json={'addresses': ['10.86.0.20', '10.86.0.150']})

    r = client.post('/api/scan/adopt', json={'addresses': ['10.86.0.20', '10.86.0.150']})
    assert r.json['created'] == 1 and r.json['skipped_dhcp'] == 1
    assert client.get('/api/addresses/lookup?address=10.86.0.150').json['record'] is None

    # Opting in records it as `dhcp`, not `active`.
    r = client.post('/api/scan/adopt', json={'addresses': ['10.86.0.150'],
                                             'include_dhcp': True})
    assert r.json['created'] == 1
    assert client.get('/api/addresses/lookup?address=10.86.0.150').json['record']['status'] == 'dhcp'


def test_vm_hypervisor_vocabulary(client):
    """A VM has a hypervisor, not a container engine."""
    for hv in ('vsphere', 'proxmox', 'kvm', 'xen', 'hyperv'):
        r = client.post('/api/vms', json={'name': 'vm-' + hv, 'platform': hv})
        assert r.status_code == 200, r.json
        assert r.json['vm']['platform'] == hv
    # Legacy values stay accepted so older records and importers keep working.
    assert client.post('/api/vms', json={'name': 'old', 'platform': 'esxi'}).status_code == 200
    assert client.post('/api/vms', json={'name': 'bad', 'platform': 'docker'}).status_code == 400


def test_vm_edit_does_not_clear_engine_the_form_no_longer_sends(client):
    """The VM form dropped the container-engine field; an edit must not wipe a
    value an importer set — same failure mode as source/ext_id."""
    vid = client.post('/api/vms', json={'name': 'dockerhost', 'platform': 'kvm',
                                        'engine': 'docker'}).json['id']
    client.post(f'/api/vms/{vid}', json={'name': 'dockerhost', 'platform': 'proxmox'})
    rec = client.get(f'/api/vms/{vid}').json
    assert rec['engine'] == 'docker' and rec['platform'] == 'proxmox'
    # Explicitly clearing it still works.
    client.post(f'/api/vms/{vid}', json={'name': 'dockerhost', 'platform': 'kvm', 'engine': ''})
    assert client.get(f'/api/vms/{vid}').json['engine'] == ''


def test_shared_mac_is_context_not_an_alert(client):
    """Several addresses on one NIC is how you run multiple services that each
    want the same port. It must not be reported as a data problem."""
    mknet(client, '10.96.0.0/24')
    for i in (1, 2, 3):
        client.post('/api/addresses', json={'address': '10.96.0.%d' % i,
                                            'mac': 'aa:bb:cc:00:00:01'})
    kinds = {i['kind'] for i in client.get('/api/health').json['issues']}
    assert 'duplicate-macs' not in kinds

    r = client.get('/api/addresses/lookup?address=10.96.0.1').json
    assert sorted(s['address'] for s in r['siblings']) == ['10.96.0.2', '10.96.0.3']


def test_new_cluster_kinds_and_device_roles(client):
    for kind in ('ai', 'storage', 'proxmox', 'vsphere', 'kubernetes'):
        assert client.post('/api/clusters',
                           json={'name': 'c-' + kind, 'kind': kind}).status_code == 200
    assert client.post('/api/clusters', json={'name': 'bad', 'kind': 'ray'}).status_code == 400

    for role in ('ai', 'mixed', 'server', 'storage'):
        assert client.post('/api/devices',
                           json={'name': 'd-' + role, 'role': role}).status_code == 200
    assert client.post('/api/devices', json={'name': 'bad', 'role': 'toaster'}).status_code == 400


def test_device_tags_normalize_and_filter(client):
    """Tags exist so one machine can be several things — a mixed box tagged
    #AI #Storage #Container must be findable under any of them."""
    client.post('/api/devices', json={'name': 'mixedbox', 'role': 'mixed',
                                      'tags': '#AI #Storage #Container'})
    client.post('/api/devices', json={'name': 'aibox', 'role': 'ai', 'tags': 'ai, gpu'})
    client.post('/api/devices', json={'name': 'plain', 'role': 'server'})

    # Hashes stripped, lower-cased, sorted, de-duplicated — so "#AI" and "ai"
    # are the same tag whichever way they were typed.
    rec = client.get('/api/devices').json['devices']
    assert next(d for d in rec if d['name'] == 'mixedbox')['tags'] == 'ai, container, storage'

    names = lambda r: sorted(d['name'] for d in r.json['devices'])
    assert names(client.get('/api/devices?tag=ai')) == ['aibox', 'mixedbox']
    assert names(client.get('/api/devices?tag=%23AI')) == ['aibox', 'mixedbox']
    assert names(client.get('/api/devices?tag=storage')) == ['mixedbox']
    assert names(client.get('/api/devices?tag=nothing')) == []

    # Exact match: "ai" must not also match a tag that merely starts with it.
    client.post('/api/devices', json={'name': 'flow', 'tags': 'airflow'})
    assert names(client.get('/api/devices?tag=ai')) == ['aibox', 'mixedbox']

    counts = {t['tag']: t['count'] for t in client.get('/api/tags').json['tags']}
    assert counts['ai'] == 2 and counts['storage'] == 1 and counts['airflow'] == 1


def test_bad_tags_are_rejected(client):
    assert client.post('/api/devices',
                       json={'name': 'x', 'tags': 'has space!'}).status_code == 400
    assert client.post('/api/devices',
                       json={'name': 'y', 'tags': ['ok', 'also/bad']}).status_code == 400


def test_device_edit_without_tags_field_keeps_them(client):
    """Same preservation rule as source/ext_id — an API caller that omits tags
    must not silently clear them."""
    did = client.post('/api/devices', json={'name': 'keeper', 'tags': 'ai storage'}).json['id']
    client.post(f'/api/devices/{did}', json={'name': 'keeper', 'role': 'mixed'})
    assert client.get(f'/api/devices/{did}').json['tags'] == 'ai, storage'


def test_list_filters_actually_filter(client):
    """Regression: list_sql for devices/vms/clusters embeds a subquery whose
    WHERE used to fool the filter builder into appending to a LEFT JOIN's ON
    clause — valid SQL that filters nothing, so every query returned the lot."""
    client.post('/api/devices', json={'name': 'imported', 'source': 'vcenter',
                                      'ext_id': 'h-1'})
    client.post('/api/devices', json={'name': 'byhand'})
    got = client.get('/api/devices?source=vcenter').json['devices']
    assert [d['name'] for d in got] == ['imported']

    client.post('/api/clusters', json={'name': 'c1', 'source': 'vcenter', 'ext_id': 'c-1'})
    client.post('/api/clusters', json={'name': 'c2'})
    assert [c['name'] for c in client.get('/api/clusters?source=vcenter').json['clusters']] == ['c1']


# ─── Soundness audit (2026-07-29): regression tests for every finding ──

def test_partial_update_preserves_all_unsent_fields(client):
    """THE clobbering class, fixed wholesale: an update that only touches one
    field must leave every other field alone. Before merge-on-update, this
    exact call wiped dns_name, mac and description."""
    mknet(client, '10.100.0.0/24')
    dev = client.post('/api/devices', json={'name': 'nas9'}).json['id']
    rid = client.post('/api/addresses', json={
        'address': '10.100.0.5', 'dns_name': 'nas9', 'mac': 'aa:bb:cc:dd:ee:09',
        'assigned_kind': 'device', 'assigned_id': dev, 'if_name': 'eth0',
        'description': 'important', 'meta': {'k': 'v'}}).json['id']

    client.post(f'/api/addresses/{rid}', json={'status': 'reserved'})
    rec = client.get(f'/api/addresses/{rid}').json
    assert rec['status'] == 'reserved'
    assert rec['dns_name'] == 'nas9' and rec['mac'] == 'aa:bb:cc:dd:ee:09'
    assert rec['assigned_kind'] == 'device' and rec['assigned_id'] == dev
    assert rec['if_name'] == 'eth0' and rec['description'] == 'important'
    assert rec['meta'] == {'k': 'v'}

    # Explicit empty still clears — absent preserves, empty means "clear it".
    client.post(f'/api/addresses/{rid}', json={'dns_name': ''})
    rec = client.get(f'/api/addresses/{rid}').json
    assert rec['dns_name'] == '' and rec['mac'] == 'aa:bb:cc:dd:ee:09'

    # And the same holds for networks: renaming must not drop the gateway.
    nid = mknet(client, '10.101.0.0/24', gateway='10.101.0.1', domain='x.lan')
    client.post(f'/api/networks/{nid}', json={'name': 'renamed'})
    n = client.get(f'/api/networks/{nid}').json
    assert n['gateway'] == '10.101.0.1' and n['domain'] == 'x.lan'
    assert n['name'] == 'renamed'


def test_disabled_dhcp_range_stays_disabled_on_update(client):
    """`0 if x is False else 1` re-enabled a disabled range whenever the
    stored 0 was echoed back or the field was omitted."""
    nid = mknet(client, '10.102.0.0/24')
    rid = client.post('/api/dhcp/ranges', json={
        'network_id': nid, 'start_addr': '10.102.0.10', 'end_addr': '10.102.0.20',
        'enabled': False}).json['id']
    assert client.get(f'/api/dhcp/ranges/{rid}').json['enabled'] == 0
    client.post(f'/api/dhcp/ranges/{rid}', json={'name': 'renamed'})  # partial
    assert client.get(f'/api/dhcp/ranges/{rid}').json['enabled'] == 0
    client.post(f'/api/dhcp/ranges/{rid}', json={'enabled': True})
    assert client.get(f'/api/dhcp/ranges/{rid}').json['enabled'] == 1


def test_v4_v6_hex_collision_isolation(client):
    """IPv6 ::a67:5 has the same integer value as IPv4 10.103.0.5. Fixed-width
    hex makes them compare equal, so every range query MUST filter on version
    or v6 records bleed into v4 networks."""
    nid = mknet(client, '10.103.0.0/24')
    client.post('/api/addresses', json={'address': '::a67:5'})  # == 0x0a670005

    detail = client.get(f'/api/networks/{nid}/detail').json
    assert detail['utilization']['records'] == 0
    assert detail['addresses'] == []
    # The colliding v4 address is still free and allocatable.
    assert '10.103.0.5' in client.get(f'/api/networks/{nid}/free?limit=10').json['free']
    # And the v6 record parented nowhere (no v6 networks defined).
    assert client.get('/api/addresses/lookup?address=::a67:5').json['record']['network_id'] is None


def test_child_network_pool_and_gateway_block_parent_allocation(client):
    """A pool or gateway declared on a nested /25 must be honoured when
    allocating from the containing /24 — otherwise two systems own the same
    addresses. Before the fix, blocked-sets were scoped to the requested
    network's id only."""
    parent = mknet(client, '10.104.0.0/24')
    child = mknet(client, '10.104.0.0/25', gateway='10.104.0.126')
    client.post('/api/dhcp/ranges', json={'network_id': child,
                                          'start_addr': '10.104.0.1',
                                          'end_addr': '10.104.0.100'})
    r = client.post('/api/allocate', json={'network_id': parent})
    assert r.json['ip'] == '10.104.0.101'          # skipped the child's pool
    free = client.get(f'/api/networks/{parent}/free?limit=200').json['free']
    assert '10.104.0.50' not in free               # inside child pool
    assert '10.104.0.126' not in free              # child's gateway

    # Parent utilization counts the child's pool as consumed space.
    u = client.get(f'/api/networks/{parent}/detail').json['utilization']
    assert u['dhcp'] >= 99                         # 100 minus the allocated record inside

    # The allocated record filed under the most specific network: the child.
    rec = client.get('/api/addresses/lookup?address=10.104.0.101').json['record']
    assert rec['network_id'] == child


def test_overlapping_pools_counted_once(client):
    """A parent scope and child scope covering the same span must not push
    utilization past reality — spans are merged before counting."""
    nid = mknet(client, '10.105.0.0/28')            # 14 usable
    child = mknet(client, '10.105.0.0/29')
    client.post('/api/dhcp/ranges', json={'network_id': nid,
                                          'start_addr': '10.105.0.1', 'end_addr': '10.105.0.6'})
    client.post('/api/dhcp/ranges', json={'network_id': child,
                                          'start_addr': '10.105.0.2', 'end_addr': '10.105.0.5'})
    u = client.get(f'/api/networks/{nid}/detail').json['utilization']
    assert u['dhcp'] == 6 and u['used'] == 6        # not 6 + 4


def test_network_resize_refused_while_ranges_would_strand(client):
    nid = mknet(client, '10.106.0.0/24')
    client.post('/api/dhcp/ranges', json={'network_id': nid,
                                          'start_addr': '10.106.0.100',
                                          'end_addr': '10.106.0.120'})
    r = client.post(f'/api/networks/{nid}', json={'cidr': '10.106.0.0/26'})
    assert r.status_code == 400 and 'DHCP range' in r.json['error']
    # A resize that still contains the range is fine.
    assert client.post(f'/api/networks/{nid}',
                       json={'cidr': '10.106.0.0/25'}).status_code == 200


def test_dhcp_range_version_must_match_network(client):
    """::a6b:1 sits numerically inside 10.107.0.0/24's hex bounds — the
    version guard is what rejects it."""
    nid = mknet(client, '10.107.0.0/24')
    r = client.post('/api/dhcp/ranges', json={'network_id': nid,
                                              'start_addr': '::a6b:1',
                                              'end_addr': '::a6b:5'})
    assert r.status_code == 400 and 'IPv4' in r.json['error']


def test_reserve_span_files_under_most_specific_network(client):
    parent = mknet(client, '10.108.0.0/16', role='container')
    child = mknet(client, '10.108.5.0/24')
    client.post(f'/api/networks/{parent}/reserve',
                json={'start': '10.108.5.1', 'end': '10.108.5.3'})
    rec = client.get('/api/addresses/lookup?address=10.108.5.2').json['record']
    assert rec['network_id'] == child


def test_verify_keeps_searching_past_squatters(client, monkeypatch):
    """Nine live squatters at the start of the range: verified allocation must
    walk past them, not give up and claim the subnet is full."""
    from nexusipam import scan as scan_mod
    squat = {'10.109.0.%d' % i for i in range(1, 10)}
    monkeypatch.setattr(scan_mod, 'probe_one',
                        lambda a, timeout=None: {'alive': a in squat,
                                                 'rtt_ms': 0.3, 'method': 'icmp'})
    nid = mknet(client, '10.109.0.0/24')
    r = client.post('/api/allocate', json={'network_id': nid, 'verify': True})
    assert r.status_code == 200, r.json
    assert r.json['ip'] == '10.109.0.10'
    # ...and the squatters were recorded as unmanaged evidence.
    rec = client.get(f'/api/scan/reconcile?network_id={nid}').json
    assert '10.109.0.1' in [u['address'] for u in rec['unmanaged']]


def test_overview_and_health_agree_on_unmanaged(client, monkeypatch):
    """One definition of 'unmanaged' everywhere — the overview card used the
    old query and disagreed with health by the size of the DHCP pool."""
    from nexusipam import scan as scan_mod
    nid = mknet(client, '10.110.0.0/24')
    client.post('/api/dhcp/ranges', json={'network_id': nid,
                                          'start_addr': '10.110.0.100',
                                          'end_addr': '10.110.0.200'})
    monkeypatch.setattr(scan_mod, 'probe_one',
                        lambda a, timeout=None: {'alive': True, 'rtt_ms': 0.3,
                                                 'method': 'icmp'})
    client.post('/api/scan/verify', json={'addresses': ['10.110.0.20', '10.110.0.150']})
    ov = client.get('/api/overview').json['scan']['unmanaged']
    health = {i['kind']: i for i in client.get('/api/health').json['issues']}
    assert ov == 1
    assert health['unmanaged-hosts']['count'] == 1


def test_backup_writes_and_prunes(client, tmp_path, monkeypatch):
    from nexusipam import backup
    import gzip, json as j
    mknet(client, '10.111.0.0/24', name='backmeup')
    monkeypatch.setattr(backup, 'BACKUP_KEEP', 2)
    paths = [backup.run_backup(str(tmp_path)) for _ in range(3)]
    import os
    left = sorted(os.listdir(tmp_path))
    assert len(left) == 2                              # pruned to keep-limit
    with gzip.open(paths[-1], 'rt') as f:
        dump = j.load(f)
    assert any(n['name'] == 'backmeup' for n in dump['tables']['networks'])
    # The dump is restorable through the normal import path.
    assert client.post('/api/import/json?mode=merge', json=dump).status_code == 200


def test_concurrent_allocation_never_duplicates(client):
    """The core safety promise: 12 threads racing for addresses in a /28
    (14 usable) must get 12 DISTINCT addresses. Empirical, not assumed."""
    import threading
    mknet(client, '10.112.0.0/28')
    results, errors = [], []

    def grab():
        # separate client per thread; same app, same database
        with client.application.test_client() as c:
            with c.session_transaction() as s:
                s['user'] = 'admin'
            r = c.post('/api/allocate', json={'cidr': '10.112.0.0/28'})
            (results if r.status_code == 200 else errors).append(
                r.json.get('ip') or r.json.get('error'))

    threads = [threading.Thread(target=grab) for _ in range(12)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert len(results) == 12, (results, errors)
    assert len(set(results)) == 12, 'duplicate allocation: %s' % results


def test_audit_prune_by_age_and_all(client):
    """The audit log is the one append-only table; retention keeps it bounded
    automatically and the admin endpoint handles the impatient case."""
    from nexusipam.core import db
    mknet(client, '10.113.0.0/24')                     # generates entries
    # Plant entries 400 days old — older than the default retention.
    old_ts = db.now() - 400 * 86400
    for i in range(5):
        db.execute('INSERT INTO audit(ts,actor,action,object_kind,object_id,detail) '
                   'VALUES(?,?,?,?,?,?)', (old_ts, 'ancient', 'create', 'networks', i, ''))

    before = client.get('/api/audit').json
    assert before['total'] >= 6
    assert before['retention_days'] == 365

    # Age-based prune: only the ancient entries go.
    r = client.post('/api/audit/prune', json={'days': 365})
    assert r.json['deleted'] == 5
    remaining = client.get('/api/audit').json
    assert all(a['actor'] != 'ancient' for a in remaining['audit'])

    # The same age logic is what the maintenance thread runs.
    for i in range(3):
        db.execute('INSERT INTO audit(ts,actor,action,object_kind,object_id,detail) '
                   'VALUES(?,?,?,?,?,?)', (old_ts, 'ancient', 'create', 'networks', i, ''))
    assert db.prune_audit(days=365) == 3

    # Full clear empties the log but records that it did so.
    r = client.post('/api/audit/prune', json={'all': True})
    assert r.json['success']
    log = client.get('/api/audit').json
    assert log['total'] == 1                            # just the prune entry
    assert log['audit'][0]['action'] == 'prune-audit'

    # Garbage input is rejected, not treated as "delete everything".
    assert client.post('/api/audit/prune', json={}).status_code == 400
    assert client.post('/api/audit/prune', json={'days': 0}).status_code == 400


def test_audit_prune_requires_admin(client, monkeypatch):
    from nexusipam.core import auth
    monkeypatch.setattr(auth, '_users',
                        lambda: {'admin': {'password': 'x', 'role': 'readonly'}})
    assert client.post('/api/audit/prune', json={'days': 30}).status_code == 403


def test_banner_setting_roundtrip(client):
    assert client.get('/api/settings/banner').json['banner'] == ''

    r = client.post('/api/settings/banner', json={'banner': 'Homelab HQ'})
    assert r.json['success'] and r.json['banner'] == 'Homelab HQ'
    assert client.get('/api/settings/banner').json['banner'] == 'Homelab HQ'
    # The sidebar learns the banner from /api/me on every page load.
    assert client.get('/api/me').json['banner'] == 'Homelab HQ'

    # One line, bounded — same barrier as every other stored text.
    assert client.post('/api/settings/banner',
                       json={'banner': 'a' * 65}).status_code == 400
    assert client.post('/api/settings/banner',
                       json={'banner': 'two\nlines'}).status_code == 400

    # Empty clears it (UI falls back to the FQDN).
    assert client.post('/api/settings/banner', json={'banner': ''}).json['success']
    assert client.get('/api/settings/banner').json['banner'] == ''


def test_batch_audit_details_name_the_objects(client, monkeypatch):
    """'1 discovered hosts' tells the operator nothing — batch operations must
    record WHICH addresses were touched, not just how many."""
    from nexusipam import scan as scan_mod
    mknet(client, '10.93.0.0/24')

    monkeypatch.setattr(scan_mod, 'probe_one',
                        lambda a, timeout=None: {'alive': True, 'rtt_ms': 0.4,
                                                 'method': 'icmp'})
    monkeypatch.setattr(scan_mod, 'resolve_ptr', lambda a: 'web01.lab')
    client.post('/api/scan/verify', json={'addresses': ['10.93.0.5']})
    client.post('/api/scan/adopt', json={'addresses': ['10.93.0.5']})
    entry = client.get('/api/audit?limit=1').json['audit'][0]
    assert entry['action'] == 'adopt'
    assert entry['detail'] == '10.93.0.5 (web01.lab)'

    client.post('/api/addresses/bulk', json={'addresses': [
        {'address': '10.93.0.10'}, {'address': '10.93.0.11'},
        {'address': '10.93.0.5'}]})            # .5 exists -> skipped
    entry = client.get('/api/audit?limit=1').json['audit'][0]
    assert entry['action'] == 'bulk-import'
    assert entry['detail'] == 'created 10.93.0.10, 10.93.0.11; 1 skipped'

    # Long batches stay bounded: first few identities plus a remainder count.
    from nexusipam.core import db
    assert db.audit_list(range(10), limit=3) == '0, 1, 2 +7 more'


def test_bulk_delete_mixes_deletions_refusals_and_missing(client):
    mknet(client, '10.94.0.0/24')
    ids = [client.post('/api/addresses', json={'address': '10.94.0.%d' % i}).json['id']
           for i in (1, 2, 3)]

    r = client.post('/api/addresses/bulk-delete', json={'ids': [ids[0], ids[1], 99999]})
    assert r.json['deleted'] == 2 and r.json['missing'] == 1 and r.json['refused'] == []
    left = [a['address'] for a in client.get('/api/addresses').json['addresses']]
    assert left == ['10.94.0.3']
    # The audit entry names what went away, not just a count.
    entry = client.get('/api/audit?limit=1').json['audit'][0]
    assert entry['action'] == 'bulk-delete'
    assert '10.94.0.1' in entry['detail'] and '10.94.0.2' in entry['detail']

    # A guarded row is refused individually; the rest still delete.
    busy = client.post('/api/devices', json={'name': 'busy', 'role': 'server'}).json['id']
    idle = client.post('/api/devices', json={'name': 'idle', 'role': 'server'}).json['id']
    client.post('/api/addresses', json={'address': '10.94.0.7',
                                        'assigned_kind': 'device', 'assigned_id': busy})
    r = client.post('/api/devices/bulk-delete', json={'ids': [busy, idle]})
    assert r.json['deleted'] == 1
    assert [x['label'] for x in r.json['refused']] == ['busy']
    assert 'assigned' in r.json['refused'][0]['error']
    assert client.get('/api/devices/%d' % busy).status_code == 200


# ─── Shared-core security fixes (2026-07-29 audit) ─────────────────────

def test_deleted_user_session_is_rejected_not_promoted(client, monkeypatch):
    """A session cookie for a user no longer in the store must be rejected, not
    resolved to admin. Regression for the _user_role(None) -> 'admin' bug."""
    from nexusipam.core import auth
    # The session says 'admin' (set by the fixture) but the store no longer has
    # that user — i.e. the account was deleted while the session was live.
    monkeypatch.setattr(auth, '_users', lambda: {})
    assert auth._user_role(None) == 'readonly'          # fails safe, never admin
    # A mutating call from the now-orphaned session is refused as unauthenticated.
    assert client.post('/api/networks', json={'cidr': '10.0.0.0/24'}).status_code == 401


def test_scope_id_addresses_are_rejected(client):
    """An IPv6 scope-id can carry newlines past ipaddress into rendered exports.
    parse_ip must reject '%', and the API must 400 rather than store it."""
    from nexusipam import netutil
    payload = 'fe80::1%lo\naddress=/evil.example/10.0.0.1'
    assert netutil.parse_ip(payload) is None
    assert netutil.parse_ip('fe80::1%eth0') is None      # even a benign scope-id
    # Every IPv6 parse helper must reject scope-ids, not just parse_ip.
    assert netutil.parse_network('fe80::1%lo/64') is None
    assert netutil.prefix_from_parts('fe80::1%lo\nx', 128) is None
    assert netutil.prefix_from_parts('2001:db8::1', 64) == '2001:db8::/64'
    r = client.post('/api/addresses', json={'address': payload})
    assert r.status_code == 400
    # A plain IPv6 address still works.
    mknet(client, '2001:db8::/64')
    assert client.post('/api/addresses', json={'address': '2001:db8::5'}).status_code == 200


def test_login_hashes_once_per_path(client, monkeypatch):
    """Unknown user and known-user-wrong-password must each cost exactly one
    password hash, so response time does not reveal whether a username exists."""
    from nexusipam.core import auth
    calls = {'n': 0}
    real = auth.check_password_hash
    monkeypatch.setattr(auth, 'check_password_hash',
                        lambda h, p: (calls.__setitem__('n', calls['n'] + 1), real(h, p))[1])
    monkeypatch.setattr(auth, 'load_config',
                        lambda: {'users': {'admin': {'password': auth.generate_password_hash('right'),
                                                      'role': 'admin'}}})
    calls['n'] = 0
    client.post('/api/login', json={'username': 'ghost', 'password': 'x'})   # unknown
    unknown_hashes = calls['n']
    calls['n'] = 0
    client.post('/api/login', json={'username': 'admin', 'password': 'wrong'})  # known, wrong
    known_wrong_hashes = calls['n']
    assert unknown_hashes == 1 and known_wrong_hashes == 1

    # Garbage input is rejected, not treated as "delete nothing quietly".
    assert client.post('/api/addresses/bulk-delete', json={}).status_code == 400
    assert client.post('/api/addresses/bulk-delete', json={'ids': 'all'}).status_code == 400


def test_banner_write_requires_admin(client, monkeypatch):
    from nexusipam.core import auth
    monkeypatch.setattr(auth, '_users',
                        lambda: {'admin': {'password': 'x', 'role': 'readonly'}})
    assert client.post('/api/settings/banner',
                       json={'banner': 'nope'}).status_code == 403
    assert client.get('/api/settings/banner').status_code == 200


# ─── Sync status (importer breadcrumbs) ───────────────────────────────

def test_sync_status_derives_sources_from_data(client):
    client.post('/api/networks', json={'cidr': '10.9.0.0/24', 'name': 'syncnet'})
    r = client.post('/api/addresses?upsert=1',
                    json={'address': '10.9.0.10', 'source': 'unifi',
                          'ext_id': 'u-1', 'dns_name': 'thing.lan'})
    assert r.json['success']
    s = client.get('/api/sync').json
    assert s['sources']['unifi']['total'] == 1
    assert s['sources']['unifi']['tables'] == {'ip_addresses': 1}
    assert s['sources']['unifi']['latest'] > 0
    assert 'manual' not in s['sources']


def test_sync_run_reports(client):
    r = client.post('/api/sync/runs',
                    json={'source': 'vcenter', 'ok': True,
                          'detail': 'inventory import completed',
                          'counts': {'vms': 42}})
    assert r.json['success']
    r = client.post('/api/sync/runs', json={'source': 'unifi', 'ok': False,
                                            'detail': 'login failed'})
    assert r.json['success']
    runs = client.get('/api/sync').json['runs']
    assert runs[0]['source'] == 'unifi' and runs[0]['ok'] is False
    assert runs[1]['source'] == 'vcenter' and runs[1]['counts'] == {'vms': 42}

    # invalid payloads are rejected cleanly
    assert client.post('/api/sync/runs', json={'source': 'bad source'}).status_code == 400
    assert client.post('/api/sync/runs',
                       json={'source': 'x', 'counts': {'a': 'lots'}}).status_code == 400


def test_sync_runs_bounded(client):
    from nexusipam import sync as sync_mod
    for i in range(sync_mod.RUNS_KEEP + 5):
        client.post('/api/sync/runs', json={'source': 'unifi', 'detail': 'run %d' % i})
    runs = client.get('/api/sync').json['runs']
    assert len(runs) == sync_mod.RUNS_KEEP
    assert runs[0]['detail'] == 'run %d' % (sync_mod.RUNS_KEEP + 4)


def test_sync_report_requires_admin(client, monkeypatch):
    from nexusipam.core import auth
    monkeypatch.setattr(auth, '_users',
                        lambda: {'admin': {'password': 'x', 'role': 'readonly'}})
    assert client.post('/api/sync/runs', json={'source': 'unifi'}).status_code == 403
    assert client.get('/api/sync').status_code == 200


# ─── Names: ordered, canonical first (phase 2) ────────────────────────

def _mk_addr(client, address, **kw):
    r = client.post('/api/addresses', json={'address': address, **kw})
    assert r.status_code == 200, r.json
    return r.json['id']


def test_names_ordered_and_cache_synced(client):
    rid = _mk_addr(client, '10.20.0.5', dns_name='stor.lan')
    # dns_name on create seeded the canonical row
    names = client.get('/api/addresses/%d/names' % rid).json['names']
    assert [n['name'] for n in names] == ['stor.lan']
    # full ordered list, aliases with own comments/ids
    r = client.post('/api/addresses/%d/names' % rid, json={'names': [
        {'name': 'stor.lan', 'comment': 'the box', 'ext_id': 'h_abc123'},
        {'name': 'nas.lan', 'comment': 'storage'},
        {'name': 'media.lan', 'enabled': False},
    ]})
    assert r.json['success']
    names = client.get('/api/addresses/%d/names' % rid).json['names']
    assert [n['name'] for n in names] == ['stor.lan', 'nas.lan', 'media.lan']
    assert names[0]['ext_id'] == 'h_abc123' and names[2]['enabled'] == 0
    rec = client.get('/api/addresses/%d' % rid).json
    assert rec['dns_name'] == 'stor.lan'
    # reorder: canonical follows position 0
    client.post('/api/addresses/%d/names' % rid,
                json={'names': ['nas.lan', 'stor.lan']})
    assert client.get('/api/addresses/%d' % rid).json['dns_name'] == 'nas.lan'
    # disabled/cname rows never become the cache
    client.post('/api/addresses/%d/names' % rid,
                json={'names': [{'name': 'off.lan', 'enabled': False},
                                {'name': 'real.lan'}]})
    assert client.get('/api/addresses/%d' % rid).json['dns_name'] == 'real.lan'


def test_names_validation(client):
    rid = _mk_addr(client, '10.20.0.6')
    bad = [
        [{'name': 'not a name'}],
        [{'name': 'a.lan'}, {'name': 'A.LAN'}],          # dup, case-insensitive
        [{'name': 'x.lan', 'rtype': 'mx'}],
        'not-a-list',
    ]
    for payload in bad:
        assert client.post('/api/addresses/%d/names' % rid,
                           json={'names': payload}).status_code == 400
    assert client.post('/api/addresses/999999/names',
                       json={'names': []}).status_code == 404


def test_dns_name_edit_keeps_aliases(client):
    """The address form only knows dns_name; editing it must never destroy
    the deliberate parallel names."""
    rid = _mk_addr(client, '10.20.0.7', dns_name='one.lan')
    client.post('/api/addresses/%d/names' % rid,
                json={'names': ['one.lan', 'two.lan', 'three.lan']})
    # rename canonical via the plain address update
    r = client.post('/api/addresses/%d' % rid, json={'dns_name': 'uno.lan'})
    assert r.json['success']
    names = [n['name'] for n in client.get('/api/addresses/%d/names' % rid).json['names']]
    assert names == ['uno.lan', 'two.lan', 'three.lan']
    # explicit empty clears the CANONICAL row only — aliases survive and the
    # next name is promoted (single-name addresses clear fully, as ever).
    client.post('/api/addresses/%d' % rid, json={'dns_name': ''})
    names = [n['name'] for n in client.get('/api/addresses/%d/names' % rid).json['names']]
    assert names == ['two.lan', 'three.lan']
    assert client.get('/api/addresses/%d' % rid).json['dns_name'] == 'two.lan'


def test_names_migration_lifts_meta_aliases(client):
    from nexusipam.core import db
    rid = _mk_addr(client, '10.20.0.8', dns_name='main.lan')
    db.execute("UPDATE ip_addresses SET meta='{\"aliases\": [\"alias1.lan\", \"alias2.lan\"]}' "
               'WHERE id=?', (rid,))
    db.execute('DELETE FROM ip_names WHERE address_id=?', (rid,))
    db._migrate_names(db.connect())
    names = [n['name'] for n in client.get('/api/addresses/%d/names' % rid).json['names']]
    assert names == ['main.lan', 'alias1.lan', 'alias2.lan']


# ─── Push engine (phase 2) ────────────────────────────────────────────

def test_push_payload_order_and_ids(client):
    from nexusipam import pushout
    a1 = _mk_addr(client, '10.30.0.2')
    a2 = _mk_addr(client, '10.30.0.10')
    client.post('/api/addresses/%d/names' % a2, json={'names': [
        {'name': 'multi.lan', 'ext_id': 'h_9ff297', 'comment': 'canonical'},
        {'name': 'alias.lan', 'ext_id': 'not-a-dnsmaq-id'},
        {'name': 'off.lan', 'enabled': False},
    ]})
    client.post('/api/addresses/%d/names' % a1, json={'names': ['first.lan']})
    recs = pushout.build_hosts()
    assert [r['name'] for r in recs] == ['first.lan', 'multi.lan', 'alias.lan']
    assert recs[1]['id'] == 'h_9ff297' and recs[1]['a'] == '10.30.0.10'
    assert recs[1]['comment'] == 'canonical'
    assert 'id' not in recs[2]              # malformed ext_id -> node assigns
    assert all(r['aaaa'] == '' for r in recs)


def test_push_targets_and_run(client, monkeypatch):
    from nexusipam import pushout
    assert client.post('/api/push/targets',
                       json={'name': 'ns1', 'url': 'http://nope', 'token': 'x'}
                       ).status_code == 400          # https only
    assert client.post('/api/push/targets',
                       json={'name': 'ns1', 'url': 'https://ns1:8443'}
                       ).status_code == 400          # token required
    r = client.post('/api/push/targets',
                    json={'name': 'ns1', 'url': 'https://ns1:8443', 'token': 'dmm_secret'})
    assert r.json['success'] and r.json['target']['has_token']
    assert 'token' not in r.json['target']
    st = client.get('/api/push').json
    assert st['targets'][0]['name'] == 'ns1' and 'token' not in st['targets'][0]

    pushed = []
    monkeypatch.setattr(pushout, 'push_target',
                        lambda t, data, serials: (pushed.append((t['name'], serials)),
                                                  (True, 'applied via restart'))[1])
    _mk_addr(client, '10.30.0.99', dns_name='pushme.lan')
    r = client.post('/api/push/run')
    assert r.json['success'] and r.json['serial'] == 1
    assert pushed == [('ns1', {'hosts': 1})]
    # Unchanged content re-sends the SAME serial: the number versions the
    # payload, not the act of pushing it.
    r = client.post('/api/push/run')
    assert r.json['serial'] == 1
    _mk_addr(client, '10.30.0.98', dns_name='pushme2.lan')
    r = client.post('/api/push/run')
    assert r.json['serial'] == 2                     # content changed
    st = client.get('/api/push').json
    assert st['targets'][0]['last']['ok'] and st['targets'][0]['serial'] == 2

    assert client.delete('/api/push/targets/ns1').json['success']
    assert client.post('/api/push/run').status_code == 400   # no targets left


def test_push_failure_recorded(client, monkeypatch):
    from nexusipam import pushout
    client.post('/api/push/targets',
                json={'name': 'ns2', 'url': 'https://ns2:9443', 'token': 'dmm_x'})
    monkeypatch.setattr(pushout, 'push_target',
                        lambda t, data, serials: (False, 'Invalid mirror token'))
    r = client.post('/api/push/run')
    assert r.status_code == 200 and r.json['success'] is False
    st = client.get('/api/push').json
    t = st['targets'][0]
    assert t['last']['ok'] is False and 'token' in t['last']['detail']
    assert t['serial'] == 0                          # never acked anything


# ─── DHCP options (schema v4) ─────────────────────────────────────────

def test_dhcp_options_are_server_neutral_and_scoped_to_a_network(client):
    nid = mknet(client, '10.60.0.0/24', gateway='10.60.0.1')
    r = client.post('/api/dhcp/options',
                    json={'network_id': nid, 'option': 'option:ntp-server',
                          'value': '10.60.0.5'})
    assert r.status_code == 200, r.json
    assert r.json['option']['option'] == 'option:ntp-server'
    assert r.json['option']['network_cidr'] == '10.60.0.0/24'

    # A bare code is equally valid — dnsmasq accepts both spellings.
    assert client.post('/api/dhcp/options',
                       json={'network_id': nid, 'option': '66',
                             'value': '10.60.0.9'}).status_code == 200
    # One value per option per network.
    assert client.post('/api/dhcp/options',
                       json={'network_id': nid, 'option': '66',
                             'value': '10.60.0.9'}).status_code == 409
    assert client.post('/api/dhcp/options',
                       json={'network_id': nid, 'option': 'not an option',
                             'value': 'x'}).status_code == 400
    assert client.post('/api/dhcp/options',
                       json={'network_id': 9999, 'option': '42',
                             'value': 'x'}).status_code == 400

    # The network detail page is where the options editor lives, so the
    # detail payload must carry them alongside the ranges.
    detail = client.get(f'/api/networks/{nid}/detail').json
    assert sorted(o['option'] for o in detail['dhcp_options']) == \
        ['66', 'option:ntp-server']


def test_dhcp_option_value_cannot_restructure_a_config_file(client):
    nid = mknet(client, '10.61.0.0/24')
    for bad in ['10.0.0.1\ndhcp-option=6,evil', '10.0.0.1 evil', '"quoted"']:
        r = client.post('/api/dhcp/options',
                        json={'network_id': nid, 'option': '42', 'value': bad})
        assert r.status_code == 400, bad


def test_router_dns_and_domain_are_refused_as_options(client):
    """They live on the network row, drive allocation and the deploy payload.
    A second copy here would drift from the first without anyone noticing."""
    nid = mknet(client, '10.62.0.0/24', gateway='10.62.0.1')
    for opt in ('option:router', '3', 'option:dns-server', '6',
                'option:domain-name', '15'):
        r = client.post('/api/dhcp/options',
                        json={'network_id': nid, 'option': opt, 'value': '10.62.0.1'})
        assert r.status_code == 400, opt
        assert 'network' in r.json['error']


def test_dhcp_options_follow_their_network_when_it_is_deleted(client):
    from nexusipam.core import db
    nid = mknet(client, '10.63.0.0/24')
    client.post('/api/dhcp/options',
                json={'network_id': nid, 'option': '42', 'value': '10.63.0.5'})
    assert client.delete('/api/networks/%d' % nid).status_code == 200
    assert db.query_one('SELECT COUNT(*) c FROM dhcp_options')['c'] == 0


def test_dhcp_options_are_in_the_backup_set(client):
    """A table missing from DUMP_TABLES is silently absent from every backup
    and every /api/export/json — which only shows up when a restore is tried."""
    from nexusipam.exports import DUMP_TABLES
    assert 'dhcp_options' in DUMP_TABLES
    nid = mknet(client, '10.64.0.0/24')
    client.post('/api/dhcp/options',
                json={'network_id': nid, 'option': '42', 'value': '10.64.0.5'})
    dump = client.get('/api/export/json').get_json()
    assert len(dump['tables']['dhcp_options']) == 1


def test_v3_database_upgrades_in_place(tmp_path, monkeypatch):
    """Open a real schema-v3 file and confirm v4 lands without touching data
    and without re-running the v2->v3 name migration."""
    import sqlite3
    from nexusipam.core import db as dbmod
    path = str(tmp_path / 'old.db')
    conn = sqlite3.connect(path)
    conn.executescript(dbmod.SCHEMA.replace(
        # strip the v4 table so the file really is a v3 one
        dbmod.SCHEMA[dbmod.SCHEMA.index('CREATE TABLE IF NOT EXISTS dhcp_options'):
                     dbmod.SCHEMA.index('CREATE INDEX IF NOT EXISTS ix_dhcp_options_net')
                     + len('CREATE INDEX IF NOT EXISTS ix_dhcp_options_net ON dhcp_options(network_id);')],
        ''))
    conn.execute("INSERT INTO meta(key,value) VALUES('schema_version','3')")
    conn.execute("INSERT INTO ip_addresses(address,version,addr_hex,dns_name,meta) "
                 "VALUES('10.70.0.1',4,'00000000000000000000000000000001','keep.lan','{}')")
    conn.execute("INSERT INTO ip_names(address_id,name,position,rtype) "
                 "VALUES(1,'keep.lan',0,'a')")
    conn.commit()
    conn.close()
    assert 'dhcp_options' not in open(path, 'rb').read().decode('latin-1')

    monkeypatch.setattr(dbmod, 'DB_PATH', path)
    monkeypatch.setattr(dbmod._local, 'conn', None, raising=False)
    fresh = dbmod.init_db()
    assert fresh.execute("SELECT value FROM meta WHERE key='schema_version'"
                         ).fetchone()[0] == str(dbmod.SCHEMA_VERSION)
    fresh.execute('SELECT * FROM dhcp_options')          # table now exists
    # The address kept its single name — the v3 migration did not run again
    # and duplicate it.
    assert fresh.execute('SELECT COUNT(*) FROM ip_names').fetchone()[0] == 1
    fresh.close()
    dbmod._local.conn = None


# ─── dhcp section renderer ────────────────────────────────────────────

def _scope(client, cidr, start, end, **net):
    nid = mknet(client, cidr, **net)
    r = client.post('/api/dhcp/ranges', json={'network_id': nid, 'start_addr': start,
                                              'end_addr': end, 'lease_time': '24h'})
    assert r.status_code == 200, r.json
    return nid


def test_build_dhcp_always_states_the_router_explicitly(client):
    """dnsmasq answers option 3 with ITSELF when it is not told otherwise, and
    the DHCP server is usually not the gateway. Every scope must carry it."""
    from nexusipam import pushout
    _scope(client, '10.80.0.0/24', '10.80.0.100', '10.80.0.200',
           name='lan', gateway='10.80.0.1', dns_servers='10.80.0.53, 1.1.1.1',
           domain='lab.lan')
    out = pushout.build_dhcp()
    assert len(out['ranges']) == 1
    rng = out['ranges'][0]
    assert (rng['start'], rng['end'], rng['netmask'], rng['lease']) == \
        ('10.80.0.100', '10.80.0.200', '255.255.255.0', '24h')
    opts = {o['option']: o['value'] for o in out['options']}
    assert opts['option:router'] == '10.80.0.1'
    assert opts['option:dns-server'] == '10.80.0.53,1.1.1.1'
    assert opts['option:domain-name'] == 'lab.lan'
    # Options are tied to their range by tag, or dnsmasq applies them globally.
    assert {o['tag'] for o in out['options']} == {rng['tag']} == {'lan'}


def test_build_dhcp_falls_back_to_the_gateway_for_dns(client):
    """A gateway-served scope with no DNS recorded hands out the gateway.
    Emitting nothing would let dnsmasq answer with itself and repoint every
    client on the segment."""
    from nexusipam import pushout
    _scope(client, '10.81.0.0/24', '10.81.0.10', '10.81.0.20',
           name='guest', gateway='10.81.0.1')
    opts = {o['option']: o['value'] for o in pushout.build_dhcp()['options']}
    assert opts['option:dns-server'] == '10.81.0.1'


def test_build_dhcp_carries_extra_options_and_reservations(client):
    from nexusipam import pushout
    nid = _scope(client, '10.82.0.0/24', '10.82.0.100', '10.82.0.200',
                 name='pxe-net', gateway='10.82.0.1')
    client.post('/api/dhcp/options', json={'network_id': nid,
                                           'option': 'option:ntp-server',
                                           'value': '10.82.0.5'})
    client.post('/api/dhcp/options', json={'network_id': nid, 'option': '66',
                                           'value': '10.82.0.236'})
    client.post('/api/dhcp/options', json={'network_id': nid, 'option': '67',
                                           'value': 'netboot.xyz.kpxe',
                                           'enabled': False})
    _mk_addr(client, '10.82.0.9', mac='aa:bb:cc:dd:ee:01', dns_name='pxe.lab.lan',
             status='reserved', is_reservation=True)
    # A hypervisor import knows this VM's MAC, but the machine is statically
    # configured and never asks for a lease — pushing it would fabricate a
    # reservation on the DHCP server for an address nobody leases.
    _mk_addr(client, '10.82.0.8', mac='aa:bb:cc:dd:ee:02', dns_name='vm.lab.lan',
             status='active')
    out = pushout.build_dhcp()
    opts = {o['option']: o['value'] for o in out['options']}
    assert opts['option:ntp-server'] == '10.82.0.5' and opts['66'] == '10.82.0.236'
    assert '67' not in opts                      # disabled options are not sent
    assert out['static_leases'] == [
        {'mac': 'aa:bb:cc:dd:ee:01', 'ip': '10.82.0.9', 'hostname': 'pxe'}]


def test_a_live_host_can_also_be_a_dhcp_reservation(client):
    """The case that made this a column rather than a status: a machine in
    daily use, with a fixed lease. Keying off status='reserved' drops it,
    because someone will quite reasonably mark it active."""
    from nexusipam import pushout
    _scope(client, '10.87.0.0/24', '10.87.0.100', '10.87.0.200', name='n',
           gateway='10.87.0.1')
    _mk_addr(client, '10.87.0.9', mac='aa:bb:cc:00:87:01', dns_name='nas.lab.lan',
             status='active', is_reservation=True)
    _mk_addr(client, '10.87.0.8', mac='aa:bb:cc:00:87:02', status='reserved')
    leases = pushout.build_dhcp()['static_leases']
    assert [l['ip'] for l in leases] == ['10.87.0.9']


def test_reservation_flag_survives_an_unrelated_edit(client):
    """Partial updates layer the stored row under the body, so an edit that
    does not mention the flag must not clear it — this is the bug class that
    bit three times before updates were centralised."""
    from nexusipam import pushout
    _scope(client, '10.88.0.0/24', '10.88.0.100', '10.88.0.200', name='n',
           gateway='10.88.0.1')
    rid = _mk_addr(client, '10.88.0.9', mac='aa:bb:cc:00:88:01',
                   status='active', is_reservation=True)
    assert client.post('/api/addresses/%d' % rid,
                       json={'description': 'moved rack'}).status_code == 200
    assert [l['ip'] for l in pushout.build_dhcp()['static_leases']] == ['10.88.0.9']


def test_v5_database_seeds_the_reservation_flag_from_what_it_replaced(client):
    """An upgrade must publish exactly what it published before."""
    from nexusipam.core import db
    _mk_addr(client, '10.89.0.9', mac='aa:bb:cc:00:89:01', status='reserved')
    _mk_addr(client, '10.89.0.8', mac='aa:bb:cc:00:89:02', status='active')
    db.execute('UPDATE ip_addresses SET is_reservation=0')      # pretend v5
    db._migrate_reservations(db.connect())
    flags = {r['address']: r['is_reservation'] for r in
             db.query('SELECT address, is_reservation FROM ip_addresses')}
    assert flags == {'10.89.0.9': 1, '10.89.0.8': 0}


def test_build_dhcp_keeps_a_disabled_scope_but_marks_it_disabled(client):
    """A documented-but-not-serving scope still consumes address space, and a
    staged cutover enables ranges one at a time — so it must survive the
    render rather than vanish from it."""
    from nexusipam import pushout
    nid = _scope(client, '10.83.0.0/24', '10.83.0.10', '10.83.0.20', name='dmz',
                 gateway='10.83.0.1')
    rid = client.get('/api/dhcp/ranges').get_json()['dhcp_ranges'][0]['id']
    assert client.post('/api/dhcp/ranges/%d' % rid, json={'enabled': False}
                       ).status_code == 200
    out = pushout.build_dhcp()
    assert len(out['ranges']) == 1 and out['ranges'][0]['enabled'] is False
    assert nid


def test_build_dhcp_tags_are_unique_per_network(client):
    from nexusipam import pushout
    _scope(client, '10.84.0.0/24', '10.84.0.10', '10.84.0.20', name='same',
           gateway='10.84.0.1')
    _scope(client, '10.85.0.0/24', '10.85.0.10', '10.85.0.20', name='same',
           gateway='10.85.0.1')
    tags = {r['tag'] for r in pushout.build_dhcp()['ranges']}
    assert len(tags) == 2, tags       # options would cross-apply otherwise


def test_push_counts_report_records_not_section_keys(client, monkeypatch):
    from nexusipam import pushout
    _scope(client, '10.86.0.0/24', '10.86.0.10', '10.86.0.20', name='n',
           gateway='10.86.0.1')
    client.post('/api/push/targets',
                json={'name': 'ns1', 'url': 'https://ns1:8443', 'token': 'dmm_x',
                      'sections': ['dhcp']})
    monkeypatch.setattr(pushout, 'push_target', lambda t, data, serials: (True, 'ok'))
    r = client.post('/api/push/run?sections=dhcp').json
    # 1 range + 2 options (router, dns fallback) — not 3 for the three keys.
    assert r['counts']['dhcp'] == 3


# ─── UniFi DHCP adapter ───────────────────────────────────────────────

_UNIFI_NET = {'192.168.9.0/24': {
    '_id': 'n1', 'name': 'LAN', 'ip_subnet': '192.168.9.1/24', 'vlan': 9,
    'purpose': 'corporate', 'igmp_snooping': True, 'ipv6_interface_type': 'none',
    'dhcpd_enabled': True, 'dhcpd_start': '192.168.9.100',
    'dhcpd_stop': '192.168.9.200', 'dhcpd_leasetime': 86400}}


def _payload(**over):
    p = {'ranges': [{'start': '192.168.9.50', 'end': '192.168.9.99',
                     'netmask': '255.255.255.0', 'lease': '12h',
                     'tag': 'lan', 'enabled': True}],
         'options': [{'tag': 'lan', 'option': 'option:router', 'value': '192.168.9.1'},
                     {'tag': 'lan', 'option': 'option:dns-server',
                      'value': '192.168.9.53,1.1.1.1'}],
         'static_leases': []}
    p.update(over)
    return p


def test_unifi_dhcp_maps_dnsmasq_options_onto_gateway_fields():
    from nexusipam import unifi
    # A router that is NOT the gateway's own interface, so the mapping is
    # exercised rather than skipped as an implicit default.
    d = unifi.desired_dhcp(_payload(options=[
        {'tag': 'lan', 'option': 'option:router', 'value': '192.168.9.254'},
        {'tag': 'lan', 'option': '6', 'value': '192.168.9.53'},
        {'tag': 'lan', 'option': 'option:ntp-server', 'value': '192.168.9.5'},
        {'tag': 'lan', 'option': '66', 'value': '192.168.9.236'},
        {'tag': 'lan', 'option': '67', 'value': 'netboot.xyz.kpxe'}]))
    scope = d['192.168.9.0/24']
    assert scope['lease'] == 43200                       # 12h -> seconds
    changes = unifi._scope_changes(scope, _UNIFI_NET['192.168.9.0/24'], False)
    assert changes['dhcpd_start'] == '192.168.9.50'
    assert changes['dhcpd_gateway'] == '192.168.9.254' and changes['dhcpd_gateway_enabled']
    assert changes['dhcpd_dns_1'] == '192.168.9.53' and changes['dhcpd_dns_2'] == ''
    assert changes['dhcpd_ntp_1'] == '192.168.9.5'
    assert changes['dhcpd_tftp_server'] == '192.168.9.236'
    assert changes['dhcpd_boot_filename'] == 'netboot.xyz.kpxe'
    assert changes['dhcpd_boot_server'] == '192.168.9.236'


def test_unifi_dhcp_leaves_an_implicit_default_alone():
    """UniFi says "hand out my own interface" by leaving the field off; the
    plan says it by naming that address. Same effect, so writing the explicit
    form is churn — and it costs the ability to prove a first push is a no-op."""
    from nexusipam import unifi
    raw = {'_id': 'n1', 'ip_subnet': '192.168.9.1/24',
           'dhcpd_enabled': True, 'dhcpd_start': '192.168.9.50',
           'dhcpd_stop': '192.168.9.99', 'dhcpd_leasetime': 43200,
           'dhcpd_gateway_enabled': False, 'dhcpd_dns_enabled': False}
    scope = unifi.desired_dhcp(_payload())['192.168.9.0/24']
    scope['options'] = {'gateway': '192.168.9.1', 'dns': '192.168.9.1'}
    assert unifi._scope_changes(scope, raw, False) == {}

    # But a value that genuinely differs is still written.
    scope['options'] = {'gateway': '192.168.9.254', 'dns': '192.168.9.1'}
    changes = unifi._scope_changes(scope, raw, False)
    assert changes == {'dhcpd_gateway_enabled': True,
                       'dhcpd_gateway': '192.168.9.254'}

    # And an explicit field already set is compared on its value, not skipped.
    raw2 = dict(raw, dhcpd_dns_enabled=True, dhcpd_dns_1='9.9.9.9')
    scope['options'] = {'dns': '192.168.9.1'}
    assert unifi._scope_changes(scope, raw2, False)['dhcpd_dns_1'] == '192.168.9.1'


def test_unifi_dhcp_never_touches_the_scope_switch_unless_asked():
    """Turning a VLAN's DHCP server off is an outage, not a config tweak."""
    from nexusipam import unifi
    scope = unifi.desired_dhcp(_payload(ranges=[
        {'start': '192.168.9.50', 'end': '192.168.9.99', 'netmask': '255.255.255.0',
         'lease': '12h', 'tag': 'lan', 'enabled': False}]))['192.168.9.0/24']
    raw = _UNIFI_NET['192.168.9.0/24']
    assert 'dhcpd_enabled' not in unifi._scope_changes(scope, raw, False)
    assert unifi._scope_changes(scope, raw, True)['dhcpd_enabled'] is False


def test_unifi_dhcp_reports_options_it_cannot_express():
    """A silently ignored option looks exactly like a satisfied one."""
    from nexusipam import unifi
    d = unifi.desired_dhcp(_payload(options=[
        {'tag': 'lan', 'option': 'option:router', 'value': '192.168.9.1'},
        {'tag': 'lan', 'option': '119', 'value': 'lab.lan'}]))
    p = unifi.plan_dhcp(d, _UNIFI_NET, {}, [])
    assert p['unsupported'] == ['119']
    # option:router IS expressible, so only the genuinely unmappable one is
    # reported — otherwise the signal drowns in noise.
    assert 'option:router' not in p['unsupported']
    assert p['scopes'], 'the mappable part of the scope must still be applied'


def test_unifi_dhcp_flags_a_scope_with_no_matching_gateway_network():
    from nexusipam import unifi
    d = unifi.desired_dhcp(_payload(ranges=[
        {'start': '10.44.0.10', 'end': '10.44.0.20', 'netmask': '255.255.255.0',
         'lease': '12h', 'tag': 'other', 'enabled': True}]))
    p = unifi.plan_dhcp(d, _UNIFI_NET, {}, [])
    assert p['unmatched'] == ['10.44.0.0/24'] and not p['scopes']


def test_unifi_dhcp_skips_networks_that_do_not_serve_dhcp():
    """A VPN pool is in the plan because the space is consumed, not because a
    DHCP server runs there — writing dhcpd_* onto it configures nothing."""
    from nexusipam import unifi
    vpn = {'_id': 'n2', 'name': 'VPN', 'ip_subnet': '10.44.0.1/24',
           'purpose': 'remote-user-vpn'}
    d = unifi.desired_dhcp(_payload(ranges=[
        {'start': '10.44.0.10', 'end': '10.44.0.20', 'netmask': '255.255.255.0',
         'lease': '12h', 'tag': 'vpn', 'enabled': True}]))
    p = unifi.plan_dhcp(d, {'10.44.0.0/24': vpn}, {}, [])
    assert p['skipped'] == [('10.44.0.0/24', 'remote-user-vpn')]
    assert not p['scopes'] and not p['unmatched']


def test_dns_authority_does_not_confer_reservation_authority(client):
    """unifi_delete_extra exists to make this IPAM authoritative over Static
    DNS. If it also governed reservations, turning on "publish my names" would
    unbind every machine the plan does not list."""
    from nexusipam import unifi
    called = {}

    def fake_plan(desired, networks, fixed, leases, mirror=False, manage_state=False):
        called['mirror'] = mirror
        return {'scopes': [], 'fixed_set': [], 'fixed_clear': [], 'unmatched': [],
                'skipped': [], 'unsupported': [], 'unchanged': 0}

    class FakeClient:
        def list_networks(self):
            return {}
        def list_fixed(self):
            return {}

    real = unifi.plan_dhcp
    unifi.plan_dhcp = fake_plan
    try:
        unifi.sync_dhcp({'unifi_delete_extra': True}, _payload(), client=FakeClient())
        assert called['mirror'] is False        # DNS authority does not leak
        unifi.sync_dhcp({'unifi_dhcp_delete_extra': True}, _payload(),
                        client=FakeClient())
        assert called['mirror'] is True         # its own flag does
    finally:
        unifi.plan_dhcp = real


def test_unifi_reservations_are_set_updated_and_withdrawn():
    from nexusipam import unifi
    d = unifi.desired_dhcp(_payload())
    leases = [{'mac': 'aa:bb:cc:00:00:01', 'ip': '192.168.9.10', 'hostname': 'a'},
              {'mac': 'aa:bb:cc:00:00:02', 'ip': '192.168.9.11', 'hostname': 'b'}]
    fixed = {'aa:bb:cc:00:00:02': {'id': 'u2', 'ip': '192.168.9.99'},
             'aa:bb:cc:00:00:09': {'id': 'u9', 'ip': '192.168.9.50'}}
    p = unifi.plan_dhcp(d, _UNIFI_NET, fixed, leases, mirror=True)
    assert [m for m, _l, _c in p['fixed_set']] == ['aa:bb:cc:00:00:01',
                                                   'aa:bb:cc:00:00:02']
    assert [m for m, _c in p['fixed_clear']] == ['aa:bb:cc:00:00:09']
    # Without mirror, a reservation we did not author is left alone.
    assert unifi.plan_dhcp(d, _UNIFI_NET, fixed, leases)['fixed_clear'] == []


def test_unifi_network_update_merges_rather_than_replaces():
    """The network object carries VLAN, purpose and IPv6 settings this app
    does not model; a PUT built from our fields alone would blank them."""
    from nexusipam import unifi
    sent = {}

    class FakeClient(unifi.UniFiClient):
        def __init__(self):
            pass
        site = 'default'
        def _req(self, method, path, body=None):
            sent.update({'method': method, 'path': path, 'body': body})
            return 200, {}

    FakeClient().update_network(_UNIFI_NET['192.168.9.0/24'],
                                {'dhcpd_start': '192.168.9.50'})
    assert sent['method'] == 'PUT' and sent['path'].endswith('/networkconf/n1')
    assert sent['body']['dhcpd_start'] == '192.168.9.50'
    assert sent['body']['vlan'] == 9 and sent['body']['purpose'] == 'corporate'
    assert sent['body']['ipv6_interface_type'] == 'none'


def test_unifi_withdrawing_a_reservation_keeps_the_client():
    """Deleting the client would discard its name, network and history too."""
    from nexusipam import unifi
    sent = {}

    class FakeClient(unifi.UniFiClient):
        def __init__(self):
            pass
        site = 'default'
        def _req(self, method, path, body=None):
            sent.update({'method': method, 'path': path, 'body': body})
            return 200, {}

    FakeClient().clear_fixed('u9', 'aa:bb:cc:00:00:09')
    assert sent['method'] == 'PUT'                    # not DELETE
    assert sent['body'] == {'use_fixedip': False}


def test_lease_seconds_round_trips_dnsmasq_spellings():
    from nexusipam import unifi
    assert unifi.lease_seconds('12h') == 43200
    assert unifi.lease_seconds('90m') == 5400
    assert unifi.lease_seconds('3600') == 3600
    assert unifi.lease_seconds('infinite') == 86400
    assert unifi.lease_seconds('nonsense') == 86400


# ─── Adopting a gateway's existing state ──────────────────────────────

_SNAPSHOT = {
    'networks': [{
        'cidr': '10.90.0.0/24', 'ext_id': 'n1', 'name': 'lan', 'vlan': 9,
        'gateway': '10.90.0.1', 'dns': ['10.90.0.53'], 'domain': 'lab.lan',
        'options': {'option:ntp-server': '10.90.0.5',
                    'option:router': '10.90.0.1'},
        'range': {'start': '10.90.0.100', 'end': '10.90.0.200',
                  'lease': '24h', 'enabled': True}}],
    'reservations': [{'mac': 'aa:bb:cc:00:90:01', 'ip': '10.90.0.10',
                      'hostname': 'printer', 'ext_id': 'u1'}],
}


def test_adopt_creates_the_whole_scope_and_is_idempotent(client):
    from nexusipam import adopt
    from nexusipam.core import db
    r = adopt.adopt_snapshot(_SNAPSHOT)
    assert r['networks_created'] == ['10.90.0.0/24']
    assert r['ranges_created'] == ['10.90.0.100-10.90.0.200']
    assert r['reservations_created'] == ['10.90.0.10'] and not r['errors']
    net = db.query_one('SELECT * FROM networks WHERE cidr=?', ('10.90.0.0/24',))
    assert (net['gateway'], net['dns_servers'], net['domain']) == \
        ('10.90.0.1', '10.90.0.53', 'lab.lan')
    assert db.query_one('SELECT vid FROM vlans')['vid'] == 9
    # option:router was adopted onto the network row, not duplicated as an
    # option — the two would drift.
    opts = [o['option'] for o in db.query('SELECT option FROM dhcp_options')]
    assert opts == ['option:ntp-server']
    # The reservation files under the network it belongs to.
    res = db.query_one('SELECT * FROM ip_addresses WHERE address=?', ('10.90.0.10',))
    assert res['status'] == 'reserved' and res['network_id'] == net['id']

    again = adopt.adopt_snapshot(_SNAPSHOT)
    assert again['networks_kept'] == ['10.90.0.0/24']
    assert again['ranges_kept'] and again['reservations_kept'] == ['10.90.0.10']
    assert not again['networks_created'] and not again['errors']
    assert db.query_one('SELECT COUNT(*) c FROM dhcp_ranges')['c'] == 1


def test_adopt_fills_gaps_but_never_overwrites(client):
    """An adopt that clobbered a corrected value would make the operator's own
    work the thing most likely to be lost."""
    from nexusipam import adopt
    from nexusipam.core import db
    nid = mknet(client, '10.90.0.0/24', name='hand-named', domain='mine.lan')
    _mk_addr(client, '10.90.0.10', dns_name='printer.mine.lan')
    adopt.adopt_snapshot(_SNAPSHOT)
    net = db.query_one('SELECT * FROM networks WHERE id=?', (nid,))
    assert net['name'] == 'hand-named' and net['domain'] == 'mine.lan'
    assert net['gateway'] == '10.90.0.1'          # the blank was filled
    rec = db.query_one('SELECT * FROM ip_addresses WHERE address=?', ('10.90.0.10',))
    assert rec['dns_name'] == 'printer.mine.lan'  # name untouched
    assert rec['mac'] == 'aa:bb:cc:00:90:01'      # MAC merged in


def test_adopt_refuses_to_add_an_overlapping_range(client):
    """Two pools handing out the same address is the conflict this app exists
    to prevent — adopting one alongside another would create it."""
    from nexusipam import adopt
    from nexusipam.core import db
    nid = mknet(client, '10.90.0.0/24')
    client.post('/api/dhcp/ranges', json={'network_id': nid,
                                          'start_addr': '10.90.0.150',
                                          'end_addr': '10.90.0.250'})
    r = adopt.adopt_snapshot(_SNAPSHOT)
    assert r['errors'] and 'overlaps' in r['errors'][0]
    assert db.query_one('SELECT COUNT(*) c FROM dhcp_ranges')['c'] == 1


def test_adopt_keeps_a_defined_but_disabled_scope(client):
    from nexusipam import adopt
    from nexusipam.core import db
    import copy
    snap = copy.deepcopy(_SNAPSHOT)
    snap['networks'][0]['range']['enabled'] = False
    adopt.adopt_snapshot(snap)
    # A defined range consumes that space whether or not it is serving, which
    # is exactly why it belongs in the plan.
    assert db.query_one('SELECT enabled FROM dhcp_ranges')['enabled'] == 0


def test_pull_route_needs_a_credential_or_a_real_target(client):
    # A dnsmaq target without a read token cannot be read — the mirror token
    # is write-only on the node by design (with one, pulling works: see
    # test_pull_from_a_dnsmaq_node_needs_the_read_token).
    client.post('/api/push/targets',
                json={'name': 'ns1', 'url': 'https://ns1:8443', 'token': 'dmm_x'})
    r = client.post('/api/push/targets/ns1/pull')
    assert r.status_code == 400 and 'read token' in r.json['error']
    assert client.post('/api/push/targets/nope/pull').status_code == 404


def test_unifi_read_state_ignores_disabled_option_fields():
    """UniFi keeps stale values in fields it is not using — adopting those
    would record addresses no client has ever been handed."""
    from nexusipam import unifi
    raw = {'_id': 'n1', 'name': 'LAN', 'ip_subnet': '10.91.0.1/24',
           'vlan_enabled': True, 'vlan': 9,
           'dhcpd_enabled': True, 'dhcpd_start': '10.91.0.100',
           'dhcpd_stop': '10.91.0.200', 'dhcpd_leasetime': 86400,
           'dhcpd_ntp_enabled': False, 'dhcpd_ntp_1': '10.91.0.99',
           'dhcpd_dns_enabled': False, 'dhcpd_dns_1': '10.91.0.98'}

    class FakeClient:
        def list_networks(self):
            return {'10.91.0.0/24': raw}
        def list_fixed(self):
            return {}

    state = unifi.read_state({}, client=FakeClient())
    net = state['networks'][0]
    assert 'option:ntp-server' not in net['options'] and net['dns'] == []
    # With no explicit dhcpd_gateway, the segment's router is the gateway's
    # own interface address.
    assert net['gateway'] == '10.91.0.1'
    assert net['range'] == {'start': '10.91.0.100', 'end': '10.91.0.200',
                            'lease': '24h', 'enabled': True}


# ─── Lease overlay ────────────────────────────────────────────────────

def test_leases_are_observed_never_written_into_the_plan(client):
    from nexusipam import leases
    from nexusipam.core import db
    mknet(client, '10.95.0.0/24')
    stored, _ = leases.record_leases('gw', [
        {'ip': '10.95.0.50', 'mac': 'aa:bb:cc:00:95:01', 'hostname': 'laptop'},
        {'ip': '10.95.0.51', 'mac': 'aa:bb:cc:00:95:02', 'hostname': 'phone'}])
    assert stored == 2
    # The whole point: none of this became an address record.
    assert db.query_one('SELECT COUNT(*) c FROM ip_addresses')['c'] == 0
    body = client.get('/api/leases').get_json()
    assert body['count'] == 2 and body['unrecorded'] == 2


def test_lease_refresh_drops_what_the_source_stopped_reporting(client):
    """A lease that has gone is absent from the next poll, never announced —
    so the overlay has to be replaced, not accumulated."""
    from nexusipam import leases
    leases.record_leases('gw', [{'ip': '10.96.0.10', 'mac': 'aa:bb:cc:00:96:01'},
                                {'ip': '10.96.0.11', 'mac': 'aa:bb:cc:00:96:02'}])
    stored, removed = leases.record_leases('gw', [{'ip': '10.96.0.10',
                                                   'mac': 'aa:bb:cc:00:96:01'}])
    assert (stored, removed) == (1, 1)
    assert client.get('/api/leases').get_json()['count'] == 1


def test_lease_refresh_leaves_other_sources_alone(client):
    from nexusipam import leases
    leases.record_leases('gw-a', [{'ip': '10.97.0.10', 'mac': 'aa:bb:cc:00:97:01'}])
    leases.record_leases('gw-b', [{'ip': '10.98.0.10', 'mac': 'aa:bb:cc:00:98:01'}])
    leases.record_leases('gw-a', [{'ip': '10.97.0.11', 'mac': 'aa:bb:cc:00:97:02'}])
    addrs = {l['address'] for l in client.get('/api/leases').get_json()['leases']}
    assert addrs == {'10.97.0.11', '10.98.0.10'}


def test_lease_flags_an_address_used_by_the_wrong_machine(client):
    """Reserved for one MAC, leased to another — the signal a ping sweep
    cannot give you."""
    from nexusipam import leases
    mknet(client, '10.99.0.0/24')
    _mk_addr(client, '10.99.0.10', mac='aa:bb:cc:00:99:01', dns_name='printer.lan')
    leases.record_leases('gw', [{'ip': '10.99.0.10', 'mac': 'ff:ee:dd:00:00:01',
                                 'hostname': 'someone-elses-laptop'}])
    body = client.get('/api/leases').get_json()
    assert body['conflicts'] == 1
    row = body['leases'][0]
    assert row['record_name'] == 'printer.lan' and row['conflict'] is True


def test_unifi_read_leases_skips_fixed_ip_clients():
    """A fixed binding is a plan record, not a dynamic lease — counting it as
    both double-counts the address."""
    from nexusipam import unifi

    class FakeClient:
        def list_active(self):
            return [{'ip': '10.99.0.20', 'mac': 'AA:BB:CC:00:00:20', 'hostname': 'dyn'},
                    {'ip': '10.99.0.21', 'mac': 'aa:bb:cc:00:00:21', 'use_fixedip': True},
                    {'mac': 'aa:bb:cc:00:00:22'}]          # no address yet

    out = unifi.read_leases({}, client=FakeClient())
    assert out == [{'ip': '10.99.0.20', 'mac': 'aa:bb:cc:00:00:20',
                    'hostname': 'dyn', 'expires': 0}]


def test_lease_refresh_all_reads_every_gateway_and_survives_one_failing(client, monkeypatch):
    """The scheduled refresher polls each enabled unifi target; a dnsmaq node
    has no leases to offer and one unreachable gateway must not stop the
    others being read."""
    from nexusipam import leases, unifi
    client.post('/api/push/targets',
                json={'name': 'ns1', 'url': 'https://ns1:8443', 'token': 'dmm_x'})
    for name in ('gw-ok', 'gw-down'):
        client.post('/api/push/targets',
                    json={'name': name, 'kind': 'unifi', 'url': 'https://gw',
                          'unifi_username': 'admin', 'unifi_password': 'pw'})

    def fake_read(peer, client=None):
        if peer['name'] == 'gw-down':
            raise unifi.UniFiError('login rejected')
        return [{'ip': '10.90.0.7', 'mac': 'aa:bb:cc:00:90:01', 'hostname': 'dyn'}]

    monkeypatch.setattr(unifi, 'read_leases', fake_read)
    report = leases.refresh_all()
    assert {r['target']: r['ok'] for r in report} == {'gw-ok': True, 'gw-down': False}
    rows = client.get('/api/leases').get_json()['leases']
    assert [(l['address'], l['source']) for l in rows] == [('10.90.0.7', 'gw-ok')]


# ─── DHCP-derived DNS names ───────────────────────────────────────────

def _fake_gateway_names(client, monkeypatch, reservations):
    """A unifi target whose read_state returns the given reservations."""
    from nexusipam import unifi
    client.post('/api/push/targets',
                json={'name': 'gw', 'kind': 'unifi', 'url': 'https://gw',
                      'unifi_username': 'admin', 'unifi_password': 'pw'})
    monkeypatch.setattr(unifi, 'read_state',
                        lambda peer, client=None: {'networks': [],
                                                   'reservations': reservations})


def test_search_finds_aliases_not_just_the_canonical_name(client):
    """dns_name caches only position 0, but the DNS servers answer for every
    name on the record — a search that misses aliases contradicts what the
    network visibly resolves (found live: vmdeploy was unfindable)."""
    mknet(client, '10.81.0.0/24')
    _mk_addr(client, '10.81.0.5', dns_name='docker.lab.test')
    rec = client.get('/api/addresses/search?q=docker.lab.test').json['addresses'][0]
    client.post('/api/addresses/%d/names' % rec['id'],
                json={'names': ['docker.lab.test', 'home.lab.test',
                                'vmdeploy.lab.test']})

    r = client.get('/api/addresses/search?q=vmdeploy').json
    assert r['count'] == 1 and r['addresses'][0]['address'] == '10.81.0.5'
    # The list shows how many names the address publishes.
    assert r['addresses'][0]['name_count'] == 3
    # The global search box finds it too.
    g = client.get('/api/search?q=vmdeploy').json
    assert [a['address'] for a in g['addresses']] == ['10.81.0.5']
    # And the canonical column is untouched — position 0 still wins.
    assert r['addresses'][0]['dns_name'] == 'docker.lab.test'


def test_name_candidates_carry_source_and_trust(client, monkeypatch):
    """Three name sources per reservation, three trust levels; names the plan
    already publishes are not candidates; lease hostnames appear flagged
    dynamic. Bare names are qualified with the network domain — push does not
    qualify, so the stored form must be the FQDN."""
    from nexusipam import leases
    mknet(client, '10.70.0.0/24', domain='example.net')
    _mk_addr(client, '10.70.0.8', dns_name='printer.example.net')
    _mk_addr(client, '10.70.0.9')
    _fake_gateway_names(client, monkeypatch, [
        # local_dns matches what is already published -> only the label is new
        {'ip': '10.70.0.8', 'mac': 'aa:bb:cc:00:70:01', 'hostname': 'Printer',
         'names': {'local_dns': 'printer.example.net', 'label': 'Office Printer',
                   'opt12_hostname': ''}},
        # bare hostname -> qualified with the network domain
        {'ip': '10.70.0.9', 'mac': 'aa:bb:cc:00:70:02', 'hostname': 'nas',
         'names': {'local_dns': '', 'label': '', 'opt12_hostname': 'nas'}},
    ])
    leases.record_leases('gw', [{'ip': '10.70.0.50', 'mac': 'aa:bb:cc:00:70:03',
                                 'hostname': 'laptop'}])

    r = client.get('/api/names/candidates').get_json()
    by_fqdn = {c['fqdn']: c for c in r['candidates']}
    assert 'printer.example.net' not in by_fqdn          # already published
    label = by_fqdn['Office Printer.example.net']
    assert label['source'] == 'label' and label['confidence'] == 'medium'
    assert label['valid'] is False                        # propose, never mangle
    nas = by_fqdn['nas.example.net']
    assert (nas['source'], nas['confidence'], nas['valid']) == \
        ('opt12_hostname', 'low', True)
    dyn = by_fqdn['laptop.example.net']
    assert dyn['dynamic'] is True and dyn['source'] == 'lease'


def test_name_adopt_rules(client, monkeypatch):
    """Adopt is explicit and conservative: canonical only on a nameless
    address, alias otherwise; collisions refused; invalid names dropped;
    lease-derived names refused outright."""
    from nexusipam import leases, pushout
    mknet(client, '10.71.0.0/24', domain='example.net')
    _mk_addr(client, '10.71.0.5')                                  # nameless
    _mk_addr(client, '10.71.0.6', dns_name='web.example.net')      # has a name
    _mk_addr(client, '10.71.0.7')                                  # collision case
    _mk_addr(client, '10.71.0.9')                                  # lease-only
    _fake_gateway_names(client, monkeypatch, [
        {'ip': '10.71.0.5', 'mac': 'aa:bb:cc:00:71:01', 'hostname': '',
         'names': {'local_dns': 'nas.example.net', 'label': 'NAS',
                   'opt12_hostname': 'nas'}},
        {'ip': '10.71.0.6', 'mac': 'aa:bb:cc:00:71:02', 'hostname': '',
         'names': {'local_dns': '', 'label': '', 'opt12_hostname': 'media'}},
        {'ip': '10.71.0.7', 'mac': 'aa:bb:cc:00:71:03', 'hostname': '',
         'names': {'local_dns': 'web.example.net', 'label': '',
                   'opt12_hostname': ''}},
    ])
    leases.record_leases('gw', [{'ip': '10.71.0.9', 'mac': 'aa:bb:cc:00:71:09',
                                 'hostname': 'roamer'}])

    r = client.post('/api/names/adopt',
                    json={'addresses': ['10.71.0.5', '10.71.0.6', '10.71.0.7',
                                        '10.71.0.9']}).get_json()
    adopted = {a['address']: a for a in r['adopted']}
    # Highest-trust source wins and lands canonical on the nameless address.
    assert adopted['10.71.0.5']['fqdn'] == 'nas.example.net'
    assert adopted['10.71.0.5']['as'] == 'canonical'
    assert adopted['10.71.0.5']['handover'] is True
    # An address with names gains an alias; position 0 (the PTR) never moves.
    assert adopted['10.71.0.6']['as'] == 'alias'
    refused = {x['address']: x['reason'] for x in r['refused']}
    assert 'web.example.net' in refused['10.71.0.7']      # resolves elsewhere
    assert 'reservation' in refused['10.71.0.9']          # lease-derived
    # The adopted names are exactly what the hosts payload now renders.
    rendered = {h['name'] for h in pushout.build_hosts()}
    assert {'nas.example.net', 'web.example.net', 'media.example.net'} <= rendered


def test_dnsmaq_leases_need_a_read_token_and_skip_statics(client, monkeypatch):
    """The mirror token is write-only on the node by design, so lease polling
    needs the separate read token; static (reservation-held) MACs are skipped
    like the UniFi reader skips fixed-IP clients."""
    from nexusipam import leases

    # DNSMAQ's /api/dhcp/leases shape -> overlay items, statics dropped.
    body = {'leases': [
        {'expiry': 1755100000, 'mac': 'AA:BB:CC:00:74:01', 'ip': '10.74.0.20',
         'hostname': 'dyn', 'static': False},
        {'expiry': 1755100000, 'mac': 'aa:bb:cc:00:74:02', 'ip': '10.74.0.21',
         'hostname': 'resv', 'static': True},
        {'expiry': 0, 'mac': 'aa:bb:cc:00:74:03', 'ip': '', 'hostname': ''},
    ]}
    assert leases.dnsmaq_lease_items(body) == [
        {'ip': '10.74.0.20', 'mac': 'aa:bb:cc:00:74:01',
         'hostname': 'dyn', 'expires': 1755100000}]

    client.post('/api/push/targets',
                json={'name': 'ns1', 'url': 'https://ns1:8443', 'token': 'dmm_x'})
    r = client.post('/api/push/targets/ns1/leases')
    assert r.status_code == 400 and 'read token' in r.json['error']

    # Adding the read token makes the node pollable; secrets stay booleans.
    r = client.post('/api/push/targets',
                    json={'name': 'ns1', 'read_token': 'dm_readonly'})
    assert r.json['target']['has_read_token'] is True
    assert 'read_token' not in r.json['target']
    monkeypatch.setattr(leases, 'read_dnsmaq_leases',
                        lambda t: [{'ip': '10.74.0.30', 'mac': 'aa:bb:cc:00:74:05',
                                    'hostname': 'polled', 'expires': 0}])
    r = client.post('/api/push/targets/ns1/leases')
    assert r.status_code == 200 and r.json['leases'] == 1
    rows = client.get('/api/leases').get_json()['leases']
    assert [(l['address'], l['source']) for l in rows] == [('10.74.0.30', 'ns1')]

    # refresh_all now includes it, and an empty save keeps the stored token.
    client.post('/api/push/targets', json={'name': 'ns1', 'read_token': ''})
    report = leases.refresh_all()
    assert report == [{'target': 'ns1', 'ok': True, 'leases': 1, 'expired': 0}]


def test_leases_are_not_in_the_backup_set():
    """Observed state is re-observed, not restored — and a stale lease table
    restored into a live instance would describe a network that has moved on."""
    from nexusipam.exports import DUMP_TABLES
    assert 'dhcp_leases' not in DUMP_TABLES


# ─── Multi-section push ───────────────────────────────────────────────

def _fake_section(monkeypatch, name, payload):
    """Register an extra renderable section for the duration of a test."""
    from nexusipam import pushout
    monkeypatch.setitem(pushout.SECTION_BUILDERS, name, lambda: payload)


def test_target_defaults_to_hosts_and_rejects_unknown_sections(client):
    r = client.post('/api/push/targets',
                    json={'name': 'ns1', 'url': 'https://ns1:8443', 'token': 'dmm_x'})
    assert r.json['target']['sections'] == ['hosts']      # default, not empty

    assert client.post('/api/push/targets',
                       json={'name': 'ns2', 'url': 'https://ns2:8443', 'token': 'dmm_x',
                             'sections': ['hosts', 'nonsense']}
                       ).status_code == 400
    assert client.post('/api/push/targets',
                       json={'name': 'ns3', 'url': 'https://ns3:8443', 'token': 'dmm_x',
                             'sections': []}
                       ).status_code == 400


def test_serials_are_per_section_and_do_not_cross_contaminate(client, monkeypatch):
    from nexusipam import pushout
    payload = [{'x': 1}]
    _fake_section(monkeypatch, 'dhcp', payload)
    client.post('/api/push/targets',
                json={'name': 'ns1', 'url': 'https://ns1:8443', 'token': 'dmm_x',
                      'sections': ['hosts', 'dhcp']})
    seen = []
    monkeypatch.setattr(pushout, 'push_target',
                        lambda t, data, serials: (seen.append(serials),
                                                  (True, 'ok'))[1])
    client.post('/api/push/run')
    assert seen[-1] == {'hosts': 1, 'dhcp': 1}

    # A dhcp-only change must not advance the hosts counter: otherwise "is
    # this node's hosts section current?" stops being answerable from the
    # serial.
    payload[0]['x'] = 2
    client.post('/api/push/run?sections=dhcp')
    assert seen[-1] == {'dhcp': 2}
    serials = client.get('/api/push').json['serials']
    # Exact keys are not asserted: a new renderable section (netboot, …)
    # legitimately appears at 0 without having been pushed.
    assert serials['hosts'] == 1 and serials['dhcp'] == 2

    # And an unchanged hosts payload keeps its version.
    client.post('/api/push/run?sections=hosts')
    assert seen[-1] == {'hosts': 1}
    assert client.post('/api/push/run?sections=bogus').status_code == 400


def test_single_target_push_does_not_strand_the_others(client, monkeypatch):
    """Serials version CONTENT, not pushes. Pushing one target with an
    unchanged payload re-sends the current serial (DNSMAQ-MGR rejects only
    strictly lower ones, so an equal serial re-applies idempotently) — the
    other subscribers must NOT flip to "behind". The push-counting version
    of this produced live whack-a-mole: every per-target catch-up push
    advanced the number the rest were judged by."""
    from nexusipam import pushout
    for name in ('ns1', 'ns2'):
        client.post('/api/push/targets',
                    json={'name': name, 'url': 'https://%s:8443' % name,
                          'token': 'dmm_x'})
    monkeypatch.setattr(pushout, 'push_target',
                        lambda t, data, serials: (True, 'ok'))
    _mk_addr(client, '10.31.0.5', dns_name='steady.lan')
    client.post('/api/push/run')                     # both targets at serial 1
    for _ in range(3):
        client.post('/api/push/run?target=ns1')      # repeated one-target pushes
    st = client.get('/api/push').json
    assert st['serials']['hosts'] == 1
    held = {t['name']: t['serials']['hosts'] for t in st['targets']}
    assert held == {'ns1': 1, 'ns2': 1}              # nobody is "behind"


def test_serials_carry_forward_from_the_pre_section_counter(client, monkeypatch):
    """A node that already holds serial 14 rejects a push numbered 1 as stale,
    so the first per-section run must continue the old global count."""
    from nexusipam import pushout
    from nexusipam.core import db
    db.set_setting(pushout.SERIAL_KEY, 14)
    client.post('/api/push/targets',
                json={'name': 'ns1', 'url': 'https://ns1:8443', 'token': 'dmm_x'})
    seen = []
    monkeypatch.setattr(pushout, 'push_target',
                        lambda t, data, serials: (seen.append(serials), (True, 'ok'))[1])
    client.post('/api/push/run')
    assert seen[-1] == {'hosts': 15}


def test_dnsmaq_store_round_trips_through_adopt(client):
    """build_dhcp emits DNSMAQ's own store shapes, so its output fed through
    the dnsmaq state mapper must reproduce the plan's facts — the same
    round-trip-fidelity bar the DNS side had to clear before authoring."""
    from nexusipam import adopt, pushout
    nid = mknet(client, '10.78.0.0/24', name='labnet', gateway='10.78.0.1',
                dns_servers='10.78.0.53, 10.78.0.54', domain='lab.example.net')
    client.post('/api/dhcp/ranges',
                json={'network_id': nid, 'start_addr': '10.78.0.100',
                      'end_addr': '10.78.0.200', 'lease_time': '24h'})
    client.post('/api/dhcp/options',
                json={'network_id': nid, 'option': 'option:ntp-server',
                      'value': '10.78.0.5'})
    client.post('/api/addresses',
                json={'address': '10.78.0.10', 'mac': 'aa:bb:cc:00:78:01',
                      'dns_name': 'nas.lab.example.net', 'is_reservation': True})

    state = adopt.dnsmaq_state(pushout.build_dhcp())
    assert len(state['networks']) == 1
    n = state['networks'][0]
    assert n['cidr'] == '10.78.0.0/24'
    assert n['gateway'] == '10.78.0.1'
    assert n['dns'] == ['10.78.0.53', '10.78.0.54']
    assert n['domain'] == 'lab.example.net'
    assert n['options'] == {'option:ntp-server': '10.78.0.5'}
    assert n['range'] == {'start': '10.78.0.100', 'end': '10.78.0.200',
                          'lease': '24h', 'enabled': True}
    assert state['reservations'] == [{'mac': 'aa:bb:cc:00:78:01',
                                      'ip': '10.78.0.10', 'hostname': 'nas',
                                      'ext_id': ''}]
    # Re-adopting our own render changes nothing — everything is kept.
    report = adopt.adopt_snapshot(state, source='roundtrip')
    assert not report['errors']
    assert report['networks_kept'] == ['10.78.0.0/24']
    assert report['ranges_kept'] and report['options_kept']
    assert report['reservations_kept'] == ['10.78.0.10']


def test_pull_from_a_dnsmaq_node_needs_the_read_token(client, monkeypatch):
    from nexusipam import adopt
    client.post('/api/push/targets',
                json={'name': 'ns1', 'url': 'https://ns1:8443', 'token': 'dmm_x'})
    r = client.post('/api/push/targets/ns1/pull')
    assert r.status_code == 400 and 'read token' in r.json['error']

    client.post('/api/push/targets', json={'name': 'ns1', 'read_token': 'dm_r'})
    monkeypatch.setattr(adopt, 'read_dnsmaq_state',
                        lambda t: {'networks': [
                            {'cidr': '10.79.0.0/24', 'ext_id': 'r_aaaaaa',
                             'name': 'pool', 'vlan': None, 'gateway': '10.79.0.1',
                             'domain': '', 'dns': [], 'options': {},
                             'range': {'start': '10.79.0.50', 'end': '10.79.0.99',
                                       'lease': '12h', 'enabled': False}}],
                            'reservations': []})
    r = client.post('/api/push/targets/ns1/pull?dry_run=1')
    assert r.json['dry_run'] and r.json['state']['networks'][0]['cidr'] == '10.79.0.0/24'
    r = client.post('/api/push/targets/ns1/pull')
    assert r.json['networks_created'] == ['10.79.0.0/24']
    assert r.json['ranges_created'] == ['10.79.0.50-10.79.0.99']


def test_netboot_section_renders_from_the_pxe_options(client):
    """PXE is recorded once (tftp + bootfile options per network) and renders
    to DNSMAQ's own netboot model — dhcp-boot, not options 66/67, which many
    PXE ROMs ignore. Half a pair renders nothing; identical pairs collapse."""
    from nexusipam import pushout
    a = mknet(client, '10.75.0.0/24', name='lab "quoted"')
    b = mknet(client, '10.76.0.0/24', name='second')
    c = mknet(client, '10.77.0.0/24', name='half-configured')
    for nid, opts in ((a, {'option:tftp-server': '10.75.0.9',
                           'option:bootfile-name': 'netboot.xyz.kpxe'}),
                      (b, {'option:tftp-server': '10.75.0.9',
                           'option:bootfile-name': 'netboot.xyz.kpxe'}),
                      (c, {'option:tftp-server': '10.77.0.9'})):
        for opt, val in opts.items():
            assert client.post('/api/dhcp/options',
                               json={'network_id': nid, 'option': opt,
                                     'value': val}).status_code == 200
    nb = pushout.build_netboot()
    assert len(nb['entries']) == 1            # dedup + half-pair skipped
    e = nb['entries'][0]
    assert e['server'] == '10.75.0.9' and e['filename'] == 'netboot.xyz.kpxe'
    assert '"' not in e['name']               # node refuses quoted names

    # dnsmaq targets can subscribe; a gateway cannot (PXE rides in its dhcp
    # section as dhcpd_boot_* — two copies could disagree).
    r = client.post('/api/push/targets',
                    json={'name': 'ns1', 'url': 'https://ns1:8443',
                          'token': 'dmm_x', 'sections': ['hosts', 'netboot']})
    assert r.status_code == 200
    r = client.post('/api/push/targets',
                    json={'name': 'gw', 'kind': 'unifi', 'url': 'https://gw',
                          'unifi_username': 'a', 'unifi_password': 'b',
                          'sections': ['netboot']})
    assert r.status_code == 400 and 'cannot carry' in r.json['error']


# ─── Technitium adapter ───────────────────────────────────────────────

def test_technitium_plan_hosts_owns_only_tagged_records():
    """Ownership is exact: reconcile touches only comment-tagged records.
    A foreign record already stating the desired mapping is covered, other
    foreign records are kept unless mirroring, and names outside every
    managed zone are skipped, never guessed into one."""
    from nexusipam import technitium
    desired = [('web.example.net', 'A', '10.0.0.5'),
               ('sub.deep.example.net', 'A', '10.0.0.6'),
               ('other.lan', 'A', '10.0.0.7')]          # outside managed zones
    existing = {'example.net': [
        {'name': 'stale.example.net', 'type': 'A',
         'rData': {'ipAddress': '10.0.0.9'}, 'comments': 'nexus-ipam'},
        {'name': 'web.example.net', 'type': 'A',
         'rData': {'ipAddress': '10.0.0.5'}, 'comments': ''},   # foreign, exact
        {'name': 'hand.example.net', 'type': 'A',
         'rData': {'ipAddress': '10.0.0.8'}, 'comments': ''},   # foreign
        {'name': 'example.net', 'type': 'SOA', 'rData': {}, 'comments': ''},
    ]}
    p = technitium.plan_hosts(desired, ['example.net'], existing)
    assert p['skipped'] == 1
    assert p['covered'] == 1                    # web served untagged — no write
    assert [(z, n) for z, n, _t, _v in p['add']] == \
        [('example.net', 'sub.deep.example.net')]
    assert [(z, n) for z, n, _t, _v in p['delete']] == \
        [('example.net', 'stale.example.net')]  # ours, no longer desired
    assert p['kept'] == 1                       # hand.example.net stays

    p = technitium.plan_hosts(desired, ['example.net'], existing, mirror=True)
    deleted = {n for _z, n, _t, _v in p['delete']}
    # Mirroring removes STALE foreign A records — but a foreign record that
    # states a desired mapping stays (it already serves the right answer, and
    # if the plan ever drops the name, mirror mode removes it then). The SOA
    # is never a candidate.
    assert deleted == {'stale.example.net', 'hand.example.net'}


def test_technitium_plan_reverse_uses_the_canonical_name():
    """One PTR per address, from the FIRST enabled A in payload order — the
    position-0 ordering finally expressed as an explicit record."""
    from nexusipam import technitium
    hosts = [{'name': 'docker.example.net', 'a': '10.0.5.10', 'enabled': True},
             {'name': 'alias.example.net', 'a': '10.0.5.10', 'enabled': True},
             {'name': 'off.example.net', 'a': '10.0.6.1', 'enabled': False}]
    p = technitium.plan_reverse(hosts, {})
    assert p['zones'] == ['5.0.10.in-addr.arpa']
    assert p['add'] == [('5.0.10.in-addr.arpa', '10.5.0.10.in-addr.arpa',
                         'docker.example.net')]


def test_technitium_scope_fields_map_the_full_option_set():
    """Everything the payload states lands natively — the contrast with the
    single-scope, router-only Pi-hole. Formats are the probed ones: lease
    split into d/h/m, dash-MAC pipe-group reservations, dnsUpdates forced
    off (an IPAM-managed zone tolerates no second writer)."""
    from nexusipam import technitium
    payload = {
        'ranges': [{'start': '10.0.0.100', 'end': '10.0.0.200',
                    'netmask': '255.255.254.0', 'lease': '26h', 'tag': 'lan',
                    'enabled': True}],
        'options': [{'tag': 'lan', 'option': 'option:router', 'value': '10.0.0.1'},
                    {'tag': 'lan', 'option': 'option:dns-server', 'value': '10.0.0.53,10.0.0.54'},
                    {'tag': 'lan', 'option': 'option:domain-name', 'value': 'example.net'},
                    {'tag': 'lan', 'option': 'option:ntp-server', 'value': '10.0.0.5'},
                    {'tag': 'lan', 'option': 'option:tftp-server', 'value': '10.0.0.9'},
                    {'tag': 'lan', 'option': 'option:bootfile-name', 'value': 'netboot.xyz.kpxe'}],
        'static_leases': [{'mac': 'aa:bb:cc:00:84:01', 'ip': '10.0.0.10',
                           'hostname': 'nas'}],
    }
    scopes = technitium.scopes_from_payload(payload)
    f = technitium.scope_fields('lan', scopes['lan'],
                                payload['static_leases'])
    assert (f['startingAddress'], f['endingAddress']) == ('10.0.0.100', '10.0.0.200')
    assert f['subnetMask'] == '255.255.254.0'
    assert (f['leaseTimeDays'], f['leaseTimeHours'], f['leaseTimeMinutes']) == (1, 2, 0)
    assert f['routerAddress'] == '10.0.0.1'
    assert f['dnsServers'] == '10.0.0.53,10.0.0.54' and f['useThisDnsServer'] == 'false'
    assert f['domainName'] == 'example.net'
    assert f['ntpServers'] == '10.0.0.5'
    assert f['serverAddress'] == '10.0.0.9'          # PXE next-server (siaddr)
    assert f['bootFileName'] == 'netboot.xyz.kpxe'
    assert f['dnsUpdates'] == 'false'
    assert f['reservedLeases'] == 'nas|AA-BB-CC-00-84-01|10.0.0.10|nexus-ipam'


def test_technitium_plan_dhcp_scopes_by_name(client):
    from nexusipam import technitium
    payload = {
        'ranges': [{'start': '10.0.0.100', 'end': '10.0.0.200',
                    'netmask': '255.255.255.0', 'lease': '24h', 'tag': 'lan',
                    'enabled': True}],
        'options': [],
        'static_leases': [
            {'mac': 'aa:bb:cc:00:84:02', 'ip': '10.99.9.9',
             'hostname': 'far'},                       # outside every subnet
            # In the subnet but outside the start–end range: dnsmasq/UniFi
            # reserve these happily, Technitium refuses them (found live) —
            # counted and reported, never failing the write.
            {'mac': 'aa:bb:cc:00:84:03', 'ip': '10.0.0.5',
             'hostname': 'below-range'}],
    }
    scope_list = [{'name': 'Default', 'enabled': False},
                  {'name': 'lan', 'enabled': False}]
    current = {'lan': {'startingAddress': '10.0.0.100',
                       'endingAddress': '10.0.0.150',   # differs
                       'subnetMask': '255.255.255.0', 'leaseTimeDays': 1,
                       'leaseTimeHours': 0, 'leaseTimeMinutes': 0,
                       'dnsUpdates': False, 'reservedLeases': []}}
    p = technitium.plan_dhcp(payload, scope_list, lambda n: current[n])
    assert p['updated'] == 1 and p['created'] == 0
    assert p['kept'] == 1                        # foreign 'Default' untouched
    assert p['skipped_reservations'] == 2
    assert any('outside every scope range' in c[2] for c in p['conflicts'])
    assert p['enable'] == []                     # manage_state off
    p = technitium.plan_dhcp(payload, scope_list, lambda n: current[n],
                             mirror=True, manage_state=True)
    assert p['delete'] == ['Default'] and p['enable'] == ['lan']

    # The server enables a scope on creation (found live). A NEW scope must
    # therefore be explicitly forced to its rightful state right after the
    # create: OFF without the state flag, the plan's bit with it.
    p = technitium.plan_dhcp(payload, [], lambda n: (_ for _ in ()).throw(
        AssertionError('no existing scopes to fetch')))
    assert p['created'] == 1 and p['post_state'] == [('lan', False)]
    p = technitium.plan_dhcp(payload, [], lambda n: None, manage_state=True)
    assert p['post_state'] == [('lan', True)]


def test_technitium_target_push_drift_and_leases(client, monkeypatch):
    from nexusipam import pushout, technitium
    # Token and at least one managed zone are required; zones are validated.
    assert client.post('/api/push/targets',
                       json={'name': 'tn', 'kind': 'technitium',
                             'url': 'https://tn:53443',
                             'technitium_zones': 'example.net'}).status_code == 400
    assert client.post('/api/push/targets',
                       json={'name': 'tn', 'kind': 'technitium',
                             'url': 'https://tn:53443',
                             'technitium_token': 'x'}).status_code == 400
    r = client.post('/api/push/targets',
                    json={'name': 'tn', 'kind': 'technitium',
                          'url': 'https://tn:53443', 'technitium_token': 'x',
                          'technitium_zones': 'example.net, bad..zone'})
    assert r.status_code == 400 and 'Invalid zone' in r.json['error']
    r = client.post('/api/push/targets',
                    json={'name': 'tn', 'kind': 'technitium',
                          'url': 'https://tn:53443', 'technitium_token': 'secret',
                          'technitium_zones': 'example.net',
                          'sections': ['hosts', 'dhcp']})
    assert r.json['target']['has_token'] is True
    assert 'technitium_token' not in r.json['target']
    assert client.post('/api/push/targets',
                       json={'name': 'tn', 'kind': 'technitium',
                             'sections': ['netboot']}).status_code == 400

    mknet(client, '10.84.0.0/24', domain='example.net')
    _mk_addr(client, '10.84.0.5', dns_name='tn-test.example.net')
    monkeypatch.setattr(technitium, 'sync_hosts',
                        lambda peer, hosts, client=None:
                            {'created': 1, 'updated': 0, 'deleted': 0, 'claimed': 0,
                             'unchanged': 0, 'covered': 0, 'conflicts': [],
                             'failed': 0, 'errors': []})
    monkeypatch.setattr(technitium, 'sync_dhcp',
                        lambda peer, payload, client=None:
                            {'created': 0, 'updated': 0, 'deleted': 0, 'claimed': 0,
                             'unchanged': 1, 'covered': 0, 'conflicts': [],
                             'failed': 0, 'errors': []})
    out, e = pushout.run_push('tn')
    assert e is None and out['success']

    class FakeClient:
        def zones(self):
            return []

        def zone_records(self, zone):
            return []

        def scopes(self):
            return []

        def scope(self, name):
            raise AssertionError('no scopes exist to fetch')

        def close(self):
            pass

        def dhcp_leases(self):
            return [{'type': 'Dynamic', 'address': '10.84.0.30',
                     'hardwareAddress': 'AA-BB-CC-00-84-30',
                     'hostName': 'dyn.example.net.',
                     'leaseExpires': '2026-08-15 04:00:00'},
                    {'type': 'Reserved', 'address': '10.84.0.10',
                     'hardwareAddress': 'AA-BB-CC-00-84-10'}]

    target = next(t for t in pushout._targets() if t['name'] == 'tn')
    report = pushout.run_drift(target, client=FakeClient())
    assert report['sections']['hosts']['counts']['missing'] == 1
    assert report['sections']['hosts']['counts']['missing_zones'] == 1
    assert report['sections']['hosts']['drifted']

    out = technitium.read_leases({'url': 'https://tn:53443'}, client=FakeClient())
    assert out == [{'ip': '10.84.0.30', 'mac': 'aa:bb:cc:00:84:30',
                    'hostname': 'dyn.example.net', 'expires': out[0]['expires']}]
    assert out[0]['expires'] > 0


# ─── Pi-hole adapter ──────────────────────────────────────────────────

def test_pihole_plan_hosts_is_additive_and_ptr_ordered():
    """dns.hosts is replaced wholesale, so additive means folding foreign
    entries back in — AFTER ours, because the PTR answer is the first
    matching hosts line and the plan's canonical order must win."""
    from nexusipam import pihole
    desired = [('web.lan', 'A', '10.0.0.5'), ('alias.lan', 'A', '10.0.0.5')]
    current = ['10.0.0.9 printer.lan',        # foreign — kept
               '10.0.0.4 web.lan']            # ours, wrong address — updated
    p = pihole.plan_hosts(desired, current)
    assert p['lines'] == ['10.0.0.5 web.lan', '10.0.0.5 alias.lan',
                          '10.0.0.9 printer.lan']
    assert (p['created'], p['updated'], p['deleted'], p['kept']) == (1, 1, 0, 1)
    # Mirroring drops the foreign entry instead.
    p = pihole.plan_hosts(desired, current, mirror=True)
    assert p['lines'] == ['10.0.0.5 web.lan', '10.0.0.5 alias.lan']
    assert p['deleted'] == 1
    # In-step content in the right order changes nothing.
    p = pihole.plan_hosts(desired, ['10.0.0.5 web.lan', '10.0.0.5 alias.lan'])
    assert not p['changed'] and p['unchanged'] == 2


def test_pihole_plan_dhcp_serves_one_scope_and_reports_the_rest():
    """A Pi-hole leases only the subnet it lives on: the matching scope's
    fields map onto dhcp.*, other scopes are skipped, options it cannot
    express become conflicts, and `active` is untouched without the opt-in —
    turning a DHCP server on or off is not a config tweak."""
    from nexusipam import pihole
    payload = {
        'ranges': [{'start': '10.0.0.100', 'end': '10.0.0.200',
                    'netmask': '255.255.255.0', 'lease': '24h', 'tag': 'lan',
                    'enabled': True},
                   {'start': '10.9.0.10', 'end': '10.9.0.90',
                    'netmask': '255.255.255.0', 'lease': '12h', 'tag': 'other',
                    'enabled': True}],
        'options': [{'tag': 'lan', 'option': 'option:router', 'value': '10.0.0.1'},
                    {'tag': 'lan', 'option': 'option:dns-server', 'value': '10.0.0.53'},
                    {'tag': 'lan', 'option': 'option:ntp-server', 'value': '10.0.0.5'}],
        'static_leases': [
            {'mac': 'aa:bb:cc:00:82:01', 'ip': '10.0.0.10', 'hostname': 'nas'},
            {'mac': 'aa:bb:cc:00:82:02', 'ip': '10.9.0.10', 'hostname': 'far'}],
    }
    cfg = {'active': False, 'start': '', 'end': '', 'router': '', 'netmask': '',
           'leaseTime': '', 'hosts': ['ee:ee:ee:ee:ee:01,10.0.0.77,foreign']}
    p = pihole.plan_dhcp(payload, cfg, own_ip='10.0.0.2')
    assert p['skipped'] == ['10.9.0.0/24']
    assert p['skipped_reservations'] == 1
    patch = p['patch']
    assert patch['start'] == '10.0.0.100' and patch['end'] == '10.0.0.200'
    assert patch['router'] == '10.0.0.1' and patch['netmask'] == '255.255.255.0'
    assert patch['leaseTime'] == '24h'
    assert 'active' not in patch                      # opt-in only
    # Ours written first, the foreign reservation folded back in.
    assert patch['hosts'] == ['aa:bb:cc:00:82:01,10.0.0.10,nas',
                              'ee:ee:ee:ee:ee:01,10.0.0.77,foreign']
    assert {c[0] for c in p['conflicts']} == {'option:dns-server',
                                              'option:ntp-server'}

    p = pihole.plan_dhcp(payload, cfg, own_ip='10.0.0.2',
                         mirror=True, manage_state=True)
    assert p['patch']['active'] is True
    assert p['patch']['hosts'] == ['aa:bb:cc:00:82:01,10.0.0.10,nas']
    assert p['deleted'] == 1


def test_pihole_target_push_drift_and_leases(client, monkeypatch):
    from nexusipam import pihole, pushout
    # netboot has no Pi-hole model — refused at subscription time.
    r = client.post('/api/push/targets',
                    json={'name': 'ph', 'kind': 'pihole', 'url': 'https://ph:8453',
                          'sections': ['netboot'], 'pihole_password': 'pw'})
    assert r.status_code == 400 and 'cannot carry' in r.json['error']
    # The password is required, stored, and only ever reported as a boolean.
    assert client.post('/api/push/targets',
                       json={'name': 'ph', 'kind': 'pihole',
                             'url': 'https://ph:8453'}).status_code == 400
    r = client.post('/api/push/targets',
                    json={'name': 'ph', 'kind': 'pihole', 'url': 'https://ph:8453',
                          'sections': ['hosts', 'dhcp'], 'pihole_password': 'pw'})
    assert r.json['target']['has_password'] is True
    assert 'pihole_password' not in r.json['target']

    nid = mknet(client, '10.82.0.0/24')
    _mk_addr(client, '10.82.0.5', dns_name='ph-test.lan')
    client.post('/api/dhcp/ranges',
                json={'network_id': nid, 'start_addr': '10.82.0.100',
                      'end_addr': '10.82.0.200'})
    seen = []
    monkeypatch.setattr(pihole, 'sync_hosts',
                        lambda peer, hosts, client=None: (seen.append(len(hosts)),
                            {'created': 1, 'updated': 0, 'deleted': 0, 'claimed': 0,
                             'unchanged': 0, 'covered': 0, 'conflicts': [],
                             'failed': 0, 'errors': []})[1])
    monkeypatch.setattr(pihole, 'sync_dhcp',
                        lambda peer, payload, client=None:
                            {'created': 0, 'updated': 0, 'deleted': 0, 'claimed': 0,
                             'unchanged': 1, 'covered': 0, 'conflicts': [],
                             'failed': 0, 'errors': []})
    out, e = pushout.run_push('ph')
    assert e is None and out['success'] and seen == [1]

    # Drift reads the config once and runs the same pure planners.
    class FakeClient:
        def get_config(self):
            return {'dns': {'hosts': []},
                    'dhcp': {'active': False, 'hosts': []}}

    target = next(t for t in pushout._targets() if t['name'] == 'ph')
    report = pushout.run_drift(target, client=FakeClient())
    assert report['sections']['hosts']['drifted']
    assert report['sections']['hosts']['counts']['missing'] == 1
    assert report['sections']['dhcp']['counts']['other_scopes'] == 1

    # Lease reading skips reservation-held MACs, like every other adapter.
    class LeaseClient(FakeClient):
        def get_config(self):
            return {'dhcp': {'hosts': ['aa:bb:cc:00:82:09,10.82.0.9,resv']}}

        def leases(self):
            return [{'ip': '10.82.0.30', 'hwaddr': 'AA:BB:CC:00:82:30',
                     'name': 'dyn', 'expires': 123},
                    {'ip': '10.82.0.9', 'hwaddr': 'aa:bb:cc:00:82:09',
                     'name': 'resv', 'expires': 123}]

    out = pihole.read_leases({'url': 'https://ph:8453'}, client=LeaseClient())
    assert out == [{'ip': '10.82.0.30', 'mac': 'aa:bb:cc:00:82:30',
                    'hostname': 'dyn', 'expires': 123}]


def test_drift_reads_the_gateway_back_and_diffs(client, monkeypatch):
    """Serials say a target ACKED the content; drift says whether it still
    HOLDS it. Same pure planners as the push, executed on nothing."""
    from nexusipam import pushout
    mknet(client, '10.72.0.0/24', domain='example.net')
    _mk_addr(client, '10.72.0.5', dns_name='drifty.example.net')
    target = {'name': 'gw', 'kind': 'unifi', 'url': 'https://gw',
              'unifi_username': 'a', 'unifi_password': 'b',
              'sections': ['hosts', 'dhcp'], 'enabled': True}

    class FakeClient:
        def __init__(self, static):
            self._static = static

        def list_static(self):
            return self._static

        def list_client_dns(self):
            return {}

        def list_networks(self):
            return {}

        def list_fixed(self):
            return {}

    in_sync = FakeClient({('drifty.example.net', 'A'):
                          {'id': 'x', 'value': '10.72.0.5', 'raw': {}}})
    r = pushout.run_drift(target, client=in_sync)
    assert r['ok'] and not r['sections']['hosts']['drifted']
    assert not r['sections']['dhcp']['drifted']
    assert r['sections']['hosts']['in_step'] == 1

    gone = FakeClient({})
    r = pushout.run_drift(target, client=gone)
    h = r['sections']['hosts']
    assert h['drifted'] and h['counts']['missing'] == 1
    assert 'missing drifty.example.net' in h['examples']


def test_drift_route_stores_the_verdict_and_refuses_dnsmaq(client, monkeypatch):
    from nexusipam import pushout
    client.post('/api/push/targets',
                json={'name': 'ns1', 'url': 'https://ns1:8443', 'token': 'dmm_x'})
    r = client.post('/api/push/targets/ns1/drift')
    assert r.status_code == 400 and 'locks' in r.json['error']

    client.post('/api/push/targets',
                json={'name': 'gw', 'kind': 'unifi', 'url': 'https://gw',
                      'unifi_username': 'a', 'unifi_password': 'b'})
    monkeypatch.setattr(pushout, 'run_drift',
                        lambda t: {'ts': 1, 'ok': True, 'sections': {
                            'hosts': {'drifted': True, 'in_step': 3,
                                      'counts': {'extra': 2},
                                      'examples': ['extra x']}}})
    r = client.post('/api/push/targets/gw/drift')
    assert r.status_code == 200 and r.json['drift']['sections']['hosts']['drifted']
    gw = next(t for t in client.get('/api/push').json['targets']
              if t['name'] == 'gw')
    assert gw['drift']['sections']['hosts']['counts'] == {'extra': 2}

    # An unreachable gateway is recorded too — a failed check must not be
    # indistinguishable from an unchecked target.
    def boom(t):
        raise OSError('no route to gateway')
    monkeypatch.setattr(pushout, 'run_drift', boom)
    assert client.post('/api/push/targets/gw/drift').status_code == 502
    gw = next(t for t in client.get('/api/push').json['targets']
              if t['name'] == 'gw')
    assert gw['drift']['ok'] is False and 'no route' in gw['drift']['error']


def test_unsubscribed_target_is_skipped_not_failed(client, monkeypatch):
    from nexusipam import pushout
    _fake_section(monkeypatch, 'dhcp', [{'x': 1}])
    client.post('/api/push/targets',
                json={'name': 'dns-only', 'url': 'https://ns1:8443', 'token': 'dmm_x',
                      'sections': ['hosts']})
    client.post('/api/push/targets',
                json={'name': 'both', 'url': 'https://ns2:8443', 'token': 'dmm_x',
                      'sections': ['hosts', 'dhcp']})
    monkeypatch.setattr(pushout, 'push_target', lambda t, data, serials: (True, 'ok'))
    r = client.post('/api/push/run?sections=dhcp').json
    by_name = {x['name']: x for x in r['results']}
    assert by_name['dns-only']['skipped'] is True and by_name['dns-only']['ok'] is True
    assert by_name['both']['sections'] == ['dhcp']
    assert r['success'] is True


def test_unifi_target_cannot_subscribe_to_an_unsupported_section(client, monkeypatch):
    """KIND_SECTIONS is the guard. A gateway *can* carry dhcp (its API exposes
    the scope options), so the check must reject only genuinely unsupported
    combinations, not everything that is not hosts."""
    from nexusipam import pushout
    _fake_section(monkeypatch, 'dhcp', [])
    monkeypatch.setitem(pushout.KIND_SECTIONS, 'unifi', ('hosts',))
    r = client.post('/api/push/targets',
                    json={'name': 'gw', 'url': 'https://10.0.0.1', 'kind': 'unifi',
                          'unifi_username': 'admin', 'unifi_password': 'pw',
                          'sections': ['dhcp']})
    assert r.status_code == 400 and 'cannot carry' in r.json['error']


# ─── UniFi gateway targets ────────────────────────────────────────────
# The adapter is vendored from DNSMAQ-MGR and exhaustively tested there; what
# is tested here is the seam — that IPAM's rendered records feed it unchanged,
# and that the target plumbing around it behaves.

def test_build_hosts_feeds_the_unifi_adapter_unchanged(client):
    """The compat claim the whole direct-push design rests on: the payload
    build_hosts() emits for a mirror push IS the adapter's input format, so
    nothing translates between the address plan and the gateway."""
    from nexusipam import pushout, unifi
    a1 = _mk_addr(client, '10.30.0.5')
    client.post('/api/addresses/%d/names' % a1, json={'names': [
        'canon.lan', 'alias.lan', {'name': 'off.lan', 'enabled': False}]})
    _mk_addr(client, '2001:db8::7', dns_name='v6.lan')

    recs = unifi.records_from_hosts(pushout.build_hosts())
    assert recs == [('canon.lan', 'A', '10.30.0.5'),
                    ('alias.lan', 'A', '10.30.0.5'),
                    ('v6.lan', 'AAAA', '2001:db8::7')]   # disabled name dropped


def test_unifi_plan_diffs_and_respects_client_dns():
    from nexusipam import unifi
    desired = [('keep.lan', 'A', '10.0.0.1'), ('move.lan', 'A', '10.0.0.2'),
               ('new.lan', 'A', '10.0.0.3')]
    static = {('keep.lan', 'A'): {'id': 'r1', 'value': '10.0.0.1', 'raw': {}},
              ('move.lan', 'A'): {'id': 'r2', 'value': '10.9.9.9', 'raw': {}},
              ('extra.lan', 'A'): {'id': 'r3', 'value': '10.0.0.8', 'raw': {}}}

    p = unifi.plan(desired, static, {}, mirror=True)
    assert p['unchanged'] == 1
    assert [x[0] for x in p['create']] == ['new.lan']
    assert [x[1] for x in p['update']] == ['move.lan']
    assert [x[1] for x in p['delete']] == ['extra.lan']

    # mirror off: an entry we did not create is left alone.
    assert unifi.plan(desired, static, {}, mirror=False)['delete'] == []

    # A name owned by a client's Local DNS Record shadows Static DNS: agreeing
    # is "covered", disagreeing is a conflict, and claim takes it over.
    owned = {'new.lan': {'id': 'c1', 'ip': '10.0.0.3'}}
    assert unifi.plan(desired, static, owned, mirror=False)['covered'] == ['new.lan']
    wrong = {'new.lan': {'id': 'c1', 'ip': '10.5.5.5'}}
    assert unifi.plan(desired, static, wrong, mirror=False)['conflicts'] == \
        [('new.lan', '10.0.0.3', '10.5.5.5')]
    claimed = unifi.plan(desired, static, wrong, mirror=False, claim=True)['claim']
    assert [x[0] for x in claimed] == ['new.lan']


def test_unifi_target_validation_and_secret_hiding(client):
    bad_kind = client.post('/api/push/targets',
                           json={'name': 'gw', 'url': 'https://10.0.0.1', 'kind': 'nope'})
    assert bad_kind.status_code == 400

    base = {'name': 'gw', 'url': 'https://10.0.0.1', 'kind': 'unifi'}
    assert client.post('/api/push/targets', json=base).status_code == 400   # no user
    assert client.post('/api/push/targets',
                       json={**base, 'unifi_username': 'admin'}
                       ).status_code == 400                                # no password
    assert client.post('/api/push/targets',
                       json={**base, 'unifi_username': 'admin',
                             'unifi_password': 'pw', 'unifi_site': 'bad site'}
                       ).status_code == 400                                # site slug

    r = client.post('/api/push/targets',
                    json={**base, 'unifi_username': 'admin', 'unifi_password': 'pw'})
    assert r.status_code == 200, r.json
    t = r.json['target']
    assert t['kind'] == 'unifi' and t['has_password'] is True
    assert 'unifi_password' not in t
    assert t['unifi_site'] == 'default'
    # Both destructive behaviours are opt-in, never a side effect of saving.
    assert t['unifi_delete_extra'] is False and t['unifi_claim_client_dns'] is False
    assert client.get('/api/push').json['targets'][0].get('unifi_password') is None


def test_unifi_target_edit_keeps_stored_password(client):
    client.post('/api/push/targets',
                json={'name': 'gw', 'url': 'https://10.0.0.1', 'kind': 'unifi',
                      'unifi_username': 'admin', 'unifi_password': 'pw'})
    r = client.post('/api/push/targets',
                    json={'name': 'gw', 'unifi_delete_extra': True})
    assert r.status_code == 200, r.json
    assert r.json['target']['has_password'] and r.json['target']['unifi_delete_extra']
    from nexusipam import pushout
    assert pushout._targets()[0]['unifi_password'] == 'pw'


def test_push_run_dispatches_to_the_unifi_adapter(client, monkeypatch):
    from nexusipam import unifi
    client.post('/api/push/targets',
                json={'name': 'gw', 'url': 'https://10.0.0.1', 'kind': 'unifi',
                      'unifi_username': 'admin', 'unifi_password': 'pw'})
    _mk_addr(client, '10.30.0.99', dns_name='pushme.lan')

    seen = {}

    def fake_sync(peer, hosts, client=None):
        seen['peer'], seen['hosts'] = peer, hosts
        return {'created': 1, 'updated': 0, 'deleted': 0, 'claimed': 0,
                'unchanged': 3, 'covered': 0, 'conflicts': [], 'failed': 0,
                'errors': []}

    monkeypatch.setattr(unifi, 'sync_hosts', fake_sync)
    r = client.post('/api/push/run')
    assert r.json['success'] is True
    assert [h['name'] for h in seen['hosts']] == ['pushme.lan']
    # No mirror token is invented for a gateway, and the verify default is this
    # module's ('insecure'), not the adapter's ('system' — which would reject
    # the gateway's self-signed cert).
    assert 'token' not in seen['peer'] and seen['peer']['verify'] == 'insecure'
    assert client.get('/api/push').json['targets'][0]['last']['detail'] == \
        '1 created, 0 updated, 0 deleted, 3 unchanged'


def test_push_run_reports_unifi_conflicts_as_failure(client, monkeypatch):
    from nexusipam import unifi
    client.post('/api/push/targets',
                json={'name': 'gw', 'url': 'https://10.0.0.1', 'kind': 'unifi',
                      'unifi_username': 'admin', 'unifi_password': 'pw'})
    monkeypatch.setattr(unifi, 'sync_hosts', lambda peer, hosts, client=None: {
        'created': 0, 'updated': 0, 'deleted': 0, 'claimed': 0, 'unchanged': 0,
        'covered': 0, 'conflicts': [('a.lan', '10.0.0.1', '10.9.9.9')],
        'failed': 0, 'errors': []})
    r = client.post('/api/push/run')
    assert r.json['success'] is False
    detail = client.get('/api/push').json['targets'][0]['last']['detail']
    assert 'client DNS holds a.lan at 10.9.9.9' in detail

    # An unreachable gateway is a failed target, never a 500.
    def boom(peer, hosts, client=None):
        raise unifi.UniFiError('login rejected: bad username or password')
    monkeypatch.setattr(unifi, 'sync_hosts', boom)
    r = client.post('/api/push/run')
    assert r.status_code == 200 and r.json['success'] is False
    assert 'login rejected' in r.json['results'][0]['detail']


def test_target_stored_without_kind_still_pushes_as_dnsmaq(client, monkeypatch):
    """Targets written before `kind` existed (ns1/ns2 on the live instance)
    must keep working untouched."""
    from nexusipam import pushout
    pushout._save_targets([{'name': 'ns1', 'url': 'https://ns1:8443',
                            'token': 'dmm_x', 'enabled': True,
                            'last': None, 'serial': 0}])
    assert client.get('/api/push').json['targets'][0]['kind'] == 'dnsmaq'
    kinds = []
    monkeypatch.setattr(pushout, 'push_target',
                        lambda t, data, serials: (kinds.append(t.get('kind')),
                                                  (True, 'ok'))[1])
    assert client.post('/api/push/run').json['success']
    assert kinds == [None]                   # dispatch defaults, store untouched


# ─── Provision / deprovision (phase 3) ────────────────────────────────

def test_provision_full_cycle(client, monkeypatch):
    from nexusipam import pushout
    pushes = []
    monkeypatch.setattr(pushout, 'run_push',
                        lambda only='': (pushes.append(only),
                                         ({'success': True, 'serial': 9,
                                           'records': 1, 'results': []}, None))[1])
    mknet(client, '10.40.0.0/24')
    r = client.post('/api/provision', json={'name': 'web01.example.net',
                                            'network': '10.40.0.0/24',
                                            'aliases': ['www.example.net'],
                                            'mac': 'aa:bb:cc:00:11:22'})
    assert r.status_code == 200, r.json
    out = r.json
    assert out['address'].startswith('10.40.0.')
    assert [n['name'] for n in out['names']] == ['web01.example.net', 'www.example.net']
    assert out['push']['success'] and len(pushes) == 1
    assert out['gateway'] is not None or 'gateway' in out    # deploy payload rode along

    # same name again → refused, not round-robin by accident
    r2 = client.post('/api/provision', json={'name': 'web01.example.net',
                                             'network': '10.40.0.0/24'})
    assert r2.status_code == 409 and out['address'] in r2.json['error']

    # deprovision by name reverses everything and pushes again
    r3 = client.post('/api/deprovision', json={'name': 'web01.example.net'})
    assert r3.json['success'] and r3.json['action'] == 'released'
    assert len(pushes) == 2
    look = client.get('/api/addresses/lookup?address=%s' % out['address']).json
    assert look['record'] is None


def test_provision_carries_the_reservation_flag(client, monkeypatch):
    """Provisioning with a MAC can publish the DHCP reservation in the same
    action, and deprovision (keep) withdraws it — a parked address must not
    keep its MAC binding published."""
    from nexusipam import pushout
    monkeypatch.setattr(pushout, 'run_push', lambda only='': (None, 'no targets'))
    mknet(client, '10.42.0.0/29')

    # The flag without a MAC is unpublishable — refused, not stored inert.
    r = client.post('/api/provision', json={'name': 'resv.example.net',
                                            'network': '10.42.0.0/29',
                                            'is_reservation': True})
    assert r.status_code == 400 and 'MAC' in r.json['error']

    r = client.post('/api/provision', json={'name': 'resv.example.net',
                                            'network': '10.42.0.0/29',
                                            'mac': 'aa:bb:cc:00:42:01',
                                            'is_reservation': True})
    assert r.status_code == 200
    leases = pushout.build_dhcp()['static_leases']
    assert [(l['mac'], l['ip']) for l in leases] == \
        [('aa:bb:cc:00:42:01', r.json['address'])]

    client.post('/api/deprovision', json={'name': 'resv.example.net', 'keep': True})
    assert pushout.build_dhcp()['static_leases'] == []
    look = client.get('/api/addresses/lookup?address=%s' % r.json['address']).json
    assert look['record']['is_reservation'] == 0


def test_one_mac_gets_one_reservation(client, monkeypatch):
    """Several addresses on one NIC is normal; several RESERVATIONS on one MAC
    is a config dnsmasq refuses to start on (past --test). Guarded at every
    write path, and the push itself refuses legacy rows that predate the
    guard."""
    from nexusipam import pushout
    from nexusipam.core import db
    monkeypatch.setattr(pushout, 'push_target',
                        lambda t, data, serials: (True, 'ok'))
    mknet(client, '10.73.0.0/24')
    mac = 'aa:bb:cc:00:73:01'
    assert client.post('/api/addresses',
                       json={'address': '10.73.0.5', 'mac': mac,
                             'is_reservation': True}).status_code == 200
    # Same MAC again, plain address: fine — several IPs on one NIC is normal.
    assert client.post('/api/addresses',
                       json={'address': '10.73.0.6', 'mac': mac}).status_code == 200
    # But a second reservation for it is refused, naming the holder.
    r = client.post('/api/addresses',
                    json={'address': '10.73.0.7', 'mac': mac,
                          'is_reservation': True})
    assert r.status_code == 400 and '10.73.0.5' in r.json['error']
    # Re-saving the holder itself is not a collision with itself.
    holder = client.get('/api/addresses/search?q=10.73.0.5').json['addresses'][0]
    assert client.post('/api/addresses/%d' % holder['id'],
                       json={'description': 'edited'}).status_code == 200
    # Provision path refuses too.
    r = client.post('/api/provision',
                    json={'name': 'dup.example.net', 'network': '10.73.0.0/24',
                          'mac': mac, 'is_reservation': True, 'push': False})
    assert r.status_code == 409 and '10.73.0.5' in r.json['error']

    # Legacy rows that predate the guard: the push refuses the payload whole
    # rather than delivering a store dnsmasq dies on at its next restart.
    db.insert('ip_addresses', {
        'address': '10.73.0.9', 'version': 4,
        'addr_hex': '0' * 24 + '0a490009', 'status': 'reserved',
        'mac': mac, 'is_reservation': 1, 'source': 'legacy', 'ext_id': ''})
    client.post('/api/push/targets',
                json={'name': 'ns1', 'url': 'https://ns1:8443', 'token': 'dmm_x',
                      'sections': ['hosts', 'dhcp']})
    out, e = pushout.run_push()
    assert out is None and mac in e and 'one MAC gets one fixed lease' in e


def test_provision_bad_alias_rolls_back_allocation(client, monkeypatch):
    from nexusipam import pushout
    monkeypatch.setattr(pushout, 'run_push', lambda only='': (None, 'no targets'))
    mknet(client, '10.41.0.0/29')
    r = client.post('/api/provision', json={'name': 'ok.example.net',
                                            'network': '10.41.0.0/29',
                                            'aliases': ['not a name']})
    assert r.status_code == 400
    # the allocated address was rolled back, not leaked
    r2 = client.post('/api/provision', json={'name': 'ok.example.net',
                                             'network': '10.41.0.0/29'})
    assert r2.status_code == 200
    r3 = client.post('/api/deprovision', json={'name': 'ok.example.net', 'keep': True})
    assert r3.json['action'] == 'deprecated'
    look = client.get('/api/addresses/lookup?address=%s' % r2.json['address']).json
    assert look['record']['status'] == 'deprecated' and look['record']['dns_name'] == ''
