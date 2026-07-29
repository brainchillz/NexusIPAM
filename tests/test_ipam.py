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


def test_banner_write_requires_admin(client, monkeypatch):
    from nexusipam.core import auth
    monkeypatch.setattr(auth, '_users',
                        lambda: {'admin': {'password': 'x', 'role': 'readonly'}})
    assert client.post('/api/settings/banner',
                       json={'banner': 'nope'}).status_code == 403
    assert client.get('/api/settings/banner').status_code == 200
