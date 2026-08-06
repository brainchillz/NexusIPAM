#!/usr/bin/env python3
"""Seed a throwaway Nexus IPAM instance with the README demo dataset.

Builds the "Demo Lab — HQ" plan the docs/screenshots pages show: a campus
supernet with four VLAN'd subnets (+ an IPv6 net), two DHCP pools, a small
cluster/device/VM/container inventory, reserved gateway blocks, a bulk
import, and — via direct SQLite writes — the sweep artifacts (ping-verified
records, three unmanaged responders, two silent records) that make the
Overview banner and Scan & Verify page show the reconcile workflow.

Usage (stdlib only, run against a THROWAWAY instance — it writes freely):

    NEXUSIPAM_TLS=0 NEXUSIPAM_PORT=8095 NEXUSIPAM_DATA_DIR=/tmp/ipam-demo \\
        NEXUSIPAM_ADMIN_PASSWORD=demopass123 python3 nexus-ipam.py &
    python3 tools/seed_demo.py --base http://127.0.0.1:8095 \\
        --password demopass123 --db /tmp/ipam-demo/ipam.db

Then take the README screenshots at 1440x900 (deviceScaleFactor 2):
Overview, Networks, the 10.0.10.0/24 detail, IP Addresses, Devices,
Topology, Scan & Verify.
"""
import argparse
import http.cookiejar
import ipaddress
import json
import sqlite3
import time
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument('--base', default='http://127.0.0.1:8095')
ap.add_argument('--password', default='demopass123')
ap.add_argument('--db', help='path to ipam.db (enables the sweep-artifact seeding)')
args = ap.parse_args()

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def call(path, body=None, quiet=False):
    req = urllib.request.Request(args.base + path)
    if body is not None:
        req.data = json.dumps(body).encode()
        req.add_header('Content-Type', 'application/json')
    try:
        with opener.open(req) as r:
            return json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors='replace')[:160]
        if not quiet:
            print('FAIL %s %s %s' % (path, e.code, detail))
        return {'_error': detail, '_code': e.code}


call('/api/login', {'username': 'admin', 'password': args.password})
print('login ok')

call('/api/settings/banner', {'banner': 'Demo Lab — HQ'})

# ─── VLANs + networks ────────────────────────────────────────────────
vlans = {}
for vid, name in ((10, 'servers'), (20, 'storage'), (30, 'iot'), (40, 'dmz')):
    r = call('/api/vlans', {'vid': vid, 'name': name, 'site': 'hq'})
    vlans[vid] = r.get('id') or (r.get('record') or {}).get('id')

nets = {}
def mknet(cidr, name, role='subnet', vlan=None, gw='', dns='', domain=''):
    r = call('/api/networks', {'cidr': cidr, 'name': name, 'role': role,
                               'vlan_id': vlans.get(vlan), 'gateway': gw,
                               'dns_servers': dns, 'domain': domain, 'site': 'hq'})
    nets[name] = r.get('id') or (r.get('record') or {}).get('id')

mknet('10.0.0.0/16', 'campus', role='container')
mknet('10.0.10.0/24', 'servers', vlan=10, gw='10.0.10.1',
      dns='10.0.10.53, 1.1.1.1', domain='lab.lan')
mknet('10.0.20.0/24', 'storage', vlan=20, gw='10.0.20.1', domain='lab.lan')
mknet('10.0.30.0/24', 'iot', vlan=30, gw='10.0.30.1', domain='lab.lan')
mknet('10.0.40.0/28', 'dmz', vlan=40, gw='10.0.40.1', domain='lab.lan')
mknet('2001:db8:10::/64', 'servers-v6', vlan=10)

# ─── Inventory ───────────────────────────────────────────────────────
def mkhost(coll, body):
    r = call(coll, body)
    return r.get('id') or (r.get('record') or {}).get('id')

pve = mkhost('/api/clusters', {'name': 'pve-cluster', 'kind': 'proxmox', 'site': 'hq'})
ceph = mkhost('/api/clusters', {'name': 'ceph-pool', 'kind': 'storage', 'site': 'hq'})

dev = {}
for name, body in (
    ('core-sw1', {'role': 'switch', 'site': 'hq', 'rack': 'r1', 'position': 'U1'}),
    ('edge-fw', {'role': 'firewall', 'tags': 'edge', 'site': 'hq', 'rack': 'r1', 'position': 'U2'}),
    ('nas01', {'role': 'storage', 'tags': 'backup, storage', 'cluster_id': ceph,
               'site': 'hq', 'rack': 'r1', 'position': 'U9'}),
    ('pve-node1', {'role': 'server', 'tags': 'prod, virt', 'cluster_id': pve,
                   'virt': 'proxmox', 'engine': 'docker', 'site': 'hq', 'rack': 'r1', 'position': 'U4'}),
    ('pve-node2', {'role': 'server', 'tags': 'prod, virt', 'cluster_id': pve,
                   'virt': 'proxmox', 'site': 'hq', 'rack': 'r1', 'position': 'U5'}),
):
    dev[name] = mkhost('/api/devices', {'name': name, **body})

vm = {}
for name, host in (('web01', 'pve-node1'), ('db01', 'pve-node1'), ('monitor01', 'pve-node1'),
                   ('web02', 'pve-node2'), ('dns01', 'pve-node2')):
    vm[name] = mkhost('/api/vms', {'name': name, 'platform': 'kvm',
                                   'host_device_id': dev[host], 'cluster_id': pve,
                                   'tags': 'proxmox'})

for name, parent in (('grafana', 'monitor01'), ('prometheus', 'monitor01'), ('nginx', 'web01')):
    mkhost('/api/containers', {'name': name, 'engine': 'docker',
                               'parent_kind': 'vm', 'parent_id': vm[parent]})

# ─── DHCP pools ──────────────────────────────────────────────────────
dhcp = mkhost('/api/dhcp/servers', {'name': 'lab-dnsmasq', 'kind': 'dnsmasq',
                                    'host_kind': 'vm', 'host_id': vm['dns01'],
                                    'address': '10.0.10.53'})
call('/api/dhcp/ranges', {'network_id': nets['servers'], 'server_id': dhcp,
                          'name': 'servers-pool', 'start_addr': '10.0.10.150',
                          'end_addr': '10.0.10.199', 'lease_time': '12h'})
call('/api/dhcp/ranges', {'network_id': nets['iot'], 'server_id': dhcp,
                          'name': 'iot-pool', 'start_addr': '10.0.30.100',
                          'end_addr': '10.0.30.210', 'lease_time': '24h'})

# ─── Addresses ───────────────────────────────────────────────────────
def addr(address, dns_name='', kind='', ref=None, mac='', status='active', primary=True):
    call('/api/addresses', {'address': address, 'status': status, 'dns_name': dns_name,
                            'assigned_kind': kind, 'assigned_id': ref, 'mac': mac,
                            'is_primary': primary})

addr('10.0.10.1', 'gw', 'device', dev['edge-fw'], 'aa:10:00:00:00:01')
addr('10.0.10.5', 'pve-node1', 'device', dev['pve-node1'], 'aa:10:00:00:00:05')
addr('10.0.10.6', 'pve-node2', 'device', dev['pve-node2'], 'aa:10:00:00:00:06')
addr('10.0.10.10', 'web01', 'vm', vm['web01'])
addr('10.0.10.11', 'web02', 'vm', vm['web02'])
addr('10.0.10.12', 'db01', 'vm', vm['db01'])
addr('10.0.10.13', 'monitor01', 'vm', vm['monitor01'])
addr('10.0.10.53', 'dns01', 'vm', vm['dns01'])
addr('10.0.20.10', 'nas01', 'device', dev['nas01'], 'aa:20:00:00:00:0a')
for ip, name in (('10.0.30.20', 'cam-front'), ('10.0.30.21', 'cam-back'),
                 ('10.0.30.30', 'hue-bridge'), ('10.0.30.40', 'thermostat')):
    addr(ip, name)

# Reserved gateway blocks (.2-.4, .7-.9)
call('/api/networks/%d/reserve' % nets['servers'],
     {'start': '10.0.10.2', 'end': '10.0.10.4', 'description': 'network gear'})
call('/api/networks/%d/reserve' % nets['servers'],
     {'start': '10.0.10.7', 'end': '10.0.10.9', 'description': 'network gear'})

# Bulk import: hosts .30-.69 (+ one duplicate so the activity shows a skip)
items = [{'address': '10.0.10.%d' % i, 'dns_name': 'host%d' % i,
          'mac': 'aa:10:00:00:01:%02x' % i} for i in range(30, 70)]
items.append({'address': '10.0.10.30', 'dns_name': 'host30'})
r = call('/api/addresses/bulk', {'addresses': items, 'source': 'import'})
print('bulk:', {k: r[k] for k in r if not k.startswith('_')})

# ─── Sweep artifacts (direct SQLite; the app derives Overview's reconcile
#     banner, PING columns and Scan & Verify tables from scan_results) ──
if args.db:
    hexify = lambda ip: format(int(ipaddress.ip_address(ip)), '032x')
    now = int(time.time())
    seen = now - 9 * 60
    con = sqlite3.connect(args.db)
    rows = []

    def alive(ip, rtt, hostname='', mac=''):
        rows.append((ip, 4, hexify(ip), 1, 'icmp', rtt, hostname, mac, seen, seen))

    def silent(ip):
        rows.append((ip, 4, hexify(ip), 0, 'icmp', None, '', '', seen, 0))

    for last, rtt in ((1, 0.4), (5, 0.5), (6, 0.6), (10, 0.9), (11, 1.1), (12, 0.8), (13, 1.0), (53, 0.7)):
        alive('10.0.10.%d' % last, rtt)
    for i in range(30, 70):
        if i in (49, 50):
            continue
        alive('10.0.10.%d' % i, round(0.3 + (i % 17) / 10.0, 1))
    silent('10.0.10.49')
    silent('10.0.10.50')
    alive('10.0.20.10', 0.4)
    # The three unmanaged responders — no address record, outside every pool.
    alive('10.0.10.77', 0.7, 'rogue-pi', 'aa:a5:00:00:02:4d')
    alive('10.0.10.78', 1.8, '', 'aa:ca:00:00:02:18')
    alive('10.0.20.99', 0.3, 'old-nas', 'aa:25:00:00:02:30')
    con.executemany(
        'INSERT OR REPLACE INTO scan_results '
        '(address, version, addr_hex, alive, method, rtt_ms, hostname, mac, last_scan, last_alive) '
        'VALUES (?,?,?,?,?,?,?,?,?,?)', rows)
    con.commit()
    con.close()
    print('scan artifacts: %d rows' % len(rows))

print('seeded')
