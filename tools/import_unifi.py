#!/usr/bin/env python3
"""Import networks, VLANs and DHCP scopes from a UniFi gateway into Nexus IPAM.

Deliberately imports **topology, not clients**. A DHCP client is a lease — true
until it expires — and writing one into an address plan records something that
stops being true without anyone touching it. What belongs here is the *scope*:
declare the range once and every address in it is accounted for as consumed,
excluded from the free list and never handed out by the allocator. That stays
correct as leases come and go, and one edit moves the whole boundary.

Fixed-IP reservations are a different thing and DO belong: a reservation is a
permanent MAC->IP binding, not a lease. Pass --reservations to bring those in.

Reads only. Nothing is ever written back to the gateway.

API surface: this uses the long-standing `/proxy/network/api/s/<site>/rest/*`
endpoints, verified against UniFi Network **10.4.57** (UCG, UniFi OS auth via
`/api/auth/login`). Ubiquiti's newer Integration API
(`/proxy/network/integration/v1/...`) is the forward-looking option but needs a
generated API key rather than a login, so it is not used here. If a controller
upgrade ever moves these endpoints, this tool reports the version it found and
exits non-zero rather than importing a partial picture.

Usage:
  ./tools/import_unifi.py --gateway https://<gateway-ip> --cred-file <file> \\
                          --ipam https://ipam:8444 --ipam-token nx_... [--dry-run]
"""
import argparse
import ipaddress
import json
import ssl
import sys
import urllib.error
import urllib.request

CTX = ssl._create_unverified_context()


def read_cred(path):
    """`username <u>` / `password <p>`, one per line — the shape used by the
    other *-cred files alongside this repo."""
    creds = {}
    with open(path) as f:
        for line in f:
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                creds[parts[0].lower()] = parts[1]
    if 'username' not in creds or 'password' not in creds:
        raise SystemExit('%s must contain "username <u>" and "password <p>" lines' % path)
    return creds


class Unifi:
    """Minimal UniFi OS client: cookie login, then read through the network
    application proxy."""

    def __init__(self, base):
        self.base = base.rstrip('/')
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(),
            urllib.request.HTTPSHandler(context=CTX))

    def login(self, username, password):
        req = urllib.request.Request(
            self.base + '/api/auth/login',
            data=json.dumps({'username': username, 'password': password}).encode(),
            headers={'Content-Type': 'application/json'}, method='POST')
        with self.opener.open(req, timeout=30) as r:
            return r.status == 200

    def get(self, path):
        req = urllib.request.Request(self.base + path)
        with self.opener.open(req, timeout=30) as r:
            return json.loads(r.read() or b'{}').get('data', [])

    def version(self):
        try:
            info = self.get('/proxy/network/api/s/default/stat/sysinfo')
            return (info[0].get('version') or '?') if info else '?'
        except (urllib.error.URLError, ValueError, KeyError):
            return '?'


# Verified against these UniFi Network releases. A newer controller is not
# refused — the endpoint check below is what actually decides — but the version
# is printed so a failed import after an upgrade is immediately explicable.
VERIFIED_VERSIONS = ('10.4',)


def ipam(url, token, path, method='GET', body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url.rstrip('/') + path, data=data, method=method)
    req.add_header('Authorization', 'Bearer ' + token)
    if data:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
            return json.loads(r.read() or b'{}'), r.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read() or b'{}'), e.code
        except ValueError:
            return {}, e.code


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--gateway', required=True)
    ap.add_argument('--cred-file', required=True,
                    help='file with "username <u>" / "password <p>" lines')
    ap.add_argument('--site', default='default', help='UniFi site id (default: default)')
    ap.add_argument('--ipam', required=True)
    ap.add_argument('--ipam-token', required=True)
    ap.add_argument('--reservations', action='store_true',
                    help='also import fixed-IP reservations as address records')
    ap.add_argument('--native-vlan', type=int, metavar='VID', default=1,
                    help='VLAN id for the native/untagged LAN (default: 1). The '
                         'UniFi API omits the number for the native network '
                         '(vlan_enabled=false, no vlan field) because it is '
                         'implicit — but it is still a real VLAN and belongs in '
                         'the plan. Pass 0 to skip it. Corporate networks only.')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    cred = read_cred(args.cred_file)
    uni = Unifi(args.gateway)
    if not uni.login(cred['username'], cred['password']):
        print('UniFi login failed', file=sys.stderr)
        return 1

    ver = uni.version()
    print('UniFi Network %s' % ver, end='')
    if not any(ver.startswith(v) for v in VERIFIED_VERSIONS):
        print('  (this tool was verified against %s — if the import looks wrong, '
              'the REST endpoints may have moved)' % '/'.join(VERIFIED_VERSIONS), end='')
    print()

    confs = uni.get('/proxy/network/api/s/%s/rest/networkconf' % args.site)
    if not confs:
        print('No networks returned by /rest/networkconf on UniFi %s. The endpoint '
              'may have changed or the account may lack visibility — refusing to '
              'import a partial picture.' % ver, file=sys.stderr)
        return 2
    mark = '~' if args.dry_run else ''

    # ─── VLANs ────────────────────────────────────────────────────────
    def vlan_of(conf):
        """The VLAN id to record for a network.

        The UniFi API reports no `vlan` for the native LAN (vlan_enabled=false)
        because the number is implicit there — but VLAN 1 is still a VLAN and
        belongs in the address plan like any other, so it is filled in rather
        than skipped. Restricted to corporate networks: a VPN or guest network
        that also happens to be untagged is not the native LAN.
        """
        if conf.get('vlan'):
            return int(conf['vlan'])
        if args.native_vlan and conf.get('purpose') == 'corporate':
            return args.native_vlan
        return None

    vlan_ids = {}
    for c in confs:
        vid = vlan_of(c)
        if not vid:
            continue
        native = not c.get('vlan')
        body = {'vid': int(vid), 'name': c.get('name', ''), 'site': 'main',
                'status': 'active', 'source': 'unifi', 'ext_id': c.get('_id', ''),
                'description': ('Native/untagged LAN — UniFi leaves the id implicit '
                                'on this network, so it is filled in here'
                                if native else 'From UniFi network "%s"' % c.get('name', ''))}
        if args.dry_run:
            print('  %s vlan %-5s %s' % (mark or '+', vid, c.get('name')))
            continue
        r, st = ipam(args.ipam, args.ipam_token, '/api/vlans?upsert=1', 'POST', body)
        if st == 200:
            vlan_ids[int(vid)] = r['id']
            print('  + vlan %-5s %s' % (vid, c.get('name')))
        elif st == 409:
            # Already present from an earlier run or added by hand — find it.
            existing, _ = ipam(args.ipam, args.ipam_token, '/api/vlans')
            for v in existing.get('vlans', []):
                if v['vid'] == int(vid):
                    vlan_ids[int(vid)] = v['id']
            print('  = vlan %-5s %s (already present)' % (vid, c.get('name')))
        else:
            print('  ! vlan %-5s %s' % (vid, r.get('error')))

    # ─── Networks ─────────────────────────────────────────────────────
    existing_nets, _ = ipam(args.ipam, args.ipam_token, '/api/networks')
    by_cidr = {n['cidr']: n for n in existing_nets.get('networks', [])}

    net_ids = {}
    for c in confs:
        subnet = c.get('ip_subnet')
        if not subnet:
            continue
        try:
            net = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            continue
        # UniFi states the subnet as the router's own address (10.0.0.1/24),
        # so the host part is the gateway.
        gateway = str(ipaddress.ip_interface(subnet).ip)
        dns = [c.get('dhcpd_dns_%d' % i) for i in (1, 2, 3, 4)]
        body = {
            'cidr': str(net), 'name': c.get('name', ''), 'role': 'subnet',
            'gateway': gateway, 'dns_servers': ', '.join(d for d in dns if d),
            'domain': c.get('domain_name') or '', 'site': 'main', 'status': 'active',
            'description': 'UniFi network "%s" (purpose: %s)'
                           % (c.get('name', ''), c.get('purpose', '')),
            'source': 'unifi', 'ext_id': c.get('_id', ''),
            'meta': {'unifi_purpose': c.get('purpose', ''),
                     'unifi_name': c.get('name', '')},
        }
        vid = vlan_of(c)
        if vid and vid in vlan_ids:
            body['vlan_id'] = vlan_ids[vid]

        prior = by_cidr.get(str(net))
        if args.dry_run:
            print('  %s %-20s vlan=%-5s %s' % ('~' if prior else '+', net,
                                               c.get('vlan') or '-', c.get('name')))
            continue

        if prior:
            # Don't overwrite a network someone curated by hand; only fill in
            # what UniFi is authoritative for and keep the existing identity.
            merged = dict(body)
            merged['name'] = prior.get('name') or body['name']
            merged['vlan_id'] = body.get('vlan_id') or prior.get('vlan_id')
            merged['source'] = prior.get('source', 'manual')
            merged['ext_id'] = prior.get('ext_id', '')
            meta = prior.get('meta') or {}
            meta.update(body['meta'])
            merged['meta'] = meta
            _, st = ipam(args.ipam, args.ipam_token,
                         '/api/networks/%s' % prior['id'], 'POST', merged)
            net_ids[str(net)] = prior['id']
            print('  ~ %-20s updated (kept existing name/source)' % net)
        else:
            r, st = ipam(args.ipam, args.ipam_token, '/api/networks?upsert=1', 'POST', body)
            if st == 200:
                net_ids[str(net)] = r['id']
                print('  + %-20s vlan=%-5s %s' % (net, c.get('vlan') or '-', c.get('name')))
            else:
                print('  ! %-20s %s' % (net, r.get('error')))

    # ─── Gateway interfaces ───────────────────────────────────────────
    # Every one of these .1 addresses is an interface of the same gateway.
    # Recording that is a fact worth having: it makes the router's footprint
    # visible and puts each address in the plan attached to something real.
    srv, _ = ipam(args.ipam, args.ipam_token, '/api/dhcp/servers')
    unifi_srv = next((s for s in srv.get('dhcp_servers', [])
                      if s.get('kind') == 'unifi'), None)
    gw_device = unifi_srv.get('host_id') if unifi_srv and \
        unifi_srv.get('host_kind') == 'device' else None
    if gw_device:
        print()
        for c in confs:
            subnet = c.get('ip_subnet')
            if not subnet:
                continue
            gw = str(ipaddress.ip_interface(subnet).ip)
            if args.dry_run:
                print('  ~ gateway %-16s -> router device' % gw)
                continue
            look, _ = ipam(args.ipam, args.ipam_token,
                           '/api/addresses/lookup?address=%s' % gw)
            rec = (look or {}).get('record')
            abody = {'address': gw, 'status': 'active', 'assigned_kind': 'device',
                     'assigned_id': gw_device,
                     'description': 'Gateway interface for %s' % c.get('name', '')}
            if rec:
                abody['dns_name'] = rec.get('dns_name', '')
                abody['mac'] = rec.get('mac', '')
                abody['is_primary'] = bool(rec.get('is_primary'))
                abody['source'] = rec.get('source', 'unifi')
                abody['ext_id'] = rec.get('ext_id', '')
                ipam(args.ipam, args.ipam_token,
                     '/api/addresses/%s' % rec['id'], 'POST', abody)
                print('  ~ gateway %-16s linked (kept DNS name %s)'
                      % (gw, rec.get('dns_name') or '-'))
            else:
                abody.update({'source': 'unifi', 'ext_id': c.get('_id', '')})
                _, st = ipam(args.ipam, args.ipam_token, '/api/addresses', 'POST', abody)
                print('  %s gateway %-16s recorded' % ('+' if st == 200 else '!', gw))

    # ─── DHCP scopes ──────────────────────────────────────────────────
    server_id = unifi_srv['id'] if unifi_srv else None
    ranges, _ = ipam(args.ipam, args.ipam_token, '/api/dhcp/ranges')
    have = {(r['network_id'], r['start_addr'], r['end_addr']) for r in ranges.get('dhcp_ranges', [])}

    for c in confs:
        # Import any network that HAS a range defined, not just ones with DHCP
        # switched on. A configured-but-disabled scope is worth documenting —
        # it records the intent and the boundary — and IPAM's `enabled` flag
        # keeps it out of the utilization maths until it is switched on.
        if not c.get('dhcpd_start') or not c.get('dhcpd_stop'):
            continue
        # A remote-user VPN hands its clients addresses out of this range
        # whether or not the DHCP server flag is set, so that space IS consumed.
        is_vpn = c.get('purpose') == 'remote-user-vpn'
        active = bool(c.get('dhcpd_enabled')) or is_vpn
        subnet = c.get('ip_subnet')
        if not subnet:
            continue
        net = str(ipaddress.ip_network(subnet, strict=False))
        nid = net_ids.get(net)
        if not nid:
            continue
        key = (nid, c['dhcpd_start'], c['dhcpd_stop'])
        if key in have:
            print('  = scope %-16s %s - %s (already recorded)'
                  % (c.get('name'), c['dhcpd_start'], c['dhcpd_stop']))
            continue
        body = {'network_id': nid, 'server_id': server_id,
                'name': '%s %s' % (c.get('name', ''), 'client pool' if is_vpn else 'scope'),
                'start_addr': c['dhcpd_start'], 'end_addr': c['dhcpd_stop'],
                'lease_time': str(c.get('dhcpd_leasetime') or 86400),
                'enabled': active, 'source': 'unifi', 'ext_id': c.get('_id', ''),
                'description': ('VPN client address pool read from the UniFi gateway'
                                if is_vpn else
                                'DHCP scope read from the UniFi gateway'
                                + ('' if active else ' — currently disabled there'))}
        state = '' if active else '  [disabled at the gateway]'
        if args.dry_run:
            print('  + scope %-16s %s - %s%s'
                  % (c.get('name'), c['dhcpd_start'], c['dhcpd_stop'], state))
            continue
        r, st = ipam(args.ipam, args.ipam_token, '/api/dhcp/ranges', 'POST', body)
        print('  %s scope %-16s %s - %s%s'
              % ('+' if st == 200 else '!', c.get('name'), c['dhcpd_start'],
                 c['dhcpd_stop'], state if st == 200 else '  ' + str(r.get('error'))))

    # ─── Fixed-IP reservations (opt-in) ───────────────────────────────
    if args.reservations:
        users = uni.get('/proxy/network/api/s/%s/rest/user' % args.site)
        fixed = [u for u in users if u.get('use_fixedip') and u.get('fixed_ip')]
        print('\n%d fixed-IP reservation(s)' % len(fixed))
        for u in fixed:
            body = {'address': u['fixed_ip'], 'status': 'reserved',
                    'mac': u.get('mac', ''),
                    'dns_name': '', 'description': 'UniFi DHCP reservation: %s'
                                                   % (u.get('name') or u.get('hostname') or ''),
                    'source': 'unifi', 'ext_id': u.get('_id', ''),
                    'meta': {'unifi_name': u.get('name') or u.get('hostname') or ''}}
            if args.dry_run:
                print('  + %-16s %-28s %s' % (u['fixed_ip'],
                                              (u.get('name') or '')[:28], u.get('mac')))
                continue
            look, _ = ipam(args.ipam, args.ipam_token,
                           '/api/addresses/lookup?address=%s' % u['fixed_ip'])
            rec = look.get('record')
            if rec:
                # An existing record (e.g. from DNS) is richer — only add the
                # MAC and note the reservation, never downgrade its name.
                body['dns_name'] = rec.get('dns_name', '')
                body['status'] = rec.get('status', 'active')
                body['source'] = rec.get('source', 'unifi')
                body['ext_id'] = rec.get('ext_id', '')
                meta = rec.get('meta') or {}
                meta['unifi_reservation'] = u.get('name') or u.get('hostname') or ''
                body['meta'] = meta
                _, st = ipam(args.ipam, args.ipam_token,
                             '/api/addresses/%s' % rec['id'], 'POST', body)
                print('  ~ %-16s %s (added MAC/reservation to existing record)'
                      % (u['fixed_ip'], (u.get('name') or '')[:28]))
            else:
                _, st = ipam(args.ipam, args.ipam_token, '/api/addresses', 'POST', body)
                print('  %s %-16s %-28s %s' % ('+' if st == 200 else '!', u['fixed_ip'],
                                               (u.get('name') or '')[:28], u.get('mac')))

    print('\nDone. Clients/leases were deliberately NOT imported — the scope '
          'accounts for them.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
