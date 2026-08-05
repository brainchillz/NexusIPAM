#!/usr/bin/env python3
"""Import clusters, ESXi hosts, VMs and their addresses from vCenter into IPAM.

Fills in the whole containment chain in one pass:

    cluster (vSphere) -> device (ESXi host) -> vm -> ip address

vCenter is the system of record for all of it, so everything is written with
`source=vcenter` and `ext_id` set to the managed-object reference (`vm-1018`,
`host-5009`, `domain-c9`). MoRefs are stable for the life of the object, which
makes re-runs idempotent even when something is renamed.

Addresses are the interesting part. A VM's guest IP is only visible when VMware
Tools is running, so powered-off VMs contribute no address — that is a gap in
the data, not an error, and is reported rather than guessed at. Where an
address record already exists (typically from the DNS import) it is *enriched*:
the VM assignment and MAC are added and the existing DNS name is kept, because
DNS is the better authority for names and vCenter is the better authority for
what the address is attached to.

Verified against vCenter 8.0.3 using the `/api/` REST surface (vSphere 7+).

Usage:
  ./tools/import_vcenter.py --vcenter https://<vcenter> \\
      --username administrator@vsphere.local --password-file <file> \\
      --ipam https://ipam:8444 --ipam-token nx_... [--dry-run]
"""
import argparse
import base64
import getpass
import ipaddress
import json
import ssl
import sys
import urllib.error
import urllib.request

CTX = ssl._create_unverified_context()


def http(url, headers=None, method='GET', body=None, auth=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if auth:
        req.add_header('Authorization', 'Basic ' +
                       base64.b64encode(('%s:%s' % auth).encode()).decode())
    if data:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
            raw = r.read()
            return (json.loads(raw) if raw else None), r.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read() or b'{}'), e.code
        except ValueError:
            return {}, e.code


class VCenter:
    def __init__(self, base, username, password):
        self.base = base.rstrip('/')
        sid, st = http(self.base + '/api/session', method='POST',
                       auth=(username, password))
        if st not in (200, 201) or not sid:
            raise SystemExit('vCenter login failed (HTTP %s)' % st)
        self.headers = {'vmware-api-session-id': sid}

    def get(self, path):
        d, st = http(self.base + path, headers=self.headers)
        return d if st == 200 else None


def ipam(url, token, path, method='GET', body=None):
    return http(url.rstrip('/') + path, headers={'Authorization': 'Bearer ' + token},
                method=method, body=body)


def usable_ips(nics):
    """Guest IPs worth recording: skip loopback and link-local, which are
    per-boot noise rather than address-plan facts."""
    out = []
    for nic in (nics or []):
        mac = nic.get('mac_address') or ''
        for ip in ((nic.get('ip') or {}).get('ip_addresses') or []):
            addr = ip.get('ip_address')
            if not addr:
                continue
            try:
                a = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if a.is_loopback or a.is_link_local:
                continue
            out.append((str(a), mac))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--vcenter', required=True)
    ap.add_argument('--username', required=True)
    ap.add_argument('--password-file', help='file containing the password (or prompt)')
    ap.add_argument('--ipam', required=True)
    ap.add_argument('--ipam-token', required=True)
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--no-addresses', action='store_true',
                    help='import inventory only, leave IP records alone')
    ap.add_argument('--all-guest-ips', action='store_true',
                    help='record every guest IP, including ones outside every '
                         'network IPAM defines. Off by default: a guest reports '
                         'its container bridges and CNI overlays as ordinary '
                         'interfaces. A Docker host shows one 172.x gateway per '
                         'compose network (a dozen is normal) and a k8s node '
                         'shows its pod CIDR — all internal to that guest, none '
                         'part of the site plan, and they churn as stacks come '
                         'and go. Add the prefix as a network if you do want to '
                         'track one.')
    ap.add_argument('--include-system', action='store_true',
                    help='also import vCLS agent VMs. vCenter destroys and '
                         'recreates these automatically with fresh MoRefs, so '
                         'by default they are skipped — importing them would '
                         'accumulate dead records nobody put there.')
    args = ap.parse_args()

    password = (open(args.password_file).read().strip() if args.password_file
                else getpass.getpass('vCenter password: '))
    vc = VCenter(args.vcenter, args.username, password)
    IP, TOK = args.ipam, args.ipam_token

    def push(path, body, label):
        """Create-or-update by (source, ext_id); report what happened."""
        if args.dry_run:
            print('  ~ %s' % label)
            return None
        r, st = ipam(IP, TOK, path + '?upsert=1', 'POST', body)
        if st == 200:
            print('  + %s' % label)
            return r['id']
        print('  ! %s -> %s' % (label, (r or {}).get('error')))
        return None

    # ─── Clusters ─────────────────────────────────────────────────────
    print('Clusters')
    cluster_ids = {}
    for c in vc.get('/api/vcenter/cluster') or []:
        cid = push('/api/clusters', {
            'name': c['name'], 'kind': 'vsphere', 'endpoint': args.vcenter,
            'site': 'main', 'status': 'active', 'source': 'vcenter',
            'ext_id': c['cluster'],
            'description': 'vSphere cluster (DRS=%s, HA=%s)'
                           % (c.get('drs_enabled'), c.get('ha_enabled')),
            'meta': {'moref': c['cluster']}},
            'cluster %s' % c['name'])
        if cid:
            cluster_ids[c['cluster']] = cid

    # ─── ESXi hosts -> devices ────────────────────────────────────────
    print('\nESXi hosts')
    host_ids, host_cluster = {}, {}
    # vCenter's /host list has no cluster field, so map it the other way round.
    for c in vc.get('/api/vcenter/cluster') or []:
        for h in vc.get('/api/vcenter/host?clusters=%s' % c['cluster']) or []:
            host_cluster[h['host']] = c['cluster']
    for h in vc.get('/api/vcenter/host') or []:
        body = {
            'name': h['name'], 'role': 'server', 'virt': 'vsphere',
            'status': 'active' if h.get('power_state') == 'POWERED_ON' else 'offline',
            'manufacturer': '', 'model': '', 'site': 'main',
            'source': 'vcenter', 'ext_id': h['host'],
            'description': 'ESXi host (%s)' % h.get('connection_state', ''),
            'meta': {'moref': h['host']}}
        cl = host_cluster.get(h['host'])
        if cl and cl in cluster_ids:
            body['cluster_id'] = cluster_ids[cl]
        hid = push('/api/devices', body, 'host %s' % h['name'])
        if hid:
            host_ids[h['host']] = hid
            # vCenter identifies an ESXi host by its management address, so the
            # host's name IS an address worth attributing. Without this the
            # ESXi management IPs sit in the plan owned by nobody, and show up
            # forever as "unmanaged hosts" on a ping sweep.
            try:
                ipaddress.ip_address(h['name'])
            except ValueError:
                continue
            look, _ = ipam(IP, TOK, '/api/addresses/lookup?address=%s' % h['name'])
            rec = (look or {}).get('record')
            abody = {'address': h['name'], 'status': 'active',
                     'assigned_kind': 'device', 'assigned_id': hid,
                     'is_primary': True, 'if_name': 'vmk0',
                     'description': 'ESXi management interface'}
            if rec:
                abody['dns_name'] = rec.get('dns_name', '')
                abody['mac'] = rec.get('mac', '')
                abody['source'] = rec.get('source', 'vcenter')
                abody['ext_id'] = rec.get('ext_id', '')
                ipam(IP, TOK, '/api/addresses/%s' % rec['id'], 'POST', abody)
                print('    linked %s to this host (kept DNS name %s)'
                      % (h['name'], rec.get('dns_name') or '-'))
            else:
                abody.update({'source': 'vcenter', 'ext_id': h['host']})
                ipam(IP, TOK, '/api/addresses', 'POST', abody)
                print('    recorded management address %s' % h['name'])

    # ─── VMs ──────────────────────────────────────────────────────────
    print('\nVirtual machines')
    vm_host = {}
    for hmoref in host_ids or {}:
        for v in vc.get('/api/vcenter/vm?hosts=%s' % hmoref) or []:
            vm_host[v['vm']] = hmoref

    vm_ids, no_tools, addr_rows = {}, [], []
    skipped_system = 0
    for v in vc.get('/api/vcenter/vm') or []:
        if not args.include_system and v['name'].startswith('vCLS-'):
            skipped_system += 1
            continue
        detail = vc.get('/api/vcenter/vm/%s' % v['vm']) or {}
        disks = (detail.get('disks') or {}).values()
        disk_gb = round(sum((d.get('capacity') or 0) for d in disks) / (1024 ** 3)) or None
        body = {
            'name': v['name'], 'platform': 'vsphere', 'vmid': v['vm'],
            'status': 'active' if v['power_state'] == 'POWERED_ON' else 'offline',
            'vcpus': v.get('cpu_count'), 'memory_mb': v.get('memory_size_MiB'),
            'disk_gb': disk_gb, 'os': detail.get('guest_OS', ''),
            'source': 'vcenter', 'ext_id': v['vm'],
            'description': 'vSphere VM',
            'meta': {'moref': v['vm'],
                     'networks': sorted({(n.get('backing') or {}).get('network_name', '')
                                         for n in (detail.get('nics') or {}).values()} - {''})}}
        hm = vm_host.get(v['vm'])
        if hm and hm in host_ids:
            body['host_device_id'] = host_ids[hm]
            cl = host_cluster.get(hm)
            if cl in cluster_ids:
                body['cluster_id'] = cluster_ids[cl]
        vid = push('/api/vms', body, '%-28s %-11s %s' % (v['name'][:28], v['power_state'],
                                                         detail.get('guest_OS', '')))
        if vid:
            vm_ids[v['vm']] = vid

        if args.no_addresses:
            continue
        # Guest IPs need VMware Tools; a powered-off VM simply has none.
        nics = vc.get('/api/vcenter/vm/%s/guest/networking/interfaces' % v['vm'])
        if not isinstance(nics, list):
            if v['power_state'] == 'POWERED_ON':
                no_tools.append(v['name'])
            continue
        for addr, mac in usable_ips(nics):
            addr_rows.append((addr, mac, v['vm'], v['name']))

    # ─── Addresses ────────────────────────────────────────────────────
    if not args.no_addresses:
        print('\nAddresses from guest tools')
        outside = 0
        for addr, mac, vmoref, vmname in addr_rows:
            vid = vm_ids.get(vmoref)
            if args.dry_run:
                print('  ~ %-16s -> %s' % (addr, vmname))
                continue
            look, _ = ipam(IP, TOK, '/api/addresses/lookup?address=%s' % addr)
            # An address in no defined prefix is not part of the plan. That is
            # the test that keeps container bridges and overlay networks out,
            # and it is self-correcting: define the prefix and a re-run adopts
            # them.
            if not (look or {}).get('network') and not args.all_guest_ips:
                outside += 1
                continue
            rec = (look or {}).get('record')
            body = {'address': addr, 'status': 'active',
                    'assigned_kind': 'vm', 'assigned_id': vid,
                    'mac': mac, 'description': 'vSphere guest interface'}
            if rec:
                # DNS is the better authority for the name; vCenter is the
                # better authority for what the address is attached to.
                body['dns_name'] = rec.get('dns_name', '')
                body['source'] = rec.get('source', 'vcenter')
                body['ext_id'] = rec.get('ext_id', '')
                body['mac'] = mac or rec.get('mac', '')
                meta = rec.get('meta') or {}
                meta['vcenter_vm'] = vmname
                body['meta'] = meta
                _, st = ipam(IP, TOK, '/api/addresses/%s' % rec['id'], 'POST', body)
                print('  ~ %-16s linked to %s (kept DNS name %s)'
                      % (addr, vmname, rec.get('dns_name') or '-'))
            else:
                body.update({'source': 'vcenter', 'ext_id': vmoref,
                             'meta': {'vcenter_vm': vmname}})
                _, st = ipam(IP, TOK, '/api/addresses', 'POST', body)
                print('  %s %-16s -> %s' % ('+' if st == 200 else '!', addr, vmname))

        if outside:
            print('\nSkipped %d guest IP(s) outside every defined network '
                  '(container bridges, CNI overlays, undeclared prefixes). '
                  'Use --all-guest-ips to keep them.' % outside)
        if skipped_system:
            print('\nSkipped %d vCLS agent VM(s) (--include-system to keep them).'
                  % skipped_system)
        if no_tools:
            print('\n%d powered-on VM(s) report no guest networking (VMware Tools '
                  'not running) — no address recorded for them:' % len(no_tools))
            for n in no_tools:
                print('    %s' % n)
    if not args.dry_run:
        try:   # breadcrumb for the Settings sync panel; never fail the import over it
            ipam(IP, TOK, '/api/sync/runs', 'POST',
                 {'source': 'vcenter', 'ok': True,
                  'detail': 'inventory import completed'})
        except Exception:
            pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
