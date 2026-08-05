#!/usr/bin/env python3
"""Import the physical host inventory from NexusController into Nexus IPAM.

NexusController is the registry of record for real machines — the layer neither
vCenter (which only knows what it virtualises) nor DNS (which only knows names)
can supply. It classifies each node (AI / Storage / Virtualization / DNS /
External / Mixed / VM), which is carried through to `meta.classification` and
shown in the UI, alongside its capabilities and tags.

Three things this has to get right, all of them learned from the real data:

  * **One machine can hold several registry entries.** A single box often
    appears once as itself and again as a service it hosts (a storage server
    that is also the DNS mirror, say). Creating two devices for one machine
    would be wrong, so entries are grouped by address and the richest one —
    most capabilities — becomes the device. The others are kept as
    `meta.also_known_as`.

  * **Some registry nodes are virtual.** A registry may list VMs (the Docker
    host, vCenter itself) that a hypervisor import already recorded; writing
    them again as physical devices would double-count the estate. Any address already attached to a VM is skipped,
    as is anything the registry itself types as `VM`.

  * **Entries can be named by hostname rather than address.** Those are
    resolved to an address so they land in the right network — and if a name
    does not resolve, the device is still created, just without an address.

Reads only. Nothing is written back to NexusController.

Usage:
  ./tools/import_nexuscontroller.py --controller https://controller:9443 \\
      --username admin --password-file <file> \\
      --ipam https://ipam:8444 --ipam-token nx_... [--dry-run]
"""
import argparse
import getpass
import http.cookiejar
import ipaddress
import json
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

CTX = ssl._create_unverified_context()

# NexusController's classification -> IPAM's device role. Most map straight
# across; 'Virtualization', 'DNS' and 'External' describe what a machine does
# rather than what it is, so they land on 'server' and keep the distinction in
# `meta.classification` and in tags.
ROLE_BY_TYPE = {
    'Storage': 'storage',
    'AI': 'ai',
    'Mixed': 'mixed',
    'Virtualization': 'server',
    'DNS': 'server',
    'External': 'server',
}


def ipam(url, token, path, method='GET', body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url.rstrip('/') + path, data=data, method=method)
    req.add_header('Authorization', 'Bearer ' + token)
    if data:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
            raw = r.read()
            return (json.loads(raw) if raw else {}), r.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read() or b'{}'), e.code
        except ValueError:
            return {}, e.code


def resolve(host):
    """Address for a registry entry: already an IP, or resolved from its name."""
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--controller', required=True)
    ap.add_argument('--username', default='admin')
    ap.add_argument('--password-file')
    ap.add_argument('--ipam', required=True)
    ap.add_argument('--ipam-token', required=True)
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    password = (open(args.password_file).read().strip() if args.password_file
                else getpass.getpass('NexusController password: '))

    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.HTTPSHandler(context=CTX))
    login = urllib.request.Request(
        args.controller.rstrip('/') + '/api/login',
        data=json.dumps({'username': args.username, 'password': password}).encode(),
        headers={'Content-Type': 'application/json'}, method='POST')
    with opener.open(login, timeout=30) as r:
        if not json.loads(r.read() or b'{}').get('success'):
            raise SystemExit('NexusController login failed')

    with opener.open(args.controller.rstrip('/') + '/api/nodes', timeout=30) as r:
        nodes = json.loads(r.read())['nodes']
    print('%d node(s) in the registry' % len(nodes))

    # ─── Group registry entries by the machine they describe ──────────
    by_addr, unresolved = {}, []
    for n in nodes:
        host = urllib.parse.urlparse(n.get('base_url') or '').hostname
        addr = resolve(host)
        if not addr:
            unresolved.append(n)
            continue
        by_addr.setdefault(addr, []).append(n)

    IP, TOK = args.ipam, args.ipam_token
    created = skipped_vm = 0

    for addr in sorted(by_addr, key=lambda a: ipaddress.ip_address(a)):
        entries = by_addr[addr]
        # Richest entry wins: the physical-box record carries the full
        # capability list, a co-located service record carries one or two.
        entries.sort(key=lambda n: -len(n.get('capabilities') or []))
        primary, others = entries[0], entries[1:]

        if primary.get('type') == 'VM':
            print('  = %-16s %-26s registry says VM — left to vCenter' % (addr, primary['name']))
            skipped_vm += 1
            continue

        look, _ = ipam(IP, TOK, '/api/addresses/lookup?address=%s' % addr)
        rec = (look or {}).get('record')
        if rec and rec.get('assigned_kind') == 'vm':
            print('  = %-16s %-26s already a VM (%s) — not a physical device'
                  % (addr, primary['name'], rec.get('assigned_name')))
            skipped_vm += 1
            continue

        classification = primary.get('type') or ''
        body = {
            'name': primary['name'],
            'role': ROLE_BY_TYPE.get(classification, 'server'),
            'status': 'active', 'site': 'main',
            'description': '%s node from NexusController' % (classification or 'Registry'),
            'source': 'nexus-controller', 'ext_id': primary.get('id', ''),
            # Registry tags go into the real `tags` column (filterable via
            # ?tag=), with the classification folded in so a Mixed box is
            # findable under what it actually does.
            'tags': sorted(set((primary.get('tags') or []) +
                               ([classification.lower()] if classification else []))),
            'meta': {
                'classification': classification,
                'capabilities': primary.get('capabilities') or [],
                'agent_version': primary.get('version') or '',
                'base_url': primary.get('base_url') or '',
                'also_known_as': [o['name'] for o in others],
            },
        }
        # A node that reports a hypervisor capability hosts VMs; say so, since
        # that is what lets VMs be placed on it in the UI.
        caps = set(primary.get('capabilities') or [])
        if 'vcenter' in caps or 'esxi' in caps:
            body['virt'] = 'vsphere'
        elif 'proxmox' in caps:
            body['virt'] = 'proxmox'
        elif 'instances' in caps or 'lxd' in caps:
            body['engine'] = 'lxd'
        if 'docker' in caps or 'compose' in caps:
            body['engine'] = 'docker'

        label = '%-16s %-26s %-15s %s' % (addr, primary['name'][:26], classification,
                                          ('+ ' + ', '.join(o['name'] for o in others))
                                          if others else '')
        if args.dry_run:
            print('  ~ %s' % label)
            continue

        r, st = ipam(IP, TOK, '/api/devices?upsert=1', 'POST', body)
        if st != 200:
            print('  ! %s -> %s' % (label, r.get('error')))
            continue
        did = r['id']
        created += 1
        print('  + %s' % label)

        # Attach the address, enriching rather than replacing what DNS knows.
        abody = {'address': addr, 'status': 'active', 'assigned_kind': 'device',
                 'assigned_id': did, 'is_primary': True,
                 'description': 'Managed node (%s)' % classification}
        if rec:
            abody['dns_name'] = rec.get('dns_name', '')
            abody['mac'] = rec.get('mac', '')
            abody['source'] = rec.get('source', 'nexus-controller')
            abody['ext_id'] = rec.get('ext_id', '')
            meta = rec.get('meta') or {}
            meta['nexus_controller_node'] = primary['name']
            abody['meta'] = meta
            ipam(IP, TOK, '/api/addresses/%s' % rec['id'], 'POST', abody)
        else:
            abody.update({'source': 'nexus-controller', 'ext_id': primary.get('id', '')})
            ipam(IP, TOK, '/api/addresses', 'POST', abody)

    if unresolved:
        print('\n%d entry(ies) whose base_url host would not resolve — no address '
              'recorded:' % len(unresolved))
        for n in unresolved:
            print('    %s (%s)' % (n['name'], n.get('base_url')))
    print('\n%d device(s) written, %d virtual node(s) left to vCenter.'
          % (created, skipped_vm))
    if not args.dry_run:
        try:   # breadcrumb for the Settings sync panel; never fail the import over it
            ipam(IP, TOK, '/api/sync/runs', 'POST',
                 {'source': 'nexus-controller', 'ok': True,
                  'detail': '%d device(s) written' % created,
                  'counts': {'devices': created}})
        except Exception:
            pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
