#!/usr/bin/env python3
"""Import DNS host records from a DNSMAQ-MGR instance into Nexus IPAM.

This is the inbound half of the DNSMAQ-MGR integration (nexusipam/exports.py is
the outbound half). Run it against the dnsmasq **primary** — a mirror serves a
copy of the same records, so importing from both would just do the work twice.

Two things make this more than a loop over records:

  * **Several names can share one address.** DNS is name -> address; IPAM is
    address -> facts, and `ip_addresses.address` is UNIQUE. Six A records
    pointing at one host is normal and must not become six rows or five
    errors. One record is written per address; the extra names are kept in
    `meta.aliases` so nothing is lost.

  * **Picking which name is canonical.** Whichever name the host answers to in
    reverse DNS is the one an operator recognises, so a PTR match wins. Failing
    that, the shortest name — `docker` over `vmdeploy`, `gateway` over
    `greatwall` — which is the usual convention.

Records are written with `source=dnsmasq-mgr` and `ext_id` set to the source
record's id, so re-running updates in place instead of duplicating, and
`GET /api/addresses/search?source=dnsmasq-mgr` lists exactly what this brought
in (and `DELETE`s cleanly if you want it gone).

Usage:
  ./tools/import_dnsmasq.py --dnsmasq https://<dnsmasq-host>:8443 --dnsmasq-token dm_... \\
                            --ipam https://ipam:8444 --ipam-token nx_... [--dry-run]
"""
import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request


def request(url, token, method='GET', body=None, insecure=True):
    ctx = ssl._create_unverified_context() if insecure else None
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header('Authorization', 'Bearer ' + token)
    if data:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            return json.loads(r.read() or b'{}'), r.status
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read() or b'{}'), e.code
        except ValueError:
            return {}, e.code


def group_by_address(hosts):
    """{address: {'entries': [{name,id,comment,enabled}], 'version': 4|6}}
    from DNSMAQ-MGR host records (each may carry an A and/or an AAAA).
    Disabled records are KEPT — lossless import means the enabled flag is
    data, not a filter."""
    out = {}
    for h in hosts:
        name = (h.get('name') or '').strip().rstrip('.')
        if not name:
            continue
        for field, version in (('a', 4), ('aaaa', 6)):
            addr = (h.get(field) or '').strip()
            if not addr:
                continue
            entry = out.setdefault(addr, {'entries': [], 'version': version})
            if name not in [e['name'] for e in entry['entries']]:
                entry['entries'].append({'name': name, 'id': h.get('id', ''),
                                         'comment': h.get('comment', '') or '',
                                         'enabled': bool(h.get('enabled', True))})
    return out


def choose_primary(entries, ptr):
    """PTR match wins; otherwise the shortest enabled name (then alphabetical,
    so the result is stable across runs rather than dependent on dict order)."""
    candidates = [e for e in entries if e['enabled']] or entries
    if ptr:
        ptr = ptr.rstrip('.')
        for e in candidates:
            if e['name'] == ptr:
                return e
    return sorted(candidates, key=lambda e: (len(e['name']), e['name']))[0]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--dnsmasq', required=True, help='DNSMAQ-MGR base URL (the primary)')
    ap.add_argument('--dnsmasq-token', required=True)
    ap.add_argument('--ipam', required=True, help='Nexus IPAM base URL')
    ap.add_argument('--ipam-token', required=True)
    ap.add_argument('--dry-run', action='store_true',
                    help='report what would change, write nothing')
    ap.add_argument('--only-managed', action='store_true',
                    help='skip addresses that fall outside every defined network')
    args = ap.parse_args()

    dns, status = request(args.dnsmasq.rstrip('/') + '/api/dns', args.dnsmasq_token)
    if status != 200:
        print('Failed to read DNSMAQ-MGR: HTTP %s %s' % (status, dns.get('error', '')),
              file=sys.stderr)
        return 1
    hosts = dns.get('hosts', [])
    grouped = group_by_address(hosts)
    print('%d host record(s) -> %d distinct address(es)' % (len(hosts), len(grouped)))

    created = updated = skipped = unmanaged = 0
    for addr, info in sorted(grouped.items()):
        # lookup gives us the existing record (if any), the containing network,
        # and the PTR the sweeper already learned — one call, three answers.
        look, st = request('%s/api/addresses/lookup?address=%s'
                           % (args.ipam.rstrip('/'), addr), args.ipam_token)
        if st != 200:
            print('  ! %-16s lookup failed (HTTP %s)' % (addr, st))
            continue

        in_network = bool(look.get('network'))
        if not in_network:
            unmanaged += 1
            if args.only_managed:
                skipped += 1
                continue

        ptr = (look.get('scan') or {}).get('hostname', '')
        primary = choose_primary(info['entries'], ptr)
        # Ordered name list, canonical first — position 0 drives PTR on push.
        ordered = [primary] + [e for e in info['entries'] if e is not primary]
        aliases = len(ordered) - 1
        existing = look.get('record')

        body = {
            'address': addr,
            'status': 'active',
            'dns_name': primary['name'] if primary['enabled'] else '',
            'description': 'DNS record from DNSMAQ-MGR',
            'source': 'dnsmasq-mgr',
            'ext_id': primary['id'],
        }
        # Never clobber an assignment or MAC someone recorded by hand.
        if existing:
            for keep in ('assigned_kind', 'assigned_id', 'if_name', 'mac', 'is_primary'):
                if existing.get(keep):
                    body[keep] = existing[keep]

        label = '%-16s %-32s' % (addr, primary['name']
                                 + (' (+%d)' % aliases if aliases else ''))
        if args.dry_run:
            print('  %s %s%s' % ('~' if existing else '+', label,
                                 '' if in_network else '  [outside every network]'))
            continue

        if existing:
            resp, st = request('%s/api/addresses/%s' % (args.ipam.rstrip('/'), existing['id']),
                               args.ipam_token, 'POST', body)
            ok, updated = st == 200, updated + (1 if st == 200 else 0)
            rid = existing['id']
        else:
            resp, st = request('%s/api/addresses' % args.ipam.rstrip('/'),
                               args.ipam_token, 'POST', body)
            ok, created = st == 200, created + (1 if st == 200 else 0)
            rid = resp.get('id')
        # The full ordered name list, lossless: every name with its own
        # comment, enabled flag and the DNSMAQ record id (ext_id) — what makes
        # the push round-trip reproduce the zone identically.
        if ok and rid:
            _, nst = request('%s/api/addresses/%s/names' % (args.ipam.rstrip('/'), rid),
                             args.ipam_token, 'POST',
                             {'names': [{'name': e['name'], 'rtype': 'a',
                                         'comment': e['comment'],
                                         'enabled': e['enabled'],
                                         'ext_id': e['id']} for e in ordered]})
            if nst != 200:
                ok = False
                print('  ! %-16s names write failed (HTTP %s)' % (addr, nst))
        print('  %s %s%s' % ('~' if existing else '+' if ok else '!', label,
                             '' if in_network else '  [outside every network]'))

    verb = 'would import' if args.dry_run else 'imported'
    print('\n%s: %d created, %d updated, %d skipped' % (verb, created, updated, skipped))
    if not args.dry_run:
        try:   # breadcrumb for the Settings sync panel; never fail the import over it
            request(args.ipam.rstrip('/') + '/api/sync/runs', args.ipam_token,
                    'POST', {'source': 'dnsmasq-mgr', 'ok': True,
                             'detail': '%d created, %d updated, %d skipped'
                                       % (created, updated, skipped),
                             'counts': {'created': created, 'updated': updated,
                                        'skipped': skipped}})
        except Exception:
            pass
    if unmanaged:
        print('%d address(es) fall outside every defined network — they are recorded '
              'but unparented.\nDefine those prefixes, or re-run with --only-managed '
              'to leave them out.' % unmanaged)
    return 0


if __name__ == '__main__':
    sys.exit(main())
