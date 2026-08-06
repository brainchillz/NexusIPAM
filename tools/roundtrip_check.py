#!/usr/bin/env python3
"""Round-trip gate: prove IPAM can reproduce the DNS zone losslessly before
it is allowed to become the writer.

Compares the authoritative DNSMAQ-MGR hosts section (what the DNS node serves
today) against IPAM's push payload (what IPAM would write), per address:

  * the same set of addresses,
  * the same names in the same order (position 0 = canonical → PTR),
  * the same comment and enabled flag on every record,
  * the same DNSMAQ record ids (so the first push updates records in place
    instead of replacing them with twins).

Exit 0 = byte-level faithful; anything else prints the exact differences and
exits 1. Run after the lossless import and before configuring push targets.

Usage:
  ./tools/roundtrip_check.py --dnsmasq https://ns1:8443 --dnsmasq-token dm_... \
                             --ipam https://ipam:8444 --ipam-token nx_...
"""
import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request

CTX = ssl._create_unverified_context()


def fetch(url, token):
    req = urllib.request.Request(url)
    req.add_header('Authorization', 'Bearer ' + token)
    with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
        return json.loads(r.read())


def by_address(records):
    """address → ordered [(name, comment, enabled, id)] preserving list order
    (the order that decides the PTR answer on the node)."""
    out = {}
    for rec in records:
        for field in ('a', 'aaaa'):
            addr = (rec.get(field) or '').strip()
            if addr:
                out.setdefault(addr, []).append(
                    (rec.get('name', ''), rec.get('comment', '') or '',
                     bool(rec.get('enabled', True)), rec.get('id', '')))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--dnsmasq', required=True)
    ap.add_argument('--dnsmasq-token', required=True)
    ap.add_argument('--ipam', required=True)
    ap.add_argument('--ipam-token', required=True)
    args = ap.parse_args()

    dns = fetch(args.dnsmasq.rstrip('/') + '/api/dns', args.dnsmasq_token)
    ipam = fetch(args.ipam.rstrip('/') + '/api/push/preview', args.ipam_token)
    a = by_address(dns.get('hosts', []))
    b = by_address(ipam.get('hosts', []))

    problems = []
    for addr in sorted(set(a) - set(b)):
        problems.append('%-16s only on the DNS node: %s'
                        % (addr, ', '.join(n for n, *_ in a[addr])))
    for addr in sorted(set(b) - set(a)):
        problems.append('%-16s only in the IPAM payload: %s'
                        % (addr, ', '.join(n for n, *_ in b[addr])))
    for addr in sorted(set(a) & set(b)):
        if a[addr] == b[addr]:
            continue
        an, bn = [n for n, *_ in a[addr]], [n for n, *_ in b[addr]]
        if an != bn:
            problems.append('%-16s name order/set differs:\n'
                            '                   node: %s\n'
                            '                   ipam: %s' % (addr, an, bn))
            continue
        for (n1, c1, e1, i1), (n2, c2, e2, i2) in zip(a[addr], b[addr]):
            if c1 != c2:
                problems.append('%-16s %s: comment differs (%r vs %r)'
                                % (addr, n1, c1, c2))
            if e1 != e2:
                problems.append('%-16s %s: enabled differs (%s vs %s)'
                                % (addr, n1, e1, e2))
            if i1 != i2:
                problems.append('%-16s %s: record id differs (%s vs %s) — '
                                'push would replace instead of update'
                                % (addr, n1, i1 or '(none)', i2 or '(none)'))

    n_records = sum(len(v) for v in a.values())
    if problems:
        print('ROUND-TRIP FAILED — %d difference(s) across %d address(es), '
              '%d record(s):\n' % (len(problems), len(a), n_records))
        for p in problems:
            print('  ' + p)
        return 1
    print('Round-trip clean: %d record(s) across %d address(es) — the IPAM '
          'payload reproduces the zone exactly (names, order, comments, '
          'enabled flags, record ids).' % (n_records, len(a)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
