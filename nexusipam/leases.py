"""Dynamic DHCP leases — observed, never authored.

A lease is only true until it expires. Writing one into the address plan
records something that stops being true with nobody touching it, which is why
this is a disposable overlay rather than rows in `ip_addresses`: refreshed
wholesale from whatever is serving DHCP, aged out on its own, and safe to lose
entirely.

What it is *for* is telling the operator which "free" addresses are actually
in use right now, and which recorded reservations are not being taken up —
questions a ping sweep answers slowly and imprecisely, and a lease table
answers exactly.
"""
import os
import time
import threading

from flask import Blueprint, jsonify, request

from . import netutil
from .core import db
from .core.auth import actor
from .core.runcmd import err, num

bp = Blueprint('leases', __name__)

# An overlay entry nobody has re-observed in this long is stale. Kept well
# above a typical lease time so a slow refresh schedule does not blank the
# view between polls.
LEASE_TTL = 7 * 86400

# How often the background refresher polls each gateway target. 0 disables —
# the overlay then only moves when someone presses Refresh in the UI, which
# quietly rots into a conflict view nobody can trust; hence a default.
LEASE_MINUTES = float(os.environ.get('NEXUSIPAM_LEASE_MINUTES', 60))


def record_leases(source, items, prune=True):
    """Replace `source`'s view of the world. Returns (stored, removed).

    Wholesale, not incremental: a lease that has gone is absent from the next
    poll rather than announced, so anything this source no longer reports has
    to be dropped or the overlay only ever grows.
    """
    ts = int(time.time())
    seen = []
    with db.WRITE_LOCK:
        for item in items:
            ip = netutil.parse_ip(item.get('ip'))
            if ip is None:
                continue
            db.execute(
                'INSERT INTO dhcp_leases(address, version, addr_hex, mac, hostname, '
                'expires, source, seen) VALUES(?,?,?,?,?,?,?,?) '
                'ON CONFLICT(address) DO UPDATE SET '
                '  mac=excluded.mac, hostname=excluded.hostname, '
                '  expires=excluded.expires, source=excluded.source, seen=excluded.seen',
                (str(ip), ip.version, netutil.hexify(int(ip)),
                 str(item.get('mac') or '').lower(), str(item.get('hostname') or '')[:128],
                 num(item.get('expires')) or 0, source, ts))
            seen.append(str(ip))
        removed = 0
        if prune:
            # By address, NOT by timestamp. `seen < ts` looks equivalent but
            # silently prunes nothing when two refreshes land in the same
            # second, which is exactly the kind of thing that works in
            # production and fails under a test or a manual double-click.
            sql = 'DELETE FROM dhcp_leases WHERE source=?'
            args = [source]
            if seen:
                sql += ' AND address NOT IN (%s)' % ','.join('?' * len(seen))
                args += seen
            removed = db.execute(sql, tuple(args)).rowcount
        db.execute('DELETE FROM dhcp_leases WHERE seen < ?', (ts - LEASE_TTL,))
    return len(seen), removed


def dnsmaq_lease_items(body):
    """DNSMAQ-MGR's /api/dhcp/leases shape -> overlay items. Static
    (reservation-held) MACs are skipped for the same reason the UniFi reader
    skips fixed-IP clients: that binding is a plan record, not a dynamic
    lease, and listing it as both double-counts the address."""
    out = []
    for l in body.get('leases') or []:
        if l.get('static') or not l.get('ip'):
            continue
        out.append({'ip': l['ip'], 'mac': (l.get('mac') or '').lower(),
                    'hostname': l.get('hostname') or '',
                    'expires': int(l.get('expiry') or 0)})
    return out


def read_dnsmaq_leases(target):
    """Poll a DNSMAQ-MGR node's lease file through its API, using the
    target's READONLY read token."""
    from .pushout import dnsmaq_get
    return dnsmaq_lease_items(dnsmaq_get(target, '/api/dhcp/leases'))


def read_target_leases(target):
    """Leases from one push target, whichever kind it is. Returns None for a
    target with no read path (a dnsmaq node without a read token) — distinct
    from an empty lease table, which is a real observation."""
    kind = target.get('kind') or 'dnsmaq'
    if kind in ('unifi', 'pihole'):
        from . import pihole, unifi
        peer = dict(target)
        peer['verify'] = target.get('verify') or 'insecure'
        adapter = unifi if kind == 'unifi' else pihole
        return adapter.read_leases(peer)
    if target.get('read_token'):
        return read_dnsmaq_leases(target)
    return None


def refresh_all():
    """Refresh the overlay from every enabled, readable push target. Returns
    one report entry per target; errors are reported, never raised — one
    unreachable server must not stop the others being read."""
    from .pushout import _targets
    out = []
    for target in _targets():
        if not target.get('enabled', True):
            continue
        try:
            items = read_target_leases(target)
        except Exception as e:
            out.append({'target': target['name'], 'ok': False, 'error': str(e)})
            continue
        if items is None:                       # nothing to read — not an error
            continue
        stored, removed = record_leases(target['name'], items)
        out.append({'target': target['name'], 'ok': True,
                    'leases': stored, 'expired': removed})
    return out


def start_refresher():
    """Daemon thread keeping the overlay current without anyone clicking.
    Observed state should be re-observed on a schedule — that is the whole
    point of it being disposable. Sleeps FIRST: a boot loop must not hammer
    the gateway with logins, and startup already has enough to do."""
    if LEASE_MINUTES <= 0:
        return

    def loop():
        while True:
            time.sleep(LEASE_MINUTES * 60)
            try:
                for r in refresh_all():
                    if not r['ok']:   # success is silent; failures must not be
                        print('lease refresh %s FAILED: %s'
                              % (r['target'], r['error']), flush=True)
            except Exception as ex:
                print('lease refresh FAILED: %s' % ex, flush=True)

    threading.Thread(target=loop, daemon=True, name='lease-refresh').start()


@bp.route('/api/leases')
def leases_list():
    """The overlay, joined to what the plan says about each address — the
    interesting rows are the ones where they disagree."""
    net_id = num(request.args.get('network_id'))
    args, clause = [], ''
    if net_id is not None:
        net = db.row('SELECT * FROM networks WHERE id=?', (net_id,))
        if not net:
            return err('No such network', 404)
        clause = (' WHERE dhcp_leases.version=? AND dhcp_leases.addr_hex '
                  'BETWEEN ? AND ?')
        args = [net['version'], net['net_start'], net['net_end']]
    rows = db.query(
        'SELECT dhcp_leases.*, ip_addresses.id AS record_id, '
        '       ip_addresses.status AS record_status, '
        '       ip_addresses.dns_name AS record_name, '
        '       ip_addresses.mac AS record_mac '
        'FROM dhcp_leases '
        'LEFT JOIN ip_addresses ON ip_addresses.address = dhcp_leases.address'
        + clause + ' ORDER BY dhcp_leases.version, dhcp_leases.addr_hex',
        tuple(args))
    for r in rows:
        # A lease whose MAC differs from the recorded one is the useful signal:
        # the address is reserved for one machine and being used by another.
        r['conflict'] = bool(r['record_mac'] and r['mac']
                             and r['record_mac'] != r['mac'])
        r['unrecorded'] = r['record_id'] is None
    return jsonify({'leases': rows, 'count': len(rows),
                    'unrecorded': sum(1 for r in rows if r['unrecorded']),
                    'conflicts': sum(1 for r in rows if r['conflict'])})


@bp.route('/api/push/targets/<name>/leases', methods=['POST'])
def target_leases(name):
    """Refresh the overlay from one target."""
    from .pushout import _targets
    target = next((t for t in _targets() if t['name'] == name), None)
    if not target:
        return err('No such target', 404)
    try:
        items = read_target_leases(target)
    except Exception as e:
        return err('Could not read leases from %s: %s' % (name, e), 502)
    if items is None:
        return err('This node has no read credential — mint a READONLY API '
                   'token there and add it to the target as its read token '
                   '(the mirror token is write-only by design)', 400)
    stored, removed = record_leases(name, items)
    db.audit(actor(), 'leases', 'push', None,
             '%s: %d lease(s), %d expired' % (name, stored, removed))
    return jsonify({'success': True, 'target': name,
                    'leases': stored, 'expired': removed})
