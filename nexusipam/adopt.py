"""Adopt a target's existing state into the address plan.

The inverse of pushout: pull once, then author here. This is what a site whose
DHCP already lives on its gateway needs before any of the push machinery is
useful — you cannot become the writer of something you have never read.

It is a deliberate, operator-triggered action rather than a background sync.
Two systems continuously merging into each other need conflict resolution
nobody can reason about; one explicit "take what is there" followed by "now I
am the author" needs none. Re-running is safe and idempotent.

The rule throughout: **fill gaps, never overwrite.** An adopt that clobbered a
name or a description someone had already corrected would make the operator's
work the thing most likely to be lost, so existing non-empty values always
win and are reported as `kept`.
"""
from flask import Blueprint, jsonify, request

from . import netutil
from .core import db
from .core.auth import actor
from .core.runcmd import err

bp = Blueprint('adopt', __name__)


def _upsert_vlan(vid, name, site=''):
    if vid is None:
        return None
    row = db.query_one('SELECT id FROM vlans WHERE vid=? AND site=?', (vid, site))
    if row:
        return row['id']
    return db.insert('vlans', {'vid': vid, 'name': name or '', 'site': site,
                               'status': 'active', 'source': 'unifi', 'ext_id': ''})


def _adopt_network(rec, source, out):
    """Create the network, or fill in only what it is missing."""
    net = netutil.parse_network(rec['cidr'])
    if net is None:
        return None
    start_hex, end_hex = netutil.net_bounds(net)
    existing = db.query_one('SELECT * FROM networks WHERE cidr=?', (str(net),))
    vlan_id = _upsert_vlan(rec.get('vlan'), rec.get('name'))
    fields = {'name': rec.get('name') or '', 'gateway': rec.get('gateway') or '',
              'dns_servers': ', '.join(rec.get('dns') or []),
              'domain': rec.get('domain') or '', 'vlan_id': vlan_id}
    if not existing:
        nid = db.insert('networks', {
            'cidr': str(net), 'version': net.version, 'prefixlen': net.prefixlen,
            'net_start': start_hex, 'net_end': end_hex, 'role': 'subnet',
            'status': 'active', 'source': source, 'ext_id': rec.get('ext_id') or '',
            **fields})
        out['networks_created'].append(str(net))
        return nid
    # Only ever fill blanks.
    patch = {k: v for k, v in fields.items() if v and not existing.get(k)}
    if patch:
        db.update('networks', existing['id'], patch)
        out['networks_updated'].append(str(net))
    else:
        out['networks_kept'].append(str(net))
    return existing['id']


def _adopt_range(nid, rng, source, out):
    if not rng:
        return
    start_hex, end_hex, e = netutil.range_bounds(rng['start'], rng['end'])
    if e:
        out['errors'].append('%s-%s: %s' % (rng['start'], rng['end'], e))
        return
    if db.query_one('SELECT id FROM dhcp_ranges WHERE network_id=? AND start_hex=? '
                    'AND end_hex=?', (nid, start_hex, end_hex)):
        out['ranges_kept'].append('%s-%s' % (rng['start'], rng['end']))
        return
    # A range that overlaps an existing one is a real disagreement, not
    # something to silently add alongside it — two pools handing out the same
    # address is the conflict this app exists to prevent.
    clash = db.query_one('SELECT start_addr, end_addr FROM dhcp_ranges '
                         'WHERE network_id=? AND start_hex <= ? AND end_hex >= ?',
                         (nid, end_hex, start_hex))
    if clash:
        out['errors'].append('%s-%s overlaps the recorded %s-%s — resolve by hand'
                             % (rng['start'], rng['end'],
                                clash['start_addr'], clash['end_addr']))
        return
    db.insert('dhcp_ranges', {
        'network_id': nid, 'start_addr': rng['start'], 'end_addr': rng['end'],
        'start_hex': start_hex, 'end_hex': end_hex,
        'lease_time': rng.get('lease') or '12h',
        'enabled': 1 if rng.get('enabled') else 0,
        'source': source, 'ext_id': ''})
    out['ranges_created'].append('%s-%s' % (rng['start'], rng['end']))


def _adopt_options(nid, options, source, out):
    from .services import RESERVED_OPTIONS
    for option, value in sorted((options or {}).items()):
        # router/dns/domain live on the network row; they were adopted there.
        if option in RESERVED_OPTIONS:
            continue
        if db.query_one('SELECT id FROM dhcp_options WHERE network_id=? AND option=?',
                        (nid, option)):
            out['options_kept'].append(option)
            continue
        db.insert('dhcp_options', {'network_id': nid, 'option': option,
                                   'value': value, 'enabled': 1,
                                   'source': source, 'ext_id': ''})
        out['options_created'].append(option)


def _adopt_reservation(res, source, out):
    ip = netutil.parse_ip(res.get('ip'))
    if ip is None:
        return
    from .networks import network_for
    addr_hex = netutil.hexify(int(ip))
    existing = db.query_one('SELECT * FROM ip_addresses WHERE address=?', (str(ip),))
    if existing:
        # Merge the MAC in if we do not have one; never touch a name or an
        # assignment that DNS or a hypervisor import already established.
        if not existing['mac'] and res.get('mac'):
            db.update('ip_addresses', existing['id'], {'mac': res['mac']})
            out['reservations_updated'].append(str(ip))
        else:
            out['reservations_kept'].append(str(ip))
        return
    owner = network_for(addr_hex, ip.version)
    db.insert('ip_addresses', {
        'address': str(ip), 'version': ip.version, 'addr_hex': addr_hex,
        'network_id': owner['id'] if owner else None,
        'status': 'reserved', 'mac': res.get('mac') or '',
        'dns_name': '', 'description': 'DHCP reservation adopted from the gateway',
        'source': source, 'ext_id': res.get('ext_id') or '', 'meta': '{}'})
    out['reservations_created'].append(str(ip))


def adopt_snapshot(state, source='unifi'):
    """Write a target's snapshot into the plan. Returns a per-object report."""
    out = {k: [] for k in (
        'networks_created', 'networks_updated', 'networks_kept',
        'ranges_created', 'ranges_kept', 'options_created', 'options_kept',
        'reservations_created', 'reservations_updated', 'reservations_kept',
        'errors')}
    with db.WRITE_LOCK:
        for rec in state.get('networks') or []:
            nid = _adopt_network(rec, source, out)
            if nid is None:
                out['errors'].append('%s: not a usable prefix' % rec.get('cidr'))
                continue
            _adopt_range(nid, rec.get('range'), source, out)
            _adopt_options(nid, rec.get('options'), source, out)
        # After networks exist, so every reservation files under the most
        # specific prefix rather than landing unparented.
        for res in state.get('reservations') or []:
            _adopt_reservation(res, source, out)
    from .networks import reindex_addresses
    reindex_addresses()
    return out


@bp.route('/api/push/targets/<name>/pull', methods=['POST'])
def target_pull(name):
    """Adopt what a target already holds. `?dry_run=1` reads and reports
    without writing — worth doing first on a populated instance."""
    from .pushout import _targets
    target = next((t for t in _targets() if t['name'] == name), None)
    if not target:
        return err('No such target', 404)
    if (target.get('kind') or 'dnsmaq') != 'unifi':
        return err('Only a UniFi gateway can be pulled from today — a DNSMAQ-MGR '
                   'node is fed by this IPAM, and tools/import_dnsmasq.py seeds '
                   'the other direction', 400)
    from . import unifi
    peer = dict(target)
    peer['verify'] = target.get('verify') or 'insecure'
    try:
        state = unifi.read_state(peer)
    except Exception as e:
        return err('Could not read %s: %s' % (name, e), 502)

    if request.args.get('dry_run') in ('1', 'true', 'yes'):
        return jsonify({'success': True, 'dry_run': True, 'state': state})
    report = adopt_snapshot(state, source=target.get('name') or 'unifi')
    db.audit(actor(), 'adopt-target', 'push', None,
             '%s: %d network(s), %d range(s), %d reservation(s) created'
             % (name, len(report['networks_created']), len(report['ranges_created']),
                len(report['reservations_created'])))
    return jsonify({'success': not report['errors'], 'target': name, **report})
