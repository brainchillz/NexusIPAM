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
        # Merge in what we learned; never touch a name or an assignment that
        # DNS or a hypervisor import already established. `is_reservation` is
        # always asserted — the gateway is the authority on whether it hands
        # this address to this MAC, and an address adopted first by another
        # importer would otherwise never be published back as a reservation.
        patch = {'is_reservation': 1}
        if not existing['mac'] and res.get('mac'):
            patch['mac'] = res['mac']
        if patch.keys() - {'is_reservation'} or not existing['is_reservation']:
            db.update('ip_addresses', existing['id'], patch)
            out['reservations_updated'].append(str(ip))
        else:
            out['reservations_kept'].append(str(ip))
        return
    owner = network_for(addr_hex, ip.version)
    db.insert('ip_addresses', {
        'address': str(ip), 'version': ip.version, 'addr_hex': addr_hex,
        'network_id': owner['id'] if owner else None,
        'status': 'reserved', 'mac': res.get('mac') or '', 'is_reservation': 1,
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


# ─── DHCP-derived DNS names ───────────────────────────────────────────
# When a host gets a DHCP reservation, the gateway resolves a name for it
# that this plan knows nothing about — so it resolves there and nowhere
# else. Three per-client sources, three trust levels, and the trust order
# drives everything below:
#
#   local_dns       a Local DNS Record: an FQDN someone chose, already
#                   served. Adopting one is a HANDOVER — the next push
#                   unticks the client record and Static DNS takes over.
#   label           the UniFi client name ("Cindys Phone") — human label,
#                   usually not DNS-safe. Proposed, never mangled into shape.
#   opt12_hostname  DHCP option 12 — client-supplied and unvalidated; a
#                   device can claim to be `ns1`. Lowest trust.
#
# Lease-derived names rank below all three and are NEVER adopted: publishing
# a dynamic name into authoritative DNS goes stale with nobody touching it —
# the exact failure the lease overlay exists to avoid. They still appear as
# candidates (flagged `dynamic`) so the operator can see them and, if one
# matters, give the machine a reservation first.

NAME_SOURCES = (('local_dns', 'high'), ('label', 'medium'),
                ('opt12_hostname', 'low'))


def _qualify(name, domain):
    """Bare name -> FQDN using the network domain. Push deliberately does not
    qualify, so anything stored must already be fully qualified."""
    name = str(name or '').strip().rstrip('.')
    if name and domain and '.' not in name:
        return '%s.%s' % (name, domain)
    return name


def name_candidates():
    """Every DHCP-side name this plan does not publish, best source first.
    Reads each enabled gateway target live plus the lease overlay; a target
    that cannot be read is reported, not fatal."""
    from . import unifi
    from .pushout import _targets
    from .core.validators import valid_fqdn
    from .networks import network_for

    raw_entries, errors = [], []
    for target in _targets():
        if (target.get('kind') or 'dnsmaq') != 'unifi' or not target.get('enabled', True):
            continue
        peer = dict(target)
        peer['verify'] = target.get('verify') or 'insecure'
        try:
            state = unifi.read_state(peer)
        except Exception as e:
            errors.append('%s: %s' % (target['name'], e))
            continue
        for res in state.get('reservations') or []:
            for source, confidence in NAME_SOURCES:
                text = (res.get('names') or {}).get(source) or ''
                if text:
                    raw_entries.append({'ip': res['ip'], 'mac': res['mac'],
                                        'target': target['name'], 'source': source,
                                        'confidence': confidence, 'raw': text,
                                        'dynamic': False})
    # Lease hostnames come from the overlay already on hand — reading them
    # does not need another gateway round trip.
    for l in db.query("SELECT address, mac, hostname, source FROM dhcp_leases "
                      "WHERE hostname <> ''"):
        raw_entries.append({'ip': l['address'], 'mac': l['mac'],
                            'target': l['source'], 'source': 'lease',
                            'confidence': 'low', 'raw': l['hostname'],
                            'dynamic': True})

    out, seen = [], set()
    for e in raw_entries:
        ip = netutil.parse_ip(e['ip'])
        if ip is None:
            continue
        rec = db.query_one('SELECT id FROM ip_addresses WHERE address=?', (str(ip),))
        net = network_for(netutil.hexify(int(ip)), ip.version)
        fqdn = _qualify(e['raw'], (net or {}).get('domain') or '')
        key = (str(ip), fqdn.lower())
        if key in seen:            # trust order: the first source for a name wins
            continue
        seen.add(key)
        published = {n['name'].lower() for n in db.query(
            'SELECT ip_names.name FROM ip_names JOIN ip_addresses '
            'ON ip_addresses.id = ip_names.address_id '
            'WHERE ip_addresses.address=? AND ip_names.enabled=1', (str(ip),))}
        if fqdn.lower() in published:
            continue               # already ours — not a candidate
        clash = db.query_one(
            'SELECT a.address FROM ip_names n JOIN ip_addresses a ON a.id=n.address_id '
            'WHERE n.name=? COLLATE NOCASE AND n.enabled=1 AND a.address<>?',
            (fqdn, str(ip)))
        out.append({'address': str(ip), 'mac': e['mac'], 'target': e['target'],
                    'source': e['source'], 'confidence': e['confidence'],
                    'dynamic': e['dynamic'], 'name': e['raw'], 'fqdn': fqdn,
                    'valid': valid_fqdn(fqdn),
                    'conflict': clash['address'] if clash else '',
                    'recorded': bool(rec),
                    'handover': e['source'] == 'local_dns'})
    # Stable sort: address order for the list, insertion (= trust) order kept
    # within one address.
    out.sort(key=lambda c: netutil.hexify(int(netutil.parse_ip(c['address']))))
    return out, errors


@bp.route('/api/names/candidates')
def names_candidates():
    cands, errors = name_candidates()
    return jsonify({'candidates': cands, 'count': len(cands), 'errors': errors})


@bp.route('/api/names/adopt', methods=['POST'])
def names_adopt():
    """Adopt the best candidate name for each listed address — explicitly, one
    operator decision per address, mirroring scan_adopt. Rules, in order:
    lease-derived names are refused; a name that fails valid_fqdn is dropped
    rather than mangled; a name already resolving elsewhere is refused (as
    /api/provision does); the name lands as canonical only when the address
    has none, else as an alias — position 0 and the PTR never move silently.
    Publishing stays a separate, ordinary push."""
    from .addresses import get_names, set_names

    data = request.get_json(silent=True) or {}
    wanted = data.get('addresses')
    if not isinstance(wanted, list) or not wanted:
        return err('Expected {"addresses": [ ... ]}')
    wanted = {str(netutil.parse_ip(a)) for a in wanted if netutil.parse_ip(a)}

    cands, errors = name_candidates()
    by_addr = {}
    for c in cands:
        by_addr.setdefault(c['address'], []).append(c)

    adopted, refused = [], []
    with db.WRITE_LOCK:
        for address in sorted(wanted):
            options = by_addr.get(address) or []
            best = next((c for c in options if not c['dynamic']), None)
            if best is None:
                refused.append({'address': address,
                                'reason': ('only a lease-derived name — give the '
                                           'machine a reservation first; a dynamic '
                                           'name in authoritative DNS goes stale on '
                                           'its own') if options else 'no candidate name'})
                continue
            if not best['valid']:
                refused.append({'address': address,
                                'reason': '%r is not a valid DNS name — dropped '
                                          'rather than mangled' % best['name']})
                continue
            if best['conflict']:
                refused.append({'address': address,
                                'reason': '%s already points at %s — deprovision it '
                                          'first, or alias it there'
                                          % (best['fqdn'], best['conflict'])})
                continue
            rec = db.query_one('SELECT id FROM ip_addresses WHERE address=?', (address,))
            if not rec:
                refused.append({'address': address,
                                'reason': 'address is not recorded — adopt the '
                                          'gateway (pull) first'})
                continue
            current = get_names(rec['id'])
            if any(n['name'].lower() == best['fqdn'].lower() for n in current):
                # Present but disabled: someone chose not to publish it, and
                # adoption must not silently overrule that choice.
                refused.append({'address': address,
                                'reason': '%s exists on the record but is disabled '
                                          '— enable it there if wanted' % best['fqdn']})
                continue
            items = list(current) + [{'name': best['fqdn'],
                                      'comment': 'adopted from %s (%s)'
                                                 % (best['target'], best['source'])}]
            _, e = set_names(rec['id'], items)
            if e:
                refused.append({'address': address, 'reason': e})
                continue
            adopted.append({'address': address, 'fqdn': best['fqdn'],
                            'source': best['source'],
                            'as': 'alias' if current else 'canonical',
                            'handover': best['handover']})
        if adopted:
            db.audit(actor(), 'adopt-names', 'ip_addresses', None,
                     db.audit_list(['%s=%s' % (a['fqdn'], a['address'])
                                    for a in adopted]))
    return jsonify({'success': not refused, 'adopted': adopted,
                    'refused': refused, 'errors': errors})


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
