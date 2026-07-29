"""VLANs and IP networks — the layer-2/layer-3 backbone.

A network's identity is its normalized CIDR. Parent/child relationships are
NOT stored: they are derived from the hex bounds on every read, so adding a
supernet after its subnets exist immediately reparents them without a
migration. `role` distinguishes a container (a supernet you carve up, e.g.
10.0.0.0/8) from a subnet (something hosts actually live in).
"""
from flask import Blueprint, jsonify, request

from . import netutil
from .core import db
from .core.auth import actor
from .core.runcmd import err, num
from .core.validators import (NETWORK_ROLES, STATUSES, clean_text, is_ip,
                              one_of, valid_fqdn)
from .resource import Resource, register, mount

bp = Blueprint('networks', __name__)


# ─── Validators ───────────────────────────────────────────────────────

def _v_vlan(data, existing):
    vid = num(data.get('vid'))
    if vid is None or not 1 <= vid <= 4094:
        return None, 'VLAN ID must be between 1 and 4094'
    name, e = clean_text(data.get('name'), 'Name', 64)
    if e:
        return None, e
    site, e = clean_text(data.get('site'), 'Site', 64)
    if e:
        return None, e
    status, e = one_of(data.get('status'), STATUSES, 'Status', 'active')
    if e:
        return None, e
    desc, e = clean_text(data.get('description'), 'Description')
    if e:
        return None, e
    return {'vid': vid, 'name': name, 'site': site, 'status': status,
            'description': desc}, None


def _v_network(data, existing):
    net = netutil.parse_network(data.get('cidr'))
    if net is None:
        return None, 'Invalid CIDR (e.g. 10.0.0.0/24 or 2001:db8::/64)'
    start_hex, end_hex = netutil.net_bounds(net)

    name, e = clean_text(data.get('name'), 'Name', 64)
    if e:
        return None, e
    role, e = one_of(data.get('role'), NETWORK_ROLES, 'Role', 'subnet')
    if e:
        return None, e
    status, e = one_of(data.get('status'), STATUSES, 'Status', 'active')
    if e:
        return None, e

    gateway = str(data.get('gateway') or '').strip()
    if gateway:
        if not is_ip(gateway):
            return None, 'Gateway must be an IP address'
        gw = netutil.parse_ip(gateway)
        if gw.version != net.version:
            return None, 'Gateway must be the same IP version as the network'
        if gw not in net:
            return None, 'Gateway %s is not inside %s' % (gateway, net)

    dns_list = netutil.split_list(data.get('dns_servers'))
    for d in dns_list:
        if not is_ip(d):
            return None, 'DNS server "%s" is not an IP address' % d

    domain = str(data.get('domain') or '').strip()
    if domain and not valid_fqdn(domain):
        return None, 'Invalid domain'

    site, e = clean_text(data.get('site'), 'Site', 64)
    if e:
        return None, e
    desc, e = clean_text(data.get('description'), 'Description')
    if e:
        return None, e

    vlan_id = num(data.get('vlan_id'))
    if vlan_id is not None and not db.query_one('SELECT id FROM vlans WHERE id=?', (vlan_id,)):
        return None, 'No such VLAN'

    # Changing the prefix must not orphan this network's DHCP ranges outside
    # the new bounds — the range rows would still count against utilization
    # while claiming addresses the network no longer contains.
    if existing:
        stranded = db.query_one(
            'SELECT COUNT(*) c FROM dhcp_ranges WHERE network_id=? '
            'AND (start_hex < ? OR end_hex > ?)',
            (existing['id'], start_hex, end_hex))['c']
        if stranded:
            return None, ('Cannot change to %s: %d DHCP range(s) would fall '
                          'outside the new prefix — move or delete them first'
                          % (net, stranded))

    return {'cidr': str(net), 'version': net.version, 'prefixlen': net.prefixlen,
            'net_start': start_hex, 'net_end': end_hex, 'name': name, 'role': role,
            'vlan_id': vlan_id, 'gateway': gateway, 'dns_servers': ', '.join(dns_list),
            'domain': domain, 'site': site, 'status': status, 'description': desc}, None


# ─── Reindexing ───────────────────────────────────────────────────────

def reindex_addresses():
    """Recompute every address's owning network (most specific prefix that
    contains it). Cheap at this scale and always correct — called whenever a
    network is added, edited or removed rather than trying to patch the
    affected subset."""
    nets = db.query('SELECT id, version, net_start, net_end, prefixlen FROM networks')
    # Most specific first, so the first match wins.
    nets.sort(key=lambda n: -n['prefixlen'])
    for ip in db.query('SELECT id, version, addr_hex, network_id FROM ip_addresses'):
        owner = None
        for n in nets:
            if n['version'] == ip['version'] and n['net_start'] <= ip['addr_hex'] <= n['net_end']:
                owner = n['id']
                break
        if owner != ip['network_id']:
            db.execute('UPDATE ip_addresses SET network_id=? WHERE id=?', (owner, ip['id']))


def network_for(addr_hex, version):
    """Most specific network containing an address, or None."""
    return db.row('SELECT * FROM networks WHERE version=? AND net_start<=? AND net_end>=? '
                  'ORDER BY prefixlen DESC LIMIT 1', (version, addr_hex, addr_hex))


def _on_network_change(action, rid, fields):
    reindex_addresses()


# ─── Utilization ──────────────────────────────────────────────────────

def overlapping_ranges(version, lo_hex, hi_hex, enabled_only=True):
    """Enabled DHCP ranges from ANY same-version network that intersect
    [lo_hex, hi_hex]. Scoping by network_id alone is wrong whenever prefixes
    nest: a pool declared on a child subnet consumes the parent's space just
    as surely, and the parent's free list / utilization / map must all see it.
    """
    sql = ('SELECT dhcp_ranges.start_hex, dhcp_ranges.end_hex FROM dhcp_ranges '
           'JOIN networks ON networks.id = dhcp_ranges.network_id '
           'WHERE networks.version=? AND dhcp_ranges.start_hex <= ? '
           'AND dhcp_ranges.end_hex >= ?')
    if enabled_only:
        sql += ' AND dhcp_ranges.enabled = 1'
    return db.query(sql, (version, hi_hex, lo_hex))


def merge_spans(spans):
    """[(start_int, end_int), ...] -> non-overlapping sorted spans. Two pools
    covering the same addresses (parent scope + child scope) must not count
    that space twice."""
    out = []
    for s, e in sorted(spans):
        if out and s <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def utilization(net_row):
    """Used/free accounting for one network.

    "Used" is every recorded address inside the prefix PLUS every address
    covered by an enabled DHCP range, since a DHCP pool consumes its span
    whether or not a lease is currently handed out. The two sets can overlap
    (a static reservation inside a pool), so they are unioned by count, not
    added: pool addresses that are also recorded are only counted once.
    """
    net = netutil.parse_network(net_row['cidr'])
    if net is None:
        return {'capacity': 0, 'used': 0, 'free': 0, 'pct': 0, 'dhcp': 0, 'records': 0}
    cap = netutil.capacity(net)
    first, last = netutil.usable_bounds(net)
    lo, hi = netutil.hexify(first), netutil.hexify(last)

    records = db.query_one(
        'SELECT COUNT(*) c FROM ip_addresses WHERE version=? AND addr_hex BETWEEN ? AND ?',
        (net_row['version'], lo, hi))['c']

    # Every enabled range that intersects this prefix, from any network —
    # clamped to the usable window, merged so overlapping pools (e.g. a parent
    # scope and a child scope covering the same span) count once.
    spans = []
    for r in overlapping_ranges(net_row['version'], lo, hi):
        s = max(int(r['start_hex'], 16), first)
        e = min(int(r['end_hex'], 16), last)
        if s <= e:
            spans.append((s, e))
    dhcp_total = 0
    for s, e in merge_spans(spans):
        dhcp_total += e - s + 1
        # Addresses recorded inside the pool are already in `records`;
        # subtract them so the union is not double-counted.
        dhcp_total -= db.query_one(
            'SELECT COUNT(*) c FROM ip_addresses WHERE version=? AND addr_hex BETWEEN ? AND ?',
            (net_row['version'], netutil.hexify(s), netutil.hexify(e)))['c']

    used = min(cap, records + max(0, dhcp_total))
    free = max(0, cap - used)
    return {'capacity': cap, 'used': used, 'free': free,
            'pct': round(used / cap * 100, 1) if cap else 0,
            'dhcp': max(0, dhcp_total), 'records': records}


def children_of(net_row):
    """Directly contained networks (one level down)."""
    kids = db.rows('SELECT * FROM networks WHERE version=? AND net_start>=? AND net_end<=? '
                   'AND id<>? ORDER BY net_start, prefixlen',
                   (net_row['version'], net_row['net_start'], net_row['net_end'], net_row['id']))
    # Keep only the outermost layer: drop any block contained by another child.
    out = []
    for k in kids:
        if not any(o['net_start'] <= k['net_start'] and k['net_end'] <= o['net_end']
                   for o in kids if o['id'] != k['id']
                   and o['prefixlen'] < k['prefixlen']):
            out.append(k)
    return out


def parent_of(net_row):
    return db.row('SELECT * FROM networks WHERE version=? AND net_start<=? AND net_end>=? '
                  'AND id<>? ORDER BY prefixlen DESC LIMIT 1',
                  (net_row['version'], net_row['net_start'], net_row['net_end'], net_row['id']))


# ─── Resources ────────────────────────────────────────────────────────

VLAN_LIST_SQL = """
SELECT vlans.*,
       (SELECT COUNT(*) FROM networks WHERE networks.vlan_id = vlans.id) AS network_count
FROM vlans
"""

NETWORK_LIST_SQL = """
SELECT networks.*, vlans.vid AS vlan_vid, vlans.name AS vlan_name
FROM networks LEFT JOIN vlans ON vlans.id = networks.vlan_id
"""

register(Resource('vlans', 'vlans', _v_vlan, list_sql=VLAN_LIST_SQL,
                  get_sql=VLAN_LIST_SQL + ' WHERE vlans.id=?',
                  order='vlans.site, vlans.vid'))

register(Resource('networks', 'networks', _v_network, list_sql=NETWORK_LIST_SQL,
                  get_sql=NETWORK_LIST_SQL + ' WHERE networks.id=?',
                  order='networks.version, networks.net_start, networks.prefixlen',
                  label='cidr', on_change=_on_network_change))

mount(bp, 'vlans')
mount(bp, 'networks')


# ─── Network detail (the page behind clicking a subnet) ───────────────

@bp.route('/api/networks/<int:rid>/detail')
def network_detail(rid):
    net_row = db.row(NETWORK_LIST_SQL + ' WHERE networks.id=?', (rid,))
    if not net_row:
        return err('No such network', 404)
    net = netutil.parse_network(net_row['cidr'])
    first, last = netutil.usable_bounds(net)
    lo, hi = netutil.hexify(first), netutil.hexify(last)

    addresses = db.rows(
        'SELECT * FROM ip_addresses WHERE version=? AND addr_hex BETWEEN ? AND ? '
        'ORDER BY addr_hex', (net_row['version'], lo, hi))
    from .addresses import expand_assignment
    for a in addresses:
        expand_assignment(a)

    ranges = db.rows('SELECT dhcp_ranges.*, dhcp_servers.name AS server_name '
                     'FROM dhcp_ranges LEFT JOIN dhcp_servers ON dhcp_servers.id = dhcp_ranges.server_id '
                     'WHERE dhcp_ranges.network_id=? ORDER BY start_hex', (rid,))

    return jsonify({'network': net_row,
                    'utilization': utilization(net_row),
                    'parent': parent_of(net_row),
                    'children': children_of(net_row),
                    'addresses': addresses,
                    'dhcp_ranges': ranges,
                    'enumerable': netutil.enumerable(net),
                    'deploy': netutil.deploy_payload(net_row)})


@bp.route('/api/networks/<int:rid>/map')
def network_map(rid):
    """Address-by-address state for the visual IP map.

    Returns one entry per usable address with its state: recorded / dhcp-pool
    / gateway / free, plus the last ping result if we have one. Refuses to
    enumerate prefixes above MAX_ENUMERATE — see netutil.enumerable.
    """
    net_row = db.row('SELECT * FROM networks WHERE id=?', (rid,))
    if not net_row:
        return err('No such network', 404)
    net = netutil.parse_network(net_row['cidr'])
    if not netutil.enumerable(net):
        return err('%s is too large to enumerate (%d addresses); browse its child '
                   'networks instead' % (net_row['cidr'], netutil.capacity(net)), 413)

    first, last = netutil.usable_bounds(net)
    lo, hi = netutil.hexify(first), netutil.hexify(last)
    recorded = {r['addr_hex']: r for r in db.rows(
        'SELECT * FROM ip_addresses WHERE version=? AND addr_hex BETWEEN ? AND ?',
        (net_row['version'], lo, hi))}
    scanned = {r['addr_hex']: r for r in db.query(
        'SELECT * FROM scan_results WHERE version=? AND addr_hex BETWEEN ? AND ?',
        (net_row['version'], lo, hi))}
    pools = overlapping_ranges(net_row['version'], lo, hi)
    gateway = net_row.get('gateway') or ''

    from .addresses import expand_assignment
    out = []
    for addr in netutil.iter_usable(net):
        h = netutil.hexify(int(addr))
        rec = recorded.get(h)
        scan = scanned.get(h)
        if rec:
            expand_assignment(rec)
            state = rec['status']
        elif any(p['start_hex'] <= h <= p['end_hex'] for p in pools):
            state = 'pool'
        elif scan and scan['alive']:
            state = 'unmanaged'   # answered a ping but we have no record for it
        else:
            state = 'free'
        entry = {'address': str(addr), 'state': state}
        if str(addr) == gateway:
            entry['gateway'] = True
        if rec:
            entry['record'] = rec
        if scan:
            entry['alive'] = bool(scan['alive'])
            entry['last_scan'] = scan['last_scan']
            entry['hostname'] = scan['hostname']
        out.append(entry)
    return jsonify({'network': net_row, 'addresses': out,
                    'utilization': utilization(net_row)})


@bp.route('/api/networks/<int:rid>/free')
def network_free(rid):
    """Free addresses in a network. `limit` caps the response; `ping=1` verifies
    each candidate is actually silent before returning it."""
    net_row = db.row('SELECT * FROM networks WHERE id=?', (rid,))
    if not net_row:
        return err('No such network', 404)
    limit = max(1, min(num(request.args.get('limit')) or 256, 4096))
    verify = request.args.get('ping') in ('1', 'true', 'yes')
    from .allocate import free_addresses
    free, checked = free_addresses(net_row, limit=limit, verify=verify)
    return jsonify({'network': net_row, 'free': [str(a) for a in free],
                    'count': len(free), 'verified': checked,
                    'utilization': utilization(net_row)})


@bp.route('/api/networks/tree')
def networks_tree():
    """Every network with its computed parent, utilization and VLAN — the data
    behind the Networks page."""
    nets = db.rows(NETWORK_LIST_SQL + ' ORDER BY networks.version, networks.net_start, '
                                      'networks.prefixlen')
    by_id = {n['id']: n for n in nets}
    for n in nets:
        n['utilization'] = utilization(n)
        parent = None
        for cand in nets:
            if cand['id'] == n['id'] or cand['version'] != n['version']:
                continue
            if cand['net_start'] <= n['net_start'] and n['net_end'] <= cand['net_end']:
                if parent is None or cand['prefixlen'] > by_id[parent]['prefixlen']:
                    parent = cand['id']
        n['parent_id'] = parent
        n['depth'] = 0
    # Depth for indentation in the UI tree.
    for n in nets:
        depth, cur = 0, n['parent_id']
        while cur is not None and depth < 16:
            depth += 1
            cur = by_id[cur]['parent_id']
        n['depth'] = depth
    return jsonify({'networks': nets})


@bp.route('/api/networks/<int:rid>/reserve', methods=['POST'])
def network_reserve(rid):
    """Bulk-reserve a span of addresses (e.g. .1-.20 for infrastructure).

    Creating them as records with status=reserved is what keeps the allocator
    and the free list from ever handing them out.
    """
    net_row = db.row('SELECT * FROM networks WHERE id=?', (rid,))
    if not net_row:
        return err('No such network', 404)
    data = request.get_json(silent=True) or {}
    start_hex, end_hex, e = netutil.range_bounds(data.get('start'), data.get('end'))
    if e:
        return err(e)
    if netutil.parse_ip(data.get('start')).version != net_row['version']:
        return err('The span must be IPv%d addresses' % net_row['version'])
    if not (net_row['net_start'] <= start_hex and end_hex <= net_row['net_end']):
        return err('That span is not inside %s' % net_row['cidr'])
    count = netutil.range_size(start_hex, end_hex)
    if count > 4096:
        return err('Refusing to reserve %d addresses in one call (max 4096)' % count)
    desc, e = clean_text(data.get('description') or 'Reserved', 'Description')
    if e:
        return err(e)

    import ipaddress
    cls = ipaddress.IPv4Address if net_row['version'] == 4 else ipaddress.IPv6Address
    created, skipped = 0, 0
    with db.WRITE_LOCK:
        for i in range(int(start_hex, 16), int(end_hex, 16) + 1):
            addr = str(cls(i))
            if db.query_one('SELECT id FROM ip_addresses WHERE address=?', (addr,)):
                skipped += 1
                continue
            # Most-specific parent, not the network the request came through:
            # reserving via a /16 must still file addresses under a /24 child
            # that contains them, or search-by-network misreports.
            addr_hex = netutil.hexify(i)
            owner = network_for(addr_hex, net_row['version'])
            db.insert('ip_addresses', {
                'address': addr, 'version': net_row['version'], 'addr_hex': addr_hex,
                'network_id': owner['id'] if owner else rid,
                'status': 'reserved', 'description': desc,
                'source': 'manual', 'ext_id': '', 'meta': '{}'})
            created += 1
        db.audit(actor(), 'reserve', 'networks', rid,
                 '%s-%s (%d created)' % (data.get('start'), data.get('end'), created))
    return jsonify({'success': True, 'created': created, 'skipped': skipped})
