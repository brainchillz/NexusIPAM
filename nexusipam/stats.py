"""Dashboard aggregates and global search."""
from flask import Blueprint, jsonify, request

from . import netutil
from .core import db
from .core.runcmd import err
from .core.validators import RE_TEXT

bp = Blueprint('stats', __name__)


def _count(table, where='', args=()):
    sql = 'SELECT COUNT(*) c FROM %s' % table + (' WHERE ' + where if where else '')
    return db.query_one(sql, args)['c']


def unmanaged_count():
    """Hosts that answered a ping, have no record, and are outside every
    enabled DHCP pool. The ONE definition of "unmanaged" — overview, health
    and the reconcile page must all agree, or the operator chases a number
    that changes meaning between pages.

    The pool test lives entirely inside NOT EXISTS: joining `networks` in the
    outer query instead would fan out — an address inside both a /23 and a
    containing supernet would match twice and be counted twice."""
    return db.query_one(
        'SELECT COUNT(*) c FROM scan_results '
        'LEFT JOIN ip_addresses ON ip_addresses.address = scan_results.address '
        'WHERE scan_results.alive=1 AND ip_addresses.id IS NULL '
        '  AND NOT EXISTS (SELECT 1 FROM dhcp_ranges '
        '                  JOIN networks ON networks.id = dhcp_ranges.network_id '
        '                  WHERE dhcp_ranges.enabled = 1 '
        '                    AND networks.version = scan_results.version '
        '                    AND scan_results.addr_hex '
        '                        BETWEEN dhcp_ranges.start_hex AND dhcp_ranges.end_hex)')['c']


@bp.route('/api/overview')
def overview():
    """Everything the Overview page shows, in one call."""
    from .networks import utilization, NETWORK_LIST_SQL

    nets = db.rows(NETWORK_LIST_SQL + " WHERE networks.role <> 'container' "
                   'ORDER BY networks.version, networks.net_start')
    total_cap = total_used = 0
    busiest = []
    for n in nets:
        u = utilization(n)
        n['utilization'] = u
        # Same rule as the busiest list below: a /8 or an IPv6 /64 has
        # astronomical capacity that pins the global percent-used at 0.0
        # forever. The totals only count prefixes small enough for "percent
        # consumed" to mean anything.
        if u['capacity'] <= 65536:
            total_cap += u['capacity']
            total_used += u['used']
        busiest.append(n)
    # Only prefixes small enough to be meaningful — a /8 container skews any
    # "percent used" reading into uselessness.
    busiest = sorted([n for n in busiest if n['utilization']['capacity'] <= 65536],
                     key=lambda n: -n['utilization']['pct'])[:8]

    scanned = db.query_one('SELECT COUNT(*) c, MAX(last_scan) m FROM scan_results')
    unmanaged = unmanaged_count()

    return jsonify({
        'counts': {
            'networks': _count('networks'),
            'containers_nets': _count('networks', "role='container'"),
            'vlans': _count('vlans'),
            'addresses': _count('ip_addresses'),
            'assigned': _count('ip_addresses', "assigned_kind <> ''"),
            'reserved': _count('ip_addresses', "status='reserved'"),
            'devices': _count('devices'),
            'clusters': _count('clusters'),
            'vms': _count('vms'),
            'containers': _count('containers'),
            'dhcp_servers': _count('dhcp_servers'),
            'dhcp_ranges': _count('dhcp_ranges'),
            'dns_servers': _count('dns_servers'),
        },
        'space': {'capacity': total_cap, 'used': total_used,
                  'free': max(0, total_cap - total_used),
                  'pct': round(total_used / total_cap * 100, 1) if total_cap else 0},
        'busiest': busiest,
        'scan': {'known': scanned['c'], 'last': scanned['m'] or 0, 'unmanaged': unmanaged},
        'recent': db.query('SELECT * FROM audit ORDER BY ts DESC, id DESC LIMIT 12'),
    })


@bp.route('/api/search')
def search():
    """One search box across addresses, networks, and every inventory object.

    A bare IP or CIDR is recognised and routed to the right lookup, so typing
    "10.0.0.42" jumps straight to that address and "10.0.0.0/24" to that
    network.
    """
    q = (request.args.get('q') or '').strip()
    if not q or len(q) > 128 or not RE_TEXT.match(q):
        return err('Invalid or missing search term')
    like = '%' + q + '%'
    out = {'query': q, 'exact': None, 'networks': [], 'addresses': [], 'objects': []}

    net = netutil.parse_network(q) if '/' in q else None
    if net is not None:
        row = db.row('SELECT * FROM networks WHERE cidr=?', (str(net),))
        if row:
            out['exact'] = {'kind': 'network', 'id': row['id'], 'label': row['cidr']}

    ip = netutil.parse_ip(q)
    if ip is not None:
        row = db.row('SELECT * FROM ip_addresses WHERE address=?', (str(ip),))
        if row:
            out['exact'] = {'kind': 'address', 'id': row['id'], 'label': row['address']}
        else:
            # Not recorded — still useful to point at its containing network.
            from .networks import network_for
            n = network_for(netutil.hexify(int(ip)), ip.version)
            if n:
                out['exact'] = {'kind': 'free-address', 'id': n['id'],
                                'label': '%s (free in %s)' % (ip, n['cidr'])}

    out['networks'] = db.rows(
        'SELECT id, cidr, name, role, description FROM networks '
        'WHERE cidr LIKE ? OR name LIKE ? OR description LIKE ? ORDER BY net_start LIMIT 25',
        (like, like, like))
    out['addresses'] = db.rows(
        'SELECT id, address, dns_name, status, description FROM ip_addresses '
        'WHERE address LIKE ? OR dns_name LIKE ? OR mac LIKE ? OR description LIKE ? '
        'ORDER BY addr_hex LIMIT 25', (like, like, like, like))

    for kind, table in (('device', 'devices'), ('vm', 'vms'),
                        ('container', 'containers'), ('cluster', 'clusters')):
        for r in db.query('SELECT id, name, description FROM %s '
                          'WHERE name LIKE ? OR description LIKE ? ORDER BY name LIMIT 15'
                          % table, (like, like)):
            out['objects'].append({'kind': kind, **r})

    return jsonify(out)


@bp.route('/api/health')
def health():
    """Consistency checks an operator should know about. Everything here is a
    real data problem, not a style opinion."""
    issues = []

    orphan = db.query('SELECT address FROM ip_addresses WHERE network_id IS NULL '
                      'ORDER BY addr_hex LIMIT 50')
    if orphan:
        issues.append({'level': 'warning', 'kind': 'orphan-addresses',
                       'count': _count('ip_addresses', 'network_id IS NULL'),
                       'message': 'addresses that fall outside every defined network',
                       'examples': [o['address'] for o in orphan[:10]]})

    # A record pointing at an object that has since been deleted.
    dangling = []
    from .addresses import KIND_TABLES
    for kind, table in KIND_TABLES.items():
        for r in db.query('SELECT address FROM ip_addresses WHERE assigned_kind=? '
                          'AND assigned_id IS NOT NULL AND assigned_id NOT IN '
                          '(SELECT id FROM %s) LIMIT 25' % table, (kind,)):
            dangling.append(r['address'])
    if dangling:
        issues.append({'level': 'error', 'kind': 'dangling-assignments',
                       'count': len(dangling),
                       'message': 'addresses assigned to objects that no longer exist',
                       'examples': dangling[:10]})

    # Deliberately NOT flagged: a network whose declared gateway has no separate
    # address record. The gateway is a property of the network — the allocator,
    # the free list and the IP map all already honour it — so a missing record
    # is redundant bookkeeping, not a defect. Router interfaces get records when
    # an importer attaches them to the router device, which is the useful case.

    # Deliberately NOT flagged: the same MAC on several addresses. Binding
    # multiple IPs to one interface is a normal, intentional pattern — it is how
    # you run several services that all want the same port on one host. It is
    # surfaced as context on the address lookup instead, where it is useful
    # rather than alarming.

    # Same definition the reconcile view uses: a responder inside an enabled
    # DHCP pool is a lease, not an anomaly. Counting those here would make the
    # Overview banner permanently red on any network that runs DHCP.
    unmanaged = unmanaged_count()
    if unmanaged:
        issues.append({'level': 'warning', 'kind': 'unmanaged-hosts', 'count': unmanaged,
                       'message': 'hosts answering pings with no address record '
                                  '(DHCP leases excluded)',
                       'examples': []})

    return jsonify({'ok': not any(i['level'] == 'error' for i in issues),
                    'issues': issues})
