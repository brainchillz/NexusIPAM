"""IP address records — the join point between the address plan and the
inventory.

An address record is deliberately generic: it points at any one of
device / vm / container / cluster through (assigned_kind, assigned_id). That
polymorphism is what lets one table track "all the IPs assigned to all the
things" without a separate table per host type, and it is why the target is
validated here in the app layer rather than by a SQL foreign key.
"""
from flask import Blueprint, jsonify, request

from . import netutil
from .core import db
from .core.auth import actor
from .core.runcmd import err, num
from .core.validators import (IP_STATUSES, RE_TEXT, clean_text, norm_mac,
                              one_of, valid_fqdn)
from .resource import Resource, register, mount

bp = Blueprint('addresses', __name__)

# Which table backs each assignable kind.
KIND_TABLES = {'device': 'devices', 'vm': 'vms',
               'container': 'containers', 'cluster': 'clusters'}


def validate_assignment(kind, assigned_id):
    """Return an error string if (kind, id) is not a real object."""
    if kind not in KIND_TABLES:
        return 'assigned_kind must be one of: %s' % ', '.join(sorted(KIND_TABLES))
    if assigned_id is None:
        return 'assigned_id is required when assigned_kind is set'
    if not db.query_one('SELECT id FROM %s WHERE id=?' % KIND_TABLES[kind], (assigned_id,)):
        return 'No such %s (id %s)' % (kind, assigned_id)
    return None


def expand_assignment(rec):
    """Attach the assigned object's name so the UI and API never need a second
    lookup per row."""
    kind, oid = rec.get('assigned_kind'), rec.get('assigned_id')
    rec['assigned_name'] = ''
    if kind in KIND_TABLES and oid:
        row = db.query_one('SELECT name FROM %s WHERE id=?' % KIND_TABLES[kind], (oid,))
        rec['assigned_name'] = row['name'] if row else ''
    return rec


def _v_address(data, existing):
    addr = netutil.parse_ip(data.get('address'))
    if addr is None:
        return None, 'Invalid IP address'

    status, e = one_of(data.get('status'), IP_STATUSES, 'Status', 'active')
    if e:
        return None, e

    kind = str(data.get('assigned_kind') or '').strip().lower()
    assigned_id = num(data.get('assigned_id'))
    if kind:
        e = validate_assignment(kind, assigned_id)
        if e:
            return None, e
    else:
        assigned_id = None

    mac = norm_mac(data.get('mac'))
    if mac is None:
        return None, 'Invalid MAC address (expected aa:bb:cc:dd:ee:ff)'

    dns_name = str(data.get('dns_name') or '').strip()
    if dns_name and not valid_fqdn(dns_name):
        return None, 'Invalid DNS name'

    if_name, e = clean_text(data.get('if_name'), 'Interface', 32)
    if e:
        return None, e
    desc, e = clean_text(data.get('description'), 'Description')
    if e:
        return None, e

    # network_id is derived, never trusted from the client: an address belongs
    # to whichever recorded prefix most specifically contains it.
    from .networks import network_for
    addr_hex = netutil.hexify(int(addr))
    owner = network_for(addr_hex, addr.version)

    return {'address': str(addr), 'version': addr.version, 'addr_hex': addr_hex,
            'network_id': owner['id'] if owner else None, 'status': status,
            'assigned_kind': kind, 'assigned_id': assigned_id, 'if_name': if_name,
            'mac': mac, 'is_primary': 1 if data.get('is_primary') else 0,
            'dns_name': dns_name, 'description': desc}, None


ADDRESS_LIST_SQL = """
SELECT ip_addresses.*, networks.cidr AS network_cidr, networks.name AS network_name,
       vlans.vid AS vlan_vid,
       scan_results.alive AS last_alive, scan_results.last_scan AS last_scan
FROM ip_addresses
LEFT JOIN networks ON networks.id = ip_addresses.network_id
LEFT JOIN vlans ON vlans.id = networks.vlan_id
LEFT JOIN scan_results ON scan_results.address = ip_addresses.address
"""

register(Resource('addresses', 'ip_addresses', _v_address,
                  list_sql=ADDRESS_LIST_SQL,
                  get_sql=ADDRESS_LIST_SQL + ' WHERE ip_addresses.id=?',
                  order='ip_addresses.version, ip_addresses.addr_hex',
                  label='address', singular='address'))

mount(bp, 'addresses')


@bp.route('/api/addresses/search')
def addresses_search():
    """Filtered address list — the query behind the IP Addresses page and the
    read-only API's main entry point.

    Filters: q (address/name/description substring), network_id, vlan_id,
    status, assigned_kind, assigned_id, source, unassigned=1.
    """
    sql = ADDRESS_LIST_SQL
    where, args = [], []

    q = (request.args.get('q') or '').strip()
    if q:
        if not RE_TEXT.match(q) or len(q) > 128:
            return err('Invalid search term')
        like = '%' + q + '%'
        where.append('(ip_addresses.address LIKE ? OR ip_addresses.dns_name LIKE ? '
                     'OR ip_addresses.description LIKE ? OR ip_addresses.mac LIKE ?)')
        args += [like, like, like, like]

    for col, arg in (('network_id', 'network_id'), ('assigned_id', 'assigned_id')):
        v = num(request.args.get(arg))
        if v is not None:
            where.append('ip_addresses.%s = ?' % col)
            args.append(v)

    vlan_id = num(request.args.get('vlan_id'))
    if vlan_id is not None:
        where.append('networks.vlan_id = ?')
        args.append(vlan_id)

    for col in ('status', 'assigned_kind', 'source'):
        v = (request.args.get(col) or '').strip()
        if v:
            where.append('ip_addresses.%s = ?' % col)
            args.append(v)

    if request.args.get('unassigned') in ('1', 'true', 'yes'):
        where.append("ip_addresses.assigned_kind = ''")

    if where:
        sql += ' WHERE ' + ' AND '.join(where)
    limit = max(1, min(num(request.args.get('limit')) or 500, 5000))
    offset = max(0, num(request.args.get('offset')) or 0)
    sql += ' ORDER BY ip_addresses.version, ip_addresses.addr_hex LIMIT ? OFFSET ?'
    args += [limit, offset]

    records = db.rows(sql, tuple(args))
    for r in records:
        expand_assignment(r)
    return jsonify({'addresses': records, 'count': len(records),
                    'limit': limit, 'offset': offset})


@bp.route('/api/addresses/lookup')
def address_lookup():
    """Resolve a single address to everything known about it: its network,
    VLAN, assignment, DNS name, DHCP pool membership and last ping result.
    The one call an external tool needs to answer "what is 10.0.0.42?"."""
    addr = netutil.parse_ip(request.args.get('address'))
    if addr is None:
        return err('Invalid or missing address')
    addr_hex = netutil.hexify(int(addr))

    from .networks import network_for, NETWORK_LIST_SQL
    net = network_for(addr_hex, addr.version)
    if net:
        net = db.row(NETWORK_LIST_SQL + ' WHERE networks.id=?', (net['id'],))

    rec = db.row(ADDRESS_LIST_SQL + ' WHERE ip_addresses.address=?', (str(addr),))
    if rec:
        expand_assignment(rec)

    # Version + hex, across every network: with nested prefixes the covering
    # pool may be declared on a parent or a child of this address's own
    # network, and either way it applies.
    pool = db.row('SELECT dhcp_ranges.*, dhcp_servers.name AS server_name '
                  'FROM dhcp_ranges '
                  'JOIN networks ON networks.id = dhcp_ranges.network_id '
                  'LEFT JOIN dhcp_servers ON dhcp_servers.id = dhcp_ranges.server_id '
                  'WHERE dhcp_ranges.enabled=1 AND networks.version=? '
                  'AND ? BETWEEN dhcp_ranges.start_hex AND dhcp_ranges.end_hex',
                  (addr.version, addr_hex))

    scan = db.query_one('SELECT * FROM scan_results WHERE address=?', (str(addr),))

    # Other addresses on the same NIC. Not a fault — running several services
    # that each want the same port means giving one interface several
    # addresses — but you want to see them together when planning a change.
    siblings = []
    if rec and rec.get('mac'):
        siblings = db.query(
            'SELECT address, dns_name, status FROM ip_addresses '
            'WHERE mac = ? AND address <> ? ORDER BY addr_hex',
            (rec['mac'], str(addr)))

    if rec:
        state = rec['status']
    elif pool:
        state = 'pool'
    elif scan and scan['alive']:
        state = 'unmanaged'
    else:
        state = 'free'

    return jsonify({'address': str(addr), 'state': state, 'record': rec,
                    'network': net, 'dhcp_range': pool, 'scan': scan,
                    'siblings': siblings,
                    'deploy': netutil.deploy_payload(net, addr) if net else None})


@bp.route('/api/addresses/bulk', methods=['POST'])
def addresses_bulk():
    """Create or update many address records in one transaction.

    Built for importers: a discovery script or a hypervisor sync posts the
    addresses it found and gets back a per-row result instead of having to
    make N requests and reconcile N failures itself.
    """
    data = request.get_json(silent=True) or {}
    items = data.get('addresses')
    if not isinstance(items, list) or not items:
        return err('Expected {"addresses": [ ... ]}')
    if len(items) > 5000:
        return err('Too many records in one call (max 5000)')
    replace = bool(data.get('replace'))  # overwrite existing records

    results = {'created': 0, 'updated': 0, 'skipped': 0, 'errors': []}
    touched = {'created': [], 'updated': []}
    with db.WRITE_LOCK:
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                results['errors'].append({'index': i, 'error': 'not an object'})
                continue
            fields, e = _v_address(item, None)
            if e:
                results['errors'].append({'index': i, 'address': item.get('address'),
                                          'error': e})
                continue
            fields['source'] = str(item.get('source') or data.get('source') or 'import')
            fields['ext_id'] = str(item.get('ext_id') or '')[:128]
            if isinstance(item.get('meta'), dict):
                fields['meta'] = item['meta']
            found = db.query_one('SELECT id FROM ip_addresses WHERE address=?',
                                 (fields['address'],))
            if found and not replace:
                results['skipped'] += 1
                continue
            if found:
                db.update('ip_addresses', found['id'], fields)
                results['updated'] += 1
                touched['updated'].append(fields['address'])
            else:
                db.insert('ip_addresses', fields)
                results['created'] += 1
                touched['created'].append(fields['address'])
        parts = ['%s %s' % (what, db.audit_list(addrs))
                 for what, addrs in touched.items() if addrs]
        if results['skipped']:
            parts.append('%d skipped' % results['skipped'])
        db.audit(actor(), 'bulk-import', 'ip_addresses', None,
                 '; '.join(parts) or 'nothing imported')
    return jsonify({'success': True, **results})
