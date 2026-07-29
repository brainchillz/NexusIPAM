"""DHCP and DNS servers, and the DHCP ranges that consume address space.

A DHCP range is modelled generically — start/end inside a network, optionally
attributed to a server — rather than in any one server's config dialect. That
is deliberate: the point is to account for the addresses a pool consumes no
matter what hands them out (dnsmasq, ISC, Kea, a UniFi gateway, a Windows
server). `url` on a server row is where its own manager lives, which is how a
DNSMAQ-MGR instance gets linked from here.
"""
from flask import Blueprint, jsonify

from . import netutil
from .core import db
from .core.runcmd import num
from .core.validators import (DHCP_KINDS, DNS_KINDS, DNS_ROLES, RE_LEASE, RE_NAME,
                              RE_URL, STATUSES, clean_text, is_ip, one_of, valid_fqdn)
from .resource import Resource, register, mount

bp = Blueprint('services', __name__)

HOST_KINDS = {'', 'device', 'vm', 'container'}


def _server_common(data):
    name = str(data.get('name') or '').strip()
    if not RE_NAME.match(name):
        return None, 'Invalid name'
    status, e = one_of(data.get('status'), STATUSES, 'Status', 'active')
    if e:
        return None, e
    address = str(data.get('address') or '').strip()
    if address and not is_ip(address):
        return None, 'Service address must be an IP address'
    url = str(data.get('url') or '').strip()
    if url and not RE_URL.match(url):
        return None, 'Management URL must be an http(s) URL'
    host_kind, e = one_of(data.get('host_kind'), HOST_KINDS, 'Host kind', '')
    if e:
        return None, e
    host_id = num(data.get('host_id'))
    if host_kind:
        from .addresses import KIND_TABLES
        if host_id is None:
            return None, 'A host id is required when a host kind is set'
        if not db.query_one('SELECT id FROM %s WHERE id=?' % KIND_TABLES[host_kind],
                            (host_id,)):
            return None, 'No such %s' % host_kind
    else:
        host_id = None
    desc, e = clean_text(data.get('description'), 'Description')
    if e:
        return None, e
    return {'name': name, 'status': status, 'address': address, 'url': url,
            'host_kind': host_kind, 'host_id': host_id, 'description': desc}, None


def _v_dhcp_server(data, existing):
    fields, e = _server_common(data)
    if e:
        return None, e
    kind, e = one_of(data.get('kind'), DHCP_KINDS, 'Kind', 'dnsmasq')
    if e:
        return None, e
    fields['kind'] = kind
    return fields, None


def _v_dns_server(data, existing):
    fields, e = _server_common(data)
    if e:
        return None, e
    kind, e = one_of(data.get('kind'), DNS_KINDS, 'Kind', 'dnsmasq')
    if e:
        return None, e
    role, e = one_of(data.get('role'), DNS_ROLES, 'Role', 'recursive')
    if e:
        return None, e
    zones = netutil.split_list(data.get('zones'))
    for z in zones:
        if not valid_fqdn(z):
            return None, 'Zone "%s" is not a valid domain' % z
    fields.update({'kind': kind, 'role': role, 'zones': ', '.join(zones)})
    return fields, None


def _v_dhcp_range(data, existing):
    network_id = num(data.get('network_id'))
    net_row = db.query_one('SELECT * FROM networks WHERE id=?', (network_id,)) \
        if network_id is not None else None
    if not net_row:
        return None, 'A valid network_id is required'

    start_hex, end_hex, e = netutil.range_bounds(data.get('start_addr'), data.get('end_addr'))
    if e:
        return None, e
    # Version first: hex bounds are version-blind, and a small IPv6 range's
    # integer value can land inside a v4 network's hex span.
    if netutil.parse_ip(data.get('start_addr')).version != net_row['version']:
        return None, 'The range must be IPv%d addresses (like %s)' \
            % (net_row['version'], net_row['cidr'])
    if not (net_row['net_start'] <= start_hex and end_hex <= net_row['net_end']):
        return None, 'The range must fall entirely inside %s' % net_row['cidr']

    # Two pools handing out the same address is a guaranteed conflict, so it
    # is rejected rather than merely flagged.
    skip = existing['id'] if existing else -1
    for other in db.query('SELECT id, start_hex, end_hex, name FROM dhcp_ranges '
                          'WHERE network_id=? AND id<>?', (network_id, skip)):
        if start_hex <= other['end_hex'] and other['start_hex'] <= end_hex:
            return None, 'This range overlaps an existing range%s in the same network' % (
                ' ("%s")' % other['name'] if other['name'] else '')

    server_id = num(data.get('server_id'))
    if server_id is not None and not db.query_one('SELECT id FROM dhcp_servers WHERE id=?',
                                                  (server_id,)):
        return None, 'No such DHCP server'

    lease = str(data.get('lease_time') or '12h').strip()
    if not RE_LEASE.match(lease):
        return None, 'Invalid lease time (e.g. 12h, 90m, infinite)'

    name, e = clean_text(data.get('name'), 'Name', 64)
    if e:
        return None, e
    desc, e = clean_text(data.get('description'), 'Description')
    if e:
        return None, e

    start = str(netutil.parse_ip(data.get('start_addr')))
    end = str(netutil.parse_ip(data.get('end_addr')))
    return {'network_id': network_id, 'server_id': server_id, 'name': name,
            'start_addr': start, 'end_addr': end, 'start_hex': start_hex,
            'end_hex': end_hex, 'lease_time': lease,
            # Truthiness, not `is False`: a stored/echoed 0 must stay 0. With
            # the old identity check, updating a disabled range re-enabled it.
            'enabled': 1 if data.get('enabled', True) else 0,
            'description': desc}, None


DHCP_SERVER_SQL = """
SELECT dhcp_servers.*,
       (SELECT COUNT(*) FROM dhcp_ranges WHERE dhcp_ranges.server_id = dhcp_servers.id)
         AS range_count
FROM dhcp_servers
"""

DHCP_RANGE_SQL = """
SELECT dhcp_ranges.*, networks.cidr AS network_cidr, networks.name AS network_name,
       networks.version AS network_version,
       dhcp_servers.name AS server_name
FROM dhcp_ranges
LEFT JOIN networks ON networks.id = dhcp_ranges.network_id
LEFT JOIN dhcp_servers ON dhcp_servers.id = dhcp_ranges.server_id
"""

register(Resource('dhcp_servers', 'dhcp_servers', _v_dhcp_server, list_sql=DHCP_SERVER_SQL,
                  get_sql=DHCP_SERVER_SQL + ' WHERE dhcp_servers.id=?',
                  order='dhcp_servers.name'))
register(Resource('dns_servers', 'dns_servers', _v_dns_server, order='name'))
register(Resource('dhcp_ranges', 'dhcp_ranges', _v_dhcp_range, list_sql=DHCP_RANGE_SQL,
                  get_sql=DHCP_RANGE_SQL + ' WHERE dhcp_ranges.id=?',
                  order='dhcp_ranges.start_hex', label='start_addr'))

mount(bp, 'dhcp_servers', '/api/dhcp/servers')
mount(bp, 'dns_servers', '/api/dns/servers')
mount(bp, 'dhcp_ranges', '/api/dhcp/ranges')


@bp.route('/api/dhcp/overview')
def dhcp_overview():
    """Every pool with its size and how much of it is already pinned down by
    static records — the "consumed IPs" picture across all DHCP servers."""
    ranges = db.rows(DHCP_RANGE_SQL + ' ORDER BY dhcp_ranges.start_hex')
    for r in ranges:
        size = netutil.range_size(r['start_hex'], r['end_hex'])
        static = db.query_one(
            'SELECT COUNT(*) c FROM ip_addresses WHERE version=? '
            'AND addr_hex BETWEEN ? AND ?',
            (r['network_version'], r['start_hex'], r['end_hex']))['c']
        r['size'] = size
        r['static_inside'] = static
        r['pct_static'] = round(static / size * 100, 1) if size else 0
    servers = db.rows(DHCP_SERVER_SQL + ' ORDER BY dhcp_servers.name')
    return jsonify({'servers': servers, 'ranges': ranges,
                    'total_pool_addresses': sum(r['size'] for r in ranges if r['enabled'])})


@bp.route('/api/dns/overview')
def dns_overview():
    servers = db.rows('SELECT * FROM dns_servers ORDER BY name')
    for s in servers:
        s['zone_list'] = netutil.split_list(s.get('zones'))
    named = db.query_one("SELECT COUNT(*) c FROM ip_addresses WHERE dns_name <> ''")['c']
    return jsonify({'servers': servers, 'named_addresses': named})
