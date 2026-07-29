"""IP address maths: normalization, prefix containment, free/used accounting.

Everything the app knows about "is this address free" comes from here. The
padded-hex representation (see core/db) is produced by hexify(); it is what
makes containment an indexed BETWEEN instead of a Python loop.
"""
import ipaddress

from .core.config import MAX_ENUMERATE

HEX_WIDTH = 32  # wide enough for IPv6; IPv4 is padded to the same width


def hexify(value):
    """Integer (or address) -> zero-padded 32-char lowercase hex.

    Padding to a fixed width is what makes string comparison equal numeric
    comparison, so SQLite can answer range questions off a plain index.
    """
    return format(int(value), '032x')


def parse_ip(text):
    """Return an ip_address, or None. Rejects anything with a prefix, and any
    IPv6 scope-id (`fe80::1%zone`): CPython's ipaddress accepts newlines, `=`,
    `,` and spaces inside a scope-id, and a stored value with an embedded
    newline would smuggle an extra line into the rendered dnsmasq exports."""
    s = str(text).strip()
    if '%' in s:
        return None
    try:
        return ipaddress.ip_address(s)
    except (ValueError, TypeError):
        return None


def parse_network(text, strict=False):
    """Return an ip_network, or None. strict=False so 10.0.0.5/24 is accepted
    and normalized to 10.0.0.0/24 (what people actually type)."""
    s = str(text).strip()
    if '%' in s:                      # no scope-ids in a network literal
        return None
    try:
        return ipaddress.ip_network(s, strict=strict)
    except (ValueError, TypeError):
        return None


def net_bounds(net):
    """(start_hex, end_hex) covering every address in the prefix, inclusive."""
    return hexify(int(net.network_address)), hexify(int(net.broadcast_address))


def netmask(net):
    return str(net.netmask) if net.version == 4 else ''


def usable_bounds(net):
    """(first, last) usable host addresses as ints.

    IPv4 drops the network and broadcast addresses, except:
      * /31 — RFC 3021 point-to-point, both addresses usable;
      * /32 — a single host route, the one address is usable.
    IPv6 has no broadcast; every address in the prefix is treated as usable
    (the subnet-router anycast at ::0 is left assignable on purpose — home
    labs routinely put the gateway there).
    """
    first, last = int(net.network_address), int(net.broadcast_address)
    if net.version == 4 and net.prefixlen <= 30:
        return first + 1, last - 1
    return first, last


def capacity(net):
    """Count of usable host addresses in the prefix."""
    first, last = usable_bounds(net)
    return max(0, last - first + 1)


def enumerable(net):
    """True when the prefix is small enough to list address-by-address.
    Beyond this the UI shows counts only — nobody reads 16M rows."""
    return capacity(net) <= MAX_ENUMERATE


def iter_usable(net, start_at=None):
    """Yield usable addresses in ascending order, optionally resuming from an
    integer offset. A generator, so 'next free in a /8' costs one step."""
    first, last = usable_bounds(net)
    cur = max(first, int(start_at)) if start_at is not None else first
    cls = ipaddress.IPv4Address if net.version == 4 else ipaddress.IPv6Address
    while cur <= last:
        yield cls(cur)
        cur += 1


def overlaps(a, b):
    """Do two prefixes share any address? Two CIDR blocks either nest or are
    disjoint, so a mutual subnet_of test is exhaustive."""
    if a.version != b.version:
        return False
    return a.subnet_of(b) or b.subnet_of(a)


def in_range(addr_hex, start_hex, end_hex):
    return start_hex <= addr_hex <= end_hex


def range_bounds(start, end):
    """Validate and hexify an arbitrary start/end address pair (DHCP ranges).
    Returns (start_hex, end_hex, error)."""
    a, b = parse_ip(start), parse_ip(end)
    if a is None or b is None:
        return None, None, 'Start and end must both be valid IP addresses'
    if a.version != b.version:
        return None, None, 'Start and end must be the same IP version'
    if int(b) < int(a):
        return None, None, 'Range end is before its start'
    return hexify(int(a)), hexify(int(b)), None


def range_size(start_hex, end_hex):
    return int(end_hex, 16) - int(start_hex, 16) + 1


def prefix_from_parts(address, prefixlen):
    """Build a normalized CIDR from an address plus a prefix length."""
    if '%' in str(address):          # no IPv6 scope-ids (same guard as parse_ip)
        return None
    try:
        return str(ipaddress.ip_network('%s/%s' % (address, prefixlen), strict=False))
    except (ValueError, TypeError):
        return None


def split_list(text):
    """Comma/space separated field -> clean list (dns_servers, zones)."""
    if not text:
        return []
    parts = str(text).replace(',', ' ').split()
    return [p for p in (s.strip() for s in parts) if p]


def deploy_payload(net_row, address=None):
    """The network's L3 facts in the shape an automated deployer wants.

    VC-Deployer's DeploySpec takes ip / cidr(prefixlen) / gateway / dns /
    network(portgroup); this returns exactly that, so a deploy tool can hand
    the result straight to its own model. `meta` carries hypervisor-specific
    placement (portgroup, datastore) that IPAM stores but never interprets.
    """
    net = parse_network(net_row['cidr'])
    meta = net_row.get('meta') or {}
    if isinstance(meta, str):
        meta = {}
    payload = {
        'cidr': net_row['cidr'],
        'prefixlen': net.prefixlen if net else None,
        'netmask': netmask(net) if net else '',
        'gateway': net_row.get('gateway') or '',
        'dns': split_list(net_row.get('dns_servers')),
        'domain': net_row.get('domain') or '',
        'vlan': net_row.get('vlan_vid'),
        'network_id': net_row.get('id'),
        'meta': meta,
    }
    if address is not None:
        payload['ip'] = str(address)
    return payload
