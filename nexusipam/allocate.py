"""Free-address discovery and atomic allocation.

This is the module an automated deployer actually cares about. `POST
/api/allocate` answers "give me an address in this network, and hold it for
this VM" in one round trip, under a lock, so two concurrent deploys can never
be handed the same IP.

An address is considered NOT free when any of these is true:
  * a record exists for it (any status — including `reserved` and
    `deprecated`, which exist precisely to keep an address out of rotation);
  * it falls inside an enabled DHCP range (the DHCP server owns that span);
  * it is the network's declared gateway;
  * `verify=1` and it answers a ping.
"""
from flask import Blueprint, jsonify, request

from . import netutil
from .core import db
from .core.auth import actor
from .core.runcmd import err, num
from .core.validators import IP_STATUSES, clean_text, one_of, valid_fqdn, norm_mac

bp = Blueprint('allocate', __name__)

# Never enumerate more than this many candidates looking for free space,
# regardless of prefix size — a full /8 sweep would take minutes.
SEARCH_LIMIT = 200_000


def _blocked_sets(net_row):
    """(recorded_hex_set, pool_spans, gateway_hex_set) for a network.

    Pools and gateways come from EVERY network that overlaps this prefix, not
    just this row: allocating from a /16 must respect a pool declared on a
    /24 inside it, and the /24's own gateway, or two systems end up owning
    the same address.
    """
    from .networks import overlapping_ranges
    lo, hi = net_row['net_start'], net_row['net_end']
    recorded = {r['addr_hex'] for r in db.query(
        'SELECT addr_hex FROM ip_addresses WHERE version=? AND addr_hex BETWEEN ? AND ?',
        (net_row['version'], lo, hi))}
    pools = [(r['start_hex'], r['end_hex'])
             for r in overlapping_ranges(net_row['version'], lo, hi)]
    gw_hexes = set()
    for g in db.query("SELECT gateway FROM networks WHERE version=? AND gateway <> ''",
                      (net_row['version'],)):
        ip = netutil.parse_ip(g['gateway'])
        if ip is not None:
            h = netutil.hexify(int(ip))
            if lo <= h <= hi:
                gw_hexes.add(h)
    return recorded, pools, gw_hexes


def free_addresses(net_row, limit=1, verify=False, skip=()):
    """Return (addresses, verified) — the first `limit` free addresses.

    `verify` pings each candidate and discards responders; a machine that
    answers but has no record is exactly the silent-conflict case an IPAM is
    supposed to catch, so it is also written to scan_results where the UI
    will surface it as "unmanaged".

    Verification works in batches and KEEPS SEARCHING until the request is
    satisfied or the prefix is exhausted. The earlier version probed one
    fixed batch of candidates and gave up — on a subnet with a run of
    unrecorded-but-alive squatters it reported "no free addresses" while
    plenty existed further along.
    """
    net = netutil.parse_network(net_row['cidr'])
    if net is None:
        return [], False
    recorded, pools, gw_hexes = _blocked_sets(net_row)
    skip = set(skip)

    candidates = netutil.iter_usable(net)
    found, examined, verified = [], 0, False
    batch_size = max(limit * 2, limit + 8) if verify else limit

    while len(found) < limit and examined <= SEARCH_LIMIT:
        batch = []
        for addr in candidates:
            examined += 1
            if examined > SEARCH_LIMIT:
                break
            h = netutil.hexify(int(addr))
            if h in recorded or h in gw_hexes or str(addr) in skip:
                continue
            if any(s <= h <= e for s, e in pools):
                continue
            batch.append(addr)
            if len(batch) >= (batch_size if verify else limit - len(found)):
                break
        if not batch:
            break  # prefix exhausted
        if verify:
            from .scan import probe_many, record_results
            results = probe_many([str(a) for a in batch])
            record_results(results)
            verified = True
            found.extend(a for a in batch
                         if not results.get(str(a), {}).get('alive'))
        else:
            found.extend(batch)

    return found[:limit], verified


# ─── Allocation API ───────────────────────────────────────────────────

def _resolve_network(data):
    """Accept network_id, cidr, or the name of a network — deployers tend to
    know a friendly name ('lab-servers') rather than an internal id."""
    from .networks import NETWORK_LIST_SQL
    nid = num(data.get('network_id'))
    if nid is not None:
        return db.row(NETWORK_LIST_SQL + ' WHERE networks.id=?', (nid,))
    cidr = str(data.get('network') or data.get('cidr') or '').strip()
    if not cidr:
        return None
    net = netutil.parse_network(cidr)
    if net is not None:
        return db.row(NETWORK_LIST_SQL + ' WHERE networks.cidr=?', (str(net),))
    return db.row(NETWORK_LIST_SQL + ' WHERE networks.name=?', (cidr,))


@bp.route('/api/allocate', methods=['POST'])
def api_allocate():
    """Allocate the next free address in a network and record it.

    Body:
      network_id | network | cidr   — which network (required)
      assigned_kind / assigned_id   — what to attach it to (optional)
      dns_name, if_name, mac, description, status, meta, source, ext_id
      verify (bool)                 — ping-check the candidate first
      count (int)                   — allocate several at once
      dry_run (bool)                — return what WOULD be allocated, write nothing

    Returns the allocation plus the network's L3 facts (gateway, prefixlen,
    dns, domain, meta) in the shape VC-Deployer's DeploySpec expects, so a
    caller needs exactly one request before it can clone a VM.
    """
    data = request.get_json(silent=True) or {}
    net_row = _resolve_network(data)
    if not net_row:
        return err('Unknown network — pass network_id, a CIDR, or a network name', 404)

    count = max(1, min(num(data.get('count')) or 1, 256))
    verify = bool(data.get('verify'))
    dry_run = bool(data.get('dry_run'))

    status, e = one_of(data.get('status'), IP_STATUSES, 'Status', 'active')
    if e:
        return err(e)
    dns_name = str(data.get('dns_name') or '').strip()
    if dns_name and not valid_fqdn(dns_name):
        return err('Invalid dns_name')
    mac = norm_mac(data.get('mac'))
    if mac is None:
        return err('Invalid MAC address')
    if_name, e = clean_text(data.get('if_name'), 'Interface', 32)
    if e:
        return err(e)
    desc, e = clean_text(data.get('description'), 'Description')
    if e:
        return err(e)

    kind = str(data.get('assigned_kind') or '').strip().lower()
    assigned_id = num(data.get('assigned_id'))
    if kind:
        from .addresses import validate_assignment
        e = validate_assignment(kind, assigned_id)
        if e:
            return err(e)
    else:
        assigned_id = None

    meta = data.get('meta') if isinstance(data.get('meta'), dict) else {}
    source = str(data.get('source') or 'manual').strip()
    ext_id = str(data.get('ext_id') or '').strip()[:128]

    # The lock is what makes this safe under concurrent deploys: find-and-claim
    # must be one indivisible step or two callers race onto the same address.
    with db.WRITE_LOCK:
        addrs, verified = free_addresses(net_row, limit=count, verify=verify)
        if len(addrs) < count:
            return err('Only %d free address(es) available in %s%s'
                       % (len(addrs), net_row['cidr'],
                          ' after ping verification' if verify else ''), 409)
        if dry_run:
            return jsonify({'success': True, 'dry_run': True, 'verified': verified,
                            'addresses': [str(a) for a in addrs],
                            **netutil.deploy_payload(net_row, addrs[0])})

        created = []
        from .networks import network_for
        for addr in addrs:
            # File under the most-specific containing network, which may be a
            # child of the one allocation was requested from.
            addr_hex = netutil.hexify(int(addr))
            owner = network_for(addr_hex, net_row['version'])
            rid = db.insert('ip_addresses', {
                'address': str(addr), 'version': net_row['version'],
                'addr_hex': addr_hex,
                'network_id': owner['id'] if owner else net_row['id'],
                'status': status, 'assigned_kind': kind, 'assigned_id': assigned_id,
                'if_name': if_name, 'mac': mac, 'is_primary': 1 if data.get('is_primary') else 0,
                'dns_name': dns_name, 'description': desc,
                'source': source, 'ext_id': ext_id, 'meta': meta})
            created.append(db.row('SELECT * FROM ip_addresses WHERE id=?', (rid,)))
            db.audit(actor(), 'allocate', 'ip_addresses', rid,
                     '%s in %s' % (addr, net_row['cidr']))

    payload = netutil.deploy_payload(net_row, addrs[0])
    return jsonify({'success': True, 'verified': verified,
                    'addresses': [str(a) for a in addrs],
                    'records': created, **payload})


@bp.route('/api/release', methods=['POST'])
def api_release():
    """Release an allocation — the teardown half of the deployer contract.

    Accepts `address`, `id`, or (`source`, `ext_id`). By default the record is
    deleted; pass `keep=1` to retain it marked `deprecated` instead, which is
    what you want when an address must stay out of rotation for a while.
    """
    data = request.get_json(silent=True) or {}
    rec = None
    if data.get('id'):
        rec = db.row('SELECT * FROM ip_addresses WHERE id=?', (num(data['id']),))
    elif data.get('address'):
        addr = netutil.parse_ip(data['address'])
        if addr is None:
            return err('Invalid address')
        rec = db.row('SELECT * FROM ip_addresses WHERE address=?', (str(addr),))
    elif data.get('ext_id'):
        rec = db.row('SELECT * FROM ip_addresses WHERE source=? AND ext_id=?',
                     (str(data.get('source') or 'manual'), str(data['ext_id'])))
    if not rec:
        return err('No matching address record', 404)

    with db.WRITE_LOCK:
        if data.get('keep'):
            db.update('ip_addresses', rec['id'],
                      {'status': 'deprecated', 'assigned_kind': '', 'assigned_id': None})
            action = 'deprecated'
        else:
            db.delete('ip_addresses', rec['id'])
            action = 'released'
        db.audit(actor(), action, 'ip_addresses', rec['id'], rec['address'])
    return jsonify({'success': True, 'address': rec['address'], 'action': action})


@bp.route('/api/next-free')
def api_next_free():
    """Read-only peek at what would be allocated. Safe for a readonly token —
    it reserves nothing."""
    net_row = _resolve_network(request.args)
    if not net_row:
        return err('Unknown network — pass network_id, cidr, or network', 404)
    count = max(1, min(num(request.args.get('count')) or 1, 256))
    verify = request.args.get('verify') in ('1', 'true', 'yes')
    addrs, verified = free_addresses(net_row, limit=count, verify=verify)
    return jsonify({'network': net_row['cidr'], 'count': len(addrs), 'verified': verified,
                    'addresses': [str(a) for a in addrs],
                    **netutil.deploy_payload(net_row, addrs[0] if addrs else None)})
