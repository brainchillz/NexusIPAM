"""Provision / deprovision — the one-action DDI workflow.

Provision = pick the next free address in a network, record it with its
name(s), and push DNS to every enforcement node, in one call. Deprovision is
the exact inverse: names gone, address released, nodes updated — the half
that everyone forgets and the reason stale records exist.

This is the endpoint VC-Deployer calls before cloning a VM: the response
carries the same L3 facts as /api/allocate (gateway, prefixlen, dns, domain,
meta.vsphere_portgroup) plus the push outcome, so a deployed machine boots
with working forward and reverse DNS and nothing else to configure.

DHCP reservations join this flow when DHCP moves onto the push path
(integration plan phase 4B); until then the MAC is recorded on the address
and the UCG reservation remains a manual step.
"""
from flask import Blueprint, jsonify, request

from . import netutil
from .core import db
from .core.auth import actor
from .core.runcmd import err, num
from .core.validators import clean_text, norm_mac, valid_fqdn

bp = Blueprint('provision', __name__)


@bp.route('/api/provision', methods=['POST'])
def api_provision():
    """Body: name (fqdn, required) · network_id|network|cidr (required) ·
    aliases[] · mac · assigned_kind/assigned_id · description ·
    push (default true) · verify (ping-check candidate first).
    """
    from .allocate import _resolve_network, free_addresses
    from .addresses import set_names, validate_assignment
    from .networks import network_for

    data = request.get_json(silent=True) or {}
    name = str(data.get('name') or '').strip().rstrip('.')
    if not valid_fqdn(name):
        return err('A valid DNS name is required')
    aliases = data.get('aliases') or []
    if not isinstance(aliases, list):
        return err('aliases must be a list')
    net_row = _resolve_network(data)
    if not net_row:
        return err('Unknown network — pass network_id, a CIDR, or a network name', 404)
    mac = norm_mac(data.get('mac'))
    if mac is None:
        return err('Invalid MAC address')
    desc, e = clean_text(data.get('description'), 'Description')
    if e:
        return err(e)
    kind = str(data.get('assigned_kind') or '').strip().lower()
    assigned_id = num(data.get('assigned_id'))
    if kind:
        e = validate_assignment(kind, assigned_id)
        if e:
            return err(e)
    else:
        assigned_id = None

    # A name that already resolves somewhere else is almost always a mistake —
    # refuse rather than silently creating round-robin.
    clash = db.query_one(
        'SELECT a.address FROM ip_names n JOIN ip_addresses a ON a.id=n.address_id '
        'WHERE n.name=? AND n.enabled=1', (name,))
    if clash:
        return err('Name %s already points at %s — deprovision it first, or '
                   'add an alias there instead' % (name, clash['address']), 409)

    with db.WRITE_LOCK:
        addrs, verified = free_addresses(net_row, limit=1,
                                         verify=bool(data.get('verify')))
        if not addrs:
            return err('No free addresses in %s' % net_row['cidr'], 409)
        addr = addrs[0]
        addr_hex = netutil.hexify(int(addr))
        owner = network_for(addr_hex, net_row['version'])
        rid = db.insert('ip_addresses', {
            'address': str(addr), 'version': net_row['version'],
            'addr_hex': addr_hex,
            'network_id': owner['id'] if owner else net_row['id'],
            'status': 'active', 'assigned_kind': kind, 'assigned_id': assigned_id,
            'mac': mac, 'dns_name': name, 'description': desc,
            'source': str(data.get('source') or 'manual').strip() or 'manual',
            'ext_id': str(data.get('ext_id') or '')[:128]})
        names, e = set_names(rid, [name] + aliases)
        if e:                       # bad alias — roll the allocation back whole
            db.delete('ip_addresses', rid)
            return err(e)
        db.audit(actor(), 'provision', 'ip_addresses', rid,
                 '%s = %s in %s' % (name, addr, net_row['cidr']))

    push = None
    if data.get('push', True):
        from .pushout import run_push
        push, _ = run_push()        # no targets configured -> None, fine

    return jsonify({'success': True, 'id': rid, 'address': str(addr),
                    'names': names, 'verified': verified, 'push': push,
                    **netutil.deploy_payload(net_row, addr)})


@bp.route('/api/deprovision', methods=['POST'])
def api_deprovision():
    """Body: name | address | id (any one) · keep (retain as deprecated) ·
    push (default true). Removes the names, releases the address, updates
    every DNS node."""
    data = request.get_json(silent=True) or {}
    rec = None
    if data.get('id'):
        rec = db.row('SELECT * FROM ip_addresses WHERE id=?', (num(data['id']),))
    elif data.get('address'):
        addr = netutil.parse_ip(data['address'])
        if addr is None:
            return err('Invalid address')
        rec = db.row('SELECT * FROM ip_addresses WHERE address=?', (str(addr),))
    elif data.get('name'):
        name = str(data['name']).strip().rstrip('.')
        hit = db.query_one('SELECT address_id FROM ip_names WHERE name=?', (name,))
        if hit:
            rec = db.row('SELECT * FROM ip_addresses WHERE id=?', (hit['address_id'],))
    if not rec:
        return err('No matching address record', 404)

    with db.WRITE_LOCK:
        if data.get('keep'):
            # Out of rotation but remembered: drop the names (CASCADE), keep
            # the row so the address is not re-allocated for a while.
            db.execute('DELETE FROM ip_names WHERE address_id=?', (rec['id'],))
            db.update('ip_addresses', rec['id'],
                      {'status': 'deprecated', 'dns_name': '',
                       'assigned_kind': '', 'assigned_id': None})
            action = 'deprecated'
        else:
            db.delete('ip_addresses', rec['id'])
            action = 'released'
        db.audit(actor(), 'deprovision', 'ip_addresses', rec['id'],
                 '%s (%s) %s' % (rec['address'], rec.get('dns_name') or '-', action))

    push = None
    if data.get('push', True):
        from .pushout import run_push
        push, _ = run_push()

    return jsonify({'success': True, 'address': rec['address'],
                    'action': action, 'push': push})
