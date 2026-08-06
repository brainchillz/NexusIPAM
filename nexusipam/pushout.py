"""Push the address plan out to DNS enforcement nodes (DNSMAQ-MGR).

This is the moment IPAM stops being a mirror of DNS and becomes its author:
every address's ordered name list renders into dnsmasq host records (one
record per name — parallel A records by design) and lands on each configured
node via DNSMAQ-MGR's own mirror-receive endpoint. That endpoint re-validates
every record, gates the swap with `dnsmasq --test`, and locks the pushed
section read-only in the receiving UI — deterministic single-writer, no new
machinery on the DNS side.

Pushes go to every node directly (a receiving node deliberately does not
re-push to its own peers), so either DNS node can die without the other going
stale, and IPAM being down never affects service — the nodes serve from local
rendered state.

Targets and the monotonic serial live in the meta table; per-name `ext_id`
preserves the DNS server's original record ids so the first push reproduces
the current zone byte-for-byte (the phase-2 round-trip gate depends on it).
"""
import re
import ssl
import json
import socket
import hashlib
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from flask import Blueprint, jsonify, request

from .core import db
from .core.auth import actor
from .core.runcmd import err
from .core.validators import RE_SLUG, clean_text

bp = Blueprint('pushout', __name__)

TARGETS_KEY = 'push_targets'
SERIAL_KEY = 'push_serial'
SOURCE_NAME = 'nexus-ipam'          # how this IPAM identifies itself to nodes
PUSH_TIMEOUT = 30

# DNSMAQ-MGR record ids (h_xxxxxx) — only ids of this shape survive its
# mirror-receive `_keep_id`; anything else gets a fresh id there.
RE_DNSMAQ_ID = re.compile(r'^[a-z]_[0-9a-f]{6}\Z')
RE_URL = re.compile(r'^https://[A-Za-z0-9.\[\]:_-]+(:\d{1,5})?\Z')
RE_FPR = re.compile(r'^[0-9a-f]{64}\Z')


# ─── Payload ──────────────────────────────────────────────────────────

def build_hosts():
    """The `hosts` section payload: one dnsmasq host record per enabled
    A/AAAA name, addresses in stable (version, hex) order, names in position
    order — position 0 first is what makes the node's PTR answer follow the
    canonical name."""
    rows = db.query(
        'SELECT n.name, n.comment, n.ext_id, a.address, a.version '
        'FROM ip_names n JOIN ip_addresses a ON a.id = n.address_id '
        "WHERE n.enabled=1 AND n.rtype='a' "
        'ORDER BY a.version, a.addr_hex, n.position, n.id')
    records = []
    for r in rows:
        rec = {'name': r['name'], 'comment': r['comment'] or '',
               'enabled': True,
               'a': r['address'] if r['version'] == 4 else '',
               'aaaa': r['address'] if r['version'] == 6 else ''}
        if RE_DNSMAQ_ID.match(r['ext_id'] or ''):
            rec['id'] = r['ext_id']
        records.append(rec)
    return records


# ─── Targets (meta-backed) ────────────────────────────────────────────

def _targets():
    try:
        t = json.loads(db.get_setting(TARGETS_KEY, '[]') or '[]')
        return t if isinstance(t, list) else []
    except ValueError:
        return []


def _save_targets(targets):
    db.set_setting(TARGETS_KEY, json.dumps(targets))


def _public(t):
    out = dict(t)
    out['has_token'] = bool(out.pop('token', ''))
    return out


# ─── Transport ────────────────────────────────────────────────────────

def _check_fingerprint(url, want):
    """TLS pinning without a CA: compare the node cert's SHA-256 (the same
    scheme DNSMAQ-MGR's own peer push uses). Returns error string or None."""
    parts = urlsplit(url)
    host, port = parts.hostname, parts.port or 443
    ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                got = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
    except OSError as e:
        return 'TLS connect failed: %s' % e
    if got != want:
        return 'Certificate fingerprint mismatch (got %s…)' % got[:16]
    return None


def push_target(target, records, serial):
    """One push to one node. Returns (ok, detail)."""
    verify = target.get('verify') or 'insecure'
    if verify.startswith('fingerprint:'):
        e = _check_fingerprint(target['url'], verify.split(':', 1)[1])
        if e:
            return False, e
    payload = {'source': SOURCE_NAME, 'serial': serial,
               'serials': {'hosts': serial}, 'sections': ['hosts'],
               'data': {'hosts': records}}
    req = urllib.request.Request(
        target['url'].rstrip('/') + '/api/mirror/receive',
        data=json.dumps(payload).encode(), method='POST',
        headers={'Content-Type': 'application/json',
                 'Authorization': 'Bearer ' + target.get('token', '')})
    try:
        with urllib.request.urlopen(req, context=ssl._create_unverified_context(),
                                    timeout=PUSH_TIMEOUT) as r:
            body = json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read() or b'{}').get('error', '')
        except ValueError:
            detail = ''
        return False, 'HTTP %d %s' % (e.code, detail)
    except (urllib.error.URLError, OSError, ValueError) as e:
        return False, str(e)
    if not body.get('success'):
        return False, body.get('error') or 'node refused the push'
    return True, 'applied via %s' % body.get('action', '?')


# ─── Routes ───────────────────────────────────────────────────────────

@bp.route('/api/push')
def push_status():
    records = build_hosts()
    return jsonify({'targets': [_public(t) for t in _targets()],
                    'serial': int(db.get_setting(SERIAL_KEY, '0') or 0),
                    'record_count': len(records),
                    'address_count': db.query_one(
                        'SELECT COUNT(DISTINCT address_id) c FROM ip_names '
                        "WHERE enabled=1 AND rtype='a'")['c']})


@bp.route('/api/push/preview')
def push_preview():
    return jsonify({'hosts': build_hosts()})


@bp.route('/api/push/targets', methods=['POST'])
def push_target_save():
    data = request.get_json(silent=True) or {}
    name = str(data.get('name') or '').strip()
    if not RE_SLUG.match(name):
        return err('Invalid target name')
    targets = _targets()
    cur = next((t for t in targets if t['name'] == name), None)
    t = dict(cur or {'name': name, 'token': '', 'enabled': True,
                     'last': None, 'serial': 0})
    if 'url' in data or not cur:
        url = str(data.get('url') or '').strip().rstrip('/')
        if not RE_URL.match(url):
            return err('Invalid URL (https://host[:port])')
        t['url'] = url
    if data.get('token'):                       # omitted = keep stored token
        t['token'] = str(data['token']).strip()
    if not t.get('token'):
        return err('A mirror token is required (generate one on the node: '
                   'Mirroring → receive token)')
    if 'verify' in data:
        v = str(data.get('verify') or 'insecure').strip()
        if v != 'insecure':
            if not v.startswith('fingerprint:') or not RE_FPR.match(v.split(':', 1)[1]):
                return err("verify must be 'insecure' or 'fingerprint:<sha256>'")
        t['verify'] = v
    if 'enabled' in data:
        t['enabled'] = bool(data['enabled'])
    desc, e = clean_text(data.get('description'), 'Description', 200)
    if e:
        return err(e)
    if 'description' in data:
        t['description'] = desc
    if cur:
        targets[targets.index(cur)] = t
    else:
        targets.append(t)
    with db.WRITE_LOCK:
        _save_targets(targets)
        db.audit(actor(), 'push-target', 'push', None,
                 '%s → %s' % (name, t.get('url', '')))
    return jsonify({'success': True, 'target': _public(t)})


@bp.route('/api/push/targets/<name>', methods=['DELETE'])
def push_target_delete(name):
    targets = _targets()
    keep = [t for t in targets if t['name'] != name]
    if len(keep) == len(targets):
        return err('No such target', 404)
    with db.WRITE_LOCK:
        _save_targets(keep)
        db.audit(actor(), 'push-target-delete', 'push', None, name)
    return jsonify({'success': True})


def run_push(only=''):
    """Push the hosts section to every enabled target (or one, by name).
    One serial per run: every node that acks it holds the same zone.
    Returns a result dict, or (None, error) when no target matches — shared
    by the route below and the provision workflow."""
    targets = _targets()
    picked = [t for t in targets
              if (t['name'] == only if only else t.get('enabled', True))]
    if not picked:
        return None, 'No matching push target — configure one first'
    records = build_hosts()
    with db.WRITE_LOCK:
        serial = int(db.get_setting(SERIAL_KEY, '0') or 0) + 1
        db.set_setting(SERIAL_KEY, serial)
    results = []
    for t in picked:
        ok, detail = push_target(t, records, serial)
        t['last'] = {'ts': db.now(), 'ok': ok, 'detail': detail, 'serial': serial}
        if ok:
            t['serial'] = serial
        results.append({'name': t['name'], 'ok': ok, 'detail': detail})
    with db.WRITE_LOCK:
        _save_targets(targets)
        db.audit(actor(), 'push-run', 'push', None,
                 'serial %d, %d record(s) → %s' % (serial, len(records),
                 ', '.join('%s:%s' % (r['name'], 'ok' if r['ok'] else 'FAIL')
                           for r in results)))
    return {'success': all(r['ok'] for r in results),
            'serial': serial, 'records': len(records),
            'results': results}, None


@bp.route('/api/push/run', methods=['POST'])
def push_run():
    out, e = run_push((request.args.get('target') or '').strip())
    if e:
        return err(e)
    return jsonify(out)
