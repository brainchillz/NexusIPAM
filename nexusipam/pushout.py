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

from . import netutil
from .core import db
from .core.auth import actor
from .core.runcmd import err
from .core.validators import RE_SLUG, clean_text

bp = Blueprint('pushout', __name__)

TARGETS_KEY = 'push_targets'
SERIAL_KEY = 'push_serial'          # legacy scalar; per-section counters below
SERIALS_KEY = 'push_serials'
SOURCE_NAME = 'nexus-ipam'          # how this IPAM identifies itself to nodes
PUSH_TIMEOUT = 30

# Two kinds of target:
#   'dnsmaq' — a DNSMAQ-MGR node, which receives the mirror payload on its own
#     API and locks each pushed section read-only.
#   'unifi'  — a UniFi Cloud Gateway, which has no mirror endpoint: its state
#     is reconciled object by object by the unifi adapter. Push-only; there is
#     nothing to lock, so the gateway's UI stays editable and drift is possible.
# Reaching the gateway directly (rather than via a DNSMAQ-MGR node re-pushing
# downstream) is the same rule already applied to ns1/ns2: every target is
# pushed independently, so no target's freshness depends on another being up.
KINDS = ('dnsmaq', 'unifi')

# Which sections each kind can carry. A UniFi gateway serves both DNS and
# DHCP and its API exposes both (rest/networkconf holds the dhcpd_* scope
# options, rest/user the fixed reservations) — the earlier hosts-only limit
# was inherited from DNSMAQ-MGR's adapter, where it described that adapter's
# scope rather than anything about UniFi.
KIND_SECTIONS = {
    'dnsmaq': ('hosts', 'dhcp'),
    'unifi': ('hosts', 'dhcp'),
}

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


def _tag_for(net, used):
    """A dnsmasq tag naming this network's scope. Tags are what tie options to
    a range, so the only hard requirement is that they are unique and
    consistent WITHIN one payload — ranges and their options are always
    rendered together, so a tag changing between pushes is harmless."""
    base = re.sub(r'[^A-Za-z0-9_-]', '-', (net.get('name') or '').strip().lower())
    base = base.strip('-')[:32] or 'net%d' % net['id']
    tag = base
    if tag in used:                       # two networks named the same
        tag = ('%s-%d' % (base[:26], net['id']))[:32]
    used.add(tag)
    return tag


def build_dhcp():
    """The `dhcp` section payload: scopes, the options each hands out, and
    reservations — in DNSMAQ-MGR's own store shapes, exactly as build_hosts()
    emits its host records. Adapters for other servers translate from here.

    Options come from two places on purpose. Router, DNS and domain are read
    off the network row (they are the address plan's own L3 facts, and are
    refused as dhcp_options rows precisely so there is one copy); everything
    else — NTP, PXE, WPAD, arbitrary codes — comes from dhcp_options.
    """
    nets = {n['id']: n for n in db.query('SELECT * FROM networks')}
    rows = db.query('SELECT * FROM dhcp_ranges ORDER BY start_hex, id')
    opt_rows = db.query('SELECT * FROM dhcp_options WHERE enabled=1 '
                        'ORDER BY network_id, option')
    by_net = {}
    for o in opt_rows:
        by_net.setdefault(o['network_id'], []).append(o)

    ranges, options, used, tagged = [], [], set(), {}
    for r in rows:
        net = nets.get(r['network_id'])
        if not net or net['version'] != 4:
            continue                      # dnsmasq static DHCP here is IPv4
        prefix = netutil.parse_network(net['cidr'])
        if prefix is None:
            continue
        if net['id'] not in tagged:
            tagged[net['id']] = _tag_for(net, used)
        tag = tagged[net['id']]
        ranges.append({'start': r['start_addr'], 'end': r['end_addr'],
                       'netmask': str(prefix.netmask),
                       'lease': r['lease_time'] or '12h',
                       'tag': tag, 'enabled': bool(r['enabled']),
                       'comment': r['name'] or r['description'] or ''})

    for nid, tag in tagged.items():
        net = nets[nid]
        # dnsmasq answers option 3 with ITSELF unless told otherwise, and the
        # DHCP server is very often not the gateway. Always state it.
        if net.get('gateway'):
            options.append({'tag': tag, 'option': 'option:router',
                            'value': net['gateway']})
        dns = netutil.split_list(net.get('dns_servers'))
        if not dns and net.get('gateway'):
            # No DNS recorded: hand out the gateway, which is what a gateway-
            # served scope does today. Silently letting dnsmasq answer with
            # itself would repoint every client on the segment.
            dns = [net['gateway']]
        if dns:
            options.append({'tag': tag, 'option': 'option:dns-server',
                            'value': ','.join(dns)})
        if net.get('domain'):
            options.append({'tag': tag, 'option': 'option:domain-name',
                            'value': net['domain']})
        for o in by_net.get(nid, []):
            options.append({'tag': tag, 'option': o['option'], 'value': o['value']})

    # Same rule as the long-standing static-lease export: a reservation needs
    # a MAC to mean anything, and dnsmasq's dhcp-host is IPv4 here.
    leases = []
    for rec in db.query(
            "SELECT address, dns_name, mac FROM ip_addresses "
            "WHERE mac <> '' AND version = 4 AND status IN ('active','reserved') "
            "ORDER BY addr_hex"):
        leases.append({'mac': rec['mac'], 'ip': rec['address'],
                       'hostname': rec['dns_name'].split('.')[0] if rec['dns_name'] else ''})

    return {'ranges': ranges, 'static_leases': leases, 'options': options}


# A section exists once something can render it. Declaring the name before the
# renderer lands would let a target subscribe to a section that silently
# pushes nothing, so the registry IS the list of valid sections.
SECTION_BUILDERS = {'hosts': build_hosts, 'dhcp': build_dhcp}


def section_size(payload):
    """How many records a section carries. `hosts` is a flat list; `dhcp` is
    several lists under one object, and reporting "3" for its three keys would
    be worse than useless in a push summary."""
    if isinstance(payload, dict):
        return sum(len(v) for v in payload.values() if isinstance(v, list))
    return len(payload)


def sections_available():
    return tuple(SECTION_BUILDERS)


def sections_for(target):
    """What this target should actually receive: what it subscribed to, kept
    to what its kind can carry and what we can render today. Targets stored
    before sections existed carry none, and mean 'hosts' — that is what they
    were created to do."""
    subs = target.get('sections') or ['hosts']
    kind = target.get('kind') or 'dnsmaq'
    allowed = KIND_SECTIONS.get(kind, ('hosts',))
    return [s for s in subs if s in allowed and s in SECTION_BUILDERS]


def build_sections(names):
    return {s: SECTION_BUILDERS[s]() for s in names if s in SECTION_BUILDERS}


# ─── Serials ──────────────────────────────────────────────────────────
# One counter PER SECTION. A single global counter was fine while `hosts` was
# the only section, but the moment there are two, a dhcp-only change bumps the
# number `hosts` is judged by and "is this node current?" stops being
# answerable. The scalar `serial` is still sent, as the max, because
# DNSMAQ-MGR's receiver accepts both shapes.

def _serials():
    try:
        s = json.loads(db.get_setting(SERIALS_KEY, '{}') or '{}')
        return s if isinstance(s, dict) else {}
    except ValueError:
        return {}


def _bump_serials(names):
    """Advance the counter for each named section; returns {section: serial}."""
    with db.WRITE_LOCK:
        cur = _serials()
        if not cur:
            # First run after the upgrade: carry the old global counter forward
            # so serials never appear to go backwards to a node that already
            # holds a higher one (it would reject the push as stale).
            legacy = int(db.get_setting(SERIAL_KEY, '0') or 0)
            cur = {s: legacy for s in sections_available()}
        for s in names:
            cur[s] = int(cur.get(s, 0)) + 1
        db.set_setting(SERIALS_KEY, json.dumps(cur))
        db.set_setting(SERIAL_KEY, max(cur.values()) if cur else 0)
    return {s: cur[s] for s in names}


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
    """Target as the UI sees it — every secret reduced to a boolean."""
    out = dict(t)
    out.setdefault('kind', 'dnsmaq')
    out['sections'] = sections_for(t)
    out['has_token'] = bool(out.pop('token', ''))
    out['has_password'] = bool(out.pop('unifi_password', ''))
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


def _push_unifi(target, data):
    """Reconcile a gateway's state against ours, section by section.
    Returns (ok, detail).

    Unlike a mirror push — one request, applied or refused whole — this is
    list/diff/N-writes, so individual records can fail while the rest land.
    The summary is reported rather than flattened to ok/failed: "2 conflicts,
    client DNS holds x at y" is the kind of thing an operator has to see to
    act on.
    """
    from . import unifi
    peer = dict(target)
    # A target saved before `verify` existed has no key at all, and the
    # adapter's own default is 'system' — which would fail against the
    # gateway's self-signed cert. Match this module's default instead.
    peer['verify'] = target.get('verify') or 'insecure'
    parts, ok = [], True
    for section, payload in data.items():
        syncer = unifi.syncer_for(section)
        if syncer is None:
            continue
        try:
            s = syncer(peer, payload)
        except Exception as e:                   # unreachable, login refused, …
            return False, str(e)
        bits = ['%d created' % s['created'], '%d updated' % s['updated'],
                '%d deleted' % s['deleted'], '%d unchanged' % s['unchanged']]
        if s.get('claimed'):
            bits.append('%d claimed from client DNS' % s['claimed'])
        if s.get('covered'):
            bits.append('%d already covered by client DNS' % s['covered'])
        line = ', '.join(bits)
        if s['failed'] or s['conflicts']:
            ok = False
            line = '%s (%s)' % (unifi.status_line(s), line)
        parts.append('%s: %s' % (section, line) if len(data) > 1 else line)
    if not parts:
        return True, 'nothing to sync'
    return ok, ' · '.join(parts)


def push_target(target, data, serials):
    """One push to one target. `data` is {section: payload}, `serials` the
    matching {section: n}. Returns (ok, detail)."""
    if target.get('kind') == 'unifi':
        return _push_unifi(target, data)
    verify = target.get('verify') or 'insecure'
    if verify.startswith('fingerprint:'):
        e = _check_fingerprint(target['url'], verify.split(':', 1)[1])
        if e:
            return False, e
    # The scalar `serial` is the max across sections: DNSMAQ-MGR's receiver
    # reads the per-section map when present and falls back to the scalar,
    # and its own peers send exactly this shape.
    payload = {'source': SOURCE_NAME,
               'serial': max(serials.values()) if serials else 0,
               'serials': dict(serials), 'sections': sorted(data),
               'data': dict(data)}
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
    counts = {s: section_size(b()) for s, b in SECTION_BUILDERS.items()}
    return jsonify({'targets': [_public(t) for t in _targets()],
                    'sections': list(sections_available()),
                    'serials': _serials(),
                    'counts': counts,
                    'serial': int(db.get_setting(SERIAL_KEY, '0') or 0),
                    # `record_count` predates sections and means hosts.
                    'record_count': counts.get('hosts', 0),
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
    kind = str(data.get('kind') or (cur or {}).get('kind') or 'dnsmaq').strip().lower()
    if kind not in KINDS:
        return err('Target type must be one of: %s' % ', '.join(KINDS))
    t['kind'] = kind

    if 'url' in data or not cur:
        url = str(data.get('url') or '').strip().rstrip('/')
        if not RE_URL.match(url):
            return err('Invalid URL (https://host[:port])')
        t['url'] = url

    if kind == 'unifi':
        t.pop('token', None)                    # gateways authenticate as a user
        username, e = clean_text(data.get('unifi_username'), 'Gateway username', 64)
        if e:
            return err(e)
        if username:
            t['unifi_username'] = username
        if not t.get('unifi_username'):
            return err('A gateway username is required')
        if data.get('unifi_password'):          # omitted = keep stored password
            password = str(data['unifi_password'])
            if len(password) > 256:
                return err('Gateway password is too long (max 256 characters)')
            t['unifi_password'] = password
        if not t.get('unifi_password'):
            return err('A gateway password is required (use a local admin with '
                       'MFA disabled — the API refuses a 2FA login)')
        if 'unifi_site' in data or not cur:
            site = str(data.get('unifi_site') or 'default').strip()
            if not RE_SLUG.match(site):
                return err('Invalid UniFi site name')
            t['unifi_site'] = site
        # Both default OFF. delete_extra makes this IPAM authoritative over the
        # gateway's whole A/AAAA table; claim_client_dns unticks a client's own
        # Local DNS Record so a static entry for that name is accepted. Neither
        # should happen because someone added a target and pressed save.
        for flag in ('unifi_delete_extra', 'unifi_claim_client_dns'):
            if flag in data or not cur:
                t[flag] = bool(data.get(flag))
    else:
        # Switching a target away from 'unifi' must not leave the gateway's
        # admin password sitting in the store for a target that can no longer
        # use it.
        for k in ('unifi_username', 'unifi_password', 'unifi_site',
                  'unifi_delete_extra', 'unifi_claim_client_dns'):
            t.pop(k, None)
        if data.get('token'):                   # omitted = keep stored token
            t['token'] = str(data['token']).strip()
        if not t.get('token'):
            return err('A mirror token is required (generate one on the node: '
                       'Mirroring → receive token)')

    if 'sections' in data or not cur:
        # Absent means "the default"; an explicit [] means "receive nothing",
        # which is not a target — say so instead of quietly substituting.
        raw = data['sections'] if data.get('sections') is not None else ['hosts']
        if not isinstance(raw, list):
            return err('sections must be a list')
        subs = [str(s).strip().lower() for s in raw if str(s).strip()]
        if not subs:
            return err('A target must subscribe to at least one section')
        unknown = [s for s in subs if s not in SECTION_BUILDERS]
        if unknown:
            return err('Unknown section(s): %s (have: %s)'
                       % (', '.join(unknown), ', '.join(sections_available())))
        wrong = [s for s in subs if s not in KIND_SECTIONS[kind]]
        if wrong:
            return err('A %s target cannot carry: %s' % (kind, ', '.join(wrong)))
        t['sections'] = sorted(set(subs))

    if 'verify' in data:
        v = str(data.get('verify') or 'insecure').strip()
        if v != 'insecure':
            if not v.startswith('fingerprint:') or not RE_FPR.match(v.split(':', 1)[1]):
                return err("verify must be 'insecure' or 'fingerprint:<sha256>'")
        t['verify'] = v
    t.setdefault('verify', 'insecure')
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
                 '%s (%s) → %s' % (name, kind, t.get('url', '')))
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


def run_push(only='', sections=None):
    """Push to every enabled target (or one, by name).

    `sections` limits the run; the default is everything renderable. Each
    target receives only what it subscribes to, so a DNS-only node is not
    handed DHCP just because a scope changed.

    Serials advance PER SECTION, once per run, and every target that acks a
    section holds the same version of it. Returns a result dict, or
    (None, error) when no target matches — shared by the route below and the
    provision workflow.
    """
    targets = _targets()
    picked = [t for t in targets
              if (t['name'] == only if only else t.get('enabled', True))]
    if not picked:
        return None, 'No matching push target — configure one first'

    wanted = [s for s in (sections or sections_available())
              if s in SECTION_BUILDERS]
    # Only advance a section's serial if something is actually going to
    # receive it — an unsubscribed section must not inflate the counter.
    live = sorted({s for t in picked for s in sections_for(t) if s in wanted})
    if not live:
        return None, ('No matching target subscribes to %s'
                      % ', '.join(wanted or ['any section']))
    data = build_sections(live)
    serials = _bump_serials(live)

    results = []
    for t in picked:
        subs = [s for s in sections_for(t) if s in live]
        if not subs:
            results.append({'name': t['name'], 'ok': True, 'skipped': True,
                            'sections': [], 'detail': 'not subscribed'})
            continue
        ok, detail = push_target(t, {s: data[s] for s in subs},
                                 {s: serials[s] for s in subs})
        t['last'] = {'ts': db.now(), 'ok': ok, 'detail': detail,
                     'sections': subs,
                     'serials': {s: serials[s] for s in subs},
                     'serial': max(serials[s] for s in subs)}
        if ok:
            held = dict(t.get('serials') or {})
            held.update({s: serials[s] for s in subs})
            t['serials'] = held
            t['serial'] = max(held.values())
        results.append({'name': t['name'], 'ok': ok, 'detail': detail,
                        'sections': subs})
    counts = {s: section_size(data[s]) for s in live}
    with db.WRITE_LOCK:
        _save_targets(targets)
        db.audit(actor(), 'push-run', 'push', None,
                 '%s → %s' % (', '.join('%s serial %d (%d)'
                                        % (s, serials[s], counts[s]) for s in live),
                              ', '.join('%s:%s' % (r['name'],
                                                   'skip' if r.get('skipped')
                                                   else ('ok' if r['ok'] else 'FAIL'))
                                        for r in results)))
    return {'success': all(r['ok'] for r in results),
            'sections': live, 'serials': serials, 'counts': counts,
            # Back-compat with callers (and the UI) written when `hosts` was
            # the only section and there was one number to show.
            'serial': max(serials.values()),
            'records': counts.get('hosts', 0),
            'results': results}, None


@bp.route('/api/push/run', methods=['POST'])
def push_run():
    raw = (request.args.get('sections') or '').strip()
    sections = [s for s in raw.replace(',', ' ').split() if s] or None
    if sections:
        bad = [s for s in sections if s not in SECTION_BUILDERS]
        if bad:
            return err('Unknown section(s): %s' % ', '.join(bad))
    out, e = run_push((request.args.get('target') or '').strip(), sections)
    if e:
        return err(e)
    return jsonify(out)
