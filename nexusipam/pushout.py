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
HASHES_KEY = 'push_hashes'          # per-section content hash behind the serial
SOURCE_NAME = 'nexus-ipam'          # how this IPAM identifies itself to nodes
PUSH_TIMEOUT = 30

# Kinds of target:
#   'dnsmaq' — a DNSMAQ-MGR node, which receives the mirror payload on its own
#     API and locks each pushed section read-only.
#   'unifi'  — a UniFi Cloud Gateway, which has no mirror endpoint: its state
#     is reconciled object by object by the unifi adapter. Push-only; there is
#     nothing to lock, so the gateway's UI stays editable and drift is possible.
#   'pihole' — a Pi-hole (v6 API): dns.hosts and the dhcp.* config reconciled
#     by the pihole adapter. Same reconcile model as 'unifi'.
# Reaching every target directly is the standing rule: no target's freshness
# depends on another being up.
KINDS = ('dnsmaq', 'unifi', 'pihole')

# Reconciling kinds (no mirror endpoint) -> adapter module. Both adapters
# share the summary schema, status_line, and the syncer registry contract, so
# the push path treats them identically.
ADAPTER_KINDS = {'unifi': 'unifi', 'pihole': 'pihole'}

# The credential/flag fields each kind owns. Switching a target's kind must
# not leave another kind's secrets sitting in the store for a target that can
# no longer use them, so on save everything NOT of the new kind is popped.
KIND_FIELDS = {
    'dnsmaq': ('token', 'read_token'),
    'unifi': ('unifi_username', 'unifi_password', 'unifi_site',
              'unifi_delete_extra', 'unifi_claim_client_dns',
              'unifi_dhcp_delete_extra', 'unifi_manage_scope_state'),
    'pihole': ('pihole_password', 'pihole_delete_extra',
               'pihole_dhcp_delete_extra', 'pihole_manage_scope_state'),
}

# Which sections each kind can carry. A UniFi gateway serves both DNS and
# DHCP and its API exposes both (rest/networkconf holds the dhcpd_* scope
# options, rest/user the fixed reservations) — the earlier hosts-only limit
# was inherited from DNSMAQ-MGR's adapter, where it described that adapter's
# scope rather than anything about UniFi.
KIND_SECTIONS = {
    # netboot is dnsmaq-only: on a UniFi gateway PXE rides inside the dhcp
    # section as dhcpd_boot_* fields (and a Pi-hole has no netboot model at
    # all) — carrying it twice would let the copies disagree.
    'dnsmaq': ('hosts', 'dhcp', 'netboot'),
    'unifi': ('hosts', 'dhcp'),
    'pihole': ('hosts', 'dhcp'),
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

    # Only addresses explicitly marked as DHCP reservations. "Has a MAC" is
    # far too loose — a hypervisor import records one for every VM it finds,
    # and those machines are statically configured and never ask for a lease;
    # publishing them would fabricate a reservation per VM for addresses
    # nobody is leasing. `status = reserved` is too loose in the other
    # direction and too tight in practice: a live host with a fixed lease is
    # legitimately `active`, so keying off status silently drops it.
    # (The older /api/export/dnsmasq/static-leases endpoint keeps the loose
    # rule; it is pull-only, so nothing acts on it unasked.)
    leases = []
    for rec in db.query(
            "SELECT address, dns_name, mac FROM ip_addresses "
            "WHERE mac <> '' AND version = 4 AND is_reservation = 1 "
            "ORDER BY addr_hex"):
        leases.append({'mac': rec['mac'], 'ip': rec['address'],
                       'hostname': rec['dns_name'].split('.')[0] if rec['dns_name'] else ''})

    return {'ranges': ranges, 'static_leases': leases, 'options': options}


def build_netboot():
    """The `netboot` section payload, in DNSMAQ-MGR's own store shape.

    Derived from each network's `option:tftp-server` + `option:bootfile-name`
    rows — the same pair the UniFi adapter maps onto `dhcpd_boot_*` — so PXE
    is recorded ONCE and renders to whichever server enforces it. It is its
    own section because dnsmasq's PXE mechanism is `dhcp-boot` (the DHCP
    header fields), not options 66/67, which many PXE ROMs ignore; shipping
    the pair as generic options would look configured and boot nothing.

    Only complete pairs render — the receiving node requires both, and half a
    PXE config also boots nothing. Identical (server, file) pairs collapse to
    one entry: an untagged dhcp-boot is global, so repeating it per network
    says nothing new. Proxy-DHCP and the PXE prompt are not modelled here and
    render as defaults — subscribing a node to `netboot` hands this app
    authorship of that whole store, like every mirrored section.
    """
    nets = {n['id']: n for n in db.query('SELECT id, cidr, name FROM networks')}
    by_net = {}
    for o in db.query("SELECT network_id, option, value FROM dhcp_options "
                      "WHERE enabled=1 AND option IN ('option:tftp-server', '66', "
                      "'option:bootfile-name', '67') ORDER BY network_id, option"):
        key = 'tftp' if o['option'] in ('option:tftp-server', '66') else 'bootfile'
        by_net.setdefault(o['network_id'], {})[key] = o['value']
    entries, seen = [], set()
    for nid, opts in sorted(by_net.items()):
        if not opts.get('bootfile') or not opts.get('tftp'):
            continue
        if (opts['tftp'], opts['bootfile']) in seen:
            continue
        seen.add((opts['tftp'], opts['bootfile']))
        net = nets.get(nid) or {}
        # The receiving node refuses quotes/newlines in an entry name; network
        # names are wider than that, so squeeze rather than fail the render.
        name = (net.get('name') or net.get('cidr') or 'net-%d' % nid)
        name = name.replace('"', '').replace('\n', ' ').strip()[:64] or 'pxe'
        entries.append({'name': name, 'filename': opts['bootfile'],
                        'server': opts['tftp'], 'arches': [], 'enabled': True,
                        'comment': 'PXE for %s' % (net.get('cidr') or 'the plan')})
    return {'entries': entries}


# A section exists once something can render it. Declaring the name before the
# renderer lands would let a target subscribe to a section that silently
# pushes nothing, so the registry IS the list of valid sections.
SECTION_BUILDERS = {'hosts': build_hosts, 'dhcp': build_dhcp,
                    'netboot': build_netboot}


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
# One counter PER SECTION, advanced only when that section's rendered CONTENT
# changes. Both halves matter:
#
#  * Per section, because with one global counter a dhcp-only change bumps the
#    number `hosts` is judged by and "is this node current?" stops being
#    answerable.
#  * Per content change, because a serial that counts PUSHES cannot answer
#    that question either: pushing one target advanced the number every other
#    subscriber was judged by, so the untouched targets read as "behind" while
#    holding identical content — and pushing them to catch up advanced it
#    again, marking the first one behind. The first live enablement produced
#    exactly that whack-a-mole (hosts 19→23 in four pushes, 61 identical
#    records every time).
#
# Re-sending the current serial to a node that already holds it is safe:
# DNSMAQ-MGR's receiver rejects only strictly LOWER serials (mirror.py checks
# `<`, not `<=`), so an equal serial re-applies idempotently — which is also
# what an operator forcing a re-push after suspected drift wants.
#
# The scalar `serial` is still sent, as the max, because DNSMAQ-MGR's
# receiver accepts both shapes.

def _serials():
    try:
        s = json.loads(db.get_setting(SERIALS_KEY, '{}') or '{}')
        return s if isinstance(s, dict) else {}
    except ValueError:
        return {}


def _hashes():
    try:
        h = json.loads(db.get_setting(HASHES_KEY, '{}') or '{}')
        return h if isinstance(h, dict) else {}
    except ValueError:
        return {}


def _advance_serials(data):
    """Serial for each section in `data` ({section: payload}), advancing a
    counter only when that section's payload differs from the last run's.
    Returns {section: serial} — the numbers the push should carry."""
    with db.WRITE_LOCK:
        cur = _serials()
        if not cur:
            # First run after the upgrade: carry the old global counter forward
            # so serials never appear to go backwards to a node that already
            # holds a higher one (it would reject the push as stale).
            legacy = int(db.get_setting(SERIAL_KEY, '0') or 0)
            cur = {s: legacy for s in sections_available()}
        hashes = _hashes()
        for s, payload in sorted(data.items()):
            digest = hashlib.sha256(
                json.dumps(payload, sort_keys=True).encode()).hexdigest()
            if hashes.get(s) != digest:
                cur[s] = int(cur.get(s, 0)) + 1
                hashes[s] = digest
        db.set_setting(SERIALS_KEY, json.dumps(cur))
        db.set_setting(HASHES_KEY, json.dumps(hashes))
        db.set_setting(SERIAL_KEY, max(cur.values()) if cur else 0)
    return {s: cur[s] for s in data}


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
    out['has_password'] = bool(out.pop('unifi_password', '')
                               or out.pop('pihole_password', ''))
    out['has_read_token'] = bool(out.pop('read_token', ''))
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


def dnsmaq_get(target, path):
    """Authenticated GET against a dnsmaq target using its READ token (the
    mirror token is write-only on the node by design), honouring the target's
    fingerprint pinning. Raises OSError on transport or TLS problems."""
    verify = target.get('verify') or 'insecure'
    if verify.startswith('fingerprint:'):
        e = _check_fingerprint(target['url'], verify.split(':', 1)[1])
        if e:
            raise OSError(e)
    req = urllib.request.Request(
        target['url'].rstrip('/') + path,
        headers={'Authorization': 'Bearer ' + (target.get('read_token') or '')})
    with urllib.request.urlopen(req, context=ssl._create_unverified_context(),
                                timeout=15) as r:
        return json.loads(r.read() or b'{}')


def _adapter_for(kind):
    from importlib import import_module
    return import_module('.' + ADAPTER_KINDS[kind], __package__)


def _push_reconcile(target, data):
    """Reconcile an adapter-kind target's state against ours, section by
    section. Returns (ok, detail).

    Unlike a mirror push — one request, applied or refused whole — this is
    list/diff/N-writes, so individual records can fail while the rest land.
    The summary is reported rather than flattened to ok/failed: "2 conflicts,
    client DNS holds x at y" is the kind of thing an operator has to see to
    act on.
    """
    adapter = _adapter_for(target.get('kind'))
    peer = dict(target)
    # A target saved before `verify` existed has no key at all, and the
    # adapters' own default is 'system' — which would fail against a
    # self-signed cert. Match this module's default instead.
    peer['verify'] = target.get('verify') or 'insecure'
    parts, ok = [], True
    for section, payload in data.items():
        syncer = adapter.syncer_for(section)
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
            line = '%s (%s)' % (adapter.status_line(s), line)
        parts.append('%s: %s' % (section, line) if len(data) > 1 else line)
    if not parts:
        return True, 'nothing to sync'
    return ok, ' · '.join(parts)


def push_target(target, data, serials):
    """One push to one target. `data` is {section: payload}, `serials` the
    matching {section: n}. Returns (ok, detail)."""
    if target.get('kind') in ADAPTER_KINDS:
        return _push_reconcile(target, data)
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
    """Exactly what would be sent, without sending it. Every renderable
    section by default, or `?sections=dhcp`.

    This is the only way to inspect a payload before it reaches a live server,
    so it renders the same builders the push does rather than approximating
    them — a preview that is not byte-identical to the push is worse than none.
    """
    raw = (request.args.get('sections') or '').strip()
    names = [s for s in raw.replace(',', ' ').split() if s] or list(sections_available())
    bad = [s for s in names if s not in SECTION_BUILDERS]
    if bad:
        return err('Unknown section(s): %s' % ', '.join(bad))
    return jsonify(build_sections(names))


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

    # Drop every field belonging to a kind this target no longer is.
    for other, fields in KIND_FIELDS.items():
        if other != kind:
            for k in fields:
                t.pop(k, None)

    if kind == 'unifi':
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
        for flag in ('unifi_delete_extra', 'unifi_claim_client_dns',
                     'unifi_dhcp_delete_extra', 'unifi_manage_scope_state'):
            if flag in data or not cur:
                t[flag] = bool(data.get(flag))
    elif kind == 'pihole':
        if data.get('pihole_password'):         # omitted = keep stored password
            password = str(data['pihole_password'])
            if len(password) > 256:
                return err('Pi-hole password is too long (max 256 characters)')
            t['pihole_password'] = password
        if not t.get('pihole_password'):
            return err('The Pi-hole app/web password is required '
                       '(the web interface password, or an app password)')
        # Same blast-radius defaults as the gateway flags: nothing destructive
        # happens because someone added a target and pressed save.
        for flag in ('pihole_delete_extra', 'pihole_dhcp_delete_extra',
                     'pihole_manage_scope_state'):
            if flag in data or not cur:
                t[flag] = bool(data.get(flag))
    else:
        if data.get('token'):                   # omitted = keep stored token
            t['token'] = str(data['token']).strip()
        if not t.get('token'):
            return err('A mirror token is required (generate one on the node: '
                       'Mirroring → receive token)')
        # Optional read-side credential. The mirror token is write-only on the
        # node by design, so polling its leases (or adopting its DHCP state)
        # needs a separate READONLY API token minted there. Empty = keep the
        # stored one (like the password); an explicit null clears it.
        if 'read_token' in data:
            if data['read_token'] is None:
                t.pop('read_token', None)
            elif str(data['read_token']).strip():
                t['read_token'] = str(data['read_token']).strip()

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


# ─── Drift ────────────────────────────────────────────────────────────
# Serials answer "did this target ack the current content?" — they cannot
# answer "does the target still HOLD it?". A DNSMAQ-MGR node locks every
# pushed section read-only, so there the two questions collapse into one; a
# gateway's UI stays editable after a push, so its state can walk away
# silently. This reads the gateway back and diffs it with the same pure
# planners the push executes — computed writes, performed nowhere.

def run_drift(target, client=None):
    """Read-only drift report for one reconciling target: for each subscribed
    section, what a push right now would have to change. Raises on an
    unreachable/refusing server; the route wraps that."""
    if target.get('kind') == 'pihole':
        return _drift_pihole(target, client)
    return _drift_unifi(target, client)


def _drift_pihole(target, client=None):
    from . import pihole
    peer = dict(target)
    peer['verify'] = target.get('verify') or 'insecure'
    data = build_sections(sections_for(target))
    report = {'ts': db.now(), 'ok': True, 'sections': {}}
    own = client is None
    if own:
        session = pihole.HttpsSession(peer['url'], peer['verify'])
        client = pihole.PiholeClient(session)
        client.login(peer.get('pihole_password') or '')
    try:
        cfg = client.get_config()
        if 'hosts' in data:
            p = pihole.plan_hosts(pihole.records_from_hosts(data['hosts']),
                                  (cfg.get('dns') or {}).get('hosts') or [],
                                  mirror=bool(peer.get('pihole_delete_extra')))
            counts = {'missing': p['created'], 'differs': p['updated'],
                      'extra': p['deleted'],
                      # A pure ordering difference is real drift: the PTR
                      # answer is the first matching hosts line.
                      'reordered': 1 if p['changed'] and not (
                          p['created'] or p['updated'] or p['deleted']) else 0}
            report['sections']['hosts'] = {'drifted': any(counts.values()),
                                           'in_step': p['unchanged'],
                                           'counts': counts, 'examples': []}
        if 'dhcp' in data:
            own_ip = pihole.split_url(peer['url'])[0]
            p = pihole.plan_dhcp(data['dhcp'], cfg.get('dhcp') or {}, own_ip,
                                 mirror=bool(peer.get('pihole_dhcp_delete_extra')),
                                 manage_state=bool(peer.get('pihole_manage_scope_state')))
            scope_fields = sorted(k for k in (p['patch'] or {}) if k != 'hosts')
            counts = {'scope_fields': len(scope_fields),
                      'reservations_missing': p['created'],
                      'reservations_differ': p['updated'],
                      'reservations_extra': p['deleted'],
                      'unsupported': len(p['conflicts']),
                      'other_scopes': len(p['skipped'])}
            # Structural facts — options Pi-hole cannot express, scopes it
            # cannot serve — must not paint the target permanently red.
            actionable = {k: v for k, v in counts.items()
                          if k not in ('unsupported', 'other_scopes')}
            report['sections']['dhcp'] = {'drifted': any(actionable.values()),
                                          'in_step': p['unchanged'],
                                          'counts': counts,
                                          'examples': ['scope %s differs' % k
                                                       for k in scope_fields][:6]}
        return report
    finally:
        if own:
            client.logout()


def _drift_unifi(target, client=None):
    from . import unifi
    peer = dict(target)
    peer['verify'] = target.get('verify') or 'insecure'
    data = build_sections(sections_for(target))
    report = {'ts': db.now(), 'ok': True, 'sections': {}}
    own = client is None
    if own:
        session = unifi.HttpsSession(peer['url'], peer['verify'])
        client = unifi.UniFiClient(session, peer.get('unifi_site') or 'default')
        client.login(peer.get('unifi_username') or '', peer.get('unifi_password') or '')
    try:
        if 'hosts' in data:
            p = unifi.plan(unifi.records_from_hosts(data['hosts']),
                           client.list_static(), client.list_client_dns(),
                           mirror=bool(peer.get('unifi_delete_extra')),
                           claim=bool(peer.get('unifi_claim_client_dns')))
            counts = {'missing': len(p['create']), 'differs': len(p['update']),
                      'extra': len(p['delete']), 'unclaimed': len(p['claim']),
                      'conflicts': len(p['conflicts'])}
            examples = ([('missing %s' % n) for n, _, _ in p['create']]
                        + [('differs %s' % n) for _, n, _, _ in p['update']]
                        + [('extra %s' % n) for _, n in p['delete']]
                        + [('client DNS holds %s' % c[0]) for c in p['claim']])[:6]
            report['sections']['hosts'] = {'drifted': any(counts.values()),
                                           'in_step': p['unchanged'],
                                           'counts': counts, 'examples': examples}
        if 'dhcp' in data:
            p = unifi.plan_dhcp(
                unifi.desired_dhcp(data['dhcp']),
                client.list_networks(), client.list_fixed(),
                data['dhcp'].get('static_leases') or [],
                mirror=bool(peer.get('unifi_dhcp_delete_extra')),
                manage_state=bool(peer.get('unifi_manage_scope_state')))
            counts = {'scopes': len(p['scopes']),
                      'reservations_missing': len(p['fixed_set']),
                      'reservations_extra': len(p['fixed_clear']),
                      'unmatched': len(p['unmatched']),
                      'unsupported': len(p['unsupported'])}
            examples = ([('scope %s: %s' % (key, ', '.join(sorted(ch))))
                         for _, key, ch in p['scopes']]
                        + [('reservation %s -> %s' % (mac, l['ip']))
                           for mac, l, _ in p['fixed_set']]
                        + [('extra reservation %s' % mac)
                           for mac, _ in p['fixed_clear']])[:6]
            # An unsupported option is a standing modelling gap a push cannot
            # fix — reported in the counts, but it must not paint the target
            # permanently red or real drift disappears into the noise.
            actionable = {k: v for k, v in counts.items() if k != 'unsupported'}
            report['sections']['dhcp'] = {'drifted': any(actionable.values()),
                                          'in_step': p['unchanged'],
                                          'counts': counts, 'examples': examples}
        return report
    finally:
        if own:
            client.logout()


@bp.route('/api/push/targets/<name>/drift', methods=['POST'])
def push_target_drift(name):
    targets = _targets()
    target = next((t for t in targets if t['name'] == name), None)
    if not target:
        return err('No such target', 404)
    if (target.get('kind') or 'dnsmaq') == 'dnsmaq':
        return err('A DNSMAQ-MGR node locks every pushed section read-only, so '
                   'it cannot drift — the serial column already answers "is it '
                   'current?". Only a reconciled target, whose own UI stays '
                   'editable, needs this check.', 400)
    try:
        report = run_drift(target)
    except Exception as e:                    # unreachable, login refused, …
        report = {'ts': db.now(), 'ok': False, 'error': str(e)}
    with db.WRITE_LOCK:
        target['drift'] = report
        _save_targets(targets)
        drifted = [s for s, v in (report.get('sections') or {}).items()
                   if v['drifted']]
        db.audit(actor(), 'drift-check', 'push', None,
                 '%s: %s' % (name,
                             'UNREACHABLE: %s' % report.get('error')
                             if not report['ok'] else
                             ('drifted: %s' % ', '.join(drifted)
                              if drifted else 'in sync')))
    if not report['ok']:
        return err('Could not read %s: %s' % (name, report.get('error')), 502)
    return jsonify({'success': True, 'target': name, 'drift': report})


def run_push(only='', sections=None):
    """Push to every enabled target (or one, by name).

    `sections` limits the run; the default is everything renderable. Each
    target receives only what it subscribes to, so a DNS-only node is not
    handed DHCP just because a scope changed.

    Serials advance PER SECTION and only when the section's content changed,
    so every target that acks a serial holds that exact content, and a
    single-target push of an unchanged payload leaves the other subscribers
    current rather than "behind". Returns a result dict, or
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
    # Refuse to push a payload dnsmasq would die on. The validators guard the
    # write paths, but imported/legacy rows can predate them — and a duplicate
    # dhcp-host MAC kills dnsmasq at its next restart, past --test. Better one
    # loud refusal here than a store that detonates later.
    if isinstance(data.get('dhcp'), dict):
        seen, dupes = set(), set()
        for l in data['dhcp'].get('static_leases') or []:
            (dupes if l['mac'] in seen else seen).add(l['mac'])
        if dupes:
            return None, ('Refusing to push: %d MAC(s) carry more than one '
                          'reservation (%s) — one MAC gets one fixed lease; '
                          'clear the extra is_reservation flags first'
                          % (len(dupes), ', '.join(sorted(dupes))))
    serials = _advance_serials(data)

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
