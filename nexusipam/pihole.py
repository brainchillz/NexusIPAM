"""Pi-hole (v6) adapter: pushes host records and the DHCP scope to a Pi-hole.

A third *kind* of push target. Pi-hole is dnsmasq underneath and its REST API
exposes the config as structured keys, so the mapping from the mirror payloads
is nearly direct: `dns.hosts` entries are hosts-file lines, `dhcp.hosts`
entries are literal dnsmasq dhcp-host strings. There is no mirror endpoint and
nothing locks — this reconciles, like the UniFi adapter, and can therefore
drift.

Facts verified against a live v6 instance, which shape the design:

* A config PATCH replaces each array wholesale and applies immediately (no
  reload step). So a sync computes the complete desired array, and "additive"
  means folding the entries we do not manage back into what we write — after
  ours, so the PTR answer (first matching line, hosts-file semantics) follows
  the plan's canonical ordering.
* Pi-hole serves exactly ONE DHCP scope: the subnet it lives on. The
  payload's other scopes are counted as skipped, and options Pi-hole cannot
  express (DNS handed out, NTP, PXE, …) are reported as conflicts — a
  silently ignored option is indistinguishable from a satisfied one.
* Sessions are a limited resource on the server, so logout matters.

Transport reuses unifi.HttpsSession (keep-alive + fingerprint pinning); the
summary schema and status_line are shared with that adapter so pushout treats
every reconciling kind identically.
"""
import ipaddress

from .unifi import (HttpsSession, desired_dhcp, in_subnet, records_from_hosts,
                    split_url)

__all__ = ['PiholeClient', 'PiholeError', 'plan_hosts', 'plan_dhcp',
           'sync_hosts', 'sync_dhcp', 'read_leases', 'syncer_for',
           'status_line', 'HttpsSession']


class PiholeError(Exception):
    pass


def status_line(summary):
    """Neutral phrasing (unlike the UniFi adapter's, whose conflicts really
    are another DNS store holding a name) — here a conflict is a modelling
    gap: an option this server cannot express."""
    if summary['failed']:
        detail = summary['errors'][0] if summary['errors'] else ''
        return 'error: %d write(s) failed%s' % (summary['failed'],
                                                ' (%s)' % detail if detail else '')
    if summary['conflicts']:
        name, ours, theirs = summary['conflicts'][0]
        extra = ' +%d more' % (len(summary['conflicts']) - 1) \
            if len(summary['conflicts']) > 1 else ''
        return 'conflict: %s (%s; %s)%s' % (name, ours, theirs, extra)
    return 'ok'


class PiholeClient:
    """Config and lease operations against one Pi-hole, over HttpsSession."""

    def __init__(self, session):
        self.s = session
        self.sid = None

    def _req(self, method, path, body=None):
        headers = {'sid': self.sid} if self.sid else {}
        status, data, _ = self.s.request(method, path, body, headers)
        return status, data

    def login(self, password):
        status, data = self._req('POST', '/api/auth', {'password': password})
        session = (data or {}).get('session') if isinstance(data, dict) else None
        if status != 200 or not (session or {}).get('valid'):
            raise PiholeError('login rejected (HTTP %s) — check the app/web '
                              'password' % status)
        self.sid = (session or {}).get('sid')

    def logout(self):
        # Sessions are limited server-side; leaking them eventually locks the
        # operator out of their own UI.
        try:
            self._req('DELETE', '/api/auth')
        except Exception:
            pass
        self.s.close()

    def get_config(self):
        status, data = self._req('GET', '/api/config')
        if status != 200 or not isinstance(data, dict):
            raise PiholeError('reading config failed: HTTP %s' % status)
        return data.get('config') or {}

    def patch_config(self, config):
        status, data = self._req('PATCH', '/api/config', {'config': config})
        if status != 200:
            raise PiholeError('config write failed: HTTP %s %s'
                              % (status, str(data)[:120]))

    def leases(self):
        status, data = self._req('GET', '/api/dhcp/leases')
        if status != 200 or not isinstance(data, dict):
            raise PiholeError('listing leases failed: HTTP %s' % status)
        return data.get('leases') or []


# ─── hosts ─────────────────────────────────────────────────────────────

def _parse_entry(line):
    """One dns.hosts line -> [(ip, name), ...] (hosts-file syntax allows
    several names per line)."""
    parts = str(line or '').split()
    return [(parts[0], n) for n in parts[1:]] if len(parts) >= 2 else []


def plan_hosts(desired, current, mirror=False):
    """Pure diff of the dns.hosts array. `desired` is records_from_hosts()
    output; `current` the stored array. Returns the full array to write plus
    the usual counts — ours first in plan order (the PTR answer is the first
    matching line), foreign entries appended unless mirroring."""
    want_pairs = [(value, name) for name, _rtype, value in desired]
    managed = {name.lower() for _ip, name in want_pairs}
    cur_pairs = [p for line in current or [] for p in _parse_entry(line)]
    by_name = {}
    for ip, name in cur_pairs:
        by_name.setdefault(name.lower(), []).append(ip)

    created = updated = unchanged = 0
    for ip, name in want_pairs:
        have = by_name.get(name.lower())
        if not have:
            created += 1
        elif have == [ip]:
            unchanged += 1
        else:
            updated += 1
    foreign = [(ip, name) for ip, name in cur_pairs
               if name.lower() not in managed]
    lines = ['%s %s' % (ip, name) for ip, name in want_pairs]
    if not mirror:
        lines += ['%s %s' % (ip, name) for ip, name in foreign]
    return {'lines': lines, 'changed': lines != list(current or []),
            'created': created, 'updated': updated,
            'deleted': len(foreign) if mirror else 0,
            'unchanged': unchanged,
            'kept': 0 if mirror else len(foreign)}


def sync_hosts(peer, hosts, client=None):
    """Reconcile dns.hosts with our host records. Returns the shared summary
    schema; raises PiholeError when the server is unreachable or refuses."""
    mirror = bool(peer.get('pihole_delete_extra', False))
    desired = records_from_hosts(hosts)
    if not desired and mirror:
        raise PiholeError('no host records to push; refusing to wipe the '
                          "Pi-hole's local DNS records")
    own = client is None
    if own:
        session = HttpsSession(peer['url'], peer.get('verify', 'insecure'))
        client = PiholeClient(session)
        client.login(peer.get('pihole_password') or '')
    try:
        cfg = client.get_config()
        p = plan_hosts(desired, (cfg.get('dns') or {}).get('hosts') or [],
                       mirror=mirror)
        if p['changed']:
            client.patch_config({'dns': {'hosts': p['lines']}})
        return {'created': p['created'], 'updated': p['updated'],
                'deleted': p['deleted'], 'claimed': 0,
                'unchanged': p['unchanged'], 'covered': 0,
                'conflicts': [], 'failed': 0, 'errors': []}
    finally:
        if own:
            client.logout()


# ─── DHCP ──────────────────────────────────────────────────────────────

# Option fields desired_dhcp() can carry that Pi-hole's dhcp.* keys cannot
# express. Reported as conflicts, never dropped.
UNSUPPORTED_OPTIONS = {'dns': 'option:dns-server', 'domain': 'option:domain-name',
                       'ntp': 'option:ntp-server', 'tftp': 'option:tftp-server',
                       'bootfile': 'option:bootfile-name', 'wpad': 'option:wpad-url'}


def lease_text(seconds):
    """Seconds -> the dnsmasq-style string dhcp.leaseTime takes."""
    s = int(seconds or 86400)
    if s % 3600 == 0:
        return '%dh' % (s // 3600)
    if s % 60 == 0:
        return '%dm' % (s // 60)
    return '%ds' % s


def plan_dhcp(payload, dhcp_cfg, own_ip, mirror=False, manage_state=False):
    """Pure diff of the dhcp.* config against the payload.

    Returns {'patch': dict-or-None, counts, 'conflicts', 'skipped',
    'skipped_reservations'}. Only the scope covering `own_ip` is written —
    Pi-hole cannot serve any other — and `active` is never touched unless the
    operator opted in: turning a DHCP server on (or off) is not a config
    tweak."""
    desired = desired_dhcp(payload or {})
    mine, skipped = None, []
    for key, scope in sorted(desired.items()):
        if mine is None and in_subnet(own_ip, key):
            mine = (key, scope)
        else:
            skipped.append(key)
    p = {'patch': None, 'created': 0, 'updated': 0, 'deleted': 0,
         'unchanged': 0, 'conflicts': [], 'skipped': skipped,
         'skipped_reservations': 0}

    changes = {}
    if mine:
        key, scope = mine
        want = {'start': scope['start'], 'end': scope['end'],
                'netmask': str(ipaddress.ip_network(key).netmask),
                'leaseTime': lease_text(scope['lease'])}
        opts = scope['options']
        if opts.get('gateway'):
            want['router'] = opts['gateway']
        if manage_state:
            want['active'] = bool(scope['enabled'])
        changes = {k: v for k, v in want.items() if dhcp_cfg.get(k) != v}
        if changes:
            p['updated'] += 1
        else:
            p['unchanged'] += 1
        for field in sorted(UNSUPPORTED_OPTIONS):
            if opts.get(field):
                p['conflicts'].append((UNSUPPORTED_OPTIONS[field],
                                       'in the plan', 'no Pi-hole equivalent'))
        for o in scope.get('unsupported') or []:
            p['conflicts'].append((o, 'in the plan', 'no Pi-hole equivalent'))

    # Reservations: dnsmasq dhcp-host strings, only those inside the one
    # subnet this server can lease. Others are skipped and counted — writing
    # them would look satisfied while never serving anyone.
    want_hosts = []
    for l in payload.get('static_leases') or []:
        if mine and in_subnet(l['ip'], mine[0]):
            entry = '%s,%s' % (l['mac'], l['ip'])
            if l.get('hostname'):
                entry += ',%s' % l['hostname']
            want_hosts.append(entry)
        else:
            p['skipped_reservations'] += 1
    cur_hosts = [str(e) for e in dhcp_cfg.get('hosts') or []]
    want_macs = {e.split(',')[0].lower() for e in want_hosts}
    foreign = [e for e in cur_hosts if e.split(',')[0].lower() not in want_macs]
    cur_by_mac = {e.split(',')[0].lower(): e for e in cur_hosts}
    for e in want_hosts:
        have = cur_by_mac.get(e.split(',')[0].lower())
        if have is None:
            p['created'] += 1
        elif have == e:
            p['unchanged'] += 1
        else:
            p['updated'] += 1
    new_hosts = want_hosts + ([] if mirror else foreign)
    if mirror:
        p['deleted'] += len(foreign)
    if new_hosts != cur_hosts:
        changes['hosts'] = new_hosts
    p['patch'] = changes or None
    return p


def sync_dhcp(peer, payload, client=None):
    """Reconcile the Pi-hole's dhcp.* config with the plan's one applicable
    scope. Mirrors sync_hosts' contract."""
    mirror = bool(peer.get('pihole_dhcp_delete_extra', False))
    manage_state = bool(peer.get('pihole_manage_scope_state', False))
    own_ip, _port = split_url(peer['url'])
    own = client is None
    if own:
        session = HttpsSession(peer['url'], peer.get('verify', 'insecure'))
        client = PiholeClient(session)
        client.login(peer.get('pihole_password') or '')
    try:
        cfg = client.get_config()
        p = plan_dhcp(payload or {}, cfg.get('dhcp') or {}, own_ip,
                      mirror=mirror, manage_state=manage_state)
        if p['patch']:
            client.patch_config({'dhcp': p['patch']})
        return {'created': p['created'], 'updated': p['updated'],
                'deleted': p['deleted'], 'claimed': 0,
                'unchanged': p['unchanged'], 'covered': 0,
                'conflicts': p['conflicts'], 'failed': 0, 'errors': []}
    finally:
        if own:
            client.logout()


def read_leases(peer, client=None):
    """Dynamic leases as the Pi-hole sees them. Reservation-held MACs are
    skipped for the usual reason: that binding is a plan record, and listing
    it as both double-counts the address."""
    own = client is None
    if own:
        session = HttpsSession(peer['url'], peer.get('verify', 'insecure'))
        client = PiholeClient(session)
        client.login(peer.get('pihole_password') or '')
    try:
        statics = {str(e).split(',')[0].lower()
                   for e in (client.get_config().get('dhcp') or {}).get('hosts') or []}
        out = []
        for l in client.leases():
            ip = str(l.get('ip') or '').strip()
            mac = str(l.get('hwaddr') or l.get('mac') or '').lower()
            if not ip or (mac and mac in statics):
                continue
            out.append({'ip': ip, 'mac': mac,
                        'hostname': str(l.get('name') or l.get('hostname') or '').strip(),
                        'expires': int(l.get('expires') or 0)})
        return out
    finally:
        if own:
            client.logout()


# Same registry contract as the UniFi adapter: a section with no syncer is
# skipped rather than silently reported as applied; names resolved at call
# time so tests can substitute.
SECTION_SYNCERS = {'hosts': 'sync_hosts', 'dhcp': 'sync_dhcp'}


def syncer_for(section):
    name = SECTION_SYNCERS.get(section)
    return globals().get(name) if name else None
