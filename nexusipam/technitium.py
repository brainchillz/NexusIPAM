"""Technitium DNS Server adapter: pushes zones and DHCP scopes.

A fourth *kind* of push target, and the richest: Technitium is a real
authoritative server with a full HTTP API, so the plan lands as proper zone
records and complete multi-scope DHCP — not a hosts-file emulation. It
reconciles (nothing locks), like the UniFi and Pi-hole adapters.

Facts probed against a live instance, which the design leans on:

* Record `comments` round-trip, so ownership is EXACT: every record this
  adapter writes is tagged, reconcile touches only tagged records, and
  foreign records are kept unless the delete-extra flag says otherwise.
  Zone NS/SOA records are never touched under any flag.
* Scopes are keyed by name and carry the full option set natively
  (router, DNS, domain, NTP, and PXE as serverAddress+bootFileName), so
  almost nothing the payload states is inexpressible here. Reservations are
  per-scope `reservedLeases`, sent as flat pipe-groups of four with
  dash-separated uppercase MACs. A scope created via the API starts
  disabled; enabling one is gated behind its own flag, because turning a
  DHCP server on is not a config tweak.
* Scopes default `dnsUpdates: true` — the server auto-registers lease
  hostnames into its own zones. Scopes THIS adapter authors set it false:
  in an IPAM-managed zone that would be a second writer, and the name-
  candidates flow is the sanctioned path for lease-derived names.

Managed zones are explicit (a per-target list) rather than guessed from
name suffixes; names outside every managed zone are counted as skipped.
Reverse (PTR) zones are opt-in: IPAM knows each address's canonical name,
so it can maintain per-/24 in-addr.arpa zones properly — the position-0
ordering finally expressed as explicit records. IPv4 only for now.

Auth is a permanent API token (query parameter). Transport reuses
unifi.HttpsSession (keep-alive + fingerprint pinning).
"""
import ipaddress
from urllib.parse import urlencode

from .unifi import OPTION_MAP, HttpsSession, lease_seconds, records_from_hosts

OWNER_TAG = 'nexus-ipam'


class TechnitiumError(Exception):
    pass


def status_line(summary):
    """Neutral phrasing shared with the Pi-hole adapter — conflicts here are
    modelling gaps, not another DNS store holding a name."""
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


class TechnitiumClient:
    """API operations against one server. The API is GET-based throughout;
    every call carries the token and returns {"status": "ok", "response":…}."""

    def __init__(self, session, token):
        self.s = session
        self.token = token

    def call(self, path, **params):
        params['token'] = self.token
        status, data, _ = self.s.request(
            'GET', '%s?%s' % (path, urlencode(params, doseq=True)))
        if status != 200 or not isinstance(data, dict):
            raise TechnitiumError('%s failed: HTTP %s' % (path, status))
        if data.get('status') != 'ok':
            raise TechnitiumError('%s: %s' % (
                path, data.get('errorMessage') or data.get('status')))
        return data.get('response') or {}

    def close(self):
        self.s.close()

    # -- zones ------------------------------------------------------------

    def zones(self):
        return [z['name'] for z in self.call('/api/zones/list').get('zones') or []]

    def create_zone(self, zone):
        self.call('/api/zones/create', zone=zone, type='Primary')

    def zone_records(self, zone):
        return self.call('/api/zones/records/get', domain=zone, zone=zone,
                         listZone='true').get('records') or []

    def add_record(self, zone, domain, rtype, value, comments=OWNER_TAG):
        params = {'zone': zone, 'domain': domain, 'type': rtype,
                  'comments': comments}
        if rtype == 'PTR':
            params['ptrName'] = value
        else:
            params['ipAddress'] = value
        self.call('/api/zones/records/add', **params)

    def delete_record(self, zone, domain, rtype, value):
        params = {'zone': zone, 'domain': domain, 'type': rtype}
        if rtype == 'PTR':
            params['ptrName'] = value
        else:
            params['ipAddress'] = value
        self.call('/api/zones/records/delete', **params)

    # -- DHCP -------------------------------------------------------------

    def scopes(self):
        return self.call('/api/dhcp/scopes/list').get('scopes') or []

    def scope(self, name):
        return self.call('/api/dhcp/scopes/get', name=name)

    def set_scope(self, **fields):
        self.call('/api/dhcp/scopes/set', **fields)

    def enable_scope(self, name):
        self.call('/api/dhcp/scopes/enable', name=name)

    def disable_scope(self, name):
        self.call('/api/dhcp/scopes/disable', name=name)

    def delete_scope(self, name):
        self.call('/api/dhcp/scopes/delete', name=name)

    def dhcp_leases(self):
        return self.call('/api/dhcp/leases/list').get('leases') or []


def _connect(peer):
    session = HttpsSession(peer['url'], peer.get('verify', 'insecure'))
    return TechnitiumClient(session, peer.get('technitium_token') or '')


def managed_zones(peer):
    return [z.strip().rstrip('.').lower()
            for z in str(peer.get('technitium_zones') or '').replace(',', ' ').split()
            if z.strip()]


def zone_for(name, zones):
    """Longest managed zone the name falls under, or None."""
    n = name.lower().rstrip('.')
    best = None
    for z in zones:
        if (n == z or n.endswith('.' + z)) and (best is None or len(z) > len(best)):
            best = z
    return best


# ─── hosts ─────────────────────────────────────────────────────────────

def plan_hosts(desired, zones, existing, mirror=False):
    """Pure diff. `desired` is records_from_hosts() output; `zones` the
    managed zone list; `existing` maps zone -> its records (API shape).

    Ours = records tagged OWNER_TAG. A foreign record that already states the
    exact desired mapping counts as covered (nothing to write); other foreign
    A/AAAA records are kept unless mirroring. NS/SOA and every other type are
    never candidates for deletion, flag or no flag."""
    p = {'add': [], 'delete': [], 'created': 0, 'deleted': 0, 'unchanged': 0,
         'covered': 0, 'kept': 0, 'skipped': 0}
    want = {}                                     # zone -> {(name, type, value)}
    for name, rtype, value in desired:
        z = zone_for(name, zones)
        if z is None:
            p['skipped'] += 1
            continue
        want.setdefault(z, set()).add((name.lower().rstrip('.'), rtype, value))

    for z in zones:
        ours, foreign = set(), set()
        for r in existing.get(z) or []:
            rtype = (r.get('type') or '').upper()
            if rtype not in ('A', 'AAAA'):
                continue
            key = ((r.get('name') or '').lower().rstrip('.'), rtype,
                   (r.get('rData') or {}).get('ipAddress') or '')
            (ours if (r.get('comments') or '') == OWNER_TAG else foreign).add(key)
        desired_z = want.get(z, set())
        for key in sorted(desired_z - ours):
            if key in foreign:
                p['covered'] += 1                 # already served, untagged
            else:
                p['add'].append((z,) + key)
                p['created'] += 1
        for key in sorted(ours - desired_z):
            p['delete'].append((z,) + key)
            p['deleted'] += 1
        p['unchanged'] += len(desired_z & ours)
        stale_foreign = sorted(foreign - desired_z)
        if mirror:
            for key in stale_foreign:
                p['delete'].append((z,) + key)
                p['deleted'] += 1
        else:
            p['kept'] += len(stale_foreign)
    return p


def reverse_zone(ip):
    """The /24-aligned in-addr.arpa zone for an IPv4 address."""
    a, b, c, _d = str(ip).split('.')
    return '%s.%s.%s.in-addr.arpa' % (c, b, a)


def reverse_name(ip):
    return str(ipaddress.ip_address(ip).reverse_pointer)


def plan_reverse(hosts, existing, mirror=False):
    """PTR plan: one record per IPv4 address, pointing at its canonical name
    (the FIRST enabled A for that address — build_hosts order). `existing`
    maps reverse zone -> records. Same ownership rules as plan_hosts."""
    canonical = {}
    for h in hosts or []:
        if h.get('enabled', True) and h.get('a') and h['a'] not in canonical:
            canonical[h['a']] = (h.get('name') or '').rstrip('.')
    want = {}                                     # zone -> {(revname, target)}
    for ip, name in canonical.items():
        if name:
            want.setdefault(reverse_zone(ip), set()).add((reverse_name(ip),
                                                          name.lower()))
    p = {'zones': sorted(want), 'add': [], 'delete': [], 'created': 0,
         'deleted': 0, 'unchanged': 0, 'kept': 0}
    for z in p['zones']:
        ours, foreign = set(), set()
        for r in existing.get(z) or []:
            if (r.get('type') or '').upper() != 'PTR':
                continue
            key = ((r.get('name') or '').lower().rstrip('.'),
                   ((r.get('rData') or {}).get('ptrName') or '').lower().rstrip('.'))
            (ours if (r.get('comments') or '') == OWNER_TAG else foreign).add(key)
        desired_z = want[z]
        for key in sorted(desired_z - ours - foreign):
            p['add'].append((z,) + key)
            p['created'] += 1
        for key in sorted(ours - desired_z):
            p['delete'].append((z,) + key)
            p['deleted'] += 1
        p['unchanged'] += len(desired_z & ours)
        stale = sorted(foreign - desired_z)
        if mirror:
            for key in stale:
                p['delete'].append((z,) + key)
                p['deleted'] += 1
        else:
            p['kept'] += len(stale)
    return p


def sync_hosts(peer, hosts, client=None):
    zones = managed_zones(peer)
    if not zones:
        raise TechnitiumError('no managed zones configured on this target — '
                              'set the zone list (e.g. example.net) so the '
                              'adapter knows which zones it authors')
    mirror = bool(peer.get('technitium_delete_extra', False))
    desired = records_from_hosts(hosts)
    if not desired and mirror:
        raise TechnitiumError('no host records to push; refusing to empty the '
                              'managed zones')
    own = client is None
    if own:
        client = _connect(peer)
    try:
        have = set(client.zones())
        all_zones = list(zones)
        rev = None
        if peer.get('technitium_manage_reverse'):
            rev = plan_reverse(hosts, {}, mirror=mirror)   # zones known up front
            all_zones += [z for z in rev['zones'] if z not in zones]
        existing = {}
        for z in all_zones:
            if z not in have:
                client.create_zone(z)
            else:
                existing[z] = client.zone_records(z)
        p = plan_hosts(desired, zones, existing, mirror=mirror)
        summary = {'created': 0, 'updated': 0, 'deleted': 0, 'claimed': 0,
                   'unchanged': p['unchanged'], 'covered': p['covered'],
                   'conflicts': [], 'failed': 0, 'errors': []}

        def _run(fn, label):
            try:
                fn()
                return True
            except TechnitiumError as e:
                summary['failed'] += 1
                if len(summary['errors']) < 5:
                    summary['errors'].append('%s: %s' % (label, e))
                return False

        for z, name, rtype, value in p['add']:
            if _run(lambda: client.add_record(z, name, rtype, value), name):
                summary['created'] += 1
        for z, name, rtype, value in p['delete']:
            if _run(lambda: client.delete_record(z, name, rtype, value), name):
                summary['deleted'] += 1

        if rev is not None:
            rp = plan_reverse(hosts, existing, mirror=mirror)
            summary['unchanged'] += rp['unchanged']
            for z, name, target in rp['add']:
                if _run(lambda: client.add_record(z, name, 'PTR', target), name):
                    summary['created'] += 1
            for z, name, target in rp['delete']:
                if _run(lambda: client.delete_record(z, name, 'PTR', target), name):
                    summary['deleted'] += 1
        return summary
    finally:
        if own:
            client.close()


# ─── DHCP ──────────────────────────────────────────────────────────────

def scopes_from_payload(payload):
    """The dnsmasq-shaped `dhcp` section -> {scope name: fields}, keeping the
    tag as the scope name (which is what makes a scope OURS on the server).
    Unlike a Pi-hole, every range maps — Technitium is multi-scope."""
    by_tag = {}
    for o in payload.get('options') or []:
        field = OPTION_MAP.get(str(o.get('option') or '').lower())
        if field:
            by_tag.setdefault(o.get('tag') or '', {})[field] = o.get('value') or ''
    unknown = sorted({str(o.get('option')) for o in payload.get('options') or []
                      if str(o.get('option') or '').lower() not in OPTION_MAP})
    out = {}
    for r in payload.get('ranges') or []:
        tag = r.get('tag') or ''
        if not tag or not r.get('netmask'):
            continue
        try:
            subnet = ipaddress.ip_network('%s/%s' % (r.get('start'), r['netmask']),
                                          strict=False)
        except ValueError:
            continue
        out[tag] = {'start': r.get('start'), 'end': r.get('end'),
                    'netmask': r['netmask'], 'subnet': subnet,
                    'lease': lease_seconds(r.get('lease')),
                    'enabled': bool(r.get('enabled', True)),
                    'options': dict(by_tag.get(tag, {})),
                    'unsupported': unknown}
    return out


def _mac_dashed(mac):
    return str(mac).replace(':', '-').upper()


def scope_fields(name, scope, leases):
    """One scope's desired /api/dhcp/scopes/set parameters — the full mapped
    set every time, so the write is deterministic. dnsUpdates is forced off:
    in an IPAM-managed zone the server registering lease names would be a
    second writer."""
    s = int(scope['lease'])
    fields = {'name': name, 'startingAddress': scope['start'],
              'endingAddress': scope['end'], 'subnetMask': scope['netmask'],
              'leaseTimeDays': s // 86400, 'leaseTimeHours': (s % 86400) // 3600,
              'leaseTimeMinutes': (s % 3600) // 60,
              'dnsUpdates': 'false'}
    opts = scope['options']
    if opts.get('gateway'):
        fields['routerAddress'] = opts['gateway']
    if opts.get('dns'):
        fields['useThisDnsServer'] = 'false'
        fields['dnsServers'] = ','.join(d for d in str(opts['dns']).split(',') if d)
    if opts.get('domain'):
        fields['domainName'] = opts['domain']
    if opts.get('ntp'):
        fields['ntpServers'] = ','.join(d for d in str(opts['ntp']).split(',') if d)
    if opts.get('tftp'):
        fields['serverAddress'] = opts['tftp']
    if opts.get('bootfile'):
        fields['bootFileName'] = opts['bootfile']
    entries = []
    for l in leases:
        entries += [l.get('hostname') or '', _mac_dashed(l['mac']),
                    l['ip'], OWNER_TAG]
    fields['reservedLeases'] = '|'.join(entries)
    return fields


def _scope_current_matches(fields, cur):
    """Does the server's scope already state every field we would set?"""
    for k, v in fields.items():
        if k in ('name', 'reservedLeases'):
            continue
        have = cur.get(k)
        if k in ('dnsServers', 'ntpServers'):
            have = ','.join(have or [])
        if k in ('dnsUpdates', 'useThisDnsServer'):
            have = 'true' if have else 'false'
        if isinstance(have, bool):
            have = 'true' if have else 'false'
        if str(have if have is not None else '') != str(v):
            return False
    parts = fields['reservedLeases'].split('|') if fields['reservedLeases'] else []
    want_res = {tuple(parts[i:i + 4]) for i in range(0, len(parts), 4)}
    have_res = {(r.get('hostName') or '', r.get('hardwareAddress') or '',
                 r.get('address') or '', r.get('comments') or '')
                for r in cur.get('reservedLeases') or []}
    return want_res == have_res


def plan_dhcp(payload, scope_list, get_scope, mirror=False, manage_state=False):
    """Diff every payload scope against the server. `scope_list` is the
    scopes/list output; `get_scope(name)` fetches one config (only called for
    scopes that exist — pure enough to drive both sync and drift)."""
    desired = scopes_from_payload(payload or {})
    existing = {s['name']: s for s in scope_list}
    p = {'set': [], 'enable': [], 'disable': [], 'delete': [],
         'created': 0, 'updated': 0, 'deleted': 0, 'unchanged': 0,
         'conflicts': [], 'kept': 0, 'skipped_reservations': 0}

    by_scope = {name: [] for name in desired}
    for l in payload.get('static_leases') or []:
        home = next((name for name, sc in desired.items()
                     if ipaddress.ip_address(l['ip']) in sc['subnet']), None)
        if home is None:
            p['skipped_reservations'] += 1
        else:
            by_scope[home].append(l)

    for name, scope in sorted(desired.items()):
        fields = scope_fields(name, scope, by_scope[name])
        cur = existing.get(name)
        if cur is None:
            p['set'].append((fields, True))
            p['created'] += 1
        else:
            full = get_scope(name)
            if _scope_current_matches(fields, full):
                p['unchanged'] += 1
            else:
                p['set'].append((fields, False))
                p['updated'] += 1
            if manage_state and bool(cur.get('enabled')) != scope['enabled']:
                (p['enable'] if scope['enabled'] else p['disable']).append(name)
        for o in scope.get('unsupported') or []:
            if (o, 'in the plan', 'no Technitium equivalent') not in p['conflicts']:
                p['conflicts'].append((o, 'in the plan', 'no Technitium equivalent'))
        if scope['options'].get('wpad'):
            p['conflicts'].append(('option:wpad-url', 'in the plan',
                                   'not mapped for Technitium yet'))
    for name in sorted(set(existing) - set(desired)):
        if mirror:
            p['delete'].append(name)
            p['deleted'] += 1
        else:
            p['kept'] += 1
    return p


def sync_dhcp(peer, payload, client=None):
    mirror = bool(peer.get('technitium_dhcp_delete_extra', False))
    manage_state = bool(peer.get('technitium_manage_scope_state', False))
    if not (payload or {}).get('ranges') and mirror:
        raise TechnitiumError('no DHCP scopes to push; refusing to strip the server')
    own = client is None
    if own:
        client = _connect(peer)
    try:
        p = plan_dhcp(payload or {}, client.scopes(), client.scope,
                      mirror=mirror, manage_state=manage_state)
        summary = {'created': 0, 'updated': 0, 'deleted': 0, 'claimed': 0,
                   'unchanged': p['unchanged'], 'covered': 0,
                   'conflicts': p['conflicts'], 'failed': 0, 'errors': []}

        def _run(fn, label):
            try:
                fn()
                return True
            except TechnitiumError as e:
                summary['failed'] += 1
                if len(summary['errors']) < 5:
                    summary['errors'].append('%s: %s' % (label, e))
                return False

        for fields, is_new in p['set']:
            if _run(lambda: client.set_scope(**fields), fields['name']):
                summary['created' if is_new else 'updated'] += 1
        for name in p['enable']:
            _run(lambda: client.enable_scope(name), name)
        for name in p['disable']:
            _run(lambda: client.disable_scope(name), name)
        for name in p['delete']:
            if _run(lambda: client.delete_scope(name), name):
                summary['deleted'] += 1
        return summary
    finally:
        if own:
            client.close()


def read_leases(peer, client=None):
    """Dynamic leases; reserved ones are plan records and skipped, as in
    every other adapter. leaseExpires is an ISO timestamp — parsed
    best-effort, 0 when unparseable."""
    import datetime
    own = client is None
    if own:
        client = _connect(peer)
    try:
        out = []
        for l in client.dhcp_leases():
            if str(l.get('type') or '').lower() == 'reserved':
                continue
            ip = str(l.get('address') or '').strip()
            if not ip:
                continue
            expires = 0
            try:
                expires = int(datetime.datetime.fromisoformat(
                    str(l.get('leaseExpires'))).timestamp())
            except (ValueError, TypeError):
                pass
            out.append({'ip': ip,
                        'mac': str(l.get('hardwareAddress') or '')
                        .replace('-', ':').lower(),
                        'hostname': str(l.get('hostName') or '').rstrip('.'),
                        'expires': expires})
        return out
    finally:
        if own:
            client.close()


SECTION_SYNCERS = {'hosts': 'sync_hosts', 'dhcp': 'sync_dhcp'}


def syncer_for(section):
    name = SECTION_SYNCERS.get(section)
    return globals().get(name) if name else None
