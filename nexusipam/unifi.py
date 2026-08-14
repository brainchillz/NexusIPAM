"""UniFi Cloud Gateway adapter: pushes host records to a gateway's Static DNS.

VENDORED, deliberately, from DNSMAQ-MGR `dnsmaqmgr/unifi.py` — a verbatim
copy but for this note. Both apps stand alone and ship separately, so a
shared package would couple two release cycles to save one file; the same
call already made for static/css/style.css. UniFi has moved the Static DNS
endpoint before (hence the runtime probe below), so when this needs fixing,
fix it in both places.

A second *kind* of push target. Where a DNSMAQ-MGR node receives a mirror
payload on its own API, a UniFi gateway has no mirror endpoint — so this
module speaks the UniFi OS Network API directly and reconciles Static DNS
entries against our host records.

The records it consumes are exactly what pushout.build_hosts() already emits
for the mirror payload ({name, a, aaaa, enabled}), so no translation layer
sits between the address plan and the gateway.

Two UniFi behaviours shape the design:

* The Static DNS REST path moved between Network versions, so the endpoint is
  discovered at runtime rather than hardcoded.
* Besides Static DNS, UniFi keeps a per-client "Local DNS Record" on fixed-IP
  clients. It shadows Static DNS: creating a static entry for a name a client
  already owns is rejected with StaticDnsOverlapsWithDeviceLocalDns. Such
  names are either reported (default) or claimed — the client's record is
  unticked so ours can take over — under the peer's claim_client_dns option.

Stdlib only, matching the rest of the app. TLS verification modes are the same
strings the peer store already uses: 'system', 'insecure', 'fingerprint:<hex>'.
"""
import ssl
import json
import socket
import hashlib
import ipaddress
import http.client
import urllib.parse

TIMEOUT = 20

# Candidate Static DNS endpoints, newest first. 'v2' returns a bare list,
# 'v1' wraps it in {"meta":..., "data":[...]}.
ENDPOINTS = (
    ('/proxy/network/v2/api/site/%s/static-dns', 'v2'),
    ('/proxy/network/api/s/%s/rest/staticdns', 'v1'),
    ('/proxy/network/api/s/%s/rest/staticdnsentry', 'v1'),
)


class UniFiError(Exception):
    pass


class Overlap(UniFiError):
    """Name is owned by a client's Local DNS Record, so Static DNS is refused."""


def split_url(url, default_port=443):
    u = urllib.parse.urlparse(url)
    if u.scheme != 'https' or not u.hostname:
        raise UniFiError('Gateway URL must be https://host[:port]')
    return u.hostname, u.port or default_port


def ssl_context(verify):
    if verify == 'system':
        return ssl.create_default_context()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class HttpsSession:
    """Keep-alive HTTPS connection carrying cookies, with fingerprint pinning.

    UniFi OS authenticates with a TOKEN cookie, so cookies must persist across
    requests; http.client does not do that for us.
    """

    def __init__(self, url, verify='insecure', timeout=TIMEOUT, default_port=443):
        self.host, self.port = split_url(url, default_port)
        self.verify = verify or 'system'
        self.timeout = timeout
        self.cookies = {}
        self._conn = None

    def _connect(self):
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout,
                                           context=ssl_context(self.verify))
        conn.connect()
        if self.verify.startswith('fingerprint:'):
            der = conn.sock.getpeercert(binary_form=True)
            got = hashlib.sha256(der or b'').hexdigest()
            if got != self.verify.split(':', 1)[1]:
                conn.close()
                raise UniFiError('gateway certificate fingerprint mismatch (got %s…)'
                                 % got[:16])
        return conn

    def _store_cookies(self, resp):
        for raw in resp.headers.get_all('Set-Cookie') or []:
            pair = raw.split(';', 1)[0].strip()
            if '=' in pair:
                name, _, value = pair.partition('=')
                self.cookies[name.strip()] = value.strip()

    def request(self, method, path, body=None, headers=None):
        """Returns (status, parsed_json_or_text, response_headers)."""
        hdrs = dict(headers or {})
        if self.cookies:
            hdrs['Cookie'] = '; '.join('%s=%s' % kv for kv in self.cookies.items())
        payload = None
        if body is not None:
            payload = json.dumps(body)
            hdrs['Content-Type'] = 'application/json'

        # One retry: a keep-alive connection may have been closed server-side.
        for attempt in (1, 2):
            try:
                if self._conn is None:
                    self._conn = self._connect()
                self._conn.request(method, path, body=payload, headers=hdrs)
                resp = self._conn.getresponse()
                text = resp.read().decode(errors='replace')
                break
            except UniFiError:
                raise
            except (http.client.HTTPException, OSError, socket.error):
                self.close()
                if attempt == 2:
                    raise
        self._store_cookies(resp)
        try:
            data = json.loads(text) if text else None
        except ValueError:
            data = text
        return resp.status, data, resp.headers

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None


class UniFiClient:
    """Static DNS operations against one gateway."""

    def __init__(self, session, site='default'):
        self.s = session
        self.site = site
        self.csrf = None
        self._endpoint = None
        self._flavour = None

    # -- plumbing ---------------------------------------------------------

    def _req(self, method, path, body=None):
        headers = {}
        if self.csrf and method != 'GET':
            headers['X-CSRF-Token'] = self.csrf
        status, data, hdrs = self.s.request(method, path, body, headers)
        # UniFi OS rotates the CSRF token and returns the replacement.
        for key in ('x-updated-csrf-token', 'x-csrf-token'):
            if hdrs.get(key):
                self.csrf = hdrs.get(key)
        return status, data

    def login(self, username, password):
        status, data = self._req('POST', '/api/auth/login',
                                 {'username': username, 'password': password,
                                  'rememberMe': True})
        if status == 499 or (isinstance(data, dict) and 'ubic_2fa_token' in str(data)):
            raise UniFiError('gateway requires 2FA; use a local admin with MFA disabled')
        if status == 401:
            raise UniFiError('login rejected: bad username or password')
        if status >= 400:
            raise UniFiError('login failed: HTTP %s' % status)

    def logout(self):
        try:
            self._req('POST', '/api/auth/logout')
        except Exception:
            pass
        self.s.close()

    @staticmethod
    def _unwrap(data, flavour):
        if flavour == 'v1':
            return (data or {}).get('data') or [] if isinstance(data, dict) else []
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get('data') or []
        return []

    def endpoint(self):
        if self._endpoint:
            return self._endpoint
        tried = []
        for template, flavour in ENDPOINTS:
            path = template % self.site
            status, data = self._req('GET', path)
            if status == 200 and isinstance(data, (list, dict)):
                self._endpoint, self._flavour = path, flavour
                return path
            tried.append('%s -> HTTP %s' % (path, status))
        raise UniFiError('no Static DNS endpoint found (%s); needs UniFi Network 8.4+'
                         % '; '.join(tried))

    # -- static DNS -------------------------------------------------------

    def list_static(self):
        """Returns {(name, type): {'id':…, 'value':…, 'raw':…}} for A/AAAA only."""
        path = self.endpoint()
        status, data = self._req('GET', path)
        if status >= 400:
            raise UniFiError('listing Static DNS failed: HTTP %s' % status)
        out = {}
        for item in self._unwrap(data, self._flavour):
            if not isinstance(item, dict):
                continue
            rtype = (item.get('record_type') or item.get('type') or 'A').upper()
            if rtype not in ('A', 'AAAA'):
                continue  # leave CNAME/TXT/SRV/MX alone
            name = (item.get('key') or item.get('name') or '').rstrip('.')
            value = item.get('value') or ''
            rid = item.get('_id') or item.get('id') or ''
            if name and value and rid:
                out[(name.lower(), rtype)] = {'id': rid, 'value': value, 'raw': item}
        return out

    @staticmethod
    def _body(name, rtype, value, ttl=0):
        body = {'enabled': True, 'key': name, 'record_type': rtype, 'value': value}
        if ttl:
            body['ttl'] = ttl
        return body

    def create(self, name, rtype, value, ttl=0):
        status, data = self._req('POST', self.endpoint(),
                                 self._body(name, rtype, value, ttl))
        if status >= 400:
            if 'StaticDnsOverlapsWithDeviceLocalDns' in str(data):
                raise Overlap(name)
            raise UniFiError('create %s failed: HTTP %s' % (name, status))

    def update(self, entry, name, rtype, value, ttl=0):
        body = dict(entry.get('raw') or {})
        body.update(self._body(name, rtype, value, ttl))
        status, _ = self._req('PUT', '%s/%s' % (self.endpoint(), entry['id']), body)
        if status >= 400:
            raise UniFiError('update %s failed: HTTP %s' % (name, status))

    def delete(self, entry, name=''):
        status, _ = self._req('DELETE', '%s/%s' % (self.endpoint(), entry['id']))
        if status >= 400:
            raise UniFiError('delete %s failed: HTTP %s' % (name or entry['id'], status))

    # -- per-client Local DNS Records --------------------------------------

    def list_client_dns(self):
        """Returns {lowercased name: {'id':…, 'ip':…}} for enabled client records."""
        status, data = self._req('GET', '/proxy/network/api/s/%s/rest/user' % self.site)
        if status >= 400:
            return {}
        out = {}
        for c in (data or {}).get('data') or []:
            if not isinstance(c, dict):
                continue
            name = c.get('local_dns_record')
            if not name or not c.get('local_dns_record_enabled', True):
                continue
            ip = c.get('fixed_ip') or c.get('last_ip') or ''
            cid = c.get('_id') or ''
            if ip and cid:
                out[name.rstrip('.').lower()] = {'id': cid, 'ip': ip}
        return out

    # -- networks and DHCP -------------------------------------------------

    def list_networks(self):
        """{normalised subnet: raw network object} for LANs that define one."""
        status, data = self._req('GET', '/proxy/network/api/s/%s/rest/networkconf'
                                 % self.site)
        if status >= 400:
            raise UniFiError('listing networks failed: HTTP %s' % status)
        out = {}
        for n in (data or {}).get('data') or []:
            key = _subnet_key(n.get('ip_subnet') or '')
            if key and n.get('_id'):
                out[key] = n
        return out

    def update_network(self, entry, changes):
        """PUT the network with `changes` merged over it.

        Merged, never replaced: the object also carries VLAN id, purpose,
        IGMP and IPv6 configuration that this app does not model, and a PUT
        built only from our fields would blank all of it.
        """
        body = dict(entry)
        body.update(changes)
        status, data = self._req('PUT', '/proxy/network/api/s/%s/rest/networkconf/%s'
                                 % (self.site, entry['_id']), body)
        if status >= 400:
            raise UniFiError('updating %s failed: HTTP %s %s'
                             % (entry.get('name') or entry['_id'], status,
                                str(data)[:120]))

    def list_active(self):
        """Clients the gateway currently sees, with their addresses."""
        status, data = self._req('GET', '/proxy/network/api/s/%s/stat/sta' % self.site)
        if status >= 400:
            raise UniFiError('listing active clients failed: HTTP %s' % status)
        return [c for c in ((data or {}).get('data') or []) if isinstance(c, dict)]

    def list_fixed(self):
        """{mac: {'id', 'ip', 'network_id', 'name'}} for fixed-IP clients."""
        status, data = self._req('GET', '/proxy/network/api/s/%s/rest/user' % self.site)
        if status >= 400:
            raise UniFiError('listing clients failed: HTTP %s' % status)
        out = {}
        for c in (data or {}).get('data') or []:
            if not isinstance(c, dict) or not c.get('use_fixedip'):
                continue
            mac = (c.get('mac') or '').lower()
            if mac and c.get('fixed_ip') and c.get('_id'):
                out[mac] = {'id': c['_id'], 'ip': c['fixed_ip'],
                            'network_id': c.get('network_id') or '',
                            'name': c.get('name') or c.get('hostname') or '',
                            'raw': c}
        return out

    def set_fixed(self, mac, lease, networks, cur=None):
        """Bind mac -> ip. Updates the client when it already exists, creates
        one when it does not (an unknown device with a reservation waiting)."""
        body = {'mac': mac, 'use_fixedip': True, 'fixed_ip': lease['ip']}
        net = next((n for k, n in sorted(networks.items())
                    if in_subnet(lease['ip'], k)), None)
        if net is None:
            raise UniFiError('%s is not inside any network on this gateway'
                             % lease['ip'])
        body['network_id'] = net['_id']
        if cur:
            merged = dict(cur['raw'])
            merged.update(body)
            status, data = self._req(
                'PUT', '/proxy/network/api/s/%s/rest/user/%s' % (self.site, cur['id']),
                merged)
        else:
            if lease.get('hostname'):
                body['name'] = lease['hostname']
            status, data = self._req('POST', '/proxy/network/api/s/%s/rest/user'
                                     % self.site, body)
        if status >= 400:
            raise UniFiError('reservation for %s failed: HTTP %s %s'
                             % (mac, status, str(data)[:120]))

    def clear_fixed(self, cid, mac=''):
        """Withdraw a reservation by unsetting the flag — NOT by deleting the
        client, which would also discard its name, network and history."""
        status, _ = self._req(
            'PUT', '/proxy/network/api/s/%s/rest/user/%s' % (self.site, cid),
            {'use_fixedip': False})
        if status >= 400:
            raise UniFiError('could not clear the reservation for %s: HTTP %s'
                             % (mac, status))

    def release_client_dns(self, cid, name=''):
        """Untick a client's Local DNS Record. Only that flag is sent, so the
        DHCP reservation (fixed_ip / use_fixedip) is left untouched."""
        status, _ = self._req(
            'PUT', '/proxy/network/api/s/%s/rest/user/%s' % (self.site, cid),
            {'local_dns_record_enabled': False})
        if status >= 400:
            raise UniFiError('could not release client DNS for %s: HTTP %s'
                             % (name, status))


# ─── Reconciliation ────────────────────────────────────────────────────────

def records_from_hosts(hosts):
    """Host store records -> [(name, 'A'|'AAAA', value)], first mapping wins."""
    out, seen = [], set()
    for h in hosts or []:
        if not h.get('enabled', True):
            continue
        name = (h.get('name') or '').strip().rstrip('.')
        if not name:
            continue
        for field, rtype in (('a', 'A'), ('aaaa', 'AAAA')):
            value = (h.get(field) or '').strip()
            if not value:
                continue
            key = (name.lower(), rtype)
            if key in seen:
                continue
            seen.add(key)
            out.append((name, rtype, value))
    return out


def plan(desired, static, client_dns, mirror=True, claim=False):
    """Diff desired records against the gateway. Pure — no I/O, so it tests cheaply."""
    want = {(n.lower(), t): (n, t, v) for n, t, v in desired}
    p = {'create': [], 'update': [], 'delete': [], 'claim': [],
         'covered': [], 'conflicts': [], 'unchanged': 0}

    for key, (name, rtype, value) in want.items():
        owner = client_dns.get(name.lower())
        if owner is not None and key not in static:
            if claim:
                p['claim'].append((name, rtype, value, owner))
            elif owner['ip'] == value:
                p['covered'].append(name)
            else:
                p['conflicts'].append((name, value, owner['ip']))
            continue
        entry = static.get(key)
        if entry is None:
            p['create'].append((name, rtype, value))
        elif entry['value'] != value:
            p['update'].append((entry, name, rtype, value))
        else:
            p['unchanged'] += 1

    if mirror:
        for key, entry in static.items():
            if key not in want:
                p['delete'].append((entry, key[0]))
    return p


def sync_hosts(peer, hosts, client=None):
    """Reconcile a gateway's Static DNS with our host records.

    Returns a summary dict. Raises UniFiError if the gateway is unreachable or
    rejects the login — individual record failures are counted, not raised.
    """
    desired = records_from_hosts(hosts)
    if not desired and peer.get('unifi_delete_extra', False):
        raise UniFiError('no host records to push; refusing to wipe gateway Static DNS')

    own = client is None
    if own:
        session = HttpsSession(peer['url'], peer.get('verify', 'system'))
        client = UniFiClient(session, peer.get('unifi_site') or 'default')
        client.login(peer.get('unifi_username') or '', peer.get('unifi_password') or '')
    try:
        claim = bool(peer.get('unifi_claim_client_dns'))
        mirror = bool(peer.get('unifi_delete_extra', False))
        static = client.list_static()
        client_dns = client.list_client_dns()
        p = plan(desired, static, client_dns, mirror=mirror, claim=claim)

        summary = {'created': 0, 'updated': 0, 'deleted': 0, 'claimed': 0,
                   'unchanged': p['unchanged'], 'covered': len(p['covered']),
                   'conflicts': p['conflicts'], 'failed': 0, 'errors': []}

        def _run(fn, label):
            try:
                fn()
                return True
            except Overlap:
                summary['covered'] += 1
                return False
            except UniFiError as e:
                summary['failed'] += 1
                if len(summary['errors']) < 5:
                    summary['errors'].append('%s: %s' % (label, e))
                return False

        # Claim first — the client record must be released before the static
        # entry for that name is accepted.
        for name, rtype, value, owner in p['claim']:
            if not _run(lambda: client.release_client_dns(owner['id'], name), name):
                continue
            if _run(lambda: client.create(name, rtype, value), name):
                summary['claimed'] += 1
        for name, rtype, value in p['create']:
            if _run(lambda: client.create(name, rtype, value), name):
                summary['created'] += 1
        for entry, name, rtype, value in p['update']:
            if _run(lambda: client.update(entry, name, rtype, value), name):
                summary['updated'] += 1
        for entry, name in p['delete']:
            if _run(lambda: client.delete(entry, name), name):
                summary['deleted'] += 1
        return summary
    finally:
        if own:
            client.logout()


# ─── DHCP ──────────────────────────────────────────────────────────────────
#
# UniFi keeps DHCP on the NETWORK object (rest/networkconf) as named dhcpd_*
# fields, and fixed reservations on the CLIENT object (rest/user). Both are
# writable; the hosts-only limit this adapter shipped with described its own
# scope, not the API's.
#
# Two safety rules shape everything below:
#
#  * A network object also carries VLAN id, subnet, purpose, IGMP and IPv6
#    settings. Writes MERGE into the object as fetched — a full-object PUT
#    built from our fields alone would silently blank everything we do not
#    model.
#  * "Remove a reservation" unsets `use_fixedip`; it never deletes the client.
#    A UniFi client object is also the device's identity, name and history on
#    the gateway, and deleting it to withdraw an IP binding destroys far more
#    than was asked.

# dnsmasq option spelling -> the UniFi field(s) that carry it. Both spellings
# (name and bare code) map to the same place, because IPAM accepts both.
OPTION_MAP = {
    'option:router': 'gateway', '3': 'gateway',
    'option:dns-server': 'dns', '6': 'dns',
    'option:domain-name': 'domain', '15': 'domain',
    'option:ntp-server': 'ntp', '42': 'ntp',
    'option:tftp-server': 'tftp', '66': 'tftp',
    'option:bootfile-name': 'bootfile', '67': 'bootfile',
    'option:wpad-url': 'wpad', '252': 'wpad',
}

_LEASE_UNITS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}


def lease_seconds(text, default=86400):
    """dnsmasq lease ('24h', '90m', '3600', 'infinite') -> seconds."""
    s = str(text or '').strip().lower()
    if not s or s == 'infinite':
        return default
    unit = _LEASE_UNITS.get(s[-1])
    try:
        return int(s[:-1]) * unit if unit else int(s)
    except ValueError:
        return default


def _subnet_key(value):
    """Normalise anything subnet-shaped to its network address form, so a
    gateway's '10.0.0.1/24' matches a plan's '10.0.0.0/24'."""
    try:
        return str(ipaddress.ip_network(str(value).strip(), strict=False))
    except ValueError:
        return ''


def in_subnet(ip, subnet_key):
    try:
        return ipaddress.ip_address(str(ip)) in ipaddress.ip_network(subnet_key)
    except ValueError:
        return False


def desired_dhcp(payload):
    """The dnsmasq-shaped `dhcp` section -> {subnet: scope} for diffing.

    Ranges carry a netmask, so the subnet each belongs to is derivable without
    the gateway's help — which keeps this function pure.
    """
    by_tag = {}
    for o in payload.get('options') or []:
        field = OPTION_MAP.get(str(o.get('option') or '').lower())
        if field:
            by_tag.setdefault(o.get('tag') or '', {})[field] = o.get('value') or ''
    out = {}
    for r in payload.get('ranges') or []:
        key = _subnet_key('%s/%s' % (r.get('start'), r.get('netmask')))
        if not key:
            continue
        scope = out.setdefault(key, {'options': {}, 'unsupported': []})
        scope.update({'start': r.get('start'), 'end': r.get('end'),
                      'lease': lease_seconds(r.get('lease')),
                      'enabled': bool(r.get('enabled', True))})
        scope['options'].update(by_tag.get(r.get('tag') or '', {}))
    # Anything we cannot express is REPORTED, never dropped on the floor: a
    # silently ignored option looks identical to a satisfied one.
    unknown = sorted({str(o.get('option')) for o in payload.get('options') or []
                      if str(o.get('option') or '').lower() not in OPTION_MAP})
    for scope in out.values():
        scope['unsupported'] = unknown
    return out


def _scope_changes(scope, raw, manage_state):
    """The dhcpd_* fields that differ from what the gateway holds."""
    want = {'dhcpd_start': scope['start'], 'dhcpd_stop': scope['end'],
            'dhcpd_leasetime': scope['lease']}
    opts = scope['options']
    if opts.get('gateway'):
        want.update({'dhcpd_gateway_enabled': True,
                     'dhcpd_gateway': opts['gateway']})
    if opts.get('dns'):
        servers = [d for d in str(opts['dns']).split(',') if d][:4]
        want['dhcpd_dns_enabled'] = True
        for i in range(1, 5):
            want['dhcpd_dns_%d' % i] = servers[i - 1] if i <= len(servers) else ''
    if opts.get('domain'):
        want['domain_name'] = opts['domain']
    if opts.get('ntp'):
        servers = [d for d in str(opts['ntp']).split(',') if d][:2]
        want['dhcpd_ntp_enabled'] = True
        for i in range(1, 3):
            want['dhcpd_ntp_%d' % i] = servers[i - 1] if i <= len(servers) else ''
    if opts.get('tftp'):
        want['dhcpd_tftp_server'] = opts['tftp']
    if opts.get('bootfile'):
        want.update({'dhcpd_boot_enabled': True,
                     'dhcpd_boot_filename': opts['bootfile']})
        if opts.get('tftp'):
            want['dhcpd_boot_server'] = opts['tftp']
    if opts.get('wpad'):
        want['dhcpd_wpad_url'] = opts['wpad']
    # Turning a VLAN's DHCP server off is not a config tweak, it is an outage.
    # Only touched when the operator has explicitly asked us to own that.
    if manage_state:
        want['dhcpd_enabled'] = scope['enabled']
    return {k: v for k, v in want.items() if raw.get(k) != v}


def plan_dhcp(desired, networks, fixed, leases, mirror=False, manage_state=False):
    """Pure diff. `networks` is {subnet: raw}, `fixed` {mac: {...}}, `leases`
    the desired reservations. Returns the same plan vocabulary as plan()."""
    p = {'scopes': [], 'fixed_set': [], 'fixed_clear': [], 'unmatched': [],
         'unsupported': [], 'unchanged': 0}
    for key, scope in sorted(desired.items()):
        entry = networks.get(key)
        if entry is None:
            p['unmatched'].append(key)      # no such network on the gateway
            continue
        changes = _scope_changes(scope, entry, manage_state)
        if changes:
            p['scopes'].append((entry, key, changes))
        else:
            p['unchanged'] += 1
        for o in scope.get('unsupported') or []:
            if o not in p['unsupported']:
                p['unsupported'].append(o)

    want = {l['mac'].lower(): l for l in leases if l.get('mac') and l.get('ip')}
    for mac, l in sorted(want.items()):
        cur = fixed.get(mac)
        if cur is None or cur.get('ip') != l['ip']:
            p['fixed_set'].append((mac, l, cur))
        else:
            p['unchanged'] += 1
    if mirror:
        for mac, cur in sorted(fixed.items()):
            if mac not in want:
                p['fixed_clear'].append((mac, cur))
    return p


def sync_dhcp(peer, payload, client=None):
    """Reconcile a gateway's DHCP scopes and reservations with the plan."""
    desired = desired_dhcp(payload or {})
    mirror = bool(peer.get('unifi_delete_extra', False))
    manage_state = bool(peer.get('unifi_manage_scope_state', False))
    if not desired and mirror:
        raise UniFiError('no DHCP scopes to push; refusing to strip the gateway')

    own = client is None
    if own:
        session = HttpsSession(peer['url'], peer.get('verify', 'system'))
        client = UniFiClient(session, peer.get('unifi_site') or 'default')
        client.login(peer.get('unifi_username') or '', peer.get('unifi_password') or '')
    try:
        networks = client.list_networks()
        fixed = client.list_fixed()
        p = plan_dhcp(desired, networks, fixed, payload.get('static_leases') or [],
                      mirror=mirror, manage_state=manage_state)
        summary = {'created': 0, 'updated': 0, 'deleted': 0, 'claimed': 0,
                   'unchanged': p['unchanged'], 'covered': 0, 'failed': 0,
                   'conflicts': [], 'errors': []}

        def _run(fn, label):
            try:
                fn()
                return True
            except UniFiError as e:
                summary['failed'] += 1
                if len(summary['errors']) < 5:
                    summary['errors'].append('%s: %s' % (label, e))
                return False

        for entry, key, changes in p['scopes']:
            if _run(lambda: client.update_network(entry, changes), key):
                summary['updated'] += 1
        for mac, l, cur in p['fixed_set']:
            if _run(lambda: client.set_fixed(mac, l, networks, cur), mac):
                summary['created' if cur is None else 'updated'] += 1
        for mac, cur in p['fixed_clear']:
            if _run(lambda: client.clear_fixed(cur['id'], mac), mac):
                summary['deleted'] += 1
        # Surfaced as conflicts so the push reports FAILED rather than a
        # cheerful "unchanged" while part of the plan never arrived.
        for key in p['unmatched']:
            summary['conflicts'].append((key, 'in the plan', 'no such network on the gateway'))
        for opt in p['unsupported']:
            summary['conflicts'].append((opt, 'in the plan', 'no UniFi equivalent'))
        return summary
    finally:
        if own:
            client.logout()


def _opts_from_network(n):
    """The gateway's dhcpd_* fields -> dnsmasq option spellings.

    Only what the gateway is actually handing out: UniFi keeps stale values in
    the disabled fields (an old NTP server sits in dhcpd_ntp_1 with
    dhcpd_ntp_enabled false), and adopting those would put addresses into the
    plan that no client has ever been told about.
    """
    out = {}
    if n.get('dhcpd_gateway_enabled') and n.get('dhcpd_gateway'):
        out['option:router'] = n['dhcpd_gateway']
    if n.get('dhcpd_dns_enabled'):
        dns = [n.get('dhcpd_dns_%d' % i) for i in (1, 2, 3, 4)]
        dns = [d for d in dns if d]
        if dns:
            out['option:dns-server'] = ','.join(dns)
    if n.get('dhcpd_ntp_enabled'):
        ntp = [n.get('dhcpd_ntp_%d' % i) for i in (1, 2) if n.get('dhcpd_ntp_%d' % i)]
        if ntp:
            out['option:ntp-server'] = ','.join(ntp)
    if n.get('dhcpd_tftp_server'):
        out['option:tftp-server'] = n['dhcpd_tftp_server']
    if n.get('dhcpd_boot_enabled') and n.get('dhcpd_boot_filename'):
        out['option:bootfile-name'] = n['dhcpd_boot_filename']
        if n.get('dhcpd_boot_server'):
            out['option:tftp-server'] = n['dhcpd_boot_server']
    if n.get('dhcpd_wpad_url'):
        out['option:wpad-url'] = n['dhcpd_wpad_url']
    return out


def read_leases(peer, client=None):
    """Currently-leased addresses, as the gateway sees them right now.

    Observed, never authored: the caller stores this as a disposable overlay.
    Clients with a fixed IP are skipped — that binding is a plan record, not a
    dynamic lease, and listing it as both double-counts the address.
    """
    own = client is None
    if own:
        session = HttpsSession(peer['url'], peer.get('verify', 'system'))
        client = UniFiClient(session, peer.get('unifi_site') or 'default')
        client.login(peer.get('unifi_username') or '', peer.get('unifi_password') or '')
    try:
        out = []
        for c in client.list_active():
            ip = (c.get('ip') or '').strip()
            if not ip or c.get('use_fixedip'):
                continue
            out.append({'ip': ip, 'mac': (c.get('mac') or '').lower(),
                        'hostname': (c.get('hostname') or c.get('name') or '').strip(),
                        'expires': int(c.get('dhcpend_time') or 0)})
        return out
    finally:
        if own:
            client.logout()


def read_state(peer, client=None):
    """Everything IPAM can adopt from a gateway, in ITS OWN vocabulary.

    This is the inverse of sync_dhcp and the starting point for a site whose
    DHCP already lives on the gateway: pull the truth in once, then author it
    here. Returns networks (each with its scope and options) and every fixed
    reservation.
    """
    own = client is None
    if own:
        session = HttpsSession(peer['url'], peer.get('verify', 'system'))
        client = UniFiClient(session, peer.get('unifi_site') or 'default')
        client.login(peer.get('unifi_username') or '', peer.get('unifi_password') or '')
    try:
        nets, fixed = client.list_networks(), client.list_fixed()
        out = {'networks': [], 'reservations': []}
        for cidr, n in sorted(nets.items()):
            iface = None
            try:
                iface = ipaddress.ip_interface(n.get('ip_subnet') or '')
            except ValueError:
                pass
            rec = {'cidr': cidr, 'ext_id': n.get('_id') or '',
                   'name': n.get('name') or '',
                   'vlan': n.get('vlan') if n.get('vlan_enabled') else None,
                   # The gateway's own interface is the segment's router, and
                   # UniFi only stores dhcpd_gateway when it is something else.
                   'gateway': n.get('dhcpd_gateway') if n.get('dhcpd_gateway_enabled')
                              else (str(iface.ip) if iface else ''),
                   'domain': n.get('domain_name') or '',
                   'options': _opts_from_network(n), 'range': None}
            dns = [n.get('dhcpd_dns_%d' % i) for i in (1, 2, 3, 4)]
            rec['dns'] = [d for d in dns if d] if n.get('dhcpd_dns_enabled') else []
            if n.get('dhcpd_start') and n.get('dhcpd_stop'):
                # Imported whether or not DHCP is switched on: a defined range
                # consumes that space regardless, which is the whole point of
                # recording it. `enabled` carries the distinction.
                rec['range'] = {'start': n['dhcpd_start'], 'end': n['dhcpd_stop'],
                                'lease': '%dh' % max(1, lease_seconds(
                                    n.get('dhcpd_leasetime'), 86400) // 3600),
                                'enabled': bool(n.get('dhcpd_enabled'))}
            out['networks'].append(rec)
        for mac, f in sorted(fixed.items()):
            out['reservations'].append({'mac': mac, 'ip': f['ip'],
                                        'hostname': f.get('name') or '',
                                        'ext_id': f.get('id') or ''})
        return out
    finally:
        if own:
            client.logout()


# Which sections this adapter can reconcile. Registering a section here is
# what makes it pushable to a gateway at all — a section with no syncer is
# skipped rather than silently reported as applied.
#
# Mapped to the FUNCTION NAME, resolved at call time, not to the function
# object: binding at import would freeze whatever was defined then, so the
# module attribute would stop being the single source of truth (and could not
# be substituted in tests).
SECTION_SYNCERS = {'hosts': 'sync_hosts', 'dhcp': 'sync_dhcp'}


def syncer_for(section):
    name = SECTION_SYNCERS.get(section)
    return globals().get(name) if name else None


def status_line(summary):
    """Condense a sync summary into the peer store's last_status string."""
    if summary['failed']:
        detail = summary['errors'][0] if summary['errors'] else ''
        return 'error: %d write(s) failed%s' % (summary['failed'],
                                                ' (%s)' % detail if detail else '')
    if summary['conflicts']:
        name, ours, theirs = summary['conflicts'][0]
        extra = ' +%d more' % (len(summary['conflicts']) - 1) \
            if len(summary['conflicts']) > 1 else ''
        return 'error: client DNS holds %s at %s, not %s%s' % (name, theirs, ours, extra)
    return 'ok'
