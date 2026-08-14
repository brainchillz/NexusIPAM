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


# Which sections this adapter can reconcile. Registering a section here is
# what makes it pushable to a gateway at all — a section with no syncer is
# skipped rather than silently reported as applied.
#
# Mapped to the FUNCTION NAME, resolved at call time, not to the function
# object: binding at import would freeze whatever was defined then, so the
# module attribute would stop being the single source of truth (and could not
# be substituted in tests).
SECTION_SYNCERS = {'hosts': 'sync_hosts'}


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
