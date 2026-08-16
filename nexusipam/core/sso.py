"""Optional single sign-on: verify an assertion from a Nexus SSO issuer.

OFF unless NEXUSIPAM_SSO_ISSUER is set, and off is the default everywhere. A
node with no issuer configured registers no route, evaluates no branch, and is
byte-identical to a node without this file — the route-map goldens are the
proof of that, not a promise.

Deliberately narrow, and narrower than the original design called for: an
assertion is accepted at exactly ONE endpoint, /sso/callback, where it is
exchanged for an ordinary session cookie. It is never accepted as a general
bearer credential, so `_resolve_identity` is untouched and no API endpoint
gains a new way in. Machines keep using API tokens; this is a browser feature.

Scope of what an assertion can do, once verified:
  * It names a subject. That subject must ALREADY have a local account —
    SSO grants access to accounts that exist, it never creates them.
  * It carries no role. The local user record decides the role, exactly as it
    does after a password login.
So the worst a compromised issuer can do is log in as an existing local user;
it cannot invent an admin on a node that has none.
"""
import os
import json
import time
import threading

from .config import env_bool, DATA_DIR, write_json_atomic
from . import ed25519

ALG = 'EdDSA'
TYP = 'nxa'
CLOCK_SKEW = 30

SSO_ISSUER = os.environ.get('NEXUSIPAM_SSO_ISSUER', '').rstrip('/')
SSO_PUBKEY = os.environ.get('NEXUSIPAM_SSO_PUBKEY', '')
SSO_KID = os.environ.get('NEXUSIPAM_SSO_KID', '')
# Which audience this node answers to. Must match the id registered at the
# issuer; defaults to the hostname because that is what an operator naturally
# registers.
SSO_AUDIENCE = os.environ.get('NEXUSIPAM_SSO_AUDIENCE', '')
# Send unauthenticated browsers straight to the issuer instead of showing the
# local password box. Off by default: the local login must stay reachable, or
# an issuer outage locks the node out of its own UI.
SSO_AUTO_REDIRECT = env_bool('NEXUSIPAM_SSO_AUTO_REDIRECT', False)

# Runtime-enrolled configuration, written by the Settings page after redeeming
# an enrollment code. Lives with the other state next to app.py — which in a
# container is the data volume, so an enrollment survives a rebuild without
# touching the image or .env.
STORE = os.path.join(DATA_DIR, 'sso.json')


def _stored():
    try:
        with open(STORE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def config():
    """Resolve the active configuration, or None.

    The environment WINS. That is the whole opt-in model: an operator who
    wants this decision fixed at install time sets the env vars, and the UI
    can then only report it. Leaving them unset is what delegates the choice
    to an admin in the UI.
    """
    if SSO_ISSUER:
        return {'issuer': SSO_ISSUER, 'pubkey': SSO_PUBKEY, 'kid': SSO_KID,
                'audience': SSO_AUDIENCE or _hostname(),
                'auto_redirect': SSO_AUTO_REDIRECT, 'source': 'env'}
    s = _stored()
    if s.get('issuer') and s.get('pubkey'):
        return {'issuer': str(s['issuer']).rstrip('/'),
                'pubkey': str(s['pubkey']), 'kid': str(s.get('kid') or ''),
                'audience': str(s.get('audience') or _hostname()),
                'auto_redirect': bool(s.get('auto_redirect')),
                'source': 'stored'}
    return None


def locked():
    """True when the host configuration fixes this and the UI must not edit."""
    return bool(SSO_ISSUER)


def save_stored(issuer, pubkey, kid, aud):
    write_json_atomic(STORE, {'issuer': str(issuer).rstrip('/'),
                              'pubkey': pubkey, 'kid': kid, 'audience': aud},
                      0o600)


def clear_stored():
    try:
        os.unlink(STORE)
        return True
    except FileNotFoundError:
        return False


def _hostname():
    import socket
    return socket.gethostname()


def _pubkey_bytes(cfg=None):
    import base64
    cfg = cfg if cfg is not None else config()
    s = (cfg or {}).get('pubkey', '')
    try:
        return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    except Exception:
        return b''


def audience():
    cfg = config()
    return (cfg or {}).get('audience') or _hostname()


def enabled():
    """True only when fully configured. A half-configured node behaves as if
    SSO were off rather than failing at login time."""
    cfg = config()
    return bool(cfg) and len(_pubkey_bytes(cfg)) == 32


def login_hint():
    """What the login screen needs in order to offer SSO. Public values only —
    this is served to unauthenticated callers."""
    cfg = config() or {}
    return {'issuer': cfg.get('issuer', ''), 'audience': audience(),
            'auto_redirect': bool(cfg.get('auto_redirect'))}


def authorize_url(next_path='/'):
    from urllib.parse import urlencode
    cfg = config() or {}
    return (cfg.get('issuer', '') + '/sso/authorize?'
            + urlencode({'aud': audience(), 'next': safe_next(next_path)}))


def redeem(issuer, code, timeout=15):
    """Redeem an enrollment code at `issuer`. Returns (result, None) or
    (None, error).

    stdlib only — urllib, like everything else here, so enrollment adds no
    dependency either. The issuer's certificate is very likely self-signed or
    signed by a private CA, so verification is not attempted; what makes this
    safe is that nothing secret is sent (the code is single-use and worthless
    once redeemed) and nothing secret comes back (the response is the same
    public key /sso/jwks already serves to anyone). An interceptor could point
    the node at a bogus issuer, but only by already controlling the network
    path an admin just typed a URL into.
    """
    import ssl as _ssl
    import urllib.request
    import urllib.error

    body = json.dumps({'code': code, 'callback': _callback_url()}).encode()
    req = urllib.request.Request(issuer.rstrip('/') + '/sso/enroll', data=body,
                                 headers={'Content-Type': 'application/json'},
                                 method='POST')
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as ex:
        try:
            return None, (json.loads(ex.read().decode()).get('error')
                          or 'Issuer refused the code (HTTP %d)' % ex.code)
        except Exception:
            return None, 'Issuer refused the code (HTTP %d)' % ex.code
    except Exception as ex:
        return None, 'Could not reach the issuer: %s' % ex
    if not data.get('success'):
        return None, data.get('error') or 'Enrollment failed'
    for k in ('issuer', 'key', 'audience'):
        if not data.get(k):
            return None, 'Issuer response was missing %r' % k
    return data, None


def _callback_url():
    """The address the issuer should send the browser back to. Derived from
    the request the admin is making, so it is whatever hostname they actually
    reach this node on — which is the one their browser must be able to use."""
    try:
        from flask import request
        return request.host_url.rstrip('/') + '/sso/callback'
    except Exception:
        return ''


def safe_next(value):
    """Reduce a caller-supplied path to something same-site. Anything that
    could send the browser elsewhere collapses to '/'."""
    if not value or not isinstance(value, str) or len(value) > 512:
        return '/'
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in value):
        return '/'
    value = value.replace('\\', '/')
    if not value.startswith('/') or value.startswith('//'):
        return '/'
    return value


# ─── replay cache ──────────────────────────────────────────────────────
# Assertions are single-use. The cache only has to outlive an assertion's own
# lifetime, so entries are dropped once they cannot possibly still verify.
_seen = {}
_seen_lock = threading.Lock()


def _remember(jti, exp, now=None):
    """Record a jti as spent. False if it was already spent.

    `now` comes from the caller so the cache and the expiry check share one
    clock — reading time.time() here instead would give the verifier two
    different notions of 'now'.
    """
    now = int(now if now is not None else time.time())
    with _seen_lock:
        for k, v in list(_seen.items()):
            if v <= now:
                del _seen[k]
        if jti in _seen:
            return False
        _seen[jti] = exp
        return True


def _b64u_decode(s):
    import base64
    if isinstance(s, str):
        s = s.encode()
    return base64.urlsafe_b64decode(s + b'=' * (-len(s) % 4))


def verify(token, now=None):
    """Verify an assertion and return its subject, or None.

    Never raises: every rejection path returns None, so the caller can hand it
    whatever arrived in the query string.
    """
    cfg = config()
    if not cfg or len(_pubkey_bytes(cfg)) != 32:
        return None
    now = int(now if now is not None else time.time())
    if not token or not isinstance(token, str) or token.count('.') != 2:
        return None
    h_b64, p_b64, s_b64 = token.split('.')
    try:
        header = json.loads(_b64u_decode(h_b64))
        payload = json.loads(_b64u_decode(p_b64))
        sig = _b64u_decode(s_b64)
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    # The algorithm is pinned, so "alg": "none" and HMAC key confusion are not
    # reachable. There is no kid-directed key lookup either — this node knows
    # the one key it trusts.
    if header.get('alg') != ALG or header.get('typ') != TYP:
        return None
    if cfg.get('kid') and header.get('kid') != cfg['kid']:
        return None
    if not ed25519.verify(_pubkey_bytes(cfg), (h_b64 + '.' + p_b64).encode(), sig):
        return None

    # Claims are trusted only after the signature checks out.
    if payload.get('iss') != cfg['issuer']:
        return None
    if payload.get('aud') != cfg['audience']:
        return None
    exp, iat = payload.get('exp'), payload.get('iat')
    if not isinstance(exp, int) or not isinstance(iat, int):
        return None
    if now >= exp or iat > now + CLOCK_SKEW:
        return None
    sub = payload.get('sub')
    if not isinstance(sub, str) or not sub:
        return None
    jti = payload.get('jti')
    if not isinstance(jti, str) or not jti or not _remember(jti, exp, now):
        return None
    return sub
