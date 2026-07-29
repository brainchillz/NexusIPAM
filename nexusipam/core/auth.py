"""Authentication, users, API tokens and RBAC — adapted from DNSMAQ-MGR
core/auth.py so both apps behave identically for an operator (and so a script
that talks to one can talk to the other with the same token pattern).

Model:
  * Session login for the UI, PBKDF2 hashes (werkzeug.security). A
    before_request guard (require_login, registered app-wide by create_app)
    protects everything except PUBLIC_ENDPOINTS.
  * Credentials + the session secret live in auth.json (mode 0600, in
    DATA_DIR; override via NEXUSIPAM_AUTH_FILE).
  * RBAC is central and method-based: any POST/PUT/DELETE/PATCH from a
    non-admin identity is refused 403 (RBAC_EXEMPT excepted). Identity comes
    from the session cookie OR an API token (Authorization: Bearer /
    X-API-Token); tokens store only a SHA-256, compared constant-time.

This is what makes the "read-only API or writable API" split work: mint a
readonly token for anything that only queries (monitoring, dashboards), an
admin token for anything that creates records (VC-Deployer, importers).
"""
import os
import re
import json
import time
import hmac
import socket
import hashlib
import secrets
from datetime import datetime
from flask import Blueprint, jsonify, request, session, g
from werkzeug.security import generate_password_hash, check_password_hash

from .config import DATA_DIR, APP_VERSION, write_json_atomic
from .runcmd import err

bp = Blueprint('auth', __name__)

AUTH_FILE = os.environ.get('NEXUSIPAM_AUTH_FILE', os.path.join(DATA_DIR, 'auth.json'))
RE_USERNAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')
MIN_PASSWORD_LEN = 8

# Compared against when a username is unknown, so a missing user costs the
# same time as a wrong password (no user enumeration via timing).
_DUMMY_HASH = generate_password_hash('nexus-ipam-dummy')

# In-memory brute-force throttle, keyed by client IP.
_LOGIN_FAILS = {}
LOCKOUT_MAX = 5
LOCKOUT_WINDOW = 300  # seconds

# Endpoints reachable without a session (BARE endpoint names — the blueprint
# prefix is stripped before comparison).
PUBLIC_ENDPOINTS = {'api_login', 'api_me', 'api_version', 'index', 'static'}

# Mutating endpoints a non-admin (read-only) account is still allowed to call.
RBAC_EXEMPT = {'api_logout', 'change_password'}

TOKEN_PREFIX = 'nx_'


def load_config():
    try:
        with open(AUTH_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_config(cfg):
    write_json_atomic(AUTH_FILE, cfg, 0o600)


def _users():
    return load_config().get('users', {})


def _user_hash(rec):
    return rec if isinstance(rec, str) else (rec or {}).get('password', '')


def _user_role(rec):
    return 'admin' if isinstance(rec, str) else (rec or {}).get('role', 'admin')


def _count_admins(users):
    return sum(1 for r in users.values() if _user_role(r) == 'admin')


def _is_admin():
    return getattr(g, 'identity_role', None) == 'admin'


def actor():
    """Who is making this request — used for the audit log."""
    return getattr(g, 'identity_name', '') or 'system'


# ─── API tokens (for automation; bearer auth, no session cookie) ───────

def _tokens():
    return load_config().get('tokens', [])


def _hash_token(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


def _bearer_token():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:].strip()
    return (request.headers.get('X-API-Token') or '').strip()


def _resolve_token(secret):
    """Return the matching token record (constant-time compare), or None."""
    if not secret or not secret.startswith(TOKEN_PREFIX):
        return None
    h = _hash_token(secret)
    for rec in _tokens():
        if hmac.compare_digest(rec.get('hash', ''), h):
            return rec
    return None


def _touch_token(rec):
    """Record last-used at day granularity (bounds writes to once/day/token)."""
    today = datetime.now().strftime('%Y-%m-%d')
    if rec.get('last_used') == today:
        return
    cfg = load_config()
    for t in cfg.get('tokens', []):
        if t.get('id') == rec.get('id'):
            t['last_used'] = today
            save_config(cfg)
            return


def _resolve_identity():
    """Resolve the caller to (name, role) from the session cookie or an API
    token. Returns (None, None) if unauthenticated."""
    user = session.get('user')
    if user:
        return user, _user_role(_users().get(user))
    rec = _resolve_token(_bearer_token())
    if rec:
        _touch_token(rec)
        return 'token:' + rec.get('name', '?'), rec.get('role', 'readonly')
    return None, None


def ensure_bootstrap():
    """Ensure a session secret and at least one user exist. Returns the config."""
    cfg = load_config()
    changed = False
    if not cfg.get('secret_key'):
        cfg['secret_key'] = secrets.token_hex(32)
        changed = True
    if not cfg.get('users'):
        pw = os.environ.get('NEXUSIPAM_ADMIN_PASSWORD')
        generated = not pw
        if not pw:
            pw = secrets.token_urlsafe(12)
        cfg.setdefault('users', {})['admin'] = {'password': generate_password_hash(pw),
                                                'role': 'admin',
                                                'must_change': generated}
        changed = True
        if generated:
            print('=' * 64, flush=True)
            print('Nexus IPAM: created initial admin account', flush=True)
            print('  username: admin', flush=True)
            print(f'  password: {pw}', flush=True)
            print('  Change it from the UI, or: python nexus-ipam.py set-password admin', flush=True)
            print('=' * 64, flush=True)
    if changed:
        save_config(cfg)
    return cfg


def _bare_endpoint(endpoint):
    """Blueprint routes get 'bp.func' endpoint names; the public/RBAC sets use
    bare function names so they stay stable across refactors."""
    return (endpoint or '').rsplit('.', 1)[-1]


def require_login():
    """App-wide before_request guard (registered by create_app)."""
    if _bare_endpoint(request.endpoint) in PUBLIC_ENDPOINTS:
        return None
    name, role = _resolve_identity()
    if not name:
        return jsonify({'success': False, 'error': 'Authentication required'}), 401
    g.identity_name = name
    g.identity_role = role
    # Role check: read-only identities may view (GET) but not change anything.
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH') and \
            _bare_endpoint(request.endpoint) not in RBAC_EXEMPT:
        if role != 'admin':
            return jsonify({'success': False,
                            'error': 'Read-only account: action not permitted'}), 403
    return None


# ─── Routes ────────────────────────────────────────────────────────────

@bp.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    ip = request.remote_addr or '?'

    cnt, first = _LOGIN_FAILS.get(ip, (0, 0))
    now = time.time()
    if now - first > LOCKOUT_WINDOW:
        cnt, first = 0, now
    if cnt >= LOCKOUT_MAX:
        return jsonify({'success': False, 'error': 'Too many attempts; try again later'}), 429

    rec = load_config().get('users', {}).get(username)
    if rec and check_password_hash(_user_hash(rec), password):
        _LOGIN_FAILS.pop(ip, None)
        session.clear()
        session['user'] = username
        session.permanent = True
        return jsonify({'success': True, 'user': username, 'role': _user_role(rec),
                        'must_change': bool(isinstance(rec, dict) and rec.get('must_change')),
                        'fqdn': socket.getfqdn()})

    check_password_hash(_DUMMY_HASH, password)  # equalize timing for unknown users
    _LOGIN_FAILS[ip] = (cnt + 1, first or now)
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401


@bp.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})


@bp.route('/api/me')
def api_me():
    # api_me is a PUBLIC_ENDPOINT, so it must resolve identity itself
    # (require_login, which sets g.identity_*, is skipped for public endpoints).
    name, role = _resolve_identity()
    if not name:
        return jsonify({'authenticated': False}), 401
    rec = _users().get(name) if not str(name).startswith('token:') else None
    return jsonify({'authenticated': True, 'user': name, 'role': role,
                    'must_change': bool(isinstance(rec, dict) and rec.get('must_change')),
                    'fqdn': socket.getfqdn(),
                    'version': APP_VERSION})


@bp.route('/api/version')
def api_version():
    return jsonify({'app': 'nexus-ipam', 'version': APP_VERSION, 'fqdn': socket.getfqdn()})


@bp.route('/api/account/password', methods=['POST'])
def change_password():
    data = request.get_json() or {}
    old = data.get('old_password') or ''
    new = data.get('new_password') or ''
    user = session.get('user')  # session-only; not applicable to API tokens
    if not user:
        return err('Only an interactive session can change a password', 401)
    cfg = load_config()
    rec = cfg.get('users', {}).get(user)
    if not rec or not check_password_hash(_user_hash(rec), old):
        return err('Current password is incorrect')
    if len(new) < MIN_PASSWORD_LEN:
        return err(f'New password must be at least {MIN_PASSWORD_LEN} characters')
    if isinstance(rec, str):
        rec = {'password': '', 'role': 'admin'}
    rec['password'] = generate_password_hash(new)
    rec.pop('must_change', None)  # first-run forced change satisfied
    cfg['users'][user] = rec
    save_config(cfg)
    return jsonify({'success': True})


# ─── User management (admin only) ─────────────────────────────────────

@bp.route('/api/users')
def users_list():
    if not _is_admin():
        return err('Administrator access required', 403)
    return jsonify([{'username': n, 'role': _user_role(r)} for n, r in _users().items()])


@bp.route('/api/users', methods=['POST'])
def users_create():
    if not _is_admin():
        return err('Administrator access required', 403)
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    role = data.get('role', 'readonly')
    if not RE_USERNAME.match(username):
        return err('Invalid username')
    if role not in ('admin', 'readonly'):
        return err('Invalid role')
    if len(password) < MIN_PASSWORD_LEN:
        return err(f'Password must be at least {MIN_PASSWORD_LEN} characters')
    cfg = load_config()
    cfg.setdefault('users', {})[username] = {'password': generate_password_hash(password),
                                             'role': role}
    save_config(cfg)
    return jsonify({'success': True})


@bp.route('/api/users/<username>/role', methods=['POST'])
def users_set_role(username):
    if not _is_admin():
        return err('Administrator access required', 403)
    role = (request.get_json() or {}).get('role')
    if role not in ('admin', 'readonly'):
        return err('Invalid role')
    cfg = load_config()
    users = cfg.get('users', {})
    if username not in users:
        return err('No such user', 404)
    if role != 'admin' and _user_role(users[username]) == 'admin' and _count_admins(users) <= 1:
        return err('Cannot demote the last administrator', 409)
    rec = users[username] if isinstance(users[username], dict) else {'password': users[username]}
    rec['role'] = role
    users[username] = rec
    save_config(cfg)
    return jsonify({'success': True})


@bp.route('/api/users/<username>/password', methods=['POST'])
def users_set_password(username):
    if not _is_admin():
        return err('Administrator access required', 403)
    password = (request.get_json() or {}).get('password') or ''
    if len(password) < MIN_PASSWORD_LEN:
        return err(f'Password must be at least {MIN_PASSWORD_LEN} characters')
    cfg = load_config()
    users = cfg.get('users', {})
    if username not in users:
        return err('No such user', 404)
    rec = users[username] if isinstance(users[username], dict) else {'role': 'admin'}
    rec['password'] = generate_password_hash(password)
    users[username] = rec
    save_config(cfg)
    return jsonify({'success': True})


@bp.route('/api/users/<username>', methods=['DELETE'])
def users_delete(username):
    if not _is_admin():
        return err('Administrator access required', 403)
    cfg = load_config()
    users = cfg.get('users', {})
    if username not in users:
        return err('No such user', 404)
    if username == session.get('user'):
        return err('Cannot delete your own account', 409)
    if _user_role(users[username]) == 'admin' and _count_admins(users) <= 1:
        return err('Cannot delete the last administrator', 409)
    del users[username]
    save_config(cfg)
    return jsonify({'success': True})


# ─── API token management (admin only) ───────────────────────────────

@bp.route('/api/tokens')
def tokens_list():
    if not _is_admin():
        return err('Administrator access required', 403)
    return jsonify([{'id': t['id'], 'name': t.get('name', ''), 'role': t.get('role', 'readonly'),
                     'created': t.get('created', ''), 'last_used': t.get('last_used', '')}
                    for t in _tokens()])


@bp.route('/api/tokens', methods=['POST'])
def tokens_create():
    if not _is_admin():
        return err('Administrator access required', 403)
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    role = data.get('role', 'readonly')
    if not RE_USERNAME.match(name):
        return err('Invalid token name')
    if role not in ('admin', 'readonly'):
        return err('Invalid role')
    secret = TOKEN_PREFIX + secrets.token_urlsafe(32)
    rec = {'id': 'tok-' + secrets.token_hex(6), 'name': name, 'role': role,
           'hash': _hash_token(secret), 'created': datetime.now().strftime('%Y-%m-%d'),
           'last_used': ''}
    cfg = load_config()
    cfg.setdefault('tokens', []).append(rec)
    save_config(cfg)
    # The secret is returned exactly once — only its SHA-256 is stored.
    return jsonify({'success': True, 'id': rec['id'], 'name': name, 'role': role,
                    'token': secret})


@bp.route('/api/tokens/<tid>', methods=['DELETE'])
def tokens_delete(tid):
    if not _is_admin():
        return err('Administrator access required', 403)
    cfg = load_config()
    before = len(cfg.get('tokens', []))
    cfg['tokens'] = [t for t in cfg.get('tokens', []) if t.get('id') != tid]
    if len(cfg.get('tokens', [])) == before:
        return err('No such token', 404)
    save_config(cfg)
    return jsonify({'success': True})
