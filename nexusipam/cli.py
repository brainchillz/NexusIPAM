"""CLI subcommands (invoked as `python nexus-ipam.py <command>`)."""
import os
import json
import sys

from werkzeug.security import generate_password_hash

from .core.auth import (RE_USERNAME, MIN_PASSWORD_LEN, ensure_bootstrap,
                        save_config, TOKEN_PREFIX, _hash_token)


def cli_set_password(argv):
    import getpass
    user = argv[2] if len(argv) > 2 else 'admin'
    if not RE_USERNAME.match(user):
        print('Invalid username')
        return 1
    pw = os.environ.get('NEXUSIPAM_ADMIN_PASSWORD')
    if not pw:
        pw = getpass.getpass(f'New password for {user}: ')
        if pw != getpass.getpass('Confirm password: '):
            print('Passwords do not match')
            return 1
    if len(pw) < MIN_PASSWORD_LEN:
        print(f'Password must be at least {MIN_PASSWORD_LEN} characters')
        return 1
    cfg = ensure_bootstrap()
    users = cfg.setdefault('users', {})
    rec = users[user] if isinstance(users.get(user), dict) else {'role': 'admin'}
    rec['password'] = generate_password_hash(pw)
    rec.pop('must_change', None)  # operator set it explicitly — no forced change
    users[user] = rec
    save_config(cfg)
    print(f'Password updated for {user}')
    return 0


def cli_token(argv):
    """`nexus-ipam.py token <name> [admin|readonly]` — mint an API token without the
    UI, for provisioning automation at install time."""
    import secrets
    from datetime import datetime
    name = argv[2] if len(argv) > 2 else ''
    role = argv[3] if len(argv) > 3 else 'readonly'
    if not RE_USERNAME.match(name or ''):
        print('Usage: nexus-ipam.py token <name> [admin|readonly]')
        return 1
    if role not in ('admin', 'readonly'):
        print('Role must be admin or readonly')
        return 1
    secret = TOKEN_PREFIX + secrets.token_urlsafe(32)
    cfg = ensure_bootstrap()
    cfg.setdefault('tokens', []).append({
        'id': 'tok-' + secrets.token_hex(6), 'name': name, 'role': role,
        'hash': _hash_token(secret), 'created': datetime.now().strftime('%Y-%m-%d'),
        'last_used': ''})
    save_config(cfg)
    print(secret)  # printed once — only the SHA-256 is stored
    return 0


def cli_reindex(argv=None):
    """Recompute every address's owning network. Safe to run any time; useful
    after a hand-edited import."""
    from .core import db
    from .networks import reindex_addresses
    db.init_db()
    reindex_addresses()
    print('Reindexed %d addresses'
          % db.query_one('SELECT COUNT(*) c FROM ip_addresses')['c'])
    return 0


def cli_export(argv=None):
    """Dump the database as JSON to stdout (backup / diffing)."""
    from .core import db
    from .exports import DUMP_TABLES
    from .core.config import APP_VERSION
    db.init_db()
    data = {'app': 'nexus-ipam', 'version': APP_VERSION, 'exported': db.now(),
            'tables': {t: db.query('SELECT * FROM %s ORDER BY id' % t) for t in DUMP_TABLES}}
    json.dump(data, sys.stdout, indent=2)
    print()
    return 0


def cli_scan(argv):
    """`nexus-ipam.py scan <cidr>` — ping sweep from the shell, no web UI needed."""
    from .core import db
    from . import netutil
    from .scan import probe_many, record_results
    db.init_db()
    if len(argv) < 3:
        print('Usage: nexus-ipam.py scan <cidr>')
        return 1
    net = netutil.parse_network(argv[2])
    if net is None:
        print('Invalid CIDR')
        return 1
    from .core.config import SCAN_MAX_HOSTS
    if netutil.capacity(net) > SCAN_MAX_HOSTS:
        print('Refusing to scan %d addresses (limit %d)'
              % (netutil.capacity(net), SCAN_MAX_HOSTS))
        return 1
    addrs = [str(a) for a in netutil.iter_usable(net)]
    print('Probing %d addresses in %s ...' % (len(addrs), net), file=sys.stderr)
    results = probe_many(addrs)
    record_results(results)
    alive = [a for a, r in results.items() if r.get('alive')]
    for a in alive:
        r = results[a]
        print('%-39s up   %s' % (a, r.get('hostname') or r.get('mac') or ''))
    print('%d of %d responded' % (len(alive), len(addrs)), file=sys.stderr)
    return 0


COMMANDS = {
    'set-password': cli_set_password,
    'token': cli_token,
    'reindex': cli_reindex,
    'export': cli_export,
    'scan': cli_scan,
}


def dispatch(argv):
    """Return an exit code if argv names a CLI subcommand, else None."""
    import inspect
    if len(argv) > 1 and argv[1] in COMMANDS:
        fn = COMMANDS[argv[1]]
        if len(inspect.signature(fn).parameters) >= 1:
            rc = fn(argv)
        else:
            rc = fn()
        # A matched command must ALWAYS yield an exit code: nexus-ipam.py starts the
        # web server when dispatch returns None.
        return 0 if rc is None else rc
    return None
