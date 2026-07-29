"""Core configuration: paths, env helpers, atomic writes.

Adapted from DNSMAQ-MGR core/config.py so the two apps stay operationally
identical (same env-var style, same DATA_DIR layout, same TLS defaults). All
knobs are NEXUSIPAM_* environment variables; the installer and Docker image
set them, so names and defaults are load-bearing once released.
"""
import os
import json
from datetime import timedelta

# APP_DIR is the directory holding the ROOT nexus-ipam.py entrypoint (the repo root or
# /opt install dir). DATA_DIR holds all mutable state (auth.json, certs/,
# ipam.db) — same as APP_DIR on bare metal, a volume (/data) in Docker.
APP_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STATIC_DIR = os.path.join(APP_DIR, 'static')
TEMPLATES_DIR = os.path.join(APP_DIR, 'templates')

APP_VERSION = '0.1.0'

DATA_DIR = os.environ.get('NEXUSIPAM_DATA_DIR', APP_DIR)
DB_PATH = os.environ.get('NEXUSIPAM_DB', os.path.join(DATA_DIR, 'ipam.db'))
BACKUP_DIR = os.path.join(DATA_DIR, 'backups')


def env_bool(name, default):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.lower() in ('1', 'true', 'yes', 'on')


# Docker mode: the app runs as root in its own container, so sudo is never
# prefixed onto the few commands we shell out to (ping, arp, openssl).
NO_SUDO = env_bool('NEXUSIPAM_NO_SUDO', False)

# ─── Scanner tunables ─────────────────────────────────────────────────
# Concurrency for the ping sweeper. 64 parallel 1-second probes clears a /24
# in well under 5s without looking like a port scan to anyone's IDS.
SCAN_WORKERS = int(os.environ.get('NEXUSIPAM_SCAN_WORKERS', 64))
SCAN_TIMEOUT = float(os.environ.get('NEXUSIPAM_SCAN_TIMEOUT', 1.0))
# Hard ceiling on how many addresses one scan job may probe. Guards against
# someone hitting "scan" on a /16 and generating 65k probes.
SCAN_MAX_HOSTS = int(os.environ.get('NEXUSIPAM_SCAN_MAX_HOSTS', 4096))
# Reverse-DNS lookup on responders (adds a resolver round trip per live host).
SCAN_RESOLVE = env_bool('NEXUSIPAM_SCAN_RESOLVE', True)

# Audit-log retention in days; entries older than this are pruned by the
# daily maintenance thread. 0 keeps everything forever (and re-opens the
# unbounded-growth question this knob exists to answer).
AUDIT_DAYS = int(os.environ.get('NEXUSIPAM_AUDIT_DAYS', 365))

# Largest prefix we will enumerate address-by-address for the UI's free-list
# and IP map. Beyond this we report counts only — enumerating a /8 would be
# 16M rows nobody can read.
MAX_ENUMERATE = int(os.environ.get('NEXUSIPAM_MAX_ENUMERATE', 65536))

# ─── TLS configuration ────────────────────────────────────────────────
# HTTPS by default with a self-signed certificate generated on first run.
# Replace it from the UI (Settings -> TLS), or point NEXUSIPAM_TLS_CERT /
# NEXUSIPAM_TLS_KEY at your own. NEXUSIPAM_TLS=0 serves plain HTTP (e.g.
# behind a TLS-terminating reverse proxy).
TLS_ENABLED = env_bool('NEXUSIPAM_TLS', True)
WEB_PORT = int(os.environ.get('NEXUSIPAM_PORT', 8444 if TLS_ENABLED else 8081))
TLS_DIR = os.environ.get('NEXUSIPAM_TLS_DIR', os.path.join(DATA_DIR, 'certs'))
TLS_CERT = os.environ.get('NEXUSIPAM_TLS_CERT', os.path.join(TLS_DIR, 'nexus-ipam.crt'))
TLS_KEY = os.environ.get('NEXUSIPAM_TLS_KEY', os.path.join(TLS_DIR, 'nexus-ipam.key'))

SESSION_COOKIE_CONFIG = dict(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=env_bool('NEXUSIPAM_COOKIE_SECURE', TLS_ENABLED),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)


def write_json_atomic(path, data, mode=0o600):
    """Write JSON to ``path`` atomically: serialize into a temp file in the same
    directory, fsync it, then os.replace() over the target (an atomic rename on
    POSIX). A crash or full disk mid-write leaves the *original* file intact
    rather than a truncated one — critical for auth.json, where a corrupt file
    would lock every user out."""
    tmp = '%s.tmp.%d' % (path, os.getpid())
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def ensure_dirs():
    """Create the DATA_DIR tree on first boot (bare metal and Docker volume)."""
    for d in (DATA_DIR, TLS_DIR, BACKUP_DIR):
        os.makedirs(d, exist_ok=True)
    for d in (TLS_DIR, BACKUP_DIR):
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
