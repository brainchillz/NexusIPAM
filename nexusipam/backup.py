"""Scheduled JSON backups of the whole database.

The entire dataset lives in one SQLite file, which is easy to back up and
just as easy to lose to a fat-fingered volume delete. Since this instance is
about to hold the whole network's plan, it protects itself: a gzip'd JSON
dump (same shape as /api/export/json, restorable via /api/import/json) is
written to BACKUP_DIR on startup and every NEXUSIPAM_BACKUP_HOURS after,
keeping the newest NEXUSIPAM_BACKUP_KEEP. Failures are logged and never
propagate — a full disk must not take the app down with it.

The same thread doubles as general maintenance: it prunes audit entries older
than NEXUSIPAM_AUDIT_DAYS, so the one append-only table cannot grow forever
even if nobody ever opens the Settings page. The loop runs even when backups
are disabled — retention must not silently stop because someone turned
backups off.
"""
import gzip
import json
import os
import threading
import time

from .core import db
from .core.config import BACKUP_DIR, APP_VERSION, AUDIT_DAYS

BACKUP_HOURS = float(os.environ.get('NEXUSIPAM_BACKUP_HOURS', 24))
BACKUP_KEEP = int(os.environ.get('NEXUSIPAM_BACKUP_KEEP', 14))


def run_backup(directory=None):
    """Write one backup file; returns its path. Prunes old ones."""
    from .exports import DUMP_TABLES
    directory = directory or BACKUP_DIR
    os.makedirs(directory, exist_ok=True)
    data = {'app': 'nexus-ipam', 'version': APP_VERSION, 'exported': db.now(),
            'tables': {}}
    with db.WRITE_LOCK:  # a consistent snapshot across tables
        for table in DUMP_TABLES:
            data['tables'][table] = db.query('SELECT * FROM %s ORDER BY id' % table)
    # Timestamp alone collides when two backups land in the same second
    # (scheduled + manual); suffix until the name is free.
    stamp = time.strftime('%Y%m%d-%H%M%S')
    path = os.path.join(directory, 'ipam-%s.json.gz' % stamp)
    n = 1
    while os.path.exists(path):
        path = os.path.join(directory, 'ipam-%s-%d.json.gz' % (stamp, n))
        n += 1
    tmp = path + '.tmp'
    with gzip.open(tmp, 'wt') as f:
        json.dump(data, f)
    os.replace(tmp, path)

    backups = sorted(f for f in os.listdir(directory)
                     if f.startswith('ipam-') and f.endswith('.json.gz'))
    for old in backups[:-BACKUP_KEEP]:
        try:
            os.remove(os.path.join(directory, old))
        except OSError:
            pass
    return path


def start_scheduler():
    """Daemon maintenance thread: backups (every BACKUP_HOURS; 0 disables)
    and audit retention (AUDIT_DAYS; 0 keeps forever). Runs even with backups
    off, so retention keeps working regardless."""
    if BACKUP_HOURS <= 0 and AUDIT_DAYS <= 0:
        return

    def loop():
        while True:
            if BACKUP_HOURS > 0:
                try:
                    path = run_backup()
                    print('backup: wrote %s' % path, flush=True)
                except Exception as ex:   # never let maintenance kill the app
                    print('backup FAILED: %s' % ex, flush=True)
            if AUDIT_DAYS > 0:
                try:
                    n = db.prune_audit(days=AUDIT_DAYS)
                    if n:
                        print('audit: pruned %d entries older than %dd'
                              % (n, AUDIT_DAYS), flush=True)
                except Exception as ex:
                    print('audit prune FAILED: %s' % ex, flush=True)
            time.sleep((BACKUP_HOURS if BACKUP_HOURS > 0 else 24) * 3600)

    threading.Thread(target=loop, daemon=True, name='maintenance').start()
