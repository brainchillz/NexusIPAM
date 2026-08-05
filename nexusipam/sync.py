"""Sync status: which external systems feed this IPAM, what they own, and
when their importers last ran.

Ownership is derived live from the data itself (every table carries `source`),
so it can never drift from reality; only the run reports are bookkeeping.
Importers POST a one-line report after each run (`/api/sync/runs`) — the
tools' cron wrapper reports failures the same way, so a broken importer shows
up here instead of only in a log file nobody reads.
"""
import json
from flask import Blueprint, jsonify, request

from .core import db
from .core.auth import actor
from .core.runcmd import err
from .core.validators import RE_SLUG, clean_text

bp = Blueprint('sync', __name__)

# Every table that carries the source/ext_id integration contract.
TABLES = ('vlans', 'networks', 'clusters', 'devices', 'vms', 'containers',
          'ip_addresses', 'dhcp_servers', 'dhcp_ranges', 'dns_servers')

RUNS_KEY = 'sync_runs'
RUNS_KEEP = 50
MAX_COUNT_KEYS = 12


def _runs():
    try:
        runs = json.loads(db.get_setting(RUNS_KEY, '[]') or '[]')
        return runs if isinstance(runs, list) else []
    except ValueError:
        return []


@bp.route('/api/sync')
def sync_status():
    sources = {}
    for table in TABLES:
        for r in db.query(
                "SELECT source, COUNT(*) n, MAX(updated) latest FROM %s "
                "WHERE source != 'manual' AND source != '' GROUP BY source" % table):
            s = sources.setdefault(r['source'],
                                   {'tables': {}, 'total': 0, 'latest': 0})
            s['tables'][table] = r['n']
            s['total'] += r['n']
            s['latest'] = max(s['latest'], r['latest'] or 0)
    return jsonify({'sources': sources, 'runs': _runs()})


@bp.route('/api/sync/runs', methods=['POST'])
def sync_report():
    """Importers report a finished run here (admin token — method-based RBAC).
    Kept as a bounded list in the meta table; this is operational breadcrumb
    data, not part of the plan."""
    data = request.get_json(silent=True) or {}
    source = str(data.get('source') or '').strip()
    if not RE_SLUG.match(source):
        return err('Invalid source (letters, digits, dot, dash, underscore)')
    detail, e = clean_text(data.get('detail'), 'detail', 500)
    if e:
        return err(e)
    counts = {}
    raw_counts = data.get('counts')
    if raw_counts is not None:
        if not isinstance(raw_counts, dict):
            return err('counts must be an object of integers')
        for k, v in list(raw_counts.items())[:MAX_COUNT_KEYS]:
            try:
                counts[str(k)[:32]] = int(v)
            except (TypeError, ValueError):
                return err('counts must be an object of integers')
    run = {'ts': db.now(), 'source': source, 'ok': bool(data.get('ok', True)),
           'detail': detail, 'counts': counts}
    with db.WRITE_LOCK:
        runs = ([run] + _runs())[:RUNS_KEEP]
        db.set_setting(RUNS_KEY, json.dumps(runs))
        db.audit(actor(), 'sync-run', source, None,
                 ('ok' if run['ok'] else 'FAILED') + (': ' + detail if detail else ''))
    return jsonify({'success': True, 'run': run})
