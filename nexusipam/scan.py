"""Ping verification — "is this address really free?"

A record saying an address is free is a claim; a silent ping is evidence. This
module supplies both directions of the reconciliation an IPAM is for:

  * addresses we think are FREE that answer  -> unmanaged hosts (someone
    static-assigned an address without telling anyone);
  * addresses we have RECORDS for that never answer -> stale records.

Responders inside an enabled DHCP pool are reported separately as leases, not
as unmanaged hosts: a DHCP client answering a ping is the system working, and
mixing those in would bury the real finding under routine noise.

ICMP is sent by the system `ping` binary rather than a raw socket: ping is
setuid/capability-granted on every distro, so the app needs no privileges and
no CAP_NET_RAW. Probes run on a bounded thread pool — a /24 clears in a couple
of seconds without looking like a port scan.
"""
import re
import time
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

from flask import Blueprint, jsonify, request

from . import netutil
from .core import db
from .core.auth import actor
from .core.config import (SCAN_MAX_HOSTS, SCAN_RESOLVE, SCAN_TIMEOUT, SCAN_WORKERS)
from .core.runcmd import err, num, run

bp = Blueprint('scan', __name__)

RE_RTT = re.compile(r'time[=<]([\d.]+)\s*ms')

# Jobs live in memory: a scan is ephemeral progress state, and the results
# that matter are written to scan_results as they land. A restart mid-scan
# loses the progress bar, not the findings.
_JOBS = {}
_JOBS_LOCK = threading.Lock()
_JOB_SEQ = [0]
MAX_JOBS_KEPT = 20


def probe_one(address, timeout=None):
    """One ICMP echo. Returns {'alive', 'rtt_ms', 'method'}."""
    timeout = timeout or SCAN_TIMEOUT
    addr = netutil.parse_ip(address)
    if addr is None:
        return {'alive': False, 'rtt_ms': None, 'method': 'invalid'}
    # -n: no reverse lookups inside ping (we do our own, controllably).
    # -c1/-W: exactly one probe, bounded wait.
    args = ['ping', '-6' if addr.version == 6 else '-4', '-c', '1', '-n',
            '-W', str(max(1, int(round(timeout)))), str(addr)]
    out, _e, rc = run(args, no_sudo=True, timeout=max(5, int(timeout) + 4))
    if rc != 0:
        return {'alive': False, 'rtt_ms': None, 'method': 'icmp'}
    m = RE_RTT.search(out or '')
    return {'alive': True, 'rtt_ms': float(m.group(1)) if m else None, 'method': 'icmp'}


def neighbour_mac(address):
    """MAC from the kernel's neighbour table — only populated for on-link IPv4
    hosts we just pinged, which is exactly when it is useful."""
    out, _e, rc = run(['ip', 'neigh', 'show', str(address)], no_sudo=True, timeout=5)
    if rc != 0:
        return ''
    m = re.search(r'lladdr\s+([0-9a-f:]{17})', out or '', re.I)
    return m.group(1).lower() if m else ''


def resolve_ptr(address):
    if not SCAN_RESOLVE:
        return ''
    try:
        return socket.gethostbyaddr(str(address))[0]
    except (OSError, socket.herror, socket.gaierror):
        return ''


def probe_many(addresses, timeout=None, on_progress=None):
    """Probe a list of addresses concurrently. Returns {address: result}."""
    results = {}
    if not addresses:
        return results
    workers = max(1, min(SCAN_WORKERS, len(addresses)))

    def work(a):
        r = probe_one(a, timeout)
        if r['alive']:
            r['mac'] = neighbour_mac(a)
            r['hostname'] = resolve_ptr(a)
        return a, r

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for a, r in pool.map(work, [str(x) for x in addresses]):
            results[a] = r
            if on_progress:
                on_progress(a, r)
    return results


def record_results(results):
    """Persist probe results. Upsert by address so history (last_alive)
    survives across scans."""
    ts = int(time.time())
    with db.WRITE_LOCK:
        for address, r in results.items():
            addr = netutil.parse_ip(address)
            if addr is None:
                continue
            alive = 1 if r.get('alive') else 0
            db.execute(
                'INSERT INTO scan_results(address, version, addr_hex, alive, method, '
                'rtt_ms, hostname, mac, last_scan, last_alive) '
                'VALUES(?,?,?,?,?,?,?,?,?,?) '
                'ON CONFLICT(address) DO UPDATE SET '
                '  alive=excluded.alive, method=excluded.method, rtt_ms=excluded.rtt_ms, '
                '  hostname=CASE WHEN excluded.hostname <> \'\' THEN excluded.hostname '
                '               ELSE scan_results.hostname END, '
                '  mac=CASE WHEN excluded.mac <> \'\' THEN excluded.mac ELSE scan_results.mac END, '
                '  last_scan=excluded.last_scan, '
                '  last_alive=CASE WHEN excluded.alive=1 THEN excluded.last_scan '
                '                  ELSE scan_results.last_alive END',
                (str(addr), addr.version, netutil.hexify(int(addr)), alive,
                 r.get('method', 'icmp'), r.get('rtt_ms'), r.get('hostname', ''),
                 r.get('mac', ''), ts, ts if alive else 0))


def in_dhcp_pool(addr_hex, version):
    """The enabled DHCP range covering an address, or None. Used to tell a
    routine lease apart from an unrecorded static assignment.

    Matched by version + hex across ALL networks, not by a single network id:
    with nested prefixes the pool may be declared on a parent or child of the
    network the address most specifically belongs to, and either way the
    address is a lease."""
    return db.query_one(
        'SELECT dhcp_ranges.* FROM dhcp_ranges '
        'JOIN networks ON networks.id = dhcp_ranges.network_id '
        'WHERE dhcp_ranges.enabled=1 AND networks.version=? '
        'AND ? BETWEEN dhcp_ranges.start_hex AND dhcp_ranges.end_hex',
        (version, addr_hex))


# ─── Job runner ───────────────────────────────────────────────────────

def _new_job(label, addresses):
    with _JOBS_LOCK:
        _JOB_SEQ[0] += 1
        jid = 'scan-%d' % _JOB_SEQ[0]
        _JOBS[jid] = {'id': jid, 'label': label, 'state': 'running',
                      'total': len(addresses), 'done': 0, 'alive': 0,
                      'started': int(time.time()), 'finished': None,
                      'responders': [], 'error': None}
        # Keep the job list bounded — old finished jobs are just clutter.
        if len(_JOBS) > MAX_JOBS_KEPT:
            for old in sorted(_JOBS.values(), key=lambda j: j['started'])[:-MAX_JOBS_KEPT]:
                if old['state'] != 'running':
                    _JOBS.pop(old['id'], None)
    return jid


def _run_job(jid, addresses):
    job = _JOBS[jid]
    results = {}

    def progress(addr, r):
        job['done'] += 1
        if r.get('alive'):
            job['alive'] += 1
            if len(job['responders']) < 512:
                job['responders'].append(addr)

    try:
        results = probe_many(addresses, on_progress=progress)
        record_results(results)
        job['state'] = 'done'
    except Exception as ex:                       # a scan must never kill the app
        job['state'] = 'error'
        job['error'] = str(ex)
    finally:
        job['finished'] = int(time.time())
    return results


def start_scan(label, addresses):
    jid = _new_job(label, addresses)
    t = threading.Thread(target=_run_job, args=(jid, addresses), daemon=True)
    t.start()
    return jid


# ─── Routes ───────────────────────────────────────────────────────────

def _addresses_for_request(data):
    """Resolve a scan target into a concrete address list.

    Accepts: network_id (whole prefix), cidr, an explicit addresses list, or
    `free_only` to probe just the addresses we believe are unused — the fast
    "verify my free list" path.
    """
    if data.get('addresses'):
        items = data['addresses']
        if not isinstance(items, list):
            return None, 'addresses must be a list'
        out = []
        for a in items[:SCAN_MAX_HOSTS]:
            ip = netutil.parse_ip(a)
            if ip is None:
                return None, 'Invalid address: %s' % a
            out.append(str(ip))
        return out, None

    net_row = None
    if data.get('network_id') is not None:
        net_row = db.row('SELECT * FROM networks WHERE id=?', (num(data.get('network_id')),))
    elif data.get('cidr'):
        n = netutil.parse_network(data.get('cidr'))
        if n is None:
            return None, 'Invalid CIDR'
        net_row = db.row('SELECT * FROM networks WHERE cidr=?', (str(n),))
        if not net_row:
            # Scanning a prefix we do not manage is legitimate (discovery).
            net_row = {'id': None, 'cidr': str(n), 'version': n.version,
                       'net_start': netutil.hexify(int(n.network_address)),
                       'net_end': netutil.hexify(int(n.broadcast_address)),
                       'gateway': ''}
    if not net_row:
        return None, 'Pass network_id, cidr, or an addresses list'

    net = netutil.parse_network(net_row['cidr'])
    if netutil.capacity(net) > SCAN_MAX_HOSTS:
        return None, ('%s has %d addresses — more than the %d-address scan limit. '
                      'Scan a smaller prefix or pass an explicit address list.'
                      % (net_row['cidr'], netutil.capacity(net), SCAN_MAX_HOSTS))

    if data.get('free_only') and net_row.get('id'):
        from .allocate import free_addresses
        free, _ = free_addresses(net_row, limit=SCAN_MAX_HOSTS, verify=False)
        return [str(a) for a in free], None

    return [str(a) for a in netutil.iter_usable(net)], None


@bp.route('/api/scan', methods=['POST'])
def scan_start():
    data = request.get_json(silent=True) or {}
    addresses, e = _addresses_for_request(data)
    if e:
        return err(e)
    if not addresses:
        return err('Nothing to scan')
    if data.get('label'):
        label = str(data['label'])
    elif data.get('cidr'):
        label = str(data['cidr'])
    elif data.get('network_id') is not None:
        label = 'network %s' % data['network_id']
    else:
        label = '%d addresses' % len(addresses)
    label = label[:64]
    jid = start_scan(label, addresses)
    db.audit(actor(), 'scan', 'scan', None, '%s (%d addresses)' % (label, len(addresses)))
    return jsonify({'success': True, 'job': jid, 'total': len(addresses)})


@bp.route('/api/scan/jobs')
def scan_jobs():
    with _JOBS_LOCK:
        jobs = sorted(_JOBS.values(), key=lambda j: -j['started'])
    return jsonify({'jobs': jobs})


@bp.route('/api/scan/jobs/<jid>')
def scan_job(jid):
    job = _JOBS.get(jid)
    if not job:
        return err('No such scan job', 404)
    return jsonify(job)


@bp.route('/api/scan/verify', methods=['POST'])
def scan_verify():
    """Synchronous probe of a small explicit list — used by the "check this is
    really free" button, where waiting a second beats polling a job."""
    data = request.get_json(silent=True) or {}
    items = data.get('addresses') or []
    if not isinstance(items, list) or not items:
        return err('Expected {"addresses": [...]}')
    if len(items) > 256:
        return err('Use the async scan endpoint for more than 256 addresses')
    addrs = []
    for a in items:
        ip = netutil.parse_ip(a)
        if ip is None:
            return err('Invalid address: %s' % a)
        addrs.append(str(ip))
    results = probe_many(addrs)
    record_results(results)
    return jsonify({'success': True, 'results': results,
                    'alive': [a for a, r in results.items() if r.get('alive')],
                    'free': [a for a, r in results.items() if not r.get('alive')]})


@bp.route('/api/scan/reconcile')
def scan_reconcile():
    """The two disagreement lists between the address plan and reality."""
    net_id = num(request.args.get('network_id'))
    args, clause = [], ''
    if net_id is not None:
        net_row = db.row('SELECT * FROM networks WHERE id=?', (net_id,))
        if not net_row:
            return err('No such network', 404)
        clause = ' AND scan_results.version=? AND scan_results.addr_hex BETWEEN ? AND ?'
        args = [net_row['version'], net_row['net_start'], net_row['net_end']]

    unmanaged = db.query(
        'SELECT scan_results.* FROM scan_results '
        'LEFT JOIN ip_addresses ON ip_addresses.address = scan_results.address '
        'WHERE scan_results.alive=1 AND ip_addresses.id IS NULL' + clause +
        ' ORDER BY scan_results.version, scan_results.addr_hex', tuple(args))

    # A responder inside an enabled DHCP pool is a lease doing exactly what it
    # should — reporting it as "unmanaged" buries the real signal (someone
    # static-assigned an address without recording it) in routine noise. Split
    # them: `dhcp_leases` is informational, `unmanaged` is the anomaly.
    from .networks import network_for
    leases = []
    keep = []
    for u in unmanaged:
        n = network_for(u['addr_hex'], u['version'])
        u['network_cidr'] = n['cidr'] if n else ''
        u['network_id'] = n['id'] if n else None
        pool = in_dhcp_pool(u['addr_hex'], u['version'])
        if pool:
            u['dhcp_range'] = pool.get('name') or '%s – %s' % (pool['start_addr'],
                                                               pool['end_addr'])
            leases.append(u)
        else:
            keep.append(u)
    unmanaged = keep

    stale_clause = clause.replace('scan_results.version', 'ip_addresses.version') \
                         .replace('scan_results.addr_hex', 'ip_addresses.addr_hex')
    stale = db.rows(
        'SELECT ip_addresses.*, networks.cidr AS network_cidr, '
        '       scan_results.last_scan, scan_results.last_alive '
        'FROM ip_addresses '
        'JOIN scan_results ON scan_results.address = ip_addresses.address '
        'LEFT JOIN networks ON networks.id = ip_addresses.network_id '
        "WHERE scan_results.alive=0 AND ip_addresses.status='active'" + stale_clause +
        ' ORDER BY ip_addresses.version, ip_addresses.addr_hex', tuple(args))
    from .addresses import expand_assignment
    for s in stale:
        expand_assignment(s)

    return jsonify({'unmanaged': unmanaged, 'stale': stale, 'dhcp_leases': leases,
                    'unmanaged_count': len(unmanaged), 'stale_count': len(stale),
                    'dhcp_lease_count': len(leases)})


@bp.route('/api/scan/adopt', methods=['POST'])
def scan_adopt():
    """Turn discovered responders into address records in one step — the
    natural follow-up to a reconcile.

    Addresses inside an enabled DHCP pool are skipped by default: recording a
    dynamic lease as a permanent entry writes down something that is only true
    until the lease expires. Pass `include_dhcp: true` to take them anyway, in
    which case they are recorded with status `dhcp` rather than `active`.
    """
    data = request.get_json(silent=True) or {}
    items = data.get('addresses')
    if not isinstance(items, list) or not items:
        return err('Expected {"addresses": [...]}')
    include_dhcp = bool(data.get('include_dhcp'))
    from .networks import network_for
    created, skipped, in_pool = 0, 0, 0
    adopted = []
    with db.WRITE_LOCK:
        for a in items[:2000]:
            ip = netutil.parse_ip(a)
            if ip is None:
                continue
            if db.query_one('SELECT id FROM ip_addresses WHERE address=?', (str(ip),)):
                skipped += 1
                continue
            addr_hex = netutil.hexify(int(ip))
            net = network_for(addr_hex, ip.version)
            pool = in_dhcp_pool(addr_hex, ip.version)
            if pool and not include_dhcp:
                in_pool += 1
                continue
            scan = db.query_one('SELECT hostname, mac FROM scan_results WHERE address=?',
                                (str(ip),)) or {}
            db.insert('ip_addresses', {
                'address': str(ip), 'version': ip.version, 'addr_hex': addr_hex,
                'network_id': net['id'] if net else None,
                'status': 'dhcp' if pool else 'active',
                'dns_name': scan.get('hostname', ''), 'mac': scan.get('mac', ''),
                'description': 'Discovered by ping sweep',
                'source': 'discovery', 'ext_id': '', 'meta': '{}'})
            created += 1
            adopted.append('%s (%s)' % (ip, scan['hostname'])
                           if scan.get('hostname') else str(ip))
        db.audit(actor(), 'adopt', 'ip_addresses', None,
                 db.audit_list(adopted) or 'nothing new to adopt')
    return jsonify({'success': True, 'created': created, 'skipped': skipped,
                    'skipped_dhcp': in_pool})
