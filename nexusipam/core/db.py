"""SQLite storage layer.

Why SQLite and not JSON files: IPAM is inherently relational (address ->
network -> VLAN, and address -> device/VM/container -> cluster). The hot
queries are range scans over IP space ("every address inside 10.0.0.0/23")
and joins across four tables; doing that over JSON means loading everything
into memory and hand-rolling the joins, with no atomicity when a single user
action touches several tables. SQLite is still "no database engine" in the
sense that matters — no server process, no extra dependency (it is Python
stdlib), one file you can copy — while giving foreign keys, indexes and real
transactions. At a few thousand entries it never breaks a sweat.

Addresses are stored BOTH as text (canonical, human-readable, unique) and as
a zero-padded 32-char lowercase hex string. The hex form makes lexicographic
comparison identical to numeric comparison, so "is this address inside that
prefix" becomes an indexed BETWEEN — the single most common IPAM query — and
it works unchanged for IPv4 and IPv6.

Integration contract (DNSMAQ-MGR, VC-Deployer, future importers): every
first-class object carries `source`, `ext_id`, `meta`, `created` and
`updated`. An external system syncs idempotently by upserting on
(source, ext_id) and pulls incremental changes with `updated > since`.
"""
import os
import json
import time
import sqlite3
import threading

from .config import DB_PATH

# One connection per thread: SQLite objects are not shareable across threads,
# and Flask serves requests on a thread pool.
_local = threading.local()

# Serializes multi-statement write transactions (allocation, reindex). WAL
# handles reader/writer concurrency; this keeps our own read-modify-write
# sequences from interleaving.
WRITE_LOCK = threading.RLock()

SCHEMA_VERSION = 2

# Objects an IP address can be assigned to. Polymorphic by design — a SQL FK
# cannot point at four tables — so the app layer validates the target exists
# and cleanup happens in delete_object().
ASSIGNABLE = ('device', 'vm', 'container', 'cluster')

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);

-- ─── Layer 2 ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vlans (
  id          INTEGER PRIMARY KEY,
  vid         INTEGER NOT NULL,
  name        TEXT NOT NULL DEFAULT '',
  site        TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'active',
  description TEXT NOT NULL DEFAULT '',
  source      TEXT NOT NULL DEFAULT 'manual',
  ext_id      TEXT NOT NULL DEFAULT '',
  meta        TEXT NOT NULL DEFAULT '{}',
  created     INTEGER NOT NULL DEFAULT 0,
  updated     INTEGER NOT NULL DEFAULT 0,
  UNIQUE (vid, site)
);

-- ─── Layer 3 ────────────────────────────────────────────────────────
-- net_start/net_end are the padded-hex bounds of the prefix; every
-- containment and overlap question is answered with them.
CREATE TABLE IF NOT EXISTS networks (
  id          INTEGER PRIMARY KEY,
  cidr        TEXT NOT NULL UNIQUE,
  version     INTEGER NOT NULL,
  prefixlen   INTEGER NOT NULL,
  net_start   TEXT NOT NULL,
  net_end     TEXT NOT NULL,
  name        TEXT NOT NULL DEFAULT '',
  role        TEXT NOT NULL DEFAULT 'subnet',   -- container | subnet | pool
  vlan_id     INTEGER REFERENCES vlans(id) ON DELETE SET NULL,
  gateway     TEXT NOT NULL DEFAULT '',
  dns_servers TEXT NOT NULL DEFAULT '',         -- comma-separated
  domain      TEXT NOT NULL DEFAULT '',
  site        TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'active',
  description TEXT NOT NULL DEFAULT '',
  source      TEXT NOT NULL DEFAULT 'manual',
  ext_id      TEXT NOT NULL DEFAULT '',
  meta        TEXT NOT NULL DEFAULT '{}',
  created     INTEGER NOT NULL DEFAULT 0,
  updated     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_networks_bounds ON networks(version, net_start, net_end);

-- ─── Inventory ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS clusters (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  kind        TEXT NOT NULL DEFAULT 'proxmox',  -- proxmox|vsphere|kubernetes|other
  endpoint    TEXT NOT NULL DEFAULT '',
  site        TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'active',
  description TEXT NOT NULL DEFAULT '',
  source      TEXT NOT NULL DEFAULT 'manual',
  ext_id      TEXT NOT NULL DEFAULT '',
  meta        TEXT NOT NULL DEFAULT '{}',
  created     INTEGER NOT NULL DEFAULT 0,
  updated     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS devices (
  id           INTEGER PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  role         TEXT NOT NULL DEFAULT 'server',  -- server|switch|router|firewall|ap|storage|other
  status       TEXT NOT NULL DEFAULT 'active',
  cluster_id   INTEGER REFERENCES clusters(id) ON DELETE SET NULL,
  manufacturer TEXT NOT NULL DEFAULT '',
  model        TEXT NOT NULL DEFAULT '',
  serial       TEXT NOT NULL DEFAULT '',
  site         TEXT NOT NULL DEFAULT '',
  rack         TEXT NOT NULL DEFAULT '',
  position     TEXT NOT NULL DEFAULT '',
  -- What this device can HOST. A physical box may run a hypervisor, a
  -- container engine, or both; these drive the "parent" pickers for VMs
  -- and containers.
  virt         TEXT NOT NULL DEFAULT '',        -- ''|vsphere|proxmox|kvm|xen|hyperv
  engine       TEXT NOT NULL DEFAULT '',        -- ''|docker|lxd|incus|podman
  -- Free-form, comma-separated, normalized lowercase. `role` is one value from
  -- a fixed list; a real machine is often several things at once, and tags are
  -- how you group those without inventing a role per combination.
  tags         TEXT NOT NULL DEFAULT '',
  description  TEXT NOT NULL DEFAULT '',
  source       TEXT NOT NULL DEFAULT 'manual',
  ext_id       TEXT NOT NULL DEFAULT '',
  meta         TEXT NOT NULL DEFAULT '{}',
  created      INTEGER NOT NULL DEFAULT 0,
  updated      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vms (
  id             INTEGER PRIMARY KEY,
  name           TEXT NOT NULL UNIQUE,
  host_device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
  cluster_id     INTEGER REFERENCES clusters(id) ON DELETE SET NULL,
  platform       TEXT NOT NULL DEFAULT 'kvm',   -- kvm|proxmox|esxi|vcenter|hyperv|other
  vmid           TEXT NOT NULL DEFAULT '',      -- Proxmox VMID / vSphere moref
  status         TEXT NOT NULL DEFAULT 'active',
  vcpus          INTEGER,
  memory_mb      INTEGER,
  disk_gb        INTEGER,
  os             TEXT NOT NULL DEFAULT '',
  engine         TEXT NOT NULL DEFAULT '',      -- container engine running INSIDE this VM
  description    TEXT NOT NULL DEFAULT '',
  source         TEXT NOT NULL DEFAULT 'manual',
  ext_id         TEXT NOT NULL DEFAULT '',
  meta           TEXT NOT NULL DEFAULT '{}',
  created        INTEGER NOT NULL DEFAULT 0,
  updated        INTEGER NOT NULL DEFAULT 0
);

-- A container's parent is a device OR a vm — polymorphic for the same reason
-- IP assignment is.
CREATE TABLE IF NOT EXISTS containers (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  engine      TEXT NOT NULL DEFAULT 'docker',   -- docker|lxd|incus|podman|kubernetes
  parent_kind TEXT NOT NULL DEFAULT '',         -- device|vm
  parent_id   INTEGER,
  cluster_id  INTEGER REFERENCES clusters(id) ON DELETE SET NULL,
  status      TEXT NOT NULL DEFAULT 'active',
  image       TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  source      TEXT NOT NULL DEFAULT 'manual',
  ext_id      TEXT NOT NULL DEFAULT '',
  meta        TEXT NOT NULL DEFAULT '{}',
  created     INTEGER NOT NULL DEFAULT 0,
  updated     INTEGER NOT NULL DEFAULT 0
);

-- ─── Addresses ──────────────────────────────────────────────────────
-- network_id is a denormalized cache of "most specific prefix containing
-- this address", rebuilt by reindex_addresses() whenever networks change.
CREATE TABLE IF NOT EXISTS ip_addresses (
  id            INTEGER PRIMARY KEY,
  address       TEXT NOT NULL UNIQUE,
  version       INTEGER NOT NULL,
  addr_hex      TEXT NOT NULL,
  network_id    INTEGER REFERENCES networks(id) ON DELETE SET NULL,
  status        TEXT NOT NULL DEFAULT 'active',  -- active|reserved|deprecated|dhcp
  assigned_kind TEXT NOT NULL DEFAULT '',
  assigned_id   INTEGER,
  if_name       TEXT NOT NULL DEFAULT '',
  mac           TEXT NOT NULL DEFAULT '',
  is_primary    INTEGER NOT NULL DEFAULT 0,
  dns_name      TEXT NOT NULL DEFAULT '',
  description   TEXT NOT NULL DEFAULT '',
  source        TEXT NOT NULL DEFAULT 'manual',
  ext_id        TEXT NOT NULL DEFAULT '',
  meta          TEXT NOT NULL DEFAULT '{}',
  created       INTEGER NOT NULL DEFAULT 0,
  updated       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_ip_hex ON ip_addresses(version, addr_hex);
CREATE INDEX IF NOT EXISTS ix_ip_network ON ip_addresses(network_id);
CREATE INDEX IF NOT EXISTS ix_ip_assigned ON ip_addresses(assigned_kind, assigned_id);
CREATE INDEX IF NOT EXISTS ix_ip_updated ON ip_addresses(updated);

-- ─── Services ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS dhcp_servers (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  kind        TEXT NOT NULL DEFAULT 'dnsmasq',  -- dnsmasq|isc-dhcp|kea|windows|unifi|other
  host_kind   TEXT NOT NULL DEFAULT '',
  host_id     INTEGER,
  address     TEXT NOT NULL DEFAULT '',
  url         TEXT NOT NULL DEFAULT '',         -- management URL (e.g. a DNSMAQ-MGR instance)
  status      TEXT NOT NULL DEFAULT 'active',
  description TEXT NOT NULL DEFAULT '',
  source      TEXT NOT NULL DEFAULT 'manual',
  ext_id      TEXT NOT NULL DEFAULT '',
  meta        TEXT NOT NULL DEFAULT '{}',
  created     INTEGER NOT NULL DEFAULT 0,
  updated     INTEGER NOT NULL DEFAULT 0
);

-- A DHCP range carves a span out of a network. Addresses inside it are
-- "consumed by DHCP" for utilization purposes even when no lease row exists.
CREATE TABLE IF NOT EXISTS dhcp_ranges (
  id          INTEGER PRIMARY KEY,
  network_id  INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  server_id   INTEGER REFERENCES dhcp_servers(id) ON DELETE SET NULL,
  name        TEXT NOT NULL DEFAULT '',
  start_addr  TEXT NOT NULL,
  end_addr    TEXT NOT NULL,
  start_hex   TEXT NOT NULL,
  end_hex     TEXT NOT NULL,
  lease_time  TEXT NOT NULL DEFAULT '12h',
  enabled     INTEGER NOT NULL DEFAULT 1,
  description TEXT NOT NULL DEFAULT '',
  source      TEXT NOT NULL DEFAULT 'manual',
  ext_id      TEXT NOT NULL DEFAULT '',
  meta        TEXT NOT NULL DEFAULT '{}',
  created     INTEGER NOT NULL DEFAULT 0,
  updated     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_dhcp_ranges_net ON dhcp_ranges(network_id);

CREATE TABLE IF NOT EXISTS dns_servers (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  kind        TEXT NOT NULL DEFAULT 'dnsmasq',  -- bind|dnsmasq|unbound|pihole|adguard|windows|other
  host_kind   TEXT NOT NULL DEFAULT '',
  host_id     INTEGER,
  address     TEXT NOT NULL DEFAULT '',
  role        TEXT NOT NULL DEFAULT 'recursive', -- authoritative|recursive|forwarder
  zones       TEXT NOT NULL DEFAULT '',          -- comma-separated
  url         TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'active',
  description TEXT NOT NULL DEFAULT '',
  source      TEXT NOT NULL DEFAULT 'manual',
  ext_id      TEXT NOT NULL DEFAULT '',
  meta        TEXT NOT NULL DEFAULT '{}',
  created     INTEGER NOT NULL DEFAULT 0,
  updated     INTEGER NOT NULL DEFAULT 0
);

-- ─── Scanner ────────────────────────────────────────────────────────
-- Keyed by address text, NOT by ip_addresses.id: the whole point of a sweep
-- is finding responders we have no record for.
CREATE TABLE IF NOT EXISTS scan_results (
  address    TEXT PRIMARY KEY,
  version    INTEGER NOT NULL,
  addr_hex   TEXT NOT NULL,
  alive      INTEGER NOT NULL DEFAULT 0,
  method     TEXT NOT NULL DEFAULT '',
  rtt_ms     REAL,
  hostname   TEXT NOT NULL DEFAULT '',
  mac        TEXT NOT NULL DEFAULT '',
  last_scan  INTEGER NOT NULL DEFAULT 0,
  last_alive INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_scan_hex ON scan_results(version, addr_hex);

-- ─── Audit ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit (
  id          INTEGER PRIMARY KEY,
  ts          INTEGER NOT NULL,
  actor       TEXT NOT NULL DEFAULT '',
  action      TEXT NOT NULL DEFAULT '',
  object_kind TEXT NOT NULL DEFAULT '',
  object_id   INTEGER,
  detail      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_audit_ts ON audit(ts);
"""


def connect():
    """Thread-local connection. autocommit (isolation_level=None) with explicit
    BEGIN for the few multi-statement transactions we run."""
    conn = getattr(_local, 'conn', None)
    if conn is not None:
        return conn
    first = not os.path.exists(DB_PATH)
    os.makedirs(os.path.dirname(DB_PATH) or '.', exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA busy_timeout=15000')
    if first:
        try:
            os.chmod(DB_PATH, 0o600)
        except OSError:
            pass
    _local.conn = conn
    return conn


# Columns added after the first release. CREATE TABLE IF NOT EXISTS will not
# alter an existing table, so new columns are applied here instead — additive
# only, which is all a single-file database at this scale ever needs.
MIGRATIONS = [
    ('devices', 'tags', "TEXT NOT NULL DEFAULT ''"),
]


def _migrate(conn):
    for table, column, decl in MIGRATIONS:
        cols = {r[1] for r in conn.execute('PRAGMA table_info(%s)' % table)}
        if column not in cols:
            conn.execute('ALTER TABLE %s ADD COLUMN %s %s' % (table, column, decl))


def init_db():
    conn = connect()
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.execute("INSERT INTO meta(key,value) VALUES('schema_version',?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (str(SCHEMA_VERSION),))
    return conn


def query(sql, args=()):
    return [dict(r) for r in connect().execute(sql, args).fetchall()]


def query_one(sql, args=()):
    row = connect().execute(sql, args).fetchone()
    return dict(row) if row else None


def execute(sql, args=()):
    return connect().execute(sql, args)


def now():
    return int(time.time())


# ─── App settings (meta key/value table) ──────────────────────────────

def get_setting(key, default=''):
    row = query_one('SELECT value FROM meta WHERE key=?', (key,))
    return row['value'] if row else default


def set_setting(key, value):
    execute("INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)))


# ─── Row <-> JSON helpers ─────────────────────────────────────────────

def load_meta(row):
    """`meta` is stored as a JSON text column so integrators can attach
    arbitrary per-object data (vSphere portgroup, datastore, Proxmox node…)
    without a schema migration. Decode it for API output."""
    if not isinstance(row, dict):
        return row
    raw = row.get('meta')
    if isinstance(raw, str):
        try:
            row['meta'] = json.loads(raw) if raw else {}
        except ValueError:
            row['meta'] = {}
    return row


def dump_meta(value):
    if value in (None, ''):
        return '{}'
    if isinstance(value, str):
        try:
            json.loads(value)
            return value
        except ValueError:
            return '{}'
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return '{}'


def rows(sql, args=()):
    return [load_meta(r) for r in query(sql, args)]


def row(sql, args=()):
    r = query_one(sql, args)
    return load_meta(r) if r else None


# ─── Generic CRUD ─────────────────────────────────────────────────────

def insert(table, fields):
    fields = dict(fields)
    ts = now()
    fields.setdefault('created', ts)
    fields['updated'] = ts
    if 'meta' in fields:
        fields['meta'] = dump_meta(fields['meta'])
    cols = ', '.join(fields)
    marks = ', '.join('?' for _ in fields)
    cur = execute('INSERT INTO %s (%s) VALUES (%s)' % (table, cols, marks),
                  tuple(fields.values()))
    return cur.lastrowid


def update(table, rid, fields):
    fields = dict(fields)
    fields['updated'] = now()
    if 'meta' in fields:
        fields['meta'] = dump_meta(fields['meta'])
    sets = ', '.join('%s=?' % k for k in fields)
    execute('UPDATE %s SET %s WHERE id=?' % (table, sets),
            tuple(fields.values()) + (rid,))


def delete(table, rid):
    execute('DELETE FROM %s WHERE id=?' % table, (rid,))


def audit(actor, action, kind, oid, detail=''):
    try:
        execute('INSERT INTO audit(ts,actor,action,object_kind,object_id,detail) '
                'VALUES(?,?,?,?,?,?)', (now(), actor or '', action, kind, oid, detail))
    except sqlite3.Error:
        pass  # auditing must never fail a request


def audit_list(items, limit=8):
    """Bounded, readable list for batch-operation audit details. "3 hosts
    adopted" tells an operator nothing; the first few identities plus a
    remainder count tells them WHAT was touched without letting a 5000-row
    import write a novel into one audit row."""
    items = [s for s in (str(i).strip() for i in items) if s]
    out = ', '.join(items[:limit])
    if len(items) > limit:
        out += ' +%d more' % (len(items) - limit)
    return out


def audit_stats():
    r = query_one('SELECT COUNT(*) c, MIN(ts) oldest FROM audit')
    return {'total': r['c'], 'oldest': r['oldest'] or 0}


def prune_audit(days=None, everything=False, vacuum=False):
    """Delete audit entries older than `days` (or all of them). Returns the
    number removed.

    The daily auto-prune never VACUUMs: freed pages are reused by future
    inserts, which is all "bounded growth" requires, and a VACUUM rewrites
    the whole database file for no operational gain. The manual prune passes
    vacuum=True so an operator clearing years of history actually gets the
    disk back."""
    with WRITE_LOCK:
        if everything:
            cur = execute('DELETE FROM audit')
        else:
            if not days or days <= 0:
                return 0
            cur = execute('DELETE FROM audit WHERE ts < ?', (now() - days * 86400,))
        deleted = cur.rowcount
        if vacuum and deleted:
            execute('VACUUM')
    return deleted
