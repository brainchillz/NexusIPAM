"""Inventory: clusters, physical devices, virtual machines, containers.

The containment chain the network actually has:

    cluster ──┬── device (physical) ──┬── vm ── container
              └── vm                  └── container

A device may belong to a cluster (a Proxmox node, an ESXi host in a vCenter);
a VM is hosted by a device and/or belongs to a cluster (vCenter can move it
between hosts, so both links are optional); a container's parent is either a
device or a VM, whichever is running its engine. All four are assignable
targets for IP addresses.
"""
from flask import Blueprint, jsonify

from .core import db
from .core.runcmd import err, num
from .core.validators import (CLUSTER_KINDS, CONTAINER_ENGINES, DEVICE_ROLES,
                              HOST_ENGINE, HOST_VIRT, PARENT_KINDS, RE_NAME,
                              STATUSES, VM_PLATFORMS, clean_text, one_of,
                              parse_tags)
from .resource import Resource, register, mount

bp = Blueprint('inventory', __name__)


def _name(data):
    """Every inventory object is keyed by a unique human name."""
    name = str(data.get('name') or '').strip()
    if not RE_NAME.match(name):
        return None, ('Name must start alphanumeric and contain only letters, '
                      'digits, spaces and . _ - @ : /')
    return name, None


def _optional_ref(data, key, table, label):
    """Validate an optional foreign key by id."""
    rid = num(data.get(key))
    if rid is None:
        return None, None
    if not db.query_one('SELECT id FROM %s WHERE id=?' % table, (rid,)):
        return None, 'No such %s' % label
    return rid, None


# ─── Validators ───────────────────────────────────────────────────────

def _v_cluster(data, existing):
    name, e = _name(data)
    if e:
        return None, e
    kind, e = one_of(data.get('kind'), CLUSTER_KINDS, 'Kind', 'proxmox')
    if e:
        return None, e
    status, e = one_of(data.get('status'), STATUSES, 'Status', 'active')
    if e:
        return None, e
    endpoint, e = clean_text(data.get('endpoint'), 'Endpoint', 200)
    if e:
        return None, e
    site, e = clean_text(data.get('site'), 'Site', 64)
    if e:
        return None, e
    desc, e = clean_text(data.get('description'), 'Description')
    if e:
        return None, e
    return {'name': name, 'kind': kind, 'endpoint': endpoint, 'site': site,
            'status': status, 'description': desc}, None


def _v_device(data, existing):
    name, e = _name(data)
    if e:
        return None, e
    role, e = one_of(data.get('role'), DEVICE_ROLES, 'Role', 'server')
    if e:
        return None, e
    status, e = one_of(data.get('status'), STATUSES, 'Status', 'active')
    if e:
        return None, e
    virt, e = one_of(data.get('virt'), HOST_VIRT, 'Hypervisor', '')
    if e:
        return None, e
    engine, e = one_of(data.get('engine'), HOST_ENGINE, 'Container engine', '')
    if e:
        return None, e
    cluster_id, e = _optional_ref(data, 'cluster_id', 'clusters', 'cluster')
    if e:
        return None, e
    # Only written when sent, so an API caller that omits the field does not
    # wipe tags someone else set — the same rule as source/ext_id and engine.
    if 'tags' in data:
        tags, e = parse_tags(data.get('tags'))
        if e:
            return None, e
    else:
        tags = parse_tags(existing.get('tags'))[0] if existing else []
    fields = {'name': name, 'role': role, 'status': status, 'cluster_id': cluster_id,
              'virt': virt, 'engine': engine, 'tags': ', '.join(tags)}
    for key, label, limit in (('manufacturer', 'Manufacturer', 64), ('model', 'Model', 64),
                              ('serial', 'Serial', 64), ('site', 'Site', 64),
                              ('rack', 'Rack', 64), ('position', 'Position', 32),
                              ('description', 'Description', 500)):
        v, e = clean_text(data.get(key), label, limit)
        if e:
            return None, e
        fields[key] = v
    return fields, None


def _v_vm(data, existing):
    name, e = _name(data)
    if e:
        return None, e
    platform, e = one_of(data.get('platform'), VM_PLATFORMS, 'Platform', 'kvm')
    if e:
        return None, e
    status, e = one_of(data.get('status'), STATUSES, 'Status', 'active')
    if e:
        return None, e
    # The VM form does not submit `engine` (a VM has a hypervisor, not a
    # container engine). The API still accepts it, so only write it when the
    # caller actually sends it — otherwise a UI edit would silently clear a
    # value an importer had set.
    if 'engine' in data:
        engine, e = one_of(data.get('engine'), HOST_ENGINE, 'Container engine', '')
        if e:
            return None, e
    else:
        engine = existing.get('engine', '') if existing else ''
    host_id, e = _optional_ref(data, 'host_device_id', 'devices', 'host device')
    if e:
        return None, e
    cluster_id, e = _optional_ref(data, 'cluster_id', 'clusters', 'cluster')
    if e:
        return None, e
    if host_id is None and cluster_id is None:
        # Not an error — an unplaced VM is a legitimate planning state — but a
        # VM with neither link is invisible in the topology views, so the UI
        # nudges toward setting one.
        pass

    sizes = {}
    for key, label, hi in (('vcpus', 'vCPUs', 512), ('memory_mb', 'Memory (MB)', 8 * 1024 * 1024),
                           ('disk_gb', 'Disk (GB)', 1024 * 1024)):
        raw = data.get(key)
        if raw in (None, ''):
            sizes[key] = None
            continue
        v = num(raw)
        if v is None or not 0 < v <= hi:
            return None, '%s must be a positive number (max %d)' % (label, hi)
        sizes[key] = v

    fields = {'name': name, 'platform': platform, 'status': status, 'engine': engine,
              'host_device_id': host_id, 'cluster_id': cluster_id, **sizes}
    for key, label, limit in (('vmid', 'VM ID', 64), ('os', 'OS', 64),
                              ('description', 'Description', 500)):
        v, e = clean_text(data.get(key), label, limit)
        if e:
            return None, e
        fields[key] = v
    return fields, None


def _v_container(data, existing):
    name, e = _name(data)
    if e:
        return None, e
    engine, e = one_of(data.get('engine'), CONTAINER_ENGINES, 'Engine', 'docker')
    if e:
        return None, e
    status, e = one_of(data.get('status'), STATUSES, 'Status', 'active')
    if e:
        return None, e
    parent_kind, e = one_of(data.get('parent_kind'), PARENT_KINDS, 'Parent kind', '')
    if e:
        return None, e
    parent_id = num(data.get('parent_id'))
    if parent_kind:
        if parent_id is None:
            return None, 'A parent id is required when a parent kind is set'
        table = 'devices' if parent_kind == 'device' else 'vms'
        if not db.query_one('SELECT id FROM %s WHERE id=?' % table, (parent_id,)):
            return None, 'No such %s' % parent_kind
    else:
        parent_id = None
    cluster_id, e = _optional_ref(data, 'cluster_id', 'clusters', 'cluster')
    if e:
        return None, e
    fields = {'name': name, 'engine': engine, 'status': status,
              'parent_kind': parent_kind, 'parent_id': parent_id, 'cluster_id': cluster_id}
    for key, label, limit in (('image', 'Image', 200), ('description', 'Description', 500)):
        v, e = clean_text(data.get(key), label, limit)
        if e:
            return None, e
        fields[key] = v
    return fields, None


# ─── Delete guards ────────────────────────────────────────────────────
# Deleting a host object silently orphaning its IP records would be the
# easiest way to corrupt an address plan, so it is refused with a count.

def _guard(kind, table_label):
    def check(row):
        n = db.query_one('SELECT COUNT(*) c FROM ip_addresses '
                         'WHERE assigned_kind=? AND assigned_id=?', (kind, row['id']))['c']
        if n:
            return ('%s still has %d IP address(es) assigned — unassign or delete '
                    'them first' % (table_label, n))
        return None
    return check


def _guard_cluster(row):
    msg = _guard('cluster', 'This cluster')(row)
    if msg:
        return msg
    for table, label in (('devices', 'device'), ('vms', 'VM'), ('containers', 'container')):
        n = db.query_one('SELECT COUNT(*) c FROM %s WHERE cluster_id=?' % table,
                         (row['id'],))['c']
        if n:
            return 'This cluster still has %d %s(s) — reassign them first' % (n, label)
    return None


def _guard_device(row):
    msg = _guard('device', 'This device')(row)
    if msg:
        return msg
    n = db.query_one('SELECT COUNT(*) c FROM vms WHERE host_device_id=?', (row['id'],))['c']
    if n:
        return 'This device still hosts %d VM(s) — move or delete them first' % n
    n = db.query_one("SELECT COUNT(*) c FROM containers WHERE parent_kind='device' "
                     "AND parent_id=?", (row['id'],))['c']
    if n:
        return 'This device still hosts %d container(s) — move or delete them first' % n
    return None


def _guard_vm(row):
    msg = _guard('vm', 'This VM')(row)
    if msg:
        return msg
    n = db.query_one("SELECT COUNT(*) c FROM containers WHERE parent_kind='vm' "
                     "AND parent_id=?", (row['id'],))['c']
    if n:
        return 'This VM still hosts %d container(s) — move or delete them first' % n
    return None


# ─── Resources ────────────────────────────────────────────────────────

def _ip_count(table_alias, kind):
    return ("(SELECT COUNT(*) FROM ip_addresses WHERE assigned_kind='%s' "
            "AND assigned_id = %s.id) AS ip_count" % (kind, table_alias))


CLUSTER_SQL = """
SELECT clusters.*, %s,
       (SELECT COUNT(*) FROM devices WHERE devices.cluster_id = clusters.id) AS device_count,
       (SELECT COUNT(*) FROM vms WHERE vms.cluster_id = clusters.id) AS vm_count
FROM clusters
""" % _ip_count('clusters', 'cluster')

DEVICE_SQL = """
SELECT devices.*, clusters.name AS cluster_name, %s,
       (SELECT COUNT(*) FROM vms WHERE vms.host_device_id = devices.id) AS vm_count,
       (SELECT COUNT(*) FROM containers WHERE containers.parent_kind='device'
          AND containers.parent_id = devices.id) AS container_count
FROM devices LEFT JOIN clusters ON clusters.id = devices.cluster_id
""" % _ip_count('devices', 'device')

VM_SQL = """
SELECT vms.*, devices.name AS host_name, clusters.name AS cluster_name, %s,
       (SELECT COUNT(*) FROM containers WHERE containers.parent_kind='vm'
          AND containers.parent_id = vms.id) AS container_count
FROM vms
LEFT JOIN devices ON devices.id = vms.host_device_id
LEFT JOIN clusters ON clusters.id = vms.cluster_id
""" % _ip_count('vms', 'vm')

CONTAINER_SQL = """
SELECT containers.*, clusters.name AS cluster_name, %s,
       CASE containers.parent_kind
            WHEN 'device' THEN (SELECT name FROM devices WHERE id = containers.parent_id)
            WHEN 'vm'     THEN (SELECT name FROM vms WHERE id = containers.parent_id)
       END AS parent_name
FROM containers LEFT JOIN clusters ON clusters.id = containers.cluster_id
""" % _ip_count('containers', 'container')

register(Resource('clusters', 'clusters', _v_cluster, list_sql=CLUSTER_SQL,
                  get_sql=CLUSTER_SQL + ' WHERE clusters.id=?', order='clusters.name',
                  protect_delete=_guard_cluster))
register(Resource('devices', 'devices', _v_device, list_sql=DEVICE_SQL,
                  get_sql=DEVICE_SQL + ' WHERE devices.id=?', order='devices.name',
                  protect_delete=_guard_device, taggable=True))
register(Resource('vms', 'vms', _v_vm, list_sql=VM_SQL,
                  get_sql=VM_SQL + ' WHERE vms.id=?', order='vms.name',
                  protect_delete=_guard_vm))
register(Resource('containers', 'containers', _v_container, list_sql=CONTAINER_SQL,
                  get_sql=CONTAINER_SQL + ' WHERE containers.id=?', order='containers.name',
                  protect_delete=_guard('container', 'This container')))

for _res in ('clusters', 'devices', 'vms', 'containers'):
    mount(bp, _res)


# ─── Cross-cutting views ──────────────────────────────────────────────

@bp.route('/api/tags')
def tags_list():
    """Every tag in use, with how many devices carry it — enough to build a
    filter UI without anyone having to remember what they typed last time."""
    counts = {}
    for r in db.query("SELECT tags FROM devices WHERE tags <> ''"):
        for t in r['tags'].replace(',', ' ').split():
            counts[t] = counts.get(t, 0) + 1
    return jsonify({'tags': [{'tag': t, 'count': c}
                             for t, c in sorted(counts.items(),
                                                key=lambda kv: (-kv[1], kv[0]))]})


@bp.route('/api/hosts')
def hosts_list():
    """Every assignable object in one list — what the "assign to" pickers and
    an external tool's autocomplete both need."""
    out = []
    for kind, sql in (('device', 'SELECT id, name, role AS subtype FROM devices'),
                      ('vm', 'SELECT id, name, platform AS subtype FROM vms'),
                      ('container', 'SELECT id, name, engine AS subtype FROM containers'),
                      ('cluster', 'SELECT id, name, kind AS subtype FROM clusters')):
        for r in db.query(sql + ' ORDER BY name'):
            out.append({'kind': kind, **r})
    return jsonify({'hosts': out, 'count': len(out)})


@bp.route('/api/hosts/<kind>/<int:rid>')
def host_detail(kind, rid):
    """One object plus its addresses and its place in the containment tree."""
    from .addresses import KIND_TABLES, ADDRESS_LIST_SQL, expand_assignment
    if kind not in KIND_TABLES:
        return err('Unknown object kind', 404)
    sql = {'device': DEVICE_SQL + ' WHERE devices.id=?',
           'vm': VM_SQL + ' WHERE vms.id=?',
           'container': CONTAINER_SQL + ' WHERE containers.id=?',
           'cluster': CLUSTER_SQL + ' WHERE clusters.id=?'}[kind]
    obj = db.row(sql, (rid,))
    if not obj:
        return err('No such %s' % kind, 404)

    addrs = db.rows(ADDRESS_LIST_SQL + ' WHERE ip_addresses.assigned_kind=? '
                    'AND ip_addresses.assigned_id=? ORDER BY ip_addresses.addr_hex',
                    (kind, rid))
    for a in addrs:
        expand_assignment(a)

    children = {}
    if kind == 'cluster':
        children['devices'] = db.rows('SELECT id, name, role, status FROM devices '
                                      'WHERE cluster_id=? ORDER BY name', (rid,))
        children['vms'] = db.rows('SELECT id, name, platform, status FROM vms '
                                  'WHERE cluster_id=? ORDER BY name', (rid,))
    elif kind == 'device':
        children['vms'] = db.rows('SELECT id, name, platform, status FROM vms '
                                  'WHERE host_device_id=? ORDER BY name', (rid,))
        children['containers'] = db.rows("SELECT id, name, engine, status FROM containers "
                                         "WHERE parent_kind='device' AND parent_id=? "
                                         "ORDER BY name", (rid,))
    elif kind == 'vm':
        children['containers'] = db.rows("SELECT id, name, engine, status FROM containers "
                                         "WHERE parent_kind='vm' AND parent_id=? "
                                         "ORDER BY name", (rid,))

    return jsonify({'kind': kind, 'object': obj, 'addresses': addrs, 'children': children})


@bp.route('/api/topology')
def topology():
    """The whole containment tree in one call — clusters holding devices and
    VMs, devices holding VMs and containers, VMs holding containers, plus
    everything unplaced. Drives the Topology page and is the cheapest way for
    an external tool to mirror the inventory."""
    clusters = db.rows(CLUSTER_SQL + ' ORDER BY clusters.name')
    devices = db.rows(DEVICE_SQL + ' ORDER BY devices.name')
    vms = db.rows(VM_SQL + ' ORDER BY vms.name')
    containers = db.rows(CONTAINER_SQL + ' ORDER BY containers.name')

    def attach(obj, kind):
        obj['kind'] = kind
        obj['children'] = []
        return obj

    cmap = {c['id']: attach(c, 'cluster') for c in clusters}
    dmap = {d['id']: attach(d, 'device') for d in devices}
    vmap = {v['id']: attach(v, 'vm') for v in vms}

    orphans = {'devices': [], 'vms': [], 'containers': []}

    for c in containers:
        node = attach(c, 'container')
        parent = (dmap if c['parent_kind'] == 'device' else vmap).get(c['parent_id']) \
            if c['parent_kind'] else None
        (parent['children'] if parent else orphans['containers']).append(node)

    for v in vms:
        node = vmap[v['id']]
        parent = dmap.get(v['host_device_id']) or cmap.get(v['cluster_id'])
        (parent['children'] if parent else orphans['vms']).append(node)

    for d in devices:
        node = dmap[d['id']]
        parent = cmap.get(d['cluster_id'])
        (parent['children'] if parent else orphans['devices']).append(node)

    return jsonify({'clusters': list(cmap.values()), 'unplaced': orphans})
