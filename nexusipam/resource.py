"""Generic REST resource machinery.

Nine of this app's tables are plain records with the same lifecycle: list,
create, read, update, delete — differing only in which fields they accept and
how they validate. Writing five near-identical route bodies nine times over
would be ~900 lines of copy-paste where a single bug would have to be fixed in
nine places. Instead each feature module declares a Resource (a validator plus
an optional richer list query) and registers it; the routes below are the only
implementation.

Every resource gets, for free:
  * `source` / `ext_id` / `meta` handling, so an external system (DNSMAQ-MGR,
    VC-Deployer, a Proxmox importer) can round-trip its own identifiers;
  * upsert-by-(source, ext_id) via `?upsert=1`, which is what makes repeated
    syncs idempotent instead of duplicating records;
  * `?since=<epoch>` filtering for incremental pulls;
  * audit-log entries naming the acting user or token.
"""
from flask import jsonify, request

from .core import db
from .core.auth import actor
from .core.runcmd import err, num
from .core.validators import RE_SLUG, clean_text

# Registered by each feature module at import time; the API index and the
# change feed both walk this.
REGISTRY = {}


class Resource:
    """Declarative description of one CRUD table.

    validate(data, existing) -> (fields, error). It receives the raw JSON body
    and, on update, the current row; it returns only the columns it wants
    written. `existing` lets a validator enforce uniqueness excluding self.
    """

    def __init__(self, name, table, validate, list_sql=None, get_sql=None,
                 order='id', label='name', on_change=None, protect_delete=None,
                 singular=None, taggable=False):
        self.name = name
        self.table = table
        # Single-record responses and error messages key off the singular. It
        # is derived by dropping ONE trailing 's' (str.rstrip would eat both
        # of them in "addresses"), overridable for anything irregular.
        self.singular = singular or (name[:-1] if name.endswith('s') else name)
        self.validate = validate
        self.list_sql = list_sql
        self.get_sql = get_sql
        self.order = order
        self.label = label
        self.taggable = taggable            # exposes ?tag= filtering
        self.on_change = on_change          # called after any write (reindex hooks)
        self.protect_delete = protect_delete  # -> error string to refuse a delete


def register(res):
    REGISTRY[res.name] = res
    return res


def _common_fields(data, existing=None):
    """source / ext_id / meta are accepted on every resource. They are the
    integration contract: `source` names the system of record, `ext_id` is
    that system's own key, `meta` is opaque passthrough we never interpret.

    All three are only written when the caller actually sends them. That
    matters on update: the UI edit forms do not carry these fields, and
    defaulting a missing `source` back to 'manual' would quietly sever the
    sync linkage of any record an importer owns the moment someone fixed a
    typo in its description.
    """
    fields = {}
    if 'source' in data:
        source = str(data.get('source') or 'manual').strip()
        if not RE_SLUG.match(source):
            return None, 'Invalid source (letters, digits, dot, dash, underscore)'
        fields['source'] = source
    elif existing is None:
        fields['source'] = 'manual'

    if 'ext_id' in data:
        ext_id, e = clean_text(data.get('ext_id'), 'ext_id', 128)
        if e:
            return None, e
        fields['ext_id'] = ext_id
    elif existing is None:
        fields['ext_id'] = ''

    if 'meta' in data:
        meta = data.get('meta')
        if meta is not None and not isinstance(meta, dict):
            return None, 'meta must be a JSON object'
        fields['meta'] = meta or {}
    return fields, None


def _upsert_key(data):
    """(source, ext_id) for the ?upsert=1 lookup — a create-time concern, so
    the defaults apply here rather than in _common_fields."""
    source = str(data.get('source') or 'manual').strip()
    if not RE_SLUG.match(source):
        return None, None, 'Invalid source (letters, digits, dot, dash, underscore)'
    ext_id, e = clean_text(data.get('ext_id'), 'ext_id', 128)
    if e:
        return None, None, e
    return source, ext_id, None


def _fetch(res, rid):
    """Read one row, using the resource's join-enriched query when it has one
    (so a GET returns the same shape the list view shows)."""
    sql = res.get_sql or ('SELECT * FROM %s WHERE id=?' % res.table)
    return db.row(sql, (rid,))


def _list(res):
    sql = res.list_sql or ('SELECT * FROM %s' % res.table)
    args = []
    where = []
    since = num(request.args.get('since'))
    if since is not None:
        where.append('%s.updated >= ?' % res.table)
        args.append(since)
    source = request.args.get('source')
    if source:
        where.append('%s.source = ?' % res.table)
        args.append(source)
    tag = (request.args.get('tag') or '').strip().lstrip('#').lower()
    if tag and res.taggable:
        # Tags are stored comma-separated; wrapping both sides in delimiters
        # makes the match exact, so filtering on "ai" never matches "airflow".
        where.append("(', ' || %s.tags || ',') LIKE ?" % res.table)
        args.append('%%, %s,%%' % tag)
    if where:
        # Always WHERE, never a conditional AND. No list_sql has a top-level
        # WHERE — but several embed a subquery that does (`(SELECT COUNT(*) …
        # WHERE assigned_kind='device')`), and sniffing the string for " WHERE "
        # saw those. The filter then landed on the trailing LEFT JOIN's ON
        # clause, which is valid SQL that filters nothing: every ?source=,
        # ?since= and ?tag= query silently returned the whole table.
        sql += ' WHERE ' + ' AND '.join(where)
    sql += ' ORDER BY %s' % res.order
    return db.rows(sql, tuple(args))


def _find_by_ext(res, source, ext_id):
    if not ext_id:
        return None
    return db.row('SELECT * FROM %s WHERE source=? AND ext_id=?' % res.table,
                  (source, ext_id))


def handle_list(name):
    res = REGISTRY[name]
    return jsonify({name: _list(res)})


def handle_get(name, rid):
    res = REGISTRY[name]
    rec = _fetch(res, rid)
    if not rec:
        return err('No such %s' % res.singular, 404)
    return jsonify(rec)


def handle_create(name):
    res = REGISTRY[name]
    data = request.get_json(silent=True) or {}

    # Idempotent sync: an importer that re-runs should update its own record,
    # not fail on the UNIQUE(name) constraint or create a twin.
    if request.args.get('upsert') in ('1', 'true', 'yes'):
        source, ext_id, e = _upsert_key(data)
        if e:
            return err(e)
        found = _find_by_ext(res, source, ext_id)
        if found:
            return handle_update(name, found['id'])

    fields, e = res.validate(data, None)
    if e:
        return err(e)
    common, e = _common_fields(data)
    if e:
        return err(e)
    fields.update(common)
    try:
        with db.WRITE_LOCK:
            rid = db.insert(res.table, fields)
            if res.on_change:
                res.on_change('create', rid, fields)
            db.audit(actor(), 'create', name, rid, fields.get(res.label, ''))
    except db.sqlite3.IntegrityError as ex:
        return err(_integrity_message(res, ex), 409)
    rec = _fetch(res, rid)
    return jsonify({'success': True, 'id': rid, res.singular: rec})


def handle_update(name, rid):
    res = REGISTRY[name]
    existing = db.row('SELECT * FROM %s WHERE id=?' % res.table, (rid,))
    if not existing:
        return err('No such %s' % res.singular, 404)
    body = request.get_json(silent=True) or {}
    # PARTIAL-UPDATE SEMANTICS, enforced in one place: any field the caller
    # does not send keeps its stored value; sending an explicit empty/null
    # clears it. Without this, every validator re-defaults unsent fields and
    # an update that only touches `status` silently wipes dns_name, mac,
    # assignment, description, … — a bug class that bit three separate times
    # (source/ext_id, vm.engine, device.tags) before being fixed wholesale.
    # The stored row layers under the request body; validators then see a
    # complete picture. Internal columns (id, created, addr_hex, …) that ride
    # along are ignored by validators and never reach the UPDATE.
    data = dict(existing)
    data.update(body)
    fields, e = res.validate(data, existing)
    if e:
        return err(e)
    common, e = _common_fields(data, existing)
    if e:
        return err(e)
    fields.update(common)
    try:
        with db.WRITE_LOCK:
            db.update(res.table, rid, fields)
            if res.on_change:
                res.on_change('update', rid, fields)
            db.audit(actor(), 'update', name, rid, fields.get(res.label, ''))
    except db.sqlite3.IntegrityError as ex:
        return err(_integrity_message(res, ex), 409)
    return jsonify({'success': True, 'id': rid, res.singular: _fetch(res, rid)})


def handle_delete(name, rid):
    res = REGISTRY[name]
    existing = db.row('SELECT * FROM %s WHERE id=?' % res.table, (rid,))
    if not existing:
        return err('No such %s' % res.singular, 404)
    if res.protect_delete:
        msg = res.protect_delete(existing)
        if msg:
            return err(msg, 409)
    with db.WRITE_LOCK:
        db.delete(res.table, rid)
        if res.on_change:
            res.on_change('delete', rid, existing)
        db.audit(actor(), 'delete', name, rid, existing.get(res.label, ''))
    return jsonify({'success': True})


def _integrity_message(res, ex):
    """Turn SQLite's constraint text into something an operator can act on."""
    text = str(ex)
    if 'UNIQUE' in text:
        if '.name' in text:
            return 'A %s with that name already exists' % res.singular
        if '.cidr' in text:
            return 'That network already exists'
        if '.address' in text:
            return 'That address is already recorded'
        if 'vid' in text:
            return 'That VLAN ID already exists at this site'
        return 'That record already exists'
    if 'FOREIGN KEY' in text:
        return 'Referenced record does not exist'
    return text


def mount(bp, name, url=None):
    """Attach the five standard routes for a registered resource.

    Endpoint names are unique per resource so Flask (and the RBAC allowlists
    in core.auth, which key off bare endpoint names) stay unambiguous.
    """
    path = url or ('/api/' + name)
    bp.add_url_rule(path, endpoint='%s_list' % name,
                    view_func=lambda n=name: handle_list(n), methods=['GET'])
    bp.add_url_rule(path, endpoint='%s_create' % name,
                    view_func=lambda n=name: handle_create(n), methods=['POST'])
    bp.add_url_rule(path + '/<int:rid>', endpoint='%s_get' % name,
                    view_func=lambda rid, n=name: handle_get(n, rid), methods=['GET'])
    bp.add_url_rule(path + '/<int:rid>', endpoint='%s_update' % name,
                    view_func=lambda rid, n=name: handle_update(n, rid), methods=['POST'])
    bp.add_url_rule(path + '/<int:rid>', endpoint='%s_delete' % name,
                    view_func=lambda rid, n=name: handle_delete(n, rid), methods=['DELETE'])
