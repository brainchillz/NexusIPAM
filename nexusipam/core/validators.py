"""Input validators.

Two jobs: keep junk out of the database, and keep hostile values out of the
text we render for other systems (hosts files, dnsmasq dhcp-host lines). The
export endpoints build those by concatenation, so a stored value containing a
newline could smuggle in an extra directive — these regexes are the barrier.
"""
import re

from ..netutil import parse_ip, parse_network

RE_HOSTNAME = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?$')
RE_MAC = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$')
# Real inventory names carry parentheses and plus signs — "NS1 (DNS primary)",
# "Synology DS723+" — so the set is a little wider than a hostname's. Still no
# line breaks, still bounded: the exports that concatenate text stay safe.
RE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._@:/()+-]{0,62}$')
RE_IFACE = re.compile(r'^[A-Za-z0-9._@:-]{1,32}$')
RE_TEXT = re.compile(r'^[^\r\n]{0,500}$')
RE_SLUG = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
RE_LEASE = re.compile(r'^(\d+[smhdw]?|infinite)$')
RE_URL = re.compile(r'^https?://[A-Za-z0-9.\[\]:_-]+(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?$')
RE_TAG = re.compile(r'^[a-z0-9][a-z0-9._-]{0,31}$')
MAX_TAGS = 24

# Controlled vocabularies. Kept as sets so the API rejects typos loudly
# instead of quietly storing a value no page will ever filter on.
NETWORK_ROLES = {'container', 'subnet', 'pool'}
IP_STATUSES = {'active', 'reserved', 'deprecated', 'dhcp'}
DEVICE_ROLES = {'server', 'switch', 'router', 'firewall', 'ap', 'storage',
                'ai', 'mixed', 'appliance', 'pdu', 'other'}
# 'ai' covers Ray and anything else that pools compute for training/inference
# (RPC, Slurm, …) — the framework matters less than the fact that it is a
# cluster of machines acting as one. 'storage' covers Ceph, Gluster and friends.
CLUSTER_KINDS = {'proxmox', 'vsphere', 'kubernetes', 'nomad',
                 'ai', 'storage', 'other'}
# The five the UI offers, plus legacy values still accepted so records created
# before the vocabulary was tightened (and any importer using them) keep working.
# An LXD/Incus VM is KVM underneath and is recorded as 'kvm'.
VM_PLATFORMS = {'vsphere', 'proxmox', 'kvm', 'xen', 'hyperv',
                'esxi', 'vcenter', 'other'}
CONTAINER_ENGINES = {'docker', 'lxd', 'incus', 'podman', 'kubernetes', 'other'}
HOST_VIRT = {'', 'vsphere', 'proxmox', 'kvm', 'xen', 'hyperv',
             'esxi', 'other'}
HOST_ENGINE = {'', 'docker', 'lxd', 'incus', 'podman', 'kubernetes', 'other'}
DHCP_KINDS = {'dnsmasq', 'isc-dhcp', 'kea', 'windows', 'unifi', 'other'}
DNS_KINDS = {'bind', 'dnsmasq', 'unbound', 'pihole', 'adguard', 'windows',
             'powerdns', 'other'}
DNS_ROLES = {'authoritative', 'recursive', 'forwarder'}
STATUSES = {'active', 'planned', 'staged', 'offline', 'decommissioned'}
PARENT_KINDS = {'', 'device', 'vm'}


def is_ip(s):
    return parse_ip(s) is not None


def is_cidr(s):
    return parse_network(s) is not None


def valid_fqdn(s):
    """A bare hostname or a dotted FQDN (each label hostname-shaped)."""
    s = str(s or '')
    if not s or len(s) > 253:
        return False
    return all(RE_HOSTNAME.match(part) for part in s.rstrip('.').split('.'))


def norm_mac(s):
    """Normalize to lowercase colon form, or None if it isn't a MAC."""
    s = str(s or '').strip()
    if not s:
        return ''
    if not RE_MAC.match(s):
        return None
    return s.replace('-', ':').lower()


def check(cond, message):
    """Tiny helper so validators read as a list of assertions."""
    return None if cond else message


def clean_text(value, field, limit=500):
    """Trim, enforce single-line, enforce length. Returns (value, error)."""
    v = str(value or '').strip()
    if len(v) > limit:
        return None, '%s is too long (max %d characters)' % (field, limit)
    if not RE_TEXT.match(v):
        return None, '%s must not contain line breaks' % field
    return v, None


def one_of(value, allowed, field, default=None):
    """Validate against a controlled vocabulary. Returns (value, error)."""
    v = str(value or '').strip().lower()
    if not v and default is not None:
        return default, None
    if v not in allowed:
        return None, '%s must be one of: %s' % (field, ', '.join(sorted(x for x in allowed if x)))
    return v, None


def parse_tags(value):
    """Free-form tags -> a normalized, de-duplicated, sorted list.

    Accepts anything an operator would plausibly type: "#AI #Storage",
    "ai, storage", "AI storage container". Leading hashes are stripped and
    everything is lower-cased, because a tag that groups things only works if
    "#AI" and "ai" are the same tag. Returns (list, error).
    """
    if value is None or value == '':
        return [], None
    if isinstance(value, (list, tuple)):
        raw = list(value)
    else:
        raw = str(value).replace(',', ' ').split()
    out = []
    for t in raw:
        t = str(t).strip().lstrip('#').lower()
        if not t:
            continue
        if not RE_TAG.match(t):
            return None, ('Invalid tag "%s" — use letters, digits, dot, dash '
                          'or underscore' % t)
        if t not in out:
            out.append(t)
    if len(out) > MAX_TAGS:
        return None, 'Too many tags (max %d)' % MAX_TAGS
    return sorted(out), None
