# Nexus IPAM

IP address management for a medium-to-large home lab — networks, addresses,
VLANs, DHCP pools, DNS servers, and the physical and virtual things that
consume addresses — in the Nexus Dashboard style: Python/Flask backend,
vanilla-JS frontend, no build step, dark burnt-orange theme with a light mode.
It shares its stylesheet and UI conventions with [DNSMAQ-MGR](https://github.com/brainchillz/nexus-dnsmasq-mgr)
so the two apps look and behave like one system.

The app tracks **what should be true** about your address plan and gives you
the tools to check it against **what is actually true** on the wire:

1. record networks, addresses and the devices/VMs/containers that use them;
2. see free space per subnet, with DHCP pools and reservations accounted for;
3. **ping-verify** that "free" really means free before you hand an address out;
4. **reconcile** — find hosts answering pings that nobody recorded, and records
   for machines that no longer answer.

It can also **make** the plan true, rather than only describing it, in two
sections: `hosts` (each address carries an ordered list of DNS names, rendered
and pushed to the servers that answer queries — DNSMAQ-MGR nodes, or a UniFi
gateway's Static DNS) and `dhcp` (scopes, the options they hand out, and
MAC→address reservations, pushed the same way). Provisioning a host becomes
one call that allocates an address, names it, optionally reserves it, and
publishes everywhere; deprovisioning removes all of it. Every target is pushed
independently, and the servers keep serving from local state, so Nexus IPAM
being down never affects name resolution or leasing.

Push is entirely optional — configure no targets and it stays a pure record of
your address plan.

---

## Screenshots

Seeded demo data; dark theme (a light theme is one click away).

![Overview](docs/screenshots/overview.png)

| | |
|---|---|
| ![Networks](docs/screenshots/networks.png) | ![Network detail with the IP map](docs/screenshots/network-detail.png) |
| ![IP addresses](docs/screenshots/addresses.png) | ![Devices](docs/screenshots/devices.png) |
| ![Topology](docs/screenshots/topology.png) | ![Scan and reconcile](docs/screenshots/scan.png) |

---

## Storage: SQLite, not a database server

The brief asked to avoid a database engine if reasonable. SQLite is the right
answer here and it *is* "no engine" in the sense that matters: no server
process, no daemon, no extra dependency (it ships with Python), and the whole
dataset is one file you can copy, diff or drop in a git-crypt repo.

Flat JSON was considered and rejected. IPAM is inherently relational — an
address belongs to a network, which belongs to a VLAN; the address is assigned
to a device, which belongs to a cluster — and the hot query is a range scan
over IP space ("every address inside 10.0.0.0/23"). With JSON that means
loading everything into memory and hand-joining on every request, with no
atomicity when one action touches several files. Address allocation in
particular *must* be a single indivisible find-and-claim or two concurrent
deploys get the same IP.

At a few thousand entries SQLite is not working hard. The design comfortably
handles hundreds of thousands.

### The one clever bit

Every address is stored twice: as canonical text (`10.0.0.42`) and as a
zero-padded 32-character hex string. Fixed-width hex makes lexicographic
comparison identical to numeric comparison, so "is this address inside that
prefix" becomes an indexed `BETWEEN` — and the same code path works unchanged
for IPv4 and IPv6.

Consequently **parent/child relationships between networks are never stored**.
They are derived on read from the hex bounds, so adding `10.0.0.0/8` after
`10.1.2.0/24` already exists immediately adopts it, with no migration and no
chance of a stale tree.

---

## Features

### Networks
- **IPv4 and IPv6**, arbitrary prefix lengths, entered as any CIDR
  (`10.0.0.5/24` normalizes to `10.0.0.0/24`).
- **Supernets and subnets** in one tree, nesting derived automatically.
  Mark a big block as a *container* and it is excluded from utilization
  averages instead of skewing them.
- Per-network gateway, DNS servers, domain, site and VLAN.
- **Utilization** that counts records *and* DHCP pool spans, without
  double-counting a static reservation that sits inside a pool.
- `/31` and `/32` handled per RFC 3021 — a point-to-point link has two usable
  addresses, not zero.

### Addresses
- Status: `active`, `reserved`, `dhcp`, `deprecated`. Reserved and deprecated
  addresses stay out of allocation, which is the point of having them.
- Assigned generically to a **device, VM, container or cluster**, with an
  optional interface name, MAC, DNS name and "is primary" flag.
- A separate **DHCP reservation** flag — deliberately not a status, because a
  reservation says how an address is *delivered* while status says what it is
  *for*, and a live host with a fixed lease is legitimately both `active` and
  reserved. The flag (plus the MAC) is what publishes the binding in the
  `dhcp` push section.
- **Visual IP map** — one cell per address in a subnet, coloured by state,
  with the gateway flagged; click any cell to see everything known about it.
- Bulk import (paste `IP hostname MAC` lines), CSV export, bulk span
  reservation (`.1`–`.20` for infrastructure in one call).

### Names — several per address, in order
One address carrying several names is a **first-class shape**, not an anomaly:
parallel A records are how a box that runs six services gets six names, and
collapsing them into one field loses information every DNS server already
holds. So names live in their own ordered list per address:

- **Position 0 is canonical.** It is what a DNS server answers for the
  reverse (PTR) lookup, and it is mirrored into the address's `dns_name` as a
  cache, so every list, search, export and importer keeps working unchanged.
- Each name carries its own **type** (`a` or `cname`), **comment**, **enabled**
  flag and **`ext_id`** — the last preserving the DNS server's own record id,
  which is what lets an import and a push back out reproduce a zone exactly
  rather than approximately.
- Reorder, add, disable or remove them in the address editor, or through
  `GET`/`POST /api/addresses/<id>/names`.

Disabling a name keeps it recorded and stops publishing it — the difference
between "we are not using this yet" and "delete it and forget it existed".

### Provision and deprovision
The two operations that actually change the world, each one action:

- **Provision** — take the next free address in a network, record it with its
  name and aliases, and push DNS to every enforcement node. The response
  carries the same L3 facts as `/api/allocate`, so a deployment tool can go
  straight from this to building a machine that boots with working forward
  *and* reverse DNS.
- **Deprovision** — names removed, address released (or parked as
  `deprecated` with `keep`), every node updated. This is the half that gets
  skipped by hand, and skipping it is why stale DNS exists everywhere.

Provision refuses a name that already resolves somewhere else rather than
silently creating round-robin, so a typo fails loudly instead of quietly.
With a MAC and `is_reservation: true` it also publishes the DHCP reservation
in the same action; deprovision (including `keep`) withdraws it — a parked
address must not keep its MAC binding live on the DHCP server.

### Free-space and ping verification
- Free list per network, excluding records, DHCP pools and the gateway.
- **Ping check** any candidate before trusting it. Verification is not
  cosmetic: `POST /api/allocate` with `verify: true` will skip a candidate
  that answers and record it as an unmanaged host.
- **Ping sweeps** of a whole subnet, or only the addresses believed free, run
  as a background job with live progress. ICMP goes through the system `ping`
  binary, so the app needs no `CAP_NET_RAW` and no root.
- Responders get a reverse-DNS lookup and, for on-link IPv4, a MAC from the
  kernel neighbour table.

### Reconciliation
Lists that tell you where the plan and reality disagree:
- **Unmanaged hosts** — answered a ping, no record exists. One click adopts
  them into the address plan with their discovered hostname and MAC.
- **Silent records** — recorded active, did not answer. Powered off,
  firewalled, or a ghost record to delete.
- **Lease overlay** — dynamic leases read straight from the DHCP server:
  observed, never written into the plan (a lease stops being true with nobody
  touching it), aged out on its own, and refreshed on a schedule. Where a
  ping sweep infers, this is the server's own ledger — and it is the only
  view that can say a reservation is being ignored: the address answered for
  a *different* MAC than the one it is reserved for.

### Inventory
The containment chain a real lab actually has:

```
cluster ──┬── device (physical) ──┬── vm ── container
          └── vm                  └── container
```

- **Clusters** — Proxmox, vSphere/vCenter, Kubernetes, Nomad, **AI** (Ray, RPC
  and anything else pooling compute — the framework matters less than the fact
  that machines act as one) and **Storage** (Ceph, Gluster, …).
- **Devices** — servers, AI nodes, storage, **mixed**, switches, routers,
  firewalls, APs; with manufacturer/model/serial and rack position. A device
  declares whether it hosts VMs (`vsphere`/`proxmox`/`kvm`/…) and/or containers
  (`docker`/`lxd`/…).
- **Tags** on devices — free-form and additive, because `role` is one value and
  a real box is often several things at once. Type `#AI #Storage #Container`;
  hashes are optional and everything is lower-cased, so `#AI` and `ai` are the
  same tag however it was typed. Filter with `?tag=ai` on the API or by
  clicking a tag in the UI; `GET /api/tags` lists every tag with a count.
- **Virtual machines** — placed on a host device and/or a cluster, with
  platform, platform ID (Proxmox VMID / vSphere moref), sizing and OS.
- **Containers** — Docker, LXD, Incus, Podman, Kubernetes; parented to a
  device *or* a VM, whichever runs the engine.
- **Topology** page renders the whole tree; objects with no parent are listed
  separately rather than silently hidden.

Deleting an object that still owns addresses or still hosts children is
refused with a count, so the address plan cannot be orphaned by accident.

### DHCP and DNS
Modelled **generically**, not in any one server's config dialect — the point
is to account for the address space a pool consumes no matter what serves it.
- DHCP servers (dnsmasq, ISC, Kea, Windows, UniFi) with a management URL, so
  a server's own DNSMAQ-MGR instance is one click away.
- DHCP ranges tied to a network, overlap-checked against each other and
  bounds-checked against the network.
- **DHCP options** per network, stored in dnsmasq's spelling
  (`option:ntp-server`, or a bare code) because it is the more expressive
  form — every renderer translates from it. Router, DNS and domain are
  deliberately **refused** as options: they already live on the network row,
  drive allocation and the deploy payload, and a second copy would drift.
- DNS servers with role (authoritative / recursive / forwarder) and zones.

### DHCP-side names
A host with a reservation usually already has a name — the gateway's own DNS
resolves it, and the plan knows nothing about it. Three sources per client,
three levels of trust: a **Local DNS Record** (an FQDN someone chose, already
served — adopting one is a handover, the next push takes it over), the
client's human **label** (not DNS-safe — proposed, never mangled into shape),
and the **option-12 hostname** the device claimed for itself (a device can
claim to be `ns1`, hence lowest trust and always collision-checked). The DNS
page lists them as candidates; adoption is explicit, per address, lands as an
alias unless the address has no names (position 0 and the PTR never move
silently), and lease-derived names are shown but never adopted — a dynamic
name published into authoritative DNS goes stale with nobody touching it.

### Health checks
Flags real data problems, not style opinions: addresses outside every defined
network, assignments pointing at deleted objects, duplicate MACs, gateways
with no record, and unmanaged hosts.

---

## Install

### Docker

```bash
docker compose up -d --build
docker compose logs | grep -A3 'initial admin'   # first-run password
```

Then open `https://<host>:8444`. The certificate is self-signed on first run.

Bridge networking is the default and is fully functional for the UI and API.
Ping sweeps from a bridge network only reach what is routable from the
container — to scan your LAN directly, switch to the `network_mode: host`
variant commented into `docker-compose.yml`.

Prebuilt images are published to GHCR by CI (`latest` from main, semver tags
from releases), so building from source is optional:

```bash
docker run -d --name nexus-ipam -p 8444:8444 \
  -v nexus-ipam-data:/data ghcr.io/brainchillz/nexusipam:latest
docker logs nexus-ipam | grep -A3 'initial admin'
```

Set `NEXUSIPAM_ADMIN_PASSWORD` to skip the generated first-run password; the
UI forces a change on first login otherwise.

### Bare metal (Debian/Ubuntu)

```bash
sudo ./install.sh
```

Installs to `/opt/nexus-ipam`, runs as the unprivileged `nexusipam` user under
systemd. No sudoers rules are needed — the app never runs a privileged command.

### Upgrading

In place, and there is no separate migration step:

```bash
sudo ./install.sh                                  # bare metal — re-run it
docker compose up -d --build                       # Docker
```

`install.sh` replaces only the code and reuses the existing venv; `ipam.db`,
`auth.json` and `certs/` are never touched. Schema changes are additive and
applied at startup — new columns and tables are created, existing rows are
migrated forward, and an older database opens without any action from you.

Migration runs *before* the startup backup, so that backup reflects the new
schema. **Copy `ipam.db` yourself before a version jump** if you want a
restore point that predates it — downgrading is not supported.

### Configuration

Everything is a `NEXUSIPAM_*` environment variable:

| Variable | Default | Meaning |
|---|---|---|
| `NEXUSIPAM_DATA_DIR` | app dir | Where `ipam.db`, `auth.json` and `certs/` live |
| `NEXUSIPAM_DB` | `$DATA_DIR/ipam.db` | Database file |
| `NEXUSIPAM_AUTH_FILE` | `$DATA_DIR/auth.json` | Users, API tokens and the session secret (mode 0600) |
| `NEXUSIPAM_PORT` | `8444` (`8081` if TLS off) | Web/API port |
| `NEXUSIPAM_TLS` | `1` | `0` serves plain HTTP (behind a TLS proxy) |
| `NEXUSIPAM_TLS_DIR` | `$DATA_DIR/certs` | Where a generated certificate is kept |
| `NEXUSIPAM_TLS_CERT` / `_KEY` | `$TLS_DIR/nexus-ipam.{crt,key}` | Point these at your own certificate instead |
| `NEXUSIPAM_COOKIE_SECURE` | follows `TLS` | Force the session cookie's `Secure` flag on or off — set `1` when TLS terminates at a proxy in front |
| `NEXUSIPAM_ADMIN_PASSWORD` | — | Skips the generated first-run password |
| `NEXUSIPAM_NO_SUDO` | `0` (`1` in Docker) | Never prefix `sudo` on the few commands run (`ping`, `ip neigh`) |
| `NEXUSIPAM_SCAN_WORKERS` | `64` | Ping concurrency |
| `NEXUSIPAM_SCAN_TIMEOUT` | `1.0` | Seconds to wait per probe |
| `NEXUSIPAM_SCAN_MAX_HOSTS` | `4096` | Ceiling on one scan job |
| `NEXUSIPAM_SCAN_RESOLVE` | `1` | Reverse-DNS responders |
| `NEXUSIPAM_MAX_ENUMERATE` | `65536` | Largest prefix the UI will draw an address map for |
| `NEXUSIPAM_BACKUP_HOURS` | `24` | Automatic JSON backups to `$DATA_DIR/backups/` (`0` disables) |
| `NEXUSIPAM_BACKUP_KEEP` | `14` | Backups retained |
| `NEXUSIPAM_LEASE_MINUTES` | `60` | Background lease-overlay refresh from every gateway push target (`0` disables — the overlay then only moves when refreshed by hand) |
| `NEXUSIPAM_AUDIT_DAYS` | `365` | Audit entries older than this are pruned daily (`0` keeps forever) |

### CLI

```bash
python nexus-ipam.py set-password admin
python nexus-ipam.py token vc-deployer admin   # prints the token once
python nexus-ipam.py scan 10.0.0.0/24          # ping sweep from the shell
python nexus-ipam.py export > backup.json
python nexus-ipam.py reindex                   # recompute address->network mapping
```

---

## API

Authentication is a session cookie (the UI) or a bearer token (automation):

```
Authorization: Bearer nx_...
X-API-Token: nx_...
```

Tokens come in two roles, and that is the read-only/writable split:

- **`readonly`** — every `GET` works, every write returns `403`. This is the
  read-only API: safe for monitoring, dashboards and anything that only asks
  questions.
- **`admin`** — can also create records and allocate addresses.

Mint them in Settings → API tokens, or with `nexus-ipam.py token <name> <role>`.

### Querying

```bash
# What is this address?  network, VLAN, assignment, DNS, pool, last ping
curl -sk -H "$AUTH" "$BASE/api/addresses/lookup?address=10.0.10.42"

# Filtered address search
curl -sk -H "$AUTH" "$BASE/api/addresses/search?network_id=2&status=active"
curl -sk -H "$AUTH" "$BASE/api/addresses/search?q=web01"

# Free space, without reserving anything
curl -sk -H "$AUTH" "$BASE/api/next-free?cidr=10.0.10.0/24&count=5"
curl -sk -H "$AUTH" "$BASE/api/next-free?network=lab-servers&verify=1"
curl -sk -H "$AUTH" "$BASE/api/networks/2/free?limit=100&ping=1"

# Inventory and topology
curl -sk -H "$AUTH" "$BASE/api/hosts"
curl -sk -H "$AUTH" "$BASE/api/topology"
curl -sk -H "$AUTH" "$BASE/api/health"
```

### Allocating (the deployer contract)

`POST /api/allocate` finds a free address and claims it in one locked step, so
concurrent deploys can never be handed the same IP. It returns the address
**plus the network's L3 facts**, so a deployment tool needs exactly one
request before it can build a VM:

```bash
curl -sk -H "$AUTH" -H 'Content-Type: application/json' -X POST \
  "$BASE/api/allocate" -d '{
    "network": "lab-servers",
    "assigned_kind": "vm", "assigned_id": 12,
    "dns_name": "web01",
    "verify": true
  }'
```

```json
{
  "success": true, "verified": true,
  "ip": "10.0.10.11", "cidr": "10.0.10.0/24",
  "prefixlen": 24, "netmask": "255.255.255.0",
  "gateway": "10.0.10.1",
  "dns": ["10.0.10.53", "1.1.1.1"],
  "domain": "lab.lan", "vlan": 10,
  "meta": {"vsphere_portgroup": "VM Network", "datastore": "ds1"}
}
```

Pass `dry_run: true` to see what *would* be allocated without writing.
`POST /api/release` frees it again (or `keep: true` to retire it as
`deprecated`).

### Provisioning (allocate + name + publish, in one call)

`/api/allocate` claims an address. `/api/provision` goes further: it also
records the names and pushes DNS, so the machine you are about to build
resolves before it boots.

```bash
curl -sk -H "$AUTH" -H 'Content-Type: application/json' -X POST \
  "$BASE/api/provision" -d '{
    "name": "web01.lab.lan",
    "network": "lab-servers",
    "aliases": ["www.lab.lan", "intranet.lab.lan"],
    "mac": "aa:bb:cc:00:11:22",
    "assigned_kind": "vm", "assigned_id": 12
  }'
```

The response carries the allocation, the resulting ordered name list, the same
L3 facts `/api/allocate` returns, and the per-target push outcome. `verify`
ping-checks the candidate first; `push: false` records everything without
publishing.

Tearing down is the mirror image, by name, address or id:

```bash
curl -sk -H "$AUTH" -X POST "$BASE/api/deprovision" \
  -d '{"name": "web01.lab.lan"}'          # + "keep": true to park it deprecated
```

### Names on an address

```bash
GET  /api/addresses/<id>/names
POST /api/addresses/<id>/names   {"names": [ ... ]}
```

The POST **replaces the whole ordered list** — list order becomes position, so
the first entry is canonical. Entries may be bare strings or objects:

```json
{"names": [
  "docker.lab.lan",
  {"name": "registry.lab.lan", "comment": "pull-through cache"},
  {"name": "old.lab.lan", "enabled": false}
]}
```

### Pushing

```
GET    /api/push                 targets, per-section serials, record counts
GET    /api/push/preview         the exact payload, unsent (+ ?sections=dhcp)
POST   /api/push/run             push every enabled target
                                 (+ ?target=<name> &sections=hosts,dhcp)
POST   /api/push/targets         create or update a target
DELETE /api/push/targets/<name>  stop pushing there (the node keeps what it has)
POST   /api/push/targets/<name>/pull    adopt a gateway's DHCP state into the
                                        plan (+ ?dry_run=1 to preview, read-only)
POST   /api/push/targets/<name>/leases  refresh the lease overlay from a gateway
POST   /api/push/targets/<name>/drift   read a gateway back and diff it against
                                        the plan — read-only (unifi targets only;
                                        a DNSMAQ-MGR node locks pushed sections,
                                        so it cannot drift)
GET    /api/names/candidates     DHCP-side names the plan does not publish
POST   /api/names/adopt          {"addresses": [...]} — adopt them, explicitly
```

A target update is partial in the same way resources are: omit `token` or
`unifi_password` and the stored secret is kept, so changing one flag never
means re-entering a credential.

**Serials version content, not pushes.** Each section carries its own counter,
advanced only when that section's rendered payload actually changes — so a
target's held serial answers "does it have the current content?", and pushing
one target never makes the others read as stale. Re-sending an equal serial
re-applies idempotently (receivers reject only strictly lower ones), which is
also what a forced re-push after suspected drift wants.

### Update semantics — partial and safe

`POST /api/<resource>/<id>` is a **partial update**: any field you do not send
keeps its stored value; sending an explicit `""`/`null` clears it. This is
enforced centrally (the stored row is layered under the request body before
validation), so a script that updates one field can never wipe the others.
`meta` is replaced as a whole object when sent.

### Backups

The app backs itself up: a gzip'd JSON dump (restorable via
`POST /api/import/json`) is written to `$DATA_DIR/backups/` at startup and
every `NEXUSIPAM_BACKUP_HOURS` (default 24), keeping the newest
`NEXUSIPAM_BACKUP_KEEP` (default 14). Set hours to `0` to disable. A copy of
`ipam.db` itself is an equivalent backup.

### Writing

Every resource takes the same five routes:

```
GET    /api/<resource>          list      (+ ?since=<epoch> &source=<name>)
POST   /api/<resource>          create    (+ ?upsert=1)
GET    /api/<resource>/<id>     read
POST   /api/<resource>/<id>     update
DELETE /api/<resource>/<id>     delete
POST   /api/<resource>/bulk-delete    {"ids": [...]}  (max 1000)
```

Bulk delete applies the same per-record guards as a single delete — a device
still hosting VMs is refused with the reason while the rest of the batch
proceeds, and the response reports `deleted` / `refused` / `missing` so
nothing disappears silently. The UI exposes it as tick boxes + a *Delete
selected* button on the networks, addresses, VLANs and inventory pages.

for `networks`, `vlans`, `addresses`, `devices`, `vms`, `containers`,
`clusters`, `dhcp/servers`, `dhcp/ranges`, `dns/servers`.

---

## Integration

The data model was built for other tools to consume and write, which is why
every object carries:

- **`source`** — which system owns the record (`manual`, `vc-deployer`,
  `proxmox`, `discovery`, …);
- **`ext_id`** — that system's own identifier;
- **`meta`** — a free-form JSON object Nexus IPAM stores but never interprets.
  Put hypervisor placement in here (`vsphere_portgroup`, `datastore`,
  `proxmox_node`) and it comes back on every allocation.

### Idempotent sync

`POST /api/<resource>?upsert=1` matches on `(source, ext_id)`. An importer
that runs every 5 minutes updates its own records instead of duplicating them
or colliding on a unique name:

```bash
curl -sk -H "$AUTH" -X POST "$BASE/api/vms?upsert=1" -d '{
  "name": "web01", "platform": "vcenter",
  "source": "vcenter", "ext_id": "vm-9001", "vcpus": 4 }'
```

### Change feed

`GET /api/changes?since=<epoch>` returns everything modified since a
timestamp, across every table, plus a `now` value to use as the next `since`.
That is enough to keep an external system in step without re-reading
everything.

### DNSMAQ-MGR — exports (pull)

If you want Nexus IPAM to *drive* dnsmasq rather than feed a script of your
own, skip to **DNS push targets** below — that needs no glue at all. These
exports are for the pull direction, and for anything that is not DNSMAQ-MGR.

The dnsmasq exports emit *exactly* the JSON bodies DNSMAQ-MGR's own endpoints
accept, so syncing is fetch-here / post-there with no translation:

| Nexus IPAM | feeds | DNSMAQ-MGR |
|---|---|---|
| `GET /api/export/dnsmasq/hosts` | → | `POST /api/dns/hosts` |
| `GET /api/export/dnsmasq/static-leases` | → | `POST /api/dhcp/static_leases` |
| `GET /api/export/hosts` | → | DNS page hosts-file import |
| `GET /api/export/zone?domain=lab.lan` | → | any BIND-style zone |

Bare hostnames are qualified with their network's domain on the way out.
**Push does not do this** — it publishes each name exactly as recorded, since
the ordered name list is meant to round-trip a zone byte-for-byte. Record
names fully qualified if you push, and the two paths agree.

### Push targets

Exports are pull. The other direction is push: Nexus IPAM renders the address
plan and delivers it to the systems that enforce it, which is what makes it
the author rather than a mirror. Configure targets in Settings → Push targets,
or drive them with `/api/push/*`.

Push is **section-based** — a target subscribes to what it should receive:

- **`hosts`** — one dnsmasq host record per enabled name, addresses in stable
  order, canonical name first (that ordering drives the PTR answer).
- **`dhcp`** — scopes (ranges with lease times), the options each hands out,
  and every MAC→address reservation. Router, DNS and domain come off the
  network rows; everything else from the per-network options. A scope with no
  DNS recorded hands out its gateway — matching what a gateway-served scope
  does, instead of letting dnsmasq silently answer with itself. Disabled
  ranges render as disabled rather than vanishing: they still consume space.

Two kinds of target:

- **DNSMAQ-MGR node** — receives its sections on its own
  `POST /api/mirror/receive`. The node re-validates every record, gates the
  swap with `dnsmasq --test`, and locks each pushed section read-only in its
  UI, so there is exactly one writer. Authenticated with a per-node mirror
  token.
- **UniFi Cloud Gateway** — has no mirror endpoint, so it is reconciled
  object by object: Static DNS against the `hosts` records (A/AAAA only;
  CNAME, TXT and the rest are left alone), and for `dhcp` the `dhcpd_*`
  fields on its network objects plus fixed-IP client bindings. Authenticated
  as a local gateway admin with MFA disabled, since the API refuses a 2FA
  login.

Every target is pushed **independently**, carrying one content-versioned
serial per section — no target's freshness depends on another being
reachable, and a node that rejects a stale serial is protected from replay
and reordering. TLS is either `insecure` or pinned to a certificate
fingerprint, which is the useful pair for self-signed appliances (pin
anything that carries a credential).

UniFi behaviours worth knowing before enabling that kind:

- Gateways keep a *second* DNS store — a per-client "Local DNS Record" on
  fixed-IP clients — which shadows Static DNS and makes the gateway refuse a
  static entry for a name a client already owns. Such names are reported as
  conflicts by default; *Take names held by a client's own Local DNS Record*
  unticks the client's flag so the static entry is accepted (its DHCP
  reservation is left untouched).
- *Delete Static DNS entries this IPAM did not create* is **off** by default,
  so a first sync only adds and updates. Turning it on makes Nexus IPAM
  authoritative over the gateway's whole A/AAAA table.
- DHCP writes **merge** into the network object as fetched — it also carries
  VLAN, purpose, IGMP and IPv6 settings this app does not model, and a PUT
  built from our fields alone would blank them. Withdrawing a reservation
  unsets `use_fixedip`, never deletes the client (which is also the device's
  identity and history). Options with no UniFi equivalent are **reported as
  conflicts**, never dropped — a silently ignored option is indistinguishable
  from a satisfied one.
- Two further flags, both **off** by default and both with a large blast
  radius: *Withdraw DHCP reservations the plan does not list* (machines
  relying on them lose their addresses at renewal) and *Manage scope on/off
  state* (a range disabled in the plan can turn a VLAN's DHCP server off —
  an outage, not a config tweak).

**Adoption** is how a populated gateway becomes manageable: *Adopt…* on a
gateway target (or `POST .../pull`) reads its networks, scopes, options and
reservations into the plan — after a read-only dry-run preview. It fills gaps
and never overwrites: values already recorded here win and are reported as
`kept`, and a scope that overlaps a recorded range is refused rather than
added alongside. You cannot become the writer of something you have never
read.

**Drift** closes the loop from the other side: serials say a target *acked*
the current content, a drift check says whether it still *holds* it. The
gateway is read back and diffed with the same planners the push executes —
computed writes, performed nowhere — because its UI stays editable after a
push. A DNSMAQ-MGR node needs no check: its pushed sections are locked.

### VC-Deployer

The allocation response maps one-to-one onto `DeploySpec`
(`ip` / `cidr` / `gateway` / `dns`), and `meta.vsphere_portgroup` carries the
portgroup name for `vm.clone -net`. A deploy becomes: allocate → clone →
`POST /api/vms?upsert=1` to record what was built. `POST /api/release` on
teardown.

With DNS push configured, use `/api/provision` in place of `/api/allocate` and
the clone starts with its name already live on every DNS node — then
`/api/deprovision` on teardown *or on a failed clone*, which is what stops a
failed deploy from leaving a record behind.

### Importers

`tools/` holds the inbound half of the integrations (exports.py is outbound):

| Tool | Pulls | Notes |
|---|---|---|
| `import_dnsmasq.py` | DNS host records from a DNSMAQ-MGR primary | **lossless** — every name kept, in the node's own record order (its first entry answers PTR, so that order *is* the canonical order); per-name comment, enabled flag and record id preserved |
| `import_unifi.py` | VLANs, networks, DHCP scopes (+ `--reservations`) from a UniFi gateway | topology only — clients are leases, the scope accounts for them |
| `import_vcenter.py` | clusters, ESXi hosts, VMs and guest addresses from vCenter | skips vCLS agents and guest IPs outside any defined network (container bridges, CNI overlays) |
| `import_nexuscontroller.py` | physical hosts and their classification from NexusController | groups multiple registry entries per machine; skips nodes that are really VMs |

All four take `--dry-run`, are idempotent via `source`/`ext_id`, and never
clobber fields another source or a human already set. Each reports its run to
`POST /api/sync/runs`, so a scheduled importer that starts failing shows up in
the UI (Settings → External sources) rather than only in a log nobody reads.
`GET /api/sync` answers "which system owns what" from the data itself — every
row carries `source`, so ownership cannot drift from reality.

Two more tools, not importers:

| Tool | Does |
|---|---|
| `roundtrip_check.py` | Proves IPAM reproduces a DNS node's zone **exactly** — same addresses, same names in the same order, same comments, enabled flags and record ids — before you let it become the writer. Run it before the first push, not after. |
| `seed_demo.py` | Fills a throwaway instance with the demo dataset the screenshots show. Writes freely; never point it at anything real. |

### Other exports

```
GET /api/export/json     full dump (backup / diffing)
GET /api/export/csv      flat address inventory
POST /api/import/json    restore, ?mode=merge (default) or ?mode=replace
GET /api/audit           who changed what, when (+ total, oldest, retention)
POST /api/audit/prune    admin: {"days": N} or {"all": true} — manual override
                         of the automatic daily retention
```

---

## Security notes

- Session cookies are `HttpOnly`, `SameSite=Lax`, `Secure` when TLS is on;
  sessions last 12 hours.
- Passwords are PBKDF2 (werkzeug). Login is rate-limited per IP (5 failures /
  5 minutes) and unknown usernames cost the same time as wrong passwords, so
  there is no user enumeration by timing.
- API tokens are stored as SHA-256 only and compared constant-time. A token is
  displayed exactly once, at creation.
- RBAC is enforced centrally in one `before_request` hook by HTTP method, not
  sprinkled per route — a new write endpoint is protected by default.
- No value is ever interpolated into a shell: `ping` and `ip neigh` are
  invoked with argument lists and `shell=False`.
- Every stored text field rejects line breaks, because the hosts-file, zone
  and dnsmasq exports are built by concatenation and a newline would otherwise
  smuggle a directive into someone else's config.
- SQL is parameterized throughout; the only interpolated identifiers are table
  and column names from fixed internal constants, never from user input.
- **Push target credentials** — a node's mirror token, a gateway's password —
  are the one class of secret stored in the database rather than hashed, since
  they must be replayed on every push. They are never returned by the API
  (`has_token` / `has_password` booleans instead), and they live in the `meta`
  key/value table, which is **not** one of the tables `/api/export/json` and
  the automatic backups dump — so a dump you hand to someone else carries no
  credentials. Treat `ipam.db` itself as sensitive.
- Push TLS is `insecure` or pinned to a certificate fingerprint. Pinning is
  worth the two minutes on any target that carries a password.

---

## Repository conventions

`main` is the publishable branch: no site-specific hostnames, addresses or
credentials, in files or commit messages.

Anything site-specific belongs in **your own private infrastructure repo** —
one with no public remote at all — not in a branch of this one. A branch is a
`git push` typo away from the wrong place; a separate private repo is not.

What stays here is the one thing that cannot live elsewhere: the term list at
`private/forbidden-terms.txt`, on a never-published `private` branch. Before
publishing, run `tools/check_public_safe.sh` — it reads that list (out of the
branch, so you can stay on `main`) and validates the tree, every commit
message and the full history against it. If the guard depended on a sibling
repo being checked out, a missing checkout would silently disarm it.

It **fails closed**, which is the whole point of running it:

```
exit 0   checked, clean
exit 1   forbidden terms found — do not push
exit 2   could not check (no term list) — do not treat as clean
```

## Development

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt -r requirements-dev.txt
NEXUSIPAM_TLS=0 NEXUSIPAM_DATA_DIR=./devdata ./venv/bin/python nexus-ipam.py
./venv/bin/python -m pytest tests/ -q
```

### Layout

```
nexus-ipam.py                  entrypoint + CLI dispatch
nexusipam/
  core/config.py        paths, env knobs, atomic writes
  core/db.py            SQLite schema, connection, generic CRUD
  core/auth.py          sessions, users, API tokens, RBAC
  core/validators.py    input validation + controlled vocabularies
  core/runcmd.py        shell-free command execution
  core/tls.py           self-signed generation, cert upload
  netutil.py            prefix maths, hex bounds, usable-range rules
  resource.py           generic REST machinery (one implementation, eleven tables)
  networks.py           VLANs, networks, containment, utilization
  addresses.py          address records, search, lookup, ordered names
  allocate.py           free-space discovery, atomic allocation
  inventory.py          clusters, devices, VMs, containers, topology
  services.py           DHCP/DNS servers, DHCP ranges, DHCP options
  scan.py               ICMP prober, scan jobs, reconciliation
  pushout.py            push targets, section renderers, serials, drift
  unifi.py              UniFi gateway adapter: Static DNS + DHCP (vendored core)
  adopt.py              pull a target's state into the plan; name candidates
  leases.py             dynamic lease overlay + scheduled refresh
  provision.py          one-action provision / deprovision
  exports.py            exports, import, change feed, audit
  sync.py               which source owns what; importer run reports
  backup.py             scheduled JSON backups + audit retention
  stats.py              overview aggregates, search, health
static/js/              one file per page, no build step
templates/index.html    the single page
```

`static/css/style.css` is DNSMAQ-MGR's stylesheet verbatim, with IPAM-specific
additions (the IP map grid, network tree, state colours) appended at the end —
so a change to the shared design system can be re-copied cleanly.
