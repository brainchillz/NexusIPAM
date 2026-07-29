#!/bin/bash
# Nexus IPAM bare-metal installer (Debian/Ubuntu).
# Installs to /opt/nexus-ipam and runs as the nexusipam system user.
#
# Unlike DNSMAQ-MGR this app drives no system service and needs no sudoers
# rules: the only external commands it runs are ping (setuid/cap_net_raw),
# `ip neigh` (read-only) and openssl against its own certs directory. It
# therefore runs entirely unprivileged.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/nexus-ipam"
APP_USER="nexusipam"
WEB_PORT="${NEXUSIPAM_PORT:-8444}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then
    error "Please run as root or with sudo"
    exit 1
fi

echo "=== Nexus IPAM Installer (Debian/Ubuntu) ==="
echo ""

info "Installing prerequisite packages..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv openssl iputils-ping iproute2 curl >/dev/null

info "Creating service user..."
if ! id -u $APP_USER &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -M -d $APP_DIR $APP_USER
fi

info "Deploying application to $APP_DIR ..."
mkdir -p $APP_DIR
cp -r "$SCRIPT_DIR"/nexus-ipam.py "$SCRIPT_DIR"/nexusipam "$SCRIPT_DIR"/templates \
      "$SCRIPT_DIR"/static "$SCRIPT_DIR"/requirements.txt $APP_DIR/
find $APP_DIR/nexusipam -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

info "Creating virtualenv..."
if [ ! -d $APP_DIR/venv ]; then
    python3 -m venv $APP_DIR/venv
fi
$APP_DIR/venv/bin/pip install -q -r $APP_DIR/requirements.txt

info "Preparing data directories..."
mkdir -p $APP_DIR/certs $APP_DIR/backups
chown -R $APP_USER:$APP_USER $APP_DIR
chmod 755 $APP_DIR
# Credentials, the database and the TLS key are private to the service user.
chmod 700 $APP_DIR/certs $APP_DIR/backups

info "Writing systemd unit..."
cat > /etc/systemd/system/nexus-ipam.service <<EOF
[Unit]
Description=Nexus IPAM — IP address management
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment=NEXUSIPAM_DATA_DIR=$APP_DIR
Environment=NEXUSIPAM_PORT=$WEB_PORT
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/nexus-ipam.py
Restart=on-failure
RestartSec=5

# The app writes only inside its own directory and runs no privileged code.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$APP_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable nexus-ipam >/dev/null 2>&1

info "Starting Nexus IPAM..."
systemctl restart nexus-ipam
sleep 3

if ! systemctl is-active --quiet nexus-ipam; then
    error "Service failed to start. Recent log:"
    journalctl -u nexus-ipam -n 30 --no-pager
    exit 1
fi

echo ""
info "Installed and running."
echo ""
echo "  Web UI:  https://$(hostname -f 2>/dev/null || hostname):$WEB_PORT"
echo "  Log:     journalctl -u nexus-ipam -f"
echo ""
# The generated first-run password is printed by the app on stdout; surface it
# here so the operator does not have to go hunting through the journal.
FIRSTPW="$(journalctl -u nexus-ipam -n 60 --no-pager 2>/dev/null | grep -m1 'password:' || true)"
if [ -n "$FIRSTPW" ]; then
    warn "Initial admin credentials (change these on first sign-in):"
    echo "  username: admin"
    echo "  ${FIRSTPW#*password: }" | sed 's/^/  password: /'
else
    echo "  Set an admin password with:"
    echo "    sudo -u $APP_USER $APP_DIR/venv/bin/python $APP_DIR/nexus-ipam.py set-password admin"
fi
echo ""
echo "  Mint an API token for automation:"
echo "    sudo -u $APP_USER $APP_DIR/venv/bin/python $APP_DIR/nexus-ipam.py token my-script readonly"
echo ""
warn "The certificate is self-signed — your browser will warn on first visit."
