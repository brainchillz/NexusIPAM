#!/bin/sh
# Deliberately tiny: the app is PID 1 so container lifecycle == app lifecycle.
set -e
mkdir -p /data/certs /data/backups
exec /opt/nexus-ipam/venv/bin/python /opt/nexus-ipam/nexus-ipam.py "$@"
