#!/usr/bin/env python3
"""Nexus IPAM — entrypoint.

`python nexus-ipam.py` boots the web UI (TLS by default, self-signed cert generated
on first run). `python nexus-ipam.py <command>` dispatches CLI subcommands
(set-password, token, reindex, export, scan) and exits without starting the
server.
"""
import sys

from nexusipam import create_app, cli
from nexusipam.core import config, auth, tls

app = create_app()


if __name__ == '__main__':
    _rc = cli.dispatch(sys.argv)
    if _rc is not None:
        sys.exit(_rc)
    app.secret_key = auth.ensure_bootstrap()['secret_key']
    from nexusipam import backup
    backup.start_scheduler()
    ssl_context = None
    if config.TLS_ENABLED:
        tls.ensure_tls_cert()
        ssl_context = (config.TLS_CERT, config.TLS_KEY)
    app.run(host='0.0.0.0', port=config.WEB_PORT,
            ssl_context=ssl_context, debug=False, threaded=True)
