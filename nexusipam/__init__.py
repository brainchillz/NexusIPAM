"""Nexus IPAM — application factory.

Same architecture as DNSMAQ-MGR (Flask + vanilla JS, no build step): a fixed
feature set, so blueprints register directly here rather than through a module
registry.
"""
from flask import Flask, send_from_directory

from .core.config import (STATIC_DIR, TEMPLATES_DIR, SESSION_COOKIE_CONFIG,
                          ensure_dirs)


def create_app():
    ensure_dirs()
    app = Flask(__name__,
                static_folder=STATIC_DIR,
                static_url_path='/static',
                template_folder=TEMPLATES_DIR)
    app.config.update(SESSION_COOKIE_CONFIG)

    from .core import auth, tls, db
    db.init_db()

    from . import (networks, addresses, inventory, services, allocate, scan,
                   exports, stats, sync, pushout)

    app.before_request(auth.require_login)

    for mod in (auth, tls, networks, addresses, inventory, services, allocate,
                scan, exports, stats, sync, pushout):
        app.register_blueprint(mod.bp)

    @app.route('/')
    def index():
        return send_from_directory(TEMPLATES_DIR, 'index.html')

    return app
