import os
import sys
import tempfile

import pytest

_tmp = tempfile.mkdtemp(prefix='nexusipam-test-')
os.environ['NEXUSIPAM_DATA_DIR'] = _tmp
os.environ['NEXUSIPAM_DB'] = os.path.join(_tmp, 'ipam.db')
os.environ['NEXUSIPAM_TLS'] = '0'
os.environ['NEXUSIPAM_NO_SUDO'] = '1'

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def client(monkeypatch):
    """Flask test client authenticated as admin, with the network never touched:
    probe_one is stubbed so tests are deterministic and offline."""
    from nexusipam import create_app
    from nexusipam import scan as scan_mod

    monkeypatch.setattr(scan_mod, 'probe_one',
                        lambda a, timeout=None: {'alive': False, 'rtt_ms': None,
                                                 'method': 'stub'})
    monkeypatch.setattr(scan_mod, 'neighbour_mac', lambda a: '')
    monkeypatch.setattr(scan_mod, 'resolve_ptr', lambda a: '')

    app = create_app()
    app.config['TESTING'] = True
    app.secret_key = 'test-secret'
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess['user'] = 'admin'
        from nexusipam.core import auth
        monkeypatch.setattr(auth, '_users',
                            lambda: {'admin': {'password': 'x', 'role': 'admin'}})
        yield c


@pytest.fixture(autouse=True)
def clean_db():
    """Every test starts from an empty database."""
    from nexusipam.core import db
    from nexusipam.exports import DUMP_TABLES
    db.init_db()
    yield
    conn = db.connect()
    for table in reversed(DUMP_TABLES):
        conn.execute('DELETE FROM %s' % table)
    conn.execute('DELETE FROM scan_results')
    conn.execute('DELETE FROM audit')
