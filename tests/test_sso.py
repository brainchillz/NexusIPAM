"""Optional SSO: the verifier, and the guarantee that an unconfigured node is
unchanged.

Assertions here are REAL issuer output, committed as a fixture by
NexusSSO tools/gen_rp_fixtures.py. That matters: this app has no crypto
dependency and cannot mint, so testing against locally-constructed tokens would
only prove the verifier agrees with itself. If the two sides ever drift, these
fail.
"""
import json
import time
from pathlib import Path

import pytest

from nexusipam.core import sso

FIXTURES = json.loads(
    (Path(__file__).parent / 'fixtures' / 'sso_assertions.json').read_text())
NOW = FIXTURES['now']


@pytest.fixture
def configured(monkeypatch):
    """Point the verifier at the fixture issuer. Module-level env is read at
    import, so the attributes are patched directly."""
    monkeypatch.setattr(sso, 'SSO_ISSUER', FIXTURES['issuer'])
    monkeypatch.setattr(sso, 'SSO_PUBKEY', FIXTURES['pubkey'])
    monkeypatch.setattr(sso, 'SSO_KID', FIXTURES['kid'])
    monkeypatch.setattr(sso, 'SSO_AUDIENCE', FIXTURES['audience'])
    monkeypatch.setattr(sso, '_seen', {})
    return sso


def tok(name):
    return FIXTURES['assertions'][name]


# ─── off by default ────────────────────────────────────────────────────

def test_disabled_out_of_the_box():
    """No env set in the test environment, so SSO must be inert."""
    assert sso.enabled() is False
    assert sso.verify(tok('valid'), now=NOW) is None



def test_half_configured_is_treated_as_off(monkeypatch):
    """An issuer with no key, or a malformed key, must not half-work."""
    monkeypatch.setattr(sso, 'SSO_ISSUER', FIXTURES['issuer'])
    monkeypatch.setattr(sso, 'SSO_PUBKEY', '')
    assert sso.enabled() is False
    monkeypatch.setattr(sso, 'SSO_PUBKEY', 'not-a-key')
    assert sso.enabled() is False
    monkeypatch.setattr(sso, 'SSO_PUBKEY', FIXTURES['pubkey'][:20])
    assert sso.enabled() is False


# ─── verification against real issuer output ───────────────────────────

def test_valid_assertion_yields_its_subject(configured):
    assert configured.verify(tok('valid'), now=NOW) == 'admin'


def test_expired_refused(configured):
    assert configured.verify(tok('expired'), now=NOW) is None


def test_assertion_for_another_node_refused(configured):
    """The containment property: the whole fleet trusts one issuer key, so
    audience is the only thing stopping an assertion minted for node A from
    working at node B."""
    assert configured.verify(tok('wrong_audience'), now=NOW) is None


def test_assertion_from_another_issuer_refused(configured):
    assert configured.verify(tok('wrong_issuer'), now=NOW) is None


def test_assertion_signed_by_another_key_refused(configured):
    assert configured.verify(tok('signed_by_another_key'), now=NOW) is None


def test_issued_in_the_future_refused(configured):
    assert configured.verify(tok('issued_in_the_future'), now=NOW) is None


def test_wrong_kid_refused(configured, monkeypatch):
    monkeypatch.setattr(sso, 'SSO_KID', '0' * 16)
    assert configured.verify(tok('valid'), now=NOW) is None


def test_kid_unset_still_verifies(configured, monkeypatch):
    """kid is a convenience for diagnosing a key mismatch, not the security
    boundary — the signature is."""
    monkeypatch.setattr(sso, 'SSO_KID', '')
    assert configured.verify(tok('valid'), now=NOW) == 'admin'


def test_single_use(configured):
    assert configured.verify(tok('valid'), now=NOW) == 'admin'
    assert configured.verify(tok('valid'), now=NOW) is None


def test_replay_cache_is_pruned(configured):
    """Entries are dropped once they have expired, so the cache cannot grow
    without bound. Pruning happens when a later assertion is redeemed — the
    cache is exercised directly here because this app cannot mint a second
    valid token to trigger it."""
    configured.verify(tok('valid'), now=NOW)
    assert len(sso._seen) == 1
    assert sso._remember('later-jti', NOW + 200000, now=NOW + 100000) is True
    assert 'later-jti' in sso._seen
    assert len(sso._seen) == 1          # the expired entry was swept


def test_replay_cache_uses_the_verification_clock(configured):
    """The cache and the expiry check must share one clock. Reading wall time
    inside the cache made a fixture-timestamped assertion replayable."""
    assert sso._remember('j1', NOW + 120, now=NOW) is True
    assert sso._remember('j1', NOW + 120, now=NOW) is False


def test_tampered_tokens_refused(configured):
    good = tok('valid')
    h, p, s = good.split('.')
    for bad in (h + '.' + p + '.' + s[:-4] + 'AAAA',
                h + '.' + p[:-4] + 'AAAA.' + s,
                'x' + good, good + 'x', good.replace('.', '', 1)):
        assert configured.verify(bad, now=NOW) is None


def test_alg_none_refused(configured):
    import base64
    _h, p, _s = tok('valid').split('.')
    header = base64.urlsafe_b64encode(
        json.dumps({'alg': 'none', 'typ': 'nxa', 'kid': FIXTURES['kid']},
                   separators=(',', ':'), sort_keys=True).encode()
    ).rstrip(b'=').decode()
    assert configured.verify(header + '.' + p + '.', now=NOW) is None


def test_garbage_never_raises(configured):
    for junk in ('', 'a', 'a.b', 'a.b.c', None, 12345, 'x' * 9000, '..'):
        assert configured.verify(junk, now=NOW) is None


# ─── redirect safety ───────────────────────────────────────────────────

def test_safe_next():
    assert sso.safe_next('/disks') == '/disks'
    for hostile in ('//evil.example.com', 'https://evil.example.com',
                    '\\\\evil.example.com', '/\\evil', 'javascript:alert(1)',
                    '/x\r\nSet-Cookie: a=b', '', None, '/x' * 400):
        assert sso.safe_next(hostile) in ('/', '/x' * 400)[:1] or \
            sso.safe_next(hostile) == '/'


def test_authorize_url_is_built_from_config(configured):
    url = configured.authorize_url('/storage')
    assert url.startswith(FIXTURES['issuer'] + '/sso/authorize?')
    assert 'aud=' + FIXTURES['audience'] in url
    assert 'next=%2Fstorage' in url


def test_authorize_url_refuses_a_hostile_next(configured):
    assert 'evil' not in configured.authorize_url('//evil.example.com')


def test_login_hint_leaks_nothing_secret(configured):
    hint = configured.login_hint()
    assert set(hint) == {'issuer', 'audience', 'auto_redirect'}
    assert FIXTURES['pubkey'] not in json.dumps(hint)


# ─── configuration precedence ──────────────────────────────────────────

def test_env_wins_over_stored(monkeypatch, tmp_path):
    """The opt-in model in one assertion: a host that fixes SSO in its
    environment cannot have that overridden by anything written at runtime."""
    store = tmp_path / 'sso.json'
    store.write_text(json.dumps({'issuer': 'https://stored.example',
                                 'pubkey': FIXTURES['pubkey'],
                                 'kid': 'aaaa', 'audience': 'stored-aud'}))
    monkeypatch.setattr(sso, 'STORE', str(store))
    monkeypatch.setattr(sso, 'SSO_ISSUER', 'https://env.example')
    monkeypatch.setattr(sso, 'SSO_PUBKEY', FIXTURES['pubkey'])
    monkeypatch.setattr(sso, 'SSO_AUDIENCE', 'env-aud')
    cfg = sso.config()
    assert cfg['source'] == 'env'
    assert cfg['issuer'] == 'https://env.example'
    assert cfg['audience'] == 'env-aud'
    assert sso.locked() is True


def test_stored_used_when_env_absent(monkeypatch, tmp_path):
    store = tmp_path / 'sso.json'
    store.write_text(json.dumps({'issuer': 'https://stored.example/',
                                 'pubkey': FIXTURES['pubkey'],
                                 'kid': 'aaaa', 'audience': 'stored-aud'}))
    monkeypatch.setattr(sso, 'STORE', str(store))
    monkeypatch.setattr(sso, 'SSO_ISSUER', '')
    cfg = sso.config()
    assert cfg['source'] == 'stored'
    assert cfg['issuer'] == 'https://stored.example'   # trailing slash trimmed
    assert sso.locked() is False
    assert sso.enabled() is True


def test_no_config_at_all_is_off(monkeypatch, tmp_path):
    monkeypatch.setattr(sso, 'STORE', str(tmp_path / 'absent.json'))
    monkeypatch.setattr(sso, 'SSO_ISSUER', '')
    assert sso.config() is None
    assert sso.enabled() is False
    assert sso.locked() is False


def test_corrupt_store_is_off_not_a_crash(monkeypatch, tmp_path):
    store = tmp_path / 'sso.json'
    store.write_text('{not json at all')
    monkeypatch.setattr(sso, 'STORE', str(store))
    monkeypatch.setattr(sso, 'SSO_ISSUER', '')
    assert sso.config() is None
    assert sso.enabled() is False


def test_stored_config_verifies_real_assertions(monkeypatch, tmp_path):
    """End of the loop: a UI-enrolled node must verify genuine issuer output
    exactly as an env-configured one does."""
    store = tmp_path / 'sso.json'
    store.write_text(json.dumps({'issuer': FIXTURES['issuer'],
                                 'pubkey': FIXTURES['pubkey'],
                                 'kid': FIXTURES['kid'],
                                 'audience': FIXTURES['audience']}))
    monkeypatch.setattr(sso, 'STORE', str(store))
    monkeypatch.setattr(sso, 'SSO_ISSUER', '')
    monkeypatch.setattr(sso, '_seen', {})
    assert sso.verify(tok('valid'), now=NOW) == 'admin'
    assert sso.verify(tok('wrong_audience'), now=NOW) is None
