"""TLS certificate management — adapted from DNSMAQ-MGR core/tls.py.
Self-signed generation on first run; custom-cert upload validated with openssl
before it replaces anything. openssl only ever touches the app-owned certs
dir, so it never needs root (no_sudo)."""
import os
import socket
from flask import Blueprint, jsonify, request

from .config import TLS_CERT, TLS_KEY, TLS_ENABLED
from .runcmd import run, err

bp = Blueprint('tls', __name__)


def _openssl(args, input_data=None):
    return run(['openssl', *args], input_data=input_data, no_sudo=True)


def generate_self_signed(cert_path=TLS_CERT, key_path=TLS_KEY):
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    cn = socket.gethostname() or 'nexus-ipam'
    _, e, rc = _openssl([
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', key_path, '-out', cert_path,
        '-days', '3650', '-subj', f'/CN={cn}',
    ])
    if rc == 0:
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
    return rc == 0, e


def ensure_tls_cert():
    """Ensure a usable cert+key exist. Generate a self-signed pair only when
    BOTH are missing - never overwrite a certificate the operator supplied."""
    have_cert, have_key = os.path.exists(TLS_CERT), os.path.exists(TLS_KEY)
    if have_cert and have_key:
        return
    if have_cert or have_key:
        raise RuntimeError(f'TLS cert/key mismatch: one of {TLS_CERT} / {TLS_KEY} is missing')
    ok, e = generate_self_signed()
    if not ok:
        raise RuntimeError(f'Failed to generate self-signed certificate: {e}')


def cert_info(cert_path=TLS_CERT):
    if not os.path.exists(cert_path):
        return {'present': False}
    out, _, rc = _openssl(['x509', '-in', cert_path, '-noout', '-subject', '-issuer', '-enddate'])
    if rc != 0:
        return {'present': True, 'error': 'unreadable certificate'}
    info = {'present': True, 'path': cert_path}
    for line in out.splitlines():
        if line.startswith('subject='):
            info['subject'] = line[8:].strip()
        elif line.startswith('issuer='):
            info['issuer'] = line[7:].strip()
        elif line.startswith('notAfter='):
            info['expires'] = line[9:].strip()
    info['self_signed'] = 'subject' in info and info.get('subject') == info.get('issuer')
    return info


@bp.route('/api/tls/info')
def tls_info():
    info = cert_info()
    info['tls_enabled'] = TLS_ENABLED
    return jsonify(info)


@bp.route('/api/tls/regenerate', methods=['POST'])
def tls_regenerate():
    ok, e = generate_self_signed()
    if not ok:
        return err(f'Failed to generate certificate: {e}', 500)
    return jsonify({'success': True, 'restart_required': True})


@bp.route('/api/tls/cert', methods=['POST'])
def tls_upload_cert():
    data = request.get_json() or {}
    cert_pem = (data.get('cert') or '').strip()
    key_pem = (data.get('key') or '').strip()
    if 'BEGIN CERTIFICATE' not in cert_pem:
        return err('Certificate must be PEM (-----BEGIN CERTIFICATE-----)')
    if 'PRIVATE KEY' not in key_pem:
        return err('Key must be a PEM private key')
    if len(cert_pem) > 100_000 or len(key_pem) > 100_000:
        return err('Certificate or key too large')

    os.makedirs(os.path.dirname(TLS_CERT), exist_ok=True)
    os.makedirs(os.path.dirname(TLS_KEY), exist_ok=True)
    tmp_cert, tmp_key = TLS_CERT + '.upload', TLS_KEY + '.upload'
    try:
        with open(tmp_cert, 'w') as f:
            f.write(cert_pem + '\n')
        fd = os.open(tmp_key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(key_pem + '\n')

        if _openssl(['x509', '-in', tmp_cert, '-noout'])[2] != 0:
            return err('Invalid certificate')
        if _openssl(['pkey', '-in', tmp_key, '-noout'])[2] != 0:
            return err('Invalid private key')
        cert_pub = _openssl(['x509', '-in', tmp_cert, '-noout', '-pubkey'])[0]
        key_pub = _openssl(['pkey', '-in', tmp_key, '-pubout'])[0]
        if not cert_pub.strip() or cert_pub.strip() != key_pub.strip():
            return err('Certificate and private key do not match')

        os.replace(tmp_cert, TLS_CERT)
        os.replace(tmp_key, TLS_KEY)
        os.chmod(TLS_KEY, 0o600)
    finally:
        for p in (tmp_cert, tmp_key):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass
    return jsonify({'success': True, 'restart_required': True})
