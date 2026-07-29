"""Command execution — NEVER through a shell.

Adapted from DNSMAQ-MGR core/runcmd.py. This app shells out for very little
(ping, ip neigh, openssl), but the rule is the same: pass an ARGUMENT LIST
and run with shell=False, so a user-supplied value can never be interpreted
by a shell. ``sudo -n`` fails fast when a sudoers rule is missing instead of
hanging on a password prompt; in Docker (NEXUSIPAM_NO_SUDO=1) the app is root
and sudo is never prefixed.
"""
import subprocess
from flask import jsonify

from .config import NO_SUDO


def run(args, input_data=None, no_sudo=False, timeout=60):
    if isinstance(args, str):
        # Only fixed, trusted command strings should ever be passed as strings.
        args = args.split()
    if not (no_sudo or NO_SUDO):
        args = ['sudo', '-n'] + list(args)
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           timeout=timeout, input=input_data)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return '', 'Command timed out', -1
    except FileNotFoundError:
        return '', 'Command not found', -1


def err(message, code=400):
    return jsonify({'success': False, 'error': message}), code


def num(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None
