#!/usr/bin/env python3
"""Run the five evidence lanes against a public 3D site and print the digest."""
from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path

import evidence_bay


def pids_referencing(path):
    needle = str(path).encode()
    found = []
    proc = Path('/proc')
    for entry in proc.iterdir() if proc.is_dir() else []:
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / 'cmdline').read_bytes().split(b'\0')
        except OSError:
            continue
        if any(needle in arg for arg in argv):
            found.append(int(entry.name))
    return found


def port_open(port=9333):
    sock = socket.socket()
    try:
        return sock.connect_ex(('127.0.0.1', port)) == 0
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='https://www.monogrid.com/')
    parser.add_argument('--headed', action='store_true', help='show the browser window')
    args = parser.parse_args()
    try:
        result = evidence_bay.capture_evidence(args.url, headless=not args.headed)
    except Exception as error:
        print(f'EVIDENCE_ERROR: {type(error).__name__}: {error}')
        print('CLEANUP: ' + json.dumps(getattr(error, 'cleanup', None)))
        return 1

    print(result['digest_text'])
    profile = Path(result.get('profile') or '')
    leftovers = pids_referencing(profile) if str(profile) else []
    screenshot = Path(result['rea']['screenshot']['path'])
    artifacts = [Path(value) for key, value in result['artifacts'].items() if key != 'dir']
    png_ok = False
    if screenshot.is_file():
        png_ok = screenshot.read_bytes()[:8] == b'\x89PNG\r\n\x1a\n'
    cleanup = result.get('cleanup') or {}
    digest = result.get('digest') or {}
    checks = {
        'title': bool(result.get('title')),
        'inspect_scripts': result['rea']['inspect']['scripts'] > 0,
        'analyze_routes': len(digest.get('routes') or []) > 0,
        'code_signals': len(digest.get('code_signals') or []) > 0,
        'stack': len(digest.get('stack') or []) > 0,
        'assets': (digest.get('asset_totals') or {}).get('resources', 0) > 0,
        'screenshot_png': png_ok and result['rea']['screenshot']['bytes'] > 0,
        'artifacts': all(path.is_file() for path in artifacts),
        'attribution': '[REA]' in result.get('digest_text', '') and '[Jarvis]' in result.get('digest_text', ''),
        'cleanup': bool(cleanup.get('ok')) and cleanup.get('profile_removed') is True
                   and cleanup.get('port_released') is True and not cleanup.get('lingering_pids'),
        'profile_gone': str(profile) and not profile.exists(),
        'no_chrome_left': not leftovers,
        'port_closed': not port_open(),
    }
    print('CHECKS: ' + json.dumps(checks, ensure_ascii=False))
    print(f"NO_CHROME_LEFT: {len(leftovers)} {leftovers}")
    print(f"PROFILE_EXISTS: {profile.exists()}")
    print(f"PORT_9333_OPEN: {port_open()}")
    ok = all(checks.values())
    print('VERDICT: ' + ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
