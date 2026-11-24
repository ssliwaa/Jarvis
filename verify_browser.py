#!/usr/bin/env python3
"""Live proof for the ephemeral teardown browser.

Runs headless, opens a public page, prints its title and load time, wheel-scrolls
it, then proves the profile was removed and no Chrome process still references it.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path

import teardown


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
    parser.add_argument('--url', default='https://en.wikipedia.org/wiki/WebSocket')
    args = parser.parse_args()
    try:
        facts = teardown.browser_visit(args.url, headless=True, scroll=True)
    except Exception as error:
        print(f'BROWSER_ERROR: {type(error).__name__}: {error}')
        return 1

    profile = Path(facts.get('profile') or '')
    leftovers = pids_referencing(profile) if str(profile) else []
    cleanup = facts.get('cleanup') or {}
    print(f"TITLE: {facts.get('title')}")
    print(f"FINAL_URL: {facts.get('url')}")
    print(f"LOAD_SECONDS: {facts.get('load_seconds')}")
    print(f"READY_STATE: {facts.get('ready_state')}")
    print(f"WINDOW_SIZE: {facts.get('window_size')}")
    print(f"VIEWPORT: {facts.get('viewport')}")
    print(f"CDP_ENDPOINT: {facts.get('cdp_endpoint')} TARGET: {facts.get('target_id')}")
    print(f"SCROLL_BEFORE: {facts.get('scroll_y_before')} SCROLL_AFTER: {facts.get('scroll_y_after')}")
    print(f"SCROLLED: {facts.get('scrolled')}")
    print(f"PROFILE: {profile}")
    print(f"PROFILE_EXISTS: {profile.exists()}")
    print(f"CHROME_LEFT: {len(leftovers)} {leftovers}")
    print(f"PORT_9333_OPEN: {port_open()}")
    print('CLEANUP: ' + json.dumps(cleanup, ensure_ascii=False))

    ok = (facts.get('ok') is True and facts.get('ready_state') == 'complete'
          and bool(facts.get('title')) and facts.get('scrolled') is True
          and facts.get('window_size') == [1280, 820]
          and cleanup.get('profile_removed') is True and cleanup.get('port_released') is True
          and not leftovers and not profile.exists() and not port_open())
    print('VERDICT: ' + ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
