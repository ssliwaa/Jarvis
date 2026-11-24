#!/usr/bin/env python3
"""Fast offline checks: spoken addresses, fingerprints, digest attribution."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ATTRIBUTION = re.compile(r'^\s*\[(?:REA|Jarvis)\]')


def check_addresses():
    import teardown
    node = teardown.find_node()
    if not node:
        raise AssertionError('Node is required for the spoken-address check; set JARVIS_NODE')
    result = subprocess.run(
        [node['path'], str(ROOT / 'tests/test_voice.js'), 'addresses'],
        cwd=ROOT, capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise AssertionError('spoken-address check failed: ' + (result.stdout + result.stderr)[-1200:])
    # The Node case asserts the five requested addresses plus a spoken scheme.
    return 5


def check_fingerprints():
    import evidence_bay
    source = {
        'url': 'synthetic.js',
        'captured_by': 'test',
        'text': 'THREE_REVISION="165"; const gsap = {}; gsap.version = "3.12.5";',
    }
    stack = evidence_bay.scan_fingerprints([source])
    versions = {item['name']: item.get('version') for item in stack}
    if versions.get('Three.js') != '165':
        raise AssertionError(f'Three.js fingerprint mismatch: {versions}')
    if versions.get('GSAP') != '3.12.5':
        raise AssertionError(f'GSAP fingerprint mismatch: {versions}')
    return versions


def synthetic_evidence():
    return {
        'ok': True,
        'title': 'Example',
        'url': 'https://example.com/',
        'url_requested': 'https://example.com/',
        'timing': {'browser_load_seconds': 0.1, 'scroll_y_after_scroll': 100},
        'cleanup': {'ok': True, 'profile_removed': True, 'port_released': True},
        'rea': {
            'target': {'target_id': 'target-1', 'url': 'https://example.com/'},
            'list_evidence_id': 'ev-target',
            'inspect': {'evidence_id': 'ev-inspect', 'scripts': 1, 'resources': 1, 'observation_ms': 1},
            'analyze': {
                'evidence_id': 'ev-analyze', 'scripts_observed': 1, 'scripts_analyzed': 1,
                'routes': ['/'],
                'scripts': [{'url': 'https://example.com/app.js', 'bytes': 100}],
                'edges': [{'from': 'https://example.com/app.js', 'to': 'https://example.com/vendor.js',
                           'kind': 'static_import'}],
            },
            'screenshot': {'evidence_id': 'ev-shot', 'path': '/tmp/shot.png', 'bytes': 8,
                           'png_width': 1, 'png_height': 1, 'sha256': 'a' * 64},
        },
        'jarvis': {
            'other_banners': [],
            'assets': {'all_path': '/tmp/assets.json'},
        },
        'digest': {
            'code_signals': [{'name': 'uTime', 'meaning': 'animation clock',
                              'captured_by': 'Jarvis (scan of REA-captured source)'}],
            'stack': [{'name': 'Three.js', 'version': '165', 'captured_by': 'REA (source capture)',
                       'scanned_by': 'Jarvis'}],
            'asset_totals': {'resources': 1, 'known_bytes': 100, 'unknown_sizes': 0,
                             'origins': {'https://example.com': {'bytes': 100, 'count': 1}},
                             'kinds': {'scripts': {'bytes': 100, 'count': 1}}, 'top': []},
        },
    }


def check_digest_attribution():
    import evidence_bay
    import teardown_brain
    result = synthetic_evidence()
    result['digest_text'] = evidence_bay.render_digest(result)
    digest = teardown_brain.build_digest(result, 'example.com', 'How is it built?')
    bad = [line for line in digest.splitlines() if line.strip() and not ATTRIBUTION.match(line)]
    if bad:
        raise AssertionError('unattributed digest lines: ' + repr(bad[:3]))
    if '[Jarvis]' not in digest or '[REA]' not in digest:
        raise AssertionError('digest lost one of its source labels')
    return len([line for line in digest.splitlines() if line.strip()])


def run_checks():
    addresses = check_addresses()
    versions = check_fingerprints()
    digest_lines = check_digest_attribution()
    return {
        'addresses': addresses,
        'fingerprints': versions,
        'digest_lines': digest_lines,
        'summary': (f"{addresses} spoken addresses; Three.js r{versions['Three.js']}; "
                    f"GSAP {versions['GSAP']}; {digest_lines} attributed digest lines"),
    }


def main():
    result = run_checks()
    print('Offline checks: PASS — ' + result['summary'])
    if '--json' in sys.argv:
        print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
