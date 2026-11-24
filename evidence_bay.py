"""Evidence capture for a teardown: REA watches, Jarvis reads the browser.

Five lanes, each labelled by who captured it:
  REA     list targets, inspect while scrolling, analyze the bundle, screenshot
  Jarvis  ephemeral Chrome, wheel scrolling, performance resource log, PNG decode

The code REA captured is also searched here, but every finding keeps both the
capture attribution and the scan attribution.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request

import net_guard
import rea_limits
import web_research

ROOT = Path(__file__).resolve().parent
ARTIFACT_ROOT = ROOT / 'artifacts' / 'evidence'
REA_ENDPOINT = 'http://127.0.0.1:9333'
INSPECT_MS = rea_limits.INSPECT_MS
ANALYZE_MS = rea_limits.ANALYZE_MS
SCROLL_STEPS = rea_limits.SCROLL_STEPS
WHEEL_DELTA = rea_limits.WHEEL_DELTA
MAX_SOURCE_BYTES = rea_limits.MAX_SOURCE_BYTES

# ONE ordered table. Order is the designer's order, not the alphabet's.
FINGERPRINT_PATTERNS = (
    {
        'category': '3D engine',
        'name': 'Three.js',
        'patterns': (
            (r'Three\.js\s+Authors[\s\S]{0,400}?(?:REVISION|revision)\s*[=:]\s*["\'`]?(\d{2,3})', 'license banner'),
            (r'THREE_REVISION\s*[:=]\s*["\'`]?(\d{2,3})', 'THREE_REVISION constant'),
            (r'(?<!THREE_)REVISION\s*[=:]\s*["\'`]?(\d{2,3})["\'`]?', 'REVISION constant'),
        ),
    },
    {
        'category': 'animation',
        'name': 'GSAP',
        'requires': r'(?i)\bgsap\b|ScrollTrigger|ScrollSmoother',
        'patterns': (
            (r'GSAP\s+(\d+\.\d+(?:\.\d+)?)', 'license banner'),
            (r'\.version\s*=\s*["\'`](3\.\d+\.\d+)["\'`]', 'version constant'),
            (r'version\s*[:=]\s*["\'`](3\.\d+\.\d+)["\'`]', 'version constant'),
        ),
    },
    {
        'category': 'animation',
        'name': 'ScrollTrigger',
        'patterns': ((r'ScrollTrigger', None),),
    },
    {
        'category': 'smooth scroll',
        'name': 'Lenis',
        'patterns': ((r'\bLenis\b', None),),
    },
    {
        'category': 'smooth scroll',
        'name': 'Locomotive Scroll',
        'patterns': ((r'locomotive-scroll|LocomotiveScroll', None),),
    },
    {
        'category': 'smooth scroll',
        'name': 'ScrollSmoother',
        'patterns': ((r'ScrollSmoother', None),),
    },
    {
        'category': 'visual effects',
        'name': 'postprocessing',
        'patterns': (
            (r'postprocessing\s+v?(\d+\.\d+(?:\.\d+)?)', 'license banner'),
            (r'EffectComposer', None),
            (r'LuminanceMaterial|UnrealBloomPass|BokehPass|SSAOPass', None),
        ),
    },
    {
        'category': 'compression',
        'name': 'Draco',
        'patterns': ((r'DRACOLoader|DracoLoader|decodeDracoFile', None),),
    },
    {
        'category': 'compression',
        'name': 'KTX2 / Basis',
        'patterns': ((r'KTX2Loader|ktx2Loader|BasisTextureLoader', None),),
    },
    {
        'category': 'compression',
        'name': 'meshopt',
        'patterns': ((r'meshoptDecoder|EXT_meshopt_compression', None),),
    },
    {
        'category': 'build tools',
        'name': 'Vite',
        'patterns': ((r'__vite__mapDeps|\bvite\b', None),),
    },
    {
        'category': 'build tools',
        'name': 'Rolldown',
        'patterns': ((r'rolldown-runtime|Rolldown', None),),
    },
    {
        'category': 'build tools',
        'name': 'webpack',
        'patterns': ((r'webpackJsonp|__webpack_require__', None),),
    },
    {
        'category': 'build tools',
        'name': 'esbuild',
        'patterns': ((r'\besbuild\b', None),),
    },
)

GENERIC_UNIFORMS = {
    'value', 'type', 'opacity', 'transparent', 'side', 'depthTest', 'depthWrite', 'blending',
    'toneMapped', 'vertexColors', 'flatShading', 'fog', 'lights', 'clipping', 'clippingPlanes',
    'diffuse', 'emissive', 'specular', 'shininess', 'roughness', 'metalness', 'scale',
    'displacementScale', 'displacementBias', 'bumpScale', 'normalScale', 'clearcoat', 'sheen',
    'transmission', 'thickness', 'attenuationColor', 'attenuationDistance', 'ior', 'reflectivity',
    'refractionRatio', 'envMapIntensity', 'backgroundIntensity', 'backgroundBlurriness',
    'backgroundRotation', 'uvTransform', 'modelMatrix', 'modelViewMatrix', 'projectionMatrix',
    'viewMatrix', 'normalMatrix', 'cameraPosition', 'isOrthographic', 'alphaTest', 'premultipliedAlpha',
    'map', 'alphaMap', 'aoMap', 'bumpMap', 'normalMap', 'displacementMap', 'emissiveMap',
    'roughnessMap', 'metalnessMap', 'envMap', 'lightMap', 'specularMap', 'gradientMap',
    'tDiffuse', 'tDiffuse1', 'tDiffuse2', 'tDiffuse3', 'tDiffuse4', 'tDiffuse5', 'tDiffuse6',
    'tDiffuse7', 'tDiffuse8', 'tDiffuse9', 'tDiffuse10', 'tDiffuse11', 'tDiffuse12',
}

ASSET_KINDS = {
    '3D models': {'.glb', '.gltf', '.fbx', '.obj', '.usdz', '.drc'},
    'compressed textures': {'.ktx2', '.basis', '.dds', '.exr', '.hdr'},
    'video': {'.mp4', '.webm', '.mov', '.m4v', '.ogv'},
    'audio': {'.mp3', '.ogg', '.wav', '.m4a', '.aac', '.flac'},
    'fonts': {'.woff2', '.woff', '.ttf', '.otf', '.eot'},
    'WebAssembly': {'.wasm'},
    'scripts': {'.js', '.mjs', '.cjs'},
    'styles': {'.css'},
    'images': {'.png', '.jpg', '.jpeg', '.webp', '.avif', '.gif', '.svg'},
    'data / API': {'.json', '.jsonld', '.xml', '.txt'},
}


class EvidenceError(RuntimeError):
    def __init__(self, message, cleanup=None):
        super().__init__(message)
        self.cleanup = cleanup


class Cancelled(RuntimeError):
    """The user cancelled a teardown between evidence lanes."""


def _check_cancel(cancel):
    if cancel is not None and cancel.is_set():
        raise Cancelled('The teardown was cancelled; no note was filed.')


def _step(progress, index):
    if progress is not None:
        progress(index)


def _rea_data(result):
    payload = result.get('result') if isinstance(result, dict) else None
    if isinstance(payload, dict) and isinstance(payload.get('data'), dict):
        return payload['data']
    return payload if isinstance(payload, dict) else {}


def _require_reok(result, label):
    if not result or not result.get('ok'):
        message = (result or {}).get('answer') or (result or {}).get('error') or 'unknown REA error'
        stderr = ((result or {}).get('stderr') or '')[-800:]
        raise EvidenceError(f'{label} failed: {message} {stderr}'.strip())


def _normalized(data):
    return (data or {}).get('normalized_result') or {}


def _host_key(host):
    host = (host or '').lower()
    return host[4:] if host.startswith('www.') else host


def select_target(list_data, requested_url, preferred_id=None):
    targets = _normalized(list_data).get('targets') or []
    if preferred_id:
        for target in targets:
            if target.get('target_id') == preferred_id:
                return target
    wanted = _host_key(urlsplit(requested_url).hostname or '')
    for target in targets:
        try:
            host = _host_key(urlsplit(target.get('url') or '').hostname or '')
        except ValueError:
            continue
        if target.get('type') == 'page' and host == wanted:
            return target
    for target in targets:
        if target.get('type') == 'page':
            return target
    raise EvidenceError('REA did not list a page target for the requested site.')


def _source_items(inspect_data):
    return ((_normalized(inspect_data).get('scripts') or {}).get('items') or [])


MAX_FALLBACK_FETCHES = rea_limits.MAX_FALLBACK_FETCHES


def _fetch_public(url: str, timeout: float, cap: int):
    """Fetch bytes through the DNS-pinned, public-only opener.

    web_research's opener resolves once, connects to that validated address
    (no second DNS answer can rebind the connection), validates every redirect
    hop, and disables environment proxies.
    """
    if not net_guard.is_public_url(url):
        return None
    request = Request(url, headers={'User-Agent': 'Jarvis evidence capture'})
    try:
        with web_research._pinned_open(request, timeout) as response:
            if not net_guard.is_public_url(response.geturl()):
                return None
            return response.read(cap + 1)
    except Exception:
        return None


def extract_sources(inspect_data, cancel=None):
    """Source text REA captured, with a hash-verified fetch fallback if needed."""
    sources = []
    seen = set()
    for item in _source_items(inspect_data):
        artifact = (item.get('source') or {}).get('artifact') or {}
        text = artifact.get('text')
        sha = artifact.get('sha256') or item.get('cdp_hash')
        if not isinstance(text, str) or not text:
            continue
        # Several unhashed scripts used to collapse into one (`None` key),
        # dropping the later libraries from fingerprinting.
        identity = sha or hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest()
        if identity in seen:
            continue
        seen.add(identity)
        sources.append({'url': item.get('url'), 'sha256': identity, 'text': text,
                        'captured_by': 'REA'})
    if sources:
        return sources

    # The artifact text was not included; fetch the exact script and prove its
    # hash. Never ask this server to reach a private/loopback URL: the page
    # controls these script URLs, so a hostile target could otherwise use REA
    # as an SSRF pivot. An unhashed body cannot be proven and is refused.
    fetched = 0
    for item in _source_items(inspect_data):
        url = item.get('url') or ''
        expected = (item.get('source') or {}).get('artifact', {}).get('sha256') or item.get('cdp_hash')
        if (not isinstance(url, str) or not url.startswith(('http://', 'https://'))
                or not expected or expected in seen or fetched >= MAX_FALLBACK_FETCHES):
            continue
        _check_cancel(cancel)
        fetched += 1
        raw = _fetch_public(url, 10, MAX_SOURCE_BYTES)
        if raw is None or len(raw) > MAX_SOURCE_BYTES:
            continue
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            continue
        seen.add(expected)
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            text = raw.decode('utf-8', 'replace')
        sources.append({'url': url, 'sha256': actual, 'text': text,
                        'captured_by': 'Jarvis (hash-verified fetch of REA capture)'})
    return sources


def scan_fingerprints(sources):
    """Scan REA-captured source with the one ordered table above."""
    results = []
    for spec in FINGERPRINT_PATTERNS:
        found = []
        for source in sources:
            text = source['text']
            if spec.get('requires') and not re.search(spec['requires'], text):
                continue
            for pattern, evidence_kind in spec['patterns']:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    version = None
                    for group in match.groups():
                        if group and re.fullmatch(r'\d+(?:\.\d+)*', group):
                            version = group
                            break
                    snippet = re.sub(r'\s+', ' ', match.group(0)).strip()[:180]
                    found.append({'version': version, 'kind': evidence_kind,
                                  'file': source.get('url'), 'evidence': snippet,
                                  'source': source.get('captured_by')})
        if found:
            versions = [item['version'] for item in found if item['version']]
            version = Counter(versions).most_common(1)[0][0] if versions else None
            first = next((item for item in found if item['version'] == version), found[0])
            results.append({
                'category': spec['category'],
                'name': spec['name'],
                'version': version,
                'evidence': first['evidence'],
                'evidence_kind': first['kind'],
                'file': first['file'],
                'captured_by': 'REA (source capture)',
                'scanned_by': 'Jarvis',
            })
    return results


def other_banners(sources):
    banners = []
    seen = set()
    for source in sources:
        for match in re.finditer(r'/\*![\s\S]{0,600}?\*/|@license[^\n]{0,220}', source['text']):
            snippet = re.sub(r'\s+', ' ', match.group(0)).strip()[:260]
            key = snippet.lower()
            if key not in seen:
                seen.add(key)
                banners.append({'banner': snippet, 'file': source.get('url'),
                                'captured_by': source.get('captured_by')})
            if len(banners) >= 12:
                return banners
    return banners


def _meaning(name):
    low = name.lower()
    if 'coc' in low:
        return 'depth of field (circle of confusion)'
    if 'bokeh' in low or 'dof' in low:
        return 'depth of field / bokeh'
    if 'bloom' in low:
        return 'bloom'
    if 'luminance' in low or 'tonemapping' in low or 'middleGrey'.lower() in low or 'whitepoint'.lower() in low:
        return 'tone mapping / exposure'
    if 'depth' in low:
        return 'depth buffer'
    if 'buffer' in low:
        return 'render buffer'
    if 'resolution' in low or 'texel' in low:
        return 'resolution / texel size'
    if 'samples' in low or 'sample' in low:
        return 'sampling'
    if 'time' in low:
        return 'animation clock'
    if 'velocity' in low:
        return 'motion / velocity'
    if 'aspect' in low:
        return 'aspect ratio'
    if 'planesize' in low or 'squaresize' in low:
        return 'grid geometry size'
    if 'imgsize' in low:
        return 'image size'
    if 'dither' in low:
        return 'dithering'
    if 'colormix' in low:
        return 'colour mixing'
    if 'bend' in low:
        return 'distortion'
    if 'displacement' in low or 'vertex' in low:
        return 'vertex displacement'
    return None


def _interesting_uniform(name):
    if name in GENERIC_UNIFORMS or len(name) < 2 or len(name) > 64:
        return False
    if re.match(r'^u[A-Z]', name) or re.match(r'^t[A-Z]', name):
        return True
    if name.isupper() and len(name) >= 3:
        return True
    return bool(re.search(r'(?i)(coc|bokeh|dof|focus|aperture|bloom|exposure|luminance|threshold|'
                          r'depth|buffer|resolution|samples|texel|radius|intensity|velocity|'
                          r'displacement|shadow|refraction|transmission)', name))


def _score_uniform(name, count):
    score = count
    if re.match(r'^u[A-Z]', name):
        score += 5
    if re.search(r'(?i)(coc|bokeh|dof|focus|aperture|bloom|exposure|luminance|threshold|samples)', name):
        score += 5
    if name.isupper():
        score += 3
    if 'Buffer' in name:
        score += 4
    return score


def scan_graphics(sources):
    """Jarvis-side scan of REA-captured code for shader uniforms/defines."""
    counts = Counter()
    files = defaultdict(set)
    for source in sources:
        text = source['text']
        for match in re.finditer(r'uniforms\s*:\s*\{([^{}]{0,3500})\}', text):
            for name in re.findall(r'([A-Za-z_$][\w$]*)\s*:', match.group(1)):
                if _interesting_uniform(name):
                    counts[name] += 1
                    files[name].add(source.get('url'))
        for match in re.finditer(r'defines\s*:\s*\{([^{}]{0,2000})\}', text):
            for name in re.findall(r'([A-Za-z_$][\w$]*)\s*:', match.group(1)):
                if _interesting_uniform(name):
                    counts[name] += 1
                    files[name].add(source.get('url'))
        for match in re.finditer(
                r'uniform\s+(?:lowp\s+|mediump\s+|highp\s+)?'
                r'(?:float|int|bool|vec[234]|mat[234]|sampler2D|samplerCube)\s+([A-Za-z_]\w*)', text):
            name = match.group(1)
            if _interesting_uniform(name):
                counts[name] += 1
                files[name].add(source.get('url'))
    signals = []
    for name, count in counts.items():
        signals.append({
            'name': name,
            'count': count,
            'score': _score_uniform(name, count),
            'meaning': _meaning(name),
            'files': sorted(files[name])[:2],
            'captured_by': 'Jarvis (scan of REA-captured source)',
        })
    signals.sort(key=lambda item: (-item['score'], item['name'].lower()))
    return signals[:24]


def rea_graphics(analyze_data):
    """Uniform/define values REA itself inferred while analysing the bundle."""
    nr = _normalized(analyze_data)
    nodes = ((nr.get('observations') or {}).get('chunks') or {}).get('nodes') or []
    key_to_url = {node.get('script_key'): node.get('url') for node in nodes}
    signals = []
    seen = set()
    for inference in nr.get('inferences') or []:
        if inference.get('kind') != 'endpoint_candidate':
            continue
        basis = (inference.get('basis') or [{}])[0]
        detector = basis.get('detector') or ''
        if 'uniforms' not in detector and 'defines' not in detector:
            continue
        value = inference.get('value')
        if not isinstance(value, str) or value in seen or len(value) > 64:
            continue
        if value in {'while', 'for', 'if', 'length', 'title', 'email', 'token'}:
            continue
        seen.add(value)
        signals.append({
            'name': value,
            'detector': detector,
            'score': _score_uniform(value, 1),
            'meaning': _meaning(value),
            'file': key_to_url.get(basis.get('script_key')),
            'captured_by': 'REA',
        })
    return signals


def classify_asset(url, initiator=''):
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        path = ''
    suffix = Path(path).suffix
    for kind, extensions in ASSET_KINDS.items():
        if suffix in extensions:
            return kind
    if initiator in ('script', 'link'):
        return 'scripts' if initiator == 'script' else 'styles'
    if initiator in ('fetch', 'xmlhttprequest'):
        return 'data / API'
    if initiator == 'navigation':
        return 'document'
    return 'other'


def read_assets(ws):
    expression = """(() => performance.getEntriesByType('resource').map(e => ({
        name: e.name,
        initiatorType: e.initiatorType,
        transferSize: e.transferSize,
        encodedBodySize: e.encodedBodySize,
        decodedBodySize: e.decodedBodySize,
        duration: e.duration,
        startTime: e.startTime,
        nextHopProtocol: e.nextHopProtocol,
        responseStatus: e.responseStatus
    })))()"""
    entries = ws.evaluate(expression) or []
    nav_expression = """(() => performance.getEntriesByType('navigation').map(e => ({
        name: e.name, transferSize: e.transferSize, encodedBodySize: e.encodedBodySize,
        decodedBodySize: e.decodedBodySize, duration: e.duration
    })))()"""
    navigation = ws.evaluate(nav_expression) or []
    if not isinstance(entries, list):
        entries = []
    if not isinstance(navigation, list):
        navigation = []

    def number(value) -> float:
        """Page JavaScript can return strings, nulls or objects here."""
        try:
            return float(value or 0)
        except (TypeError, ValueError):
            return 0.0

    def integer(value) -> int:
        try:
            return int(number(value))
        except (OverflowError, ValueError):
            return 0

    def origin_of(url: str) -> str:
        try:
            parsed = urlsplit(url)
            return f'{parsed.scheme}://{parsed.netloc}' if parsed.netloc else (parsed.scheme or 'unknown')
        except ValueError:
            return 'unknown'

    rows = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get('name') or '')
        initiator = str(entry.get('initiatorType') or '')
        size, source = 0, 'unknown'
        for field, label in (('transferSize', 'transferSize'), ('encodedBodySize', 'encodedBodySize'),
                             ('decodedBodySize', 'decodedBodySize')):
            value = integer(entry.get(field))
            if value:
                size, source = value, label
                break
        rows.append({
            'url': name,
            'origin': origin_of(name),
            'kind': classify_asset(name, initiator),
            'initiator': initiator,
            'size': size if size else None,
            'size_source': source,
            'duration_ms': round(number(entry.get('duration')), 1),
            'protocol': entry.get('nextHopProtocol'),
        })
    for entry in navigation:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get('name') or '')
        size = integer(entry.get('transferSize') or entry.get('encodedBodySize'))
        rows.append({'url': name, 'origin': origin_of(name), 'kind': 'document',
                     'initiator': 'navigation', 'size': size or None,
                     'size_source': 'transferSize' if entry.get('transferSize') else 'unknown',
                     'duration_ms': round(number(entry.get('duration')), 1), 'protocol': None})

    known = [row for row in rows if row['size']]
    unknown = [row for row in rows if not row['size']]
    unique_top = {}
    for row in known:
        key = row['url']
        if key not in unique_top or row['size'] > unique_top[key]['size']:
            unique_top[key] = row
    top = sorted(unique_top.values(), key=lambda row: row['size'], reverse=True)[:12]
    kind_totals = {kind: {'count': 0, 'bytes': 0, 'unknown_sizes': 0}
                   for kind in list(ASSET_KINDS) + ['document', 'other']}
    for row in rows:
        bucket = kind_totals.setdefault(row['kind'], {'count': 0, 'bytes': 0, 'unknown_sizes': 0})
        bucket['count'] += 1
        if row['size']:
            bucket['bytes'] += row['size']
        else:
            bucket['unknown_sizes'] += 1
    origin_totals = {}
    for row in rows:
        bucket = origin_totals.setdefault(row['origin'], {'count': 0, 'bytes': 0, 'unknown_sizes': 0})
        bucket['count'] += 1
        if row['size']:
            bucket['bytes'] += row['size']
        else:
            bucket['unknown_sizes'] += 1
    return {
        'entries': rows,
        'resource_count': len(entries),
        'total_count': len(rows),
        'known_bytes': sum(row['size'] for row in rows if row['size']),
        'unknown_sizes': len(unknown),
        'kinds': kind_totals,
        'origins': origin_totals,
        'top': top,
        'captured_by': 'Jarvis (performance.getEntriesByType)',
    }


def _scroll_to_top(ws, max_steps=40):
    for _ in range(max_steps):
        try:
            position = ws.evaluate('window.scrollY') or 0
        except Exception:
            position = 0
        if position <= 1:
            break
        ws.wheel(-1200)
        time.sleep(0.08)
    time.sleep(0.5)
    return ws.evaluate('window.scrollY') or 0


def _routes(analyze_data):
    routes = ((_normalized(analyze_data).get('observations') or {}).get('routes') or [])
    seen, result = set(), []
    for route in routes:
        value = route.get('value')
        if isinstance(value, str) and value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _edges(analyze_data, limit=15):
    nr = _normalized(analyze_data)
    chunks = (nr.get('observations') or {}).get('chunks') or {}
    nodes = chunks.get('nodes') or []
    key_to_url = {node.get('script_key'): node.get('url') for node in nodes}
    seen, result = set(), []
    for edge in chunks.get('edges') or []:
        from_url = key_to_url.get(edge.get('from_script_key')) or edge.get('from_script_key')
        to_url = edge.get('resolved_url') or edge.get('specifier')
        key = (from_url, to_url, edge.get('specifier'), edge.get('kind'))
        if key in seen:
            continue
        seen.add(key)
        result.append({'from': from_url, 'to': to_url, 'specifier': edge.get('specifier'),
                       'kind': edge.get('kind')})
        if len(result) >= limit:
            break
    return result


def _top_scripts(analyze_data, limit=8):
    nr = _normalized(analyze_data)
    nodes = ((nr.get('observations') or {}).get('chunks') or {}).get('nodes') or []
    return sorted(nodes, key=lambda node: node.get('bytes') or 0, reverse=True)[:limit]


def _decode_screenshot(shot_data, artifact_dir):
    nr = _normalized(shot_data)
    artifact = nr.get('artifact') or {}
    encoded = artifact.get('data_base64')
    if not encoded:
        raise EvidenceError('REA screenshot returned no base64 PNG.')
    try:
        raw = base64.b64decode(encoded, validate=False)
    except (ValueError, TypeError):
        raise EvidenceError('REA screenshot PNG base64 was invalid.') from None
    if not raw.startswith(b'\x89PNG\r\n\x1a\n'):
        raise EvidenceError('Decoded screenshot is not a PNG.')
    digest = hashlib.sha256(raw).hexdigest()
    claimed = artifact.get('sha256')
    if claimed and digest != claimed:
        raise EvidenceError('Decoded screenshot hash does not match REA artifact sha256.')
    path = artifact_dir / 'screenshot.png'
    path.write_bytes(raw)
    width = height = None
    if len(raw) >= 24 and raw[12:16] == b'IHDR':
        width, height = struct.unpack('>II', raw[16:24])
    return {
        'path': str(path),
        'sha256': digest,
        'bytes': len(raw),
        'png_width': width,
        'png_height': height,
        'viewport': nr.get('viewport'),
        'captured_at': nr.get('captured_at'),
        'evidence_id': shot_data.get('evidence_id'),
        'captured_by': 'REA (capture-web-screenshot)',
        'saved_by': 'Jarvis',
    }


def _one_line(value, limit=300):
    """Collapse page-controlled text to one short line.

    A newline in a title or URL used to create a new ``[REA]``/``[Jarvis]``
    digest line, letting a hostile page forge evidence attribution.
    """
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def _basename(url):
    try:
        return Path(urlsplit(url).path).name or url
    except Exception:
        return url


def _bytes_label(value):
    if not value:
        return '?'
    if value >= 1024 * 1024:
        return f'{value / (1024 * 1024):.2f} MB'
    if value >= 1024:
        return f'{value / 1024:.1f} kB'
    return f'{value} B'


def render_digest(result):
    lines = []
    lines.append(f"[Jarvis] TITLE: {_one_line(result.get('title'))}")
    lines.append(f"[Jarvis] URL: {_one_line(result.get('url'), 2048)}")
    lines.append(f"[REA] TARGET: {_one_line(result['rea']['target']['target_id'], 200)} "
                 f"{_one_line(result['rea']['target'].get('url'), 2048)}")
    inspect = result['rea']['inspect']
    lines.append(f"[REA] INSPECT: {inspect['scripts']} scripts, {inspect['resources']} same-origin resources, "
                 f"{inspect['observation_ms']} ms observation while Jarvis wheel-scrolled")
    analyze = result['rea']['analyze']
    lines.append(f"[REA] ANALYZE: {analyze['scripts_observed']} scripts observed, "
                 f"{analyze['scripts_analyzed']} parsed, {len(analyze['routes'])} routes")
    lines.append('[REA] SCRIPTS BY SIZE:')
    for script in analyze['scripts']:
        lines.append(f"  [REA] {_bytes_label(script.get('bytes')):>9}  "
                     f"{_one_line(_basename(script.get('url')))}")
    lines.append('[REA] ROUTES: ' + ', '.join(_one_line(route, 120) for route in analyze['routes'][:14]))
    lines.append('[REA] FILE LOADS FILE (first edges):')
    for edge in analyze['edges'][:5]:
        lines.append(f"  [REA] {_one_line(_basename(edge['from']))} -> "
                     f"{_one_line(_basename(edge['to']))} ({_one_line(edge['kind'], 40)})")
    lines.append('[Jarvis] CODE SIGNALS:')
    for signal in result['digest']['code_signals'][:12]:
        label = 'REA' if signal.get('captured_by', '').startswith('REA') else 'Jarvis'
        meaning = f" — {_one_line(signal['meaning'], 220)}" if signal.get('meaning') else ''
        lines.append(f"  [{label}] {_one_line(signal['name'], 120)}{meaning}")
    lines.append('[REA] OTHER BANNERS: ' + (
        ' | '.join(_one_line(item['banner'], 120) for item in result['jarvis']['other_banners'][:4])
        if result['jarvis']['other_banners'] else 'none found'))
    lines.append('[Jarvis] STACK:')
    for item in result['digest']['stack']:
        version = _one_line(item.get('version'), 60) if item.get('version') else 'version not exposed'
        if item['name'] == 'Three.js' and item.get('version'):
            version = f"r{version}"
        source = 'REA' if str(item.get('scanned_by', 'REA')).startswith('REA') else 'Jarvis'
        lines.append(f"  [{source}] {_one_line(item['name'], 80)} {version} "
                     f"(captured by {_one_line(item.get('captured_by', 'unknown'), 80)})")
    assets = result['digest']['asset_totals']
    lines.append(f"[Jarvis] ASSETS: {assets['resources']} resource entries, "
                 f"{_bytes_label(assets['known_bytes'])}, {assets['unknown_sizes']} unknown sizes")
    lines.append('[Jarvis] ORIGINS: ' + ', '.join(
        f"{_one_line(origin, 300)} ({_bytes_label(bucket['bytes'])}, {bucket['count']})"
        for origin, bucket in sorted(assets['origins'].items(), key=lambda item: item[1]['bytes'], reverse=True)[:6]))
    lines.append('[Jarvis] KINDS: ' + ', '.join(
        f"{_one_line(kind, 60)} {bucket['count']}" for kind, bucket in sorted(
            assets['kinds'].items(), key=lambda item: item[1]['bytes'], reverse=True)))
    if assets['unknown_sizes']:
        lines.append('[Jarvis] NOTE: cross-origin entries without Timing-Allow-Origin expose no size; '
                     'full per-entry log is in assets.json')
    lines.append(f"[Jarvis] ASSET LOG: {result['jarvis']['assets'].get('all_path')}")
    lines.append('[Jarvis] TOP 12 ASSETS:')
    for row in assets['top']:
        lines.append(f"  [Jarvis] {_bytes_label(row.get('size')):>9}  "
                     f"{_one_line(row['kind'], 60)}: {_one_line(_basename(row['url']))}")
    shot = result['rea']['screenshot']
    dimensions = (f"{shot.get('png_width')}x{shot.get('png_height')}"
                  if shot.get('png_width') else 'dimensions unknown')
    lines.append(f"[REA] SCREENSHOT: {shot['path']} ({shot['bytes']} B, {dimensions}, "
                 f"sha256 {shot['sha256'][:16]}…)")
    lines.append(f"[Jarvis] SCREENSHOT DECODE: PNG verified and saved at {shot['path']}")
    lines.append(f"[Jarvis] CLEANUP: {result.get('cleanup', {}).get('ok')}; profile_removed="
                 f"{result.get('cleanup', {}).get('profile_removed')}; "
                 f"port_released={result.get('cleanup', {}).get('port_released')}")
    return '\n'.join(lines)


def capture_evidence(url, headless=True, job_id=None, inspect_ms=INSPECT_MS,
                     analyze_ms=ANALYZE_MS, scroll_steps=SCROLL_STEPS,
                     progress=None, cancel=None):
    """Run all five evidence lanes and return a compact, attributed result."""
    import teardown  # Lazy import: teardown owns the browser/REA doors.

    job = None
    facts = {}
    cleanup = {}
    error = None
    try:
        _check_cancel(cancel)
        _step(progress, 0)  # Opening the site in a clean browser
        job = teardown.browser_job(url, job_id=job_id, headless=headless, scroll=False)
        _step(progress, 1)  # Waiting for it to load
        facts = job.start()
        # A public URL can redirect the ephemeral browser to loopback or the
        # LAN. Check the final document before REA reads or screenshots it.
        if not net_guard.is_public_url(str(facts.get('url') or url)):
            raise EvidenceError('The site redirected to a non-public address; no evidence was captured.')
        _check_cancel(cancel)
        endpoint = facts['cdp_endpoint']
        preferred = facts.get('target_id')

        list_result = teardown.run('list-browser-targets', endpoint, timeout=60, cancel=cancel)
        _require_reok(list_result, 'list-browser-targets')
        target_data = _rea_data(list_result)
        list_evidence_id = target_data.get('evidence_id')
        target = select_target(target_data, facts.get('url') or url, preferred)
        target_id = target['target_id']
        if preferred and target_id != preferred:
            raise EvidenceError(f'REA selected target {target_id} but the owned page is {preferred}.')

        job_id_value = job.job_id
        artifact_dir = ARTIFACT_ROOT / job_id_value
        artifact_dir.mkdir(parents=True, exist_ok=True)

        box = {}

        def watch():
            try:
                box['inspect'] = teardown.run(
                    'inspect-web-page', endpoint,
                    [target_id, '--observation-ms', str(int(inspect_ms)),
                     '--include-script-sources', '--full-output'],
                    timeout=rea_limits.REA_INSPECT_TIMEOUT, cancel=cancel)
            except BaseException as exc:  # delivered below, never silently swallowed
                box['error'] = exc

        _check_cancel(cancel)
        _step(progress, 2)  # REA is watching while I scroll
        thread = threading.Thread(target=watch, daemon=True)
        thread.start()
        time.sleep(1.0)
        for _ in range(int(scroll_steps)):
            _check_cancel(cancel)
            job.ws.wheel(WHEEL_DELTA)
            time.sleep(0.10)
        time.sleep(0.6)
        scroll_y_after = job.ws.evaluate('window.scrollY') or 0
        thread.join(timeout=max(60, rea_limits.REA_INSPECT_TIMEOUT + 30))
        if thread.is_alive():
            raise EvidenceError('inspect-web-page did not finish while the page was scrolling.')
        if 'error' in box:
            if cancel is not None and cancel.is_set():
                raise Cancelled('The teardown was cancelled; no note was filed.') from None
            raise EvidenceError(f'inspect-web-page failed: {box["error"]}')
        _check_cancel(cancel)
        inspect_result = box.get('inspect') or {}
        _require_reok(inspect_result, 'inspect-web-page')
        inspect_data = _rea_data(inspect_result)
        (artifact_dir / 'inspect.json').write_text(json.dumps(inspect_result, ensure_ascii=False), encoding='utf-8')

        _step(progress, 3)  # REA is reading the code
        analyze_result = teardown.run(
            'analyze-web-bundle', endpoint,
            [target_id, '--observation-ms', str(int(analyze_ms)), '--full-output'],
            timeout=rea_limits.REA_ANALYZE_TIMEOUT, cancel=cancel)
        _require_reok(analyze_result, 'analyze-web-bundle')
        analyze_data = _rea_data(analyze_result)
        (artifact_dir / 'analyze.json').write_text(json.dumps(analyze_result, ensure_ascii=False), encoding='utf-8')

        _check_cancel(cancel)
        _step(progress, 4)  # Taking a snapshot
        scroll_y_top = _scroll_to_top(job.ws)
        shot_result = teardown.run('capture-web-screenshot', endpoint, [target_id],
                                   timeout=rea_limits.REA_SCREENSHOT_TIMEOUT, cancel=cancel)
        _require_reok(shot_result, 'capture-web-screenshot')
        shot_data = _rea_data(shot_result)
        screenshot = _decode_screenshot(shot_data, artifact_dir)

        _check_cancel(cancel)
        _step(progress, 5)  # Listing everything it loaded
        assets = read_assets(job.ws)

        _check_cancel(cancel)
        _step(progress, 6)  # Identifying the stack
        sources = extract_sources(inspect_data, cancel=cancel)
        fingerprints = scan_fingerprints(sources)
        graphics_rea = rea_graphics(analyze_data)
        graphics_jarvis = scan_graphics(sources)
        banners = other_banners(sources)

        # Keep both attributions when the same name appears in both lanes.
        code_signals = []
        seen_names = set()
        for signal in graphics_rea + graphics_jarvis:
            if signal['name'] not in seen_names:
                seen_names.add(signal['name'])
                code_signals.append(signal)
        code_signals.sort(key=lambda signal: (-signal.get('score', 0), signal['name'].lower()))
        code_signals = code_signals[:16]

        nr = _normalized(analyze_data)
        stack = list(fingerprints)
        known_stack = {item['name'].lower() for item in stack}
        for inference in nr.get('inferences') or []:
            kind = inference.get('kind')
            if kind in ('vendor_fingerprint', 'bundle_runtime'):
                value = inference.get('value')
                if isinstance(value, str) and value.lower() not in known_stack:
                    known_stack.add(value.lower())
                    stack.append({'category': 'framework' if kind == 'vendor_fingerprint' else 'build tools',
                                  'name': value, 'version': None,
                                  'evidence': 'REA bundle inference',
                                  'captured_by': 'REA', 'scanned_by': 'REA'})

        assets['all_path'] = str(artifact_dir / 'assets.json')
        (artifact_dir / 'assets.json').write_text(json.dumps(assets, ensure_ascii=False), encoding='utf-8')

        _check_cancel(cancel)
        if not (facts.get('title') or '').strip():
            try:
                refreshed_title = job.ws.evaluate('document.title')
                if refreshed_title and str(refreshed_title).strip():
                    facts['title'] = str(refreshed_title).strip()[:500]
            except Exception:
                pass
        if not (facts.get('title') or '').strip() and target.get('title'):
            facts['title'] = str(target.get('title')).strip()[:500]
        cleanup = job.close(raise_on_error=False)
        job = None
        if not cleanup.get('ok'):
            raise EvidenceError('; '.join(cleanup.get('errors') or ['Browser cleanup failed.']), cleanup)

        result = {
            'ok': True,
            'job_id': job_id_value,
            'title': facts.get('title'),
            'url': facts.get('url') or url,
            'url_requested': url,
            'target_id': target_id,
            'profile': facts.get('profile'),
            'chrome_pid': facts.get('chrome_pid'),
            'cleanup': cleanup,
            'timing': {'browser_load_seconds': facts.get('load_seconds'),
                       'inspect_ms': inspect_ms, 'analyze_ms': analyze_ms,
                       'scroll_steps': scroll_steps,
                       'scroll_y_after_scroll': scroll_y_after,
                       'scroll_y_at_snapshot': scroll_y_top},
            'attribution': {
                'REA': ['list-browser-targets', 'inspect-web-page with script sources',
                        'analyze-web-bundle graph/routes/uniform inferences',
                        'capture-web-screenshot'],
                'Jarvis': ['ephemeral Chrome and wheel input',
                           "performance.getEntriesByType('resource') asset log",
                           'fingerprint scan of REA-captured source', 'PNG decode and save'],
            },
            'rea': {
                'target': target,
                'list_evidence_id': list_evidence_id,
                'inspect': {
                    'evidence_id': (inspect_data or {}).get('evidence_id'),
                    'scripts': len(_source_items(inspect_data)),
                    'resources': len(_normalized(inspect_data).get('resources') or []),
                    'observation_ms': inspect_ms,
                    'completeness': _normalized(inspect_data).get('completeness'),
                    'captured_by': 'REA',
                },
                'analyze': {
                    'evidence_id': (analyze_data or {}).get('evidence_id'),
                    'scripts_observed': (nr.get('capture') or {}).get('scripts_observed'),
                    'scripts_analyzed': (nr.get('capture') or {}).get('scripts_analyzed'),
                    'routes': _routes(analyze_data),
                    'edges': _edges(analyze_data),
                    'scripts': _top_scripts(analyze_data),
                    'captured_by': 'REA',
                },
                'screenshot': screenshot,
            },
            'jarvis': {
                'assets': assets,
                'fingerprints': fingerprints,
                'graphics_scan': graphics_jarvis[:16],
                'other_banners': banners,
                'source_files': len(sources),
                'captured_by': 'Jarvis',
            },
            'digest': {
                'scripts': _top_scripts(analyze_data),
                'routes': _routes(analyze_data),
                'code_signals': code_signals,
                'stack': stack,
                'asset_totals': {
                    'resources': assets['resource_count'],
                    'total_count': assets['total_count'],
                    'known_bytes': assets['known_bytes'],
                    'unknown_sizes': assets['unknown_sizes'],
                    'origins': assets['origins'],
                    'kinds': assets['kinds'],
                    'top': assets['top'],
                },
            },
            'artifacts': {'dir': str(artifact_dir), 'screenshot': screenshot['path'],
                          'inspect': str(artifact_dir / 'inspect.json'),
                          'analyze': str(artifact_dir / 'analyze.json'),
                          'assets': str(artifact_dir / 'assets.json'),
                          'digest': str(artifact_dir / 'digest.json')},
        }
        result['digest_text'] = render_digest(result)
        (artifact_dir / 'digest.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        (artifact_dir / 'digest.txt').write_text(result['digest_text'] + '\n', encoding='utf-8')
        return result
    except BaseException as exc:
        error = exc
        if isinstance(exc, EvidenceError):
            exc.cleanup = cleanup
        raise
    finally:
        if job is not None:
            cleanup = job.close(raise_on_error=False)
        if error is None and cleanup and not cleanup.get('ok'):
            raise EvidenceError('; '.join(cleanup.get('errors') or ['Browser cleanup failed.']), cleanup)
