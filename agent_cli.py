"""External coding agents as read-only workers with their own folder.

The owner's rule: an agent may see the whole computer and copy anything it
needs, but it may never modify a file that is not its own. Updated code goes to
its ``outbox/``; Jarvis analyses that and applies changes itself.

That rule is enforced in the kernel, not in a prompt: every run happens inside
``bwrap`` with the whole filesystem bind-mounted read-only and exactly two
writable places — the agent's own root and its CLI's own state directory. A run
that tries to write anywhere else fails with "Read-only file system".

Nothing here starts an agent without an explicit ``approved=True``; consent is
the caller's job (the Operator approval, or a spoken confirmation).
"""
from __future__ import annotations

import fcntl
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

ROOT = Path.home() / '.jarvis-tools' / 'agents'
DEFAULT_TIMEOUT = 900
MAX_TASK = 8000
MAX_RUNS_KEPT = 20
MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_OUTBOX_ENTRIES = 200


class AgentError(Exception):
    """The agent could not be configured or run; nothing was started."""


# One row per agent, describing only what its CLI really accepts. A setting with
# ``None`` is not offered in the UI: an honest "not supported" beats a dead switch.
AGENTS = {
    'claude': {
        'label': 'Claude Code',
        'binary': 'claude',
        'version_args': ['--version'],
        'prompt_args': ['-p'],            # prompt is the next argv element
        'settings': {
            # A hand-typed id is offered too (this CLI can be pointed at another
            # provider), but a dropdown keeps a truncated id like "dee" out.
            'model': {'kind': 'choice', 'flag': '--model', 'allow_custom': True,
                      'hint': 'np. deepseek-flash albo claude-sonnet-4-6'},
            'effort': {'kind': 'choice', 'flag': '--effort',
                       'choices': ['low', 'medium', 'high', 'max']},
            'reasoning': None,            # covered by --effort
        },
        'session': {'flag': '--session-id', 'kind': 'uuid'},
        'state_paths': ['~/.claude', '~/.claude.json'],
        'env_credentials': {'ANTHROPIC_API_KEY': 'anthropic-api-key'},
        # Non-interactive runs cannot answer a permission prompt, so edits inside
        # the sandbox are pre-approved. The kernel is still the boundary: anything
        # outside the agent's own mounts is EROFS whatever the CLI believes.
        'extra_args': ['--permission-mode', 'acceptEdits', '--add-dir', str(Path.home())],
        'notes': 'Read-only sandbox; writes only under its own folder.',
    },
    'opencode': {
        'label': 'OpenCode',
        'binary': 'opencode',
        'version_args': ['--version'],
        'prompt_args': ['run'],
        'settings': {
            'model': {'kind': 'text', 'flag': '--model',
                      'hint': 'provider/model#variant'},
            'effort': None,
            'reasoning': None,
        },
        'session': {'flag': '--session', 'kind': 'text'},
        'state_paths': ['~/.config/opencode', '~/.local/share/opencode'],
        'env_credentials': {},
        'extra_args': ['--auto'],
        'notes': 'Accepts --format json; no thinking-level flag.',
    },
    'antigravity': {
        'label': 'Antigravity',
        'binary': 'agy',
        'version_args': ['--version'],
        'prompt_args': ['-p'],
        'settings': {
            # agy refuses --model together with --effort: its model ids already
            # encode the effort (gemini-3.8-flash-low/-medium/-high), so the level
            # is chosen by picking a model, not by a second flag.
            'model': {'kind': 'choice', 'flag': '--model', 'allow_custom': True},
            'effort': None,
            'mode': {'kind': 'choice', 'flag': '--mode',
                     'choices': ['accept-edits', 'auto', 'plan']},
        },
        'session': {'flag': '--conversation', 'kind': 'text'},
        'state_paths': ['~/.gemini/antigravity-cli'],
        'env_credentials': {},
        'extra_args': ['--dangerously-skip-permissions', '--add-dir', str(Path.home())],
        'notes': 'Model list from `agy models`; the effort is part of the model id. '
                 'Mode: accept-edits/auto/plan.',
    },
    'hermes': {
        'label': 'Hermes Agent',
        'binary': 'hermes',
        'version_args': ['--version'],
        'prompt_args': ['-z'],            # one-shot prompt
        'settings': {
            'model': {'kind': 'choice', 'flag': '-m', 'allow_custom': True,
                      'hint': 'własny model (np. deepseek-v4.1-flash-uncensored)'},
            'effort': None,
            'reasoning': {'kind': 'choice', 'flag': '--reasoning',
                          'choices': ['low', 'medium', 'high']},
            'provider': {'kind': 'choice', 'flag': '--provider', 'allow_custom': True,
                         'hint': 'własny provider (np. openrouter, custom)'},
        },
        'session': {'flag': '--resume', 'kind': 'text'},
        'state_paths': ['~/.hermes'],
        'env_credentials': {},
        'extra_args': ['--yolo'],
        'notes': 'River rejects agent.reasoning_effort; leave reasoning empty there.',
    },
}


# Where each agent's model list comes from. A CLI that can enumerate its own
# models is asked; the rest get a curated list. The stored value is always added
# back, so a hand-typed id is never silently replaced.
MODEL_SOURCES = {
    # Claude Code here talks to whichever API its own config points at, so the list
    # carries both the Anthropic ids and the DeepSeek ones this install accepts.
    'claude': {'static': ['deepseek-flash', 'deepseek-v4-pro', 'deepseek-chat',
                          'sonnet', 'opus', 'haiku', 'claude-sonnet-4-6',
                          'claude-opus-4-6-thinking']},
    'opencode': {'command': ['opencode', 'models']},
    'hermes': {'static': ['deepseek-v4.1-flash-uncensored', 'deepseek-v4.1-flash-1017',
                          'deepseek-chat']},
    'antigravity': {'command': ['agy', 'models']},
}
MODELS_CACHE_TTL = 3600
MAX_MODELS = 200

# Where each agent's provider list comes from. CLIs that manage provider credentials
# or define custom provider profiles are probed; the rest get a curated list.
PROVIDER_SOURCES = {
    'hermes': {
        'command': ['hermes', 'auth', 'list'],
        'static': [
            'custom', 'nous', 'openrouter', 'deepseek', 'anthropic',
            'openai-api', 'vertex', 'gemini', 'nvidia', 'gmi',
            'modal', 'river', 'river-glm', 'xpl-1017', 'ollama',
            'groq', 'mistral', 'bedrock', 'zai', 'kimi-coding',
            'stepfun', 'minimax',
        ],
    },
}
PROVIDERS_CACHE_TTL = 3600
MAX_PROVIDERS = 100


def agent_ids():
    return sorted(AGENTS)


def _agent(agent_id):
    if agent_id not in AGENTS:
        raise AgentError(f'Unknown agent {agent_id!r}.')
    return AGENTS[agent_id]


def agent_root(agent_id):
    _agent(agent_id)
    return ROOT / agent_id


def workspace(agent_id):
    return agent_root(agent_id) / 'workspace'


def outbox_path(agent_id):
    return agent_root(agent_id) / 'outbox'


def _ensure_dirs(agent_id):
    for path in (agent_root(agent_id), workspace(agent_id), outbox_path(agent_id),
                 agent_root(agent_id) / 'runs'):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = agent_root(agent_id).stat()
    if info.st_mode & 0o077:
        os.chmod(agent_root(agent_id), 0o700)


@contextmanager
def _lock(agent_id):
    _ensure_dirs(agent_id)
    fd = os.open(agent_root(agent_id) / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AgentError(f'{AGENTS[agent_id]["label"]} is already running a task.') from None
        yield
    finally:
        os.close(fd)


SEARCH_DIRS = ('~/.local/bin', '~/.opencode/bin', '~/.npm-global/bin', '~/.claude/local',
               '~/.bun/bin', '/usr/local/bin', '/usr/bin', '/bin', '/snap/bin')


def _which(binary):
    """Resolve a CLI binary even when the service PATH is the bare systemd one.

    The unit runs with the system PATH, so a per-user install in ~/.local/bin is
    invisible to ``shutil.which`` even though the owner can run it in a shell.
    """
    found = shutil.which(binary)
    if found:
        return found
    for raw in SEARCH_DIRS:
        candidate = Path(raw).expanduser() / binary
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def binary_present(agent_id):
    return _which(AGENTS[agent_id]['binary']) is not None


_VERSION_CACHE = {}
VERSION_CACHE_TTL = 3600


def binary_version(agent_id, refresh=False):
    path = _which(AGENTS[agent_id]['binary'])
    if not path:
        return ''
    now = time.time()
    cached = _VERSION_CACHE.get(agent_id)
    if not refresh and cached and (now - cached[0] < VERSION_CACHE_TTL) and cached[2] == path:
        return cached[1]
    try:
        result = subprocess.run([path, *AGENTS[agent_id]['version_args']],
                                capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return ''
    raw_out = (result.stdout or result.stderr or '').strip()
    lines = raw_out.splitlines() if raw_out else []
    version = lines[0][:80] if lines else ''
    _VERSION_CACHE[agent_id] = (now, version, path)
    return version


def _models_cache_path():
    return ROOT / 'models-cache.json'


_MODELS_BY_PROVIDER_CACHE = {}


def list_models_by_provider(agent_id, refresh=False):
    """Mapping of provider -> [model_ids] for agents supporting providers."""
    _agent(agent_id)
    if agent_id != 'hermes':
        return {}

    now = time.time()
    cached = _MODELS_BY_PROVIDER_CACHE.get(agent_id)
    if not refresh and cached and (now - cached[0] < MODELS_CACHE_TTL):
        return dict(cached[1])

    models_by_provider = {}

    # 1. Hermes provider_models_cache.json (live cached models for active providers)
    pmc_path = Path('~/.hermes/provider_models_cache.json').expanduser()
    if pmc_path.is_file():
        try:
            data = json.loads(pmc_path.read_text(encoding='utf-8'))
            if isinstance(data, dict):
                for prov, val in data.items():
                    if isinstance(val, dict) and isinstance(val.get('models'), list):
                        models_by_provider[prov] = [str(m).strip() for m in val['models'] if m][:MAX_MODELS]
        except Exception:
            pass

    # 2. ~/.hermes/config.yaml (model aliases, custom providers, provider sections)
    cfg_path = Path('~/.hermes/config.yaml').expanduser()
    if cfg_path.is_file():
        try:
            try:
                import yaml
                cfg = yaml.safe_load(cfg_path.read_text(encoding='utf-8')) or {}
            except Exception:
                cfg = {}
            if isinstance(cfg, dict):
                model_sec = cfg.get('model') or {}
                if isinstance(model_sec, dict):
                    aliases = model_sec.get('aliases') or {}
                    if isinstance(aliases, dict):
                        for name, spec in aliases.items():
                            if isinstance(spec, dict) and spec.get('model'):
                                m = str(spec['model']).strip()
                                existing = models_by_provider.setdefault(name, [])
                                if m and m not in existing:
                                    existing.insert(0, m)
                for cp in cfg.get('custom_providers') or []:
                    if isinstance(cp, dict):
                        name = cp.get('name') or cp.get('model')
                        m = cp.get('model')
                        models_dict = cp.get('models') or {}
                        ms = list(models_dict.keys()) if isinstance(models_dict, dict) else []
                        if m and m not in ms:
                            ms.append(m)
                        if name:
                            existing = models_by_provider.setdefault(str(name), [])
                            for x in ms:
                                sx = str(x).strip()
                                if sx and sx not in existing:
                                    existing.append(sx)
                for pname, pspec in (cfg.get('providers') or {}).items():
                    if isinstance(pspec, dict):
                        models_dict = pspec.get('models') or {}
                        pms = list(models_dict.keys()) if isinstance(models_dict, dict) else []
                        dm = pspec.get('default_model')
                        if dm and dm not in pms:
                            pms.insert(0, dm)
                        if pms:
                            existing = models_by_provider.setdefault(str(pname), [])
                            for x in pms:
                                sx = str(x).strip()
                                if sx and sx not in existing:
                                    existing.append(sx)
        except Exception:
            pass

    # 3. ~/.hermes/models_dev_cache.json (broad catalog per provider)
    dev_path = Path('~/.hermes/models_dev_cache.json').expanduser()
    if dev_path.is_file():
        try:
            dev_data = json.loads(dev_path.read_text(encoding='utf-8'))
            if isinstance(dev_data, dict):
                for prov, val in dev_data.items():
                    if isinstance(val, dict) and isinstance(val.get('models'), dict):
                        existing = models_by_provider.setdefault(prov, [])
                        for m in list(val['models'].keys())[:MAX_MODELS]:
                            sm = str(m).strip()
                            if sm and sm not in existing:
                                existing.append(sm)
        except Exception:
            pass

    # 4. Curated standard fallbacks so every listed provider always has solid choices
    curated = {
        'deepseek': ['deepseek-v4.1-flash-uncensored', 'deepseek-v4.1-flash-1017', 'deepseek-chat', 'deepseek-flash', 'deepseek-v4-pro'],
        'nous': ['deepseek-v4.1-flash-uncensored', 'deepseek-v4.1-flash-1017', 'deepseek-chat'],
        'custom': ['deepseek-v4.1-flash-uncensored', 'deepseek-v4.1-flash-1017'],
        'custom:ollama': ['gemma4-uncensored', 'llama3.3', 'qwen2.5-coder', 'deepseek-r1'],
        'ollama': ['llama3.3', 'qwen2.5-coder', 'deepseek-r1', 'gemma4-uncensored'],
        'openrouter': ['anthropic/claude-sonnet-4-6', 'deepseek/deepseek-v4.1-flash-1017', 'openai/gpt-5.5', 'google/gemini-3.8-flash'],
        'anthropic': ['claude-sonnet-4-6', 'claude-opus-4-6-thinking', 'claude-3-5-sonnet-latest', 'claude-3-5-haiku-latest'],
        'gemini': ['gemini-3.8-flash', 'gemini-3.1-pro-preview', 'gemini-2.5-pro', 'gemini-2.5-flash'],
        'openai-api': ['gpt-6.1-sol', 'gpt-5.5', 'gpt-5.4', 'gpt-4o', 'gpt-4o-mini'],
        'nvidia': ['nvidia/nemotron-3.5-super-vl-120b-a12b', 'deepseek-ai/deepseek-v4.1-flash', 'google/gemini-3.8-flash'],
        'gmi': ['deepseek-ai/deepseek-v4.1-flash-1017', 'google/gemini-3.8-flash', 'zai-org/GLM-5.3-Flash'],
        'vertex': ['google/gemini-3.8-flash', 'google/gemini-4-argon', 'google/gemini-3.7-flash'],
        'modal': ['Qwen/Qwen3.8-2.4T-A95B'],
        'river': ['deepseek-ai/DeepSeek-V4.1-Flash-1017'],
        'river-glm': ['zai-org/GLM-5.3-Flash'],
        'xpl-1017': ['deepseek-v4.1-flash-1017'],
        'groq': ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant', 'mixtral-8x7b-32768'],
        'mistral': ['mistral-large-latest', 'mistral-small-latest', 'codestral-latest'],
        'bedrock': ['anthropic.claude-3-5-sonnet-20241022-v2:0', 'amazon.nova-pro-v1:0'],
        'zai': ['glm-4-plus', 'glm-4-flash'],
        'kimi-coding': ['kimi-k2.7-code', 'kimi-k3'],
        'stepfun': ['step-2-16k', 'step-1-8k'],
        'minimax': ['MiniMax-Text-01', 'abab6.5s-chat'],
    }
    for prov, models in curated.items():
        existing = models_by_provider.setdefault(prov, [])
        for m in reversed(models):
            if m not in existing:
                existing.insert(0, m)

    for prov in list(models_by_provider.keys()):
        models_by_provider[prov] = models_by_provider[prov][:MAX_MODELS]

    _MODELS_BY_PROVIDER_CACHE[agent_id] = (now, models_by_provider)
    return dict(models_by_provider)


def list_models(agent_id, provider=None, refresh=False):
    """Model ids for the dropdown; dynamic when the CLI can list them itself."""
    _agent(agent_id)
    if agent_id == 'hermes':
        by_prov = list_models_by_provider('hermes', refresh=refresh)
        if provider:
            clean_p = str(provider).strip()
            if clean_p in by_prov and by_prov[clean_p]:
                return list(by_prov[clean_p])[:MAX_MODELS]
            if clean_p.startswith('custom:') and clean_p[7:] in by_prov:
                return list(by_prov[clean_p[7:]])[:MAX_MODELS]
        default_list = by_prov.get('deepseek') or MODEL_SOURCES['hermes']['static']
        return list(default_list)[:MAX_MODELS]

    source = MODEL_SOURCES.get(agent_id) or {}
    now = time.time()
    cache = {}
    try:
        cache = json.loads(_models_cache_path().read_text(encoding='utf-8'))
    except (OSError, ValueError):
        cache = {}
    entry = cache.get(agent_id) if isinstance(cache, dict) else None
    if not refresh and isinstance(entry, dict) and now - entry.get('at', 0) < MODELS_CACHE_TTL:
        return list(entry.get('models') or [])[:MAX_MODELS]
    models = list(source.get('static') or [])
    command = source.get('command')
    if command:
        binary = _which(command[0])
        if binary:
            try:
                result = subprocess.run([binary, *command[1:]], capture_output=True, text=True,
                                        timeout=25, check=False, env=_env(agent_id))
                for line in (result.stdout or '').splitlines():
                    value = line.split('\t')[0].strip()
                    if value and not value.startswith('#') and len(value) <= 80:
                        models.append(value)
            except (OSError, subprocess.SubprocessError):
                models = models or []
    seen = []
    for value in models:
        if value not in seen:
            seen.append(value)
    seen = seen[:MAX_MODELS]
    if seen:
        try:
            ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
            payload = cache if isinstance(cache, dict) else {}
            payload[agent_id] = {'at': now, 'models': seen}
            target_p = _models_cache_path()
            temporary = target_p.with_name(f".{target_p.name}.{os.getpid()}.{threading.get_ident()}.{time.time_ns()}.tmp")
            temporary.write_text(json.dumps(payload), encoding='utf-8')
            os.chmod(temporary, 0o600)
            temporary.replace(target_p)
        except OSError:
            pass
    return seen


def _providers_cache_path():
    return ROOT / 'providers-cache.json'


def list_providers(agent_id, refresh=False):
    """Provider identifiers for dropdowns; dynamic when the CLI or config enumerates them."""
    _agent(agent_id)
    source = PROVIDER_SOURCES.get(agent_id) or {}
    now = time.time()
    cache = {}
    try:
        cache = json.loads(_providers_cache_path().read_text(encoding='utf-8'))
    except (OSError, ValueError):
        cache = {}
    entry = cache.get(agent_id) if isinstance(cache, dict) else None
    if not refresh and isinstance(entry, dict) and now - entry.get('at', 0) < PROVIDERS_CACHE_TTL:
        return list(entry.get('providers') or [])[:MAX_PROVIDERS]

    providers = []
    command = source.get('command')
    if command:
        binary = _which(command[0])
        if binary:
            try:
                result = subprocess.run([binary, *command[1:]], capture_output=True, text=True,
                                        timeout=25, check=False, env=_env(agent_id))
                for line in (result.stdout or '').splitlines():
                    line = line.strip()
                    if line and '(' in line and ':' in line:
                        prov = line.split('(')[0].strip()
                        if prov and len(prov) <= 60:
                            providers.append(prov)
            except (OSError, subprocess.SubprocessError):
                pass

    if agent_id == 'hermes':
        cfg_path = Path('~/.hermes/config.yaml').expanduser()
        if cfg_path.is_file():
            try:
                try:
                    import yaml
                    data = yaml.safe_load(cfg_path.read_text(encoding='utf-8')) or {}
                except Exception:
                    data = {}
                if isinstance(data, dict):
                    model_section = data.get('model') or {}
                    if isinstance(model_section, dict):
                        def_prov = model_section.get('provider')
                        if def_prov and isinstance(def_prov, str):
                            providers.append(def_prov.strip())
                        aliases = model_section.get('aliases') or {}
                        if isinstance(aliases, dict):
                            for alias in aliases.keys():
                                if isinstance(alias, str) and alias.strip():
                                    providers.append(alias.strip())
            except Exception:
                pass

    providers.extend(source.get('static') or [])

    seen = []
    for value in providers:
        if value and value not in seen:
            seen.append(value)
    seen = seen[:MAX_PROVIDERS]
    if seen:
        try:
            ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
            payload = cache if isinstance(cache, dict) else {}
            payload[agent_id] = {'at': now, 'providers': seen}
            target_p = _providers_cache_path()
            temporary = target_p.with_name(f".{target_p.name}.{os.getpid()}.{threading.get_ident()}.{time.time_ns()}.tmp")
            temporary.write_text(json.dumps(payload), encoding='utf-8')
            os.chmod(temporary, 0o600)
            temporary.replace(target_p)
        except OSError:
            pass
    return seen


def load_config(agent_id):
    """Per-agent settings; only keys this CLI really supports survive."""
    spec = _agent(agent_id)
    config = {'model': '', 'effort': '', 'reasoning': '', 'provider': '', 'mode': '',
              'session': '', 'timeout': DEFAULT_TIMEOUT}
    path = agent_root(agent_id) / 'config.json'
    try:
        stored = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        stored = {}
    if isinstance(stored, dict):
        for key, value in stored.items():
            if key in config and isinstance(value, (str, int)):
                config[key] = value
    for key, setting in spec['settings'].items():
        if setting is None:
            config[key] = ''
    return config


REASONING_INCOMPATIBLE_PROVIDERS = frozenset({'river', 'river-glm'})


def save_config(agent_id, patch):
    """Validate and persist a settings change. Credentials never live here."""
    spec = _agent(agent_id)
    if not isinstance(patch, dict):
        raise AgentError('Settings must be an object.')
    unknown = set(patch) - {'model', 'effort', 'reasoning', 'provider', 'mode', 'session', 'timeout'}
    if unknown:
        raise AgentError('Unknown setting(s): ' + ', '.join(sorted(unknown)))
    config = load_config(agent_id)
    for key, value in patch.items():
        if key == 'timeout':
            if type(value) is not int or not 30 <= value <= 7200:
                raise AgentError('The timeout must be between 30 and 7200 seconds.')
            config['timeout'] = value
            continue
        value = '' if value is None else str(value).strip()
        if len(value) > 200 or any(ord(ch) < 32 for ch in value):
            raise AgentError(f'Invalid {key} value.')
        setting = spec['settings'].get(key)
        if setting is None:
            raise AgentError(f'{spec["label"]} does not support {key}; refusing to store a setting it cannot apply.')
        # A model list can be dynamic (antigravity, opencode), so a choice setting
        # may have no static list at all; then anything sane is accepted.
        allowed = list(setting.get('choices') or [])
        if (setting['kind'] == 'choice' and value and allowed and value not in allowed
                and not setting.get('allow_custom')):
            raise AgentError(f'{key} must be one of: {", ".join(allowed)}.')
        config[key] = value
    if agent_id == 'hermes':
        prov = str(config.get('provider') or '').strip().lower()
        if prov in REASONING_INCOMPATIBLE_PROVIDERS:
            requested_reasoning = str(patch.get('reasoning') or '').strip() if 'reasoning' in patch else ''
            if requested_reasoning:
                raise AgentError(
                    f"Provider '{config['provider']}' rejects reasoning_effort; leave reasoning empty."
                )
            config['reasoning'] = ''
    _ensure_dirs(agent_id)
    path = agent_root(agent_id) / 'config.json'
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.{time.time_ns()}.tmp")
    temporary.write_text(json.dumps(config, indent=2), encoding='utf-8')
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    return config


def setting_warnings(agent_id, config=None):
    """Advisory notes about a stored config; a warning never blocks a save.

    A free-text model id is accepted on purpose (custom providers exist), but a
    truncated one like "dee" persists invisibly and only shows up as a failed run
    minutes later. This says it out loud at save time.
    """
    spec = _agent(agent_id)
    config = config if isinstance(config, dict) else load_config(agent_id)
    notes = []

    model = str(config.get('model') or '').strip()
    if model and spec['settings'].get('model') is not None:
        try:
            known = list_models(agent_id, provider=config.get('provider'))
        except Exception:
            known = []
        if known and model not in known:
            notes.append(
                f"Model '{model}' nie występuje na liście {spec['label']} — "
                f"uruchomienie może się nie udać (sprawdź nazwę)."
            )

    if agent_id == 'hermes':
        prov = str(config.get('provider') or '').strip().lower()
        if prov in REASONING_INCOMPATIBLE_PROVIDERS and str(config.get('reasoning') or '').strip():
            notes.append(f"Provider '{prov}' odrzuca pole reasoning — wyczyść je.")

    return notes


def build_argv(agent_id, prompt, config=None):
    """The agent command, with only the flags this CLI accepts."""
    spec = _agent(agent_id)
    config = config or load_config(agent_id)
    # Absolute path: the systemd PATH does not include ~/.local/bin, and the
    # sandboxed process inherits that same minimal environment.
    binary = _which(spec['binary']) or spec['binary']
    argv = [binary, *spec['prompt_args'], str(prompt)]
    prov = str(config.get('provider') or '').strip().lower() if agent_id == 'hermes' else ''
    for key, setting in spec['settings'].items():
        if setting is None:
            continue
        if key == 'reasoning' and prov in REASONING_INCOMPATIBLE_PROVIDERS:
            continue
        value = str(config.get(key) or '').strip()
        if value:
            argv.extend([setting['flag'], value])
    session = str(config.get('session') or '').strip()
    if session:
        argv.extend([spec['session']['flag'], session])
    argv.extend(spec.get('extra_args') or [])
    return argv


SENSITIVE_PATHS = (
    '~/.ssh',
    '~/.gnupg',
    '~/.aws',
    '~/.kube',
    '~/.docker',
    '~/.config/gh',
    '~/.pki',
    '~/.local/share/keyrings',
    '~/.netrc',
    '~/.git-credentials',
    '~/.pypirc',
    '~/.jarvis-tools',
)

PROTECTED_STATE_PATHS = {
    'claude': (
        '~/.claude/settings.json',
        '~/.claude/settings.local.json',
        '~/.claude/hooks',
        '~/.claude/CLAUDE.md',
    ),
    'hermes': (
        '~/.hermes/.env',
        '~/.hermes/config.yaml',
        '~/.hermes/tools',
    ),
    'opencode': (
        '~/.config/opencode/opencode.json',
        '~/.config/opencode/config.json',
    ),
    'antigravity': (
        '~/.gemini/antigravity-cli/settings.json',
    ),
}


def _is_ancestor(parent, child):
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _empty_mask_file():
    """Return a 0-byte regular file path so --ro-bind works on MS_NODEV userns mounts."""
    empty = ROOT / '.empty'
    try:
        ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not empty.is_file() or empty.stat().st_size != 0:
            empty.write_bytes(b'')
        os.chmod(empty, 0o444)
        return str(empty)
    except OSError:
        return '/dev/null'


def _state_paths(agent_id):
    spec = _agent(agent_id)
    return [Path(raw).expanduser() for raw in (spec.get('state_paths') or [])
            if Path(raw).expanduser().exists()]


def _protected_state_paths(agent_id):
    _agent(agent_id)
    paths = []
    for raw in PROTECTED_STATE_PATHS.get(agent_id, ()):
        candidate = Path(raw).expanduser()
        if candidate.exists():
            paths.append(candidate)
    return paths


def _masked_paths(agent_id):
    own_state = {p.resolve() for p in _state_paths(agent_id)}
    raw_candidates = [str(ROOT), *SENSITIVE_PATHS]
    for other_id, other_spec in sorted(AGENTS.items()):
        if other_id == agent_id:
            continue
        for raw in (other_spec.get('state_paths') or []):
            # Keep ~/.hermes/tools (shared Python/Node runtimes) readable for other
            # agents while masking every credential, config, and session entry in ~/.hermes.
            expanded = Path(raw).expanduser()
            if other_id == 'hermes' and raw == '~/.hermes' and expanded.is_dir():
                if (expanded / 'tools').exists():
                    try:
                        for child in sorted(expanded.iterdir()):
                            if child.name != 'tools':
                                raw_candidates.append(str(child))
                        continue
                    except OSError:
                        pass
            raw_candidates.append(raw)

    masked = []
    seen = set()
    for raw in raw_candidates:
        candidate = Path(raw).expanduser()
        if not candidate.exists():
            continue
        resolved = candidate.resolve()
        if resolved in own_state or resolved in seen:
            continue
        seen.add(resolved)
        masked.append(resolved)

    masked_dirs = [p for p in masked if p.is_dir()]
    return [
        p for p in masked
        if not any(d != p and _is_ancestor(d, p) for d in masked_dirs)
    ]


def projects_root():
    return ROOT.parent / 'projects'


def sandbox_argv(agent_id, inner_argv, cwd=None, network=True, extra_rw_paths=None, extra_ro_paths=None):
    """Wrap the command so the whole filesystem except the agent's own is read-only.

    Sensitive host credentials ($HOME/.ssh, .gnupg, .aws, keyrings, Jarvis state)
    and sibling agents' CLI directories are masked with empty read-only mounts.
    Inside the agent's own CLI state directory, config and hook files are remounted
    read-only so a run cannot alter its own permissions or credentials.
    Optional extra_rw_paths must reside under projects_root() for team rooms.
    """
    if not shutil.which('bwrap'):
        raise AgentError('bubblewrap (bwrap) is required to confine an agent and is not installed.')
    argv = ['bwrap', '--ro-bind', '/', '/', '--tmpfs', '/tmp', '--dev', '/dev', '--proc', '/proc',
            '--unshare-ipc', '--die-with-parent']
    if not network:
        argv.append('--unshare-net')

    ws = workspace(agent_id)
    out = outbox_path(agent_id)
    work = Path(cwd or agent_root(agent_id)).expanduser().resolve()

    proj_base = projects_root()
    extra_rw = []
    for raw_path in (extra_rw_paths or ()):
        candidate = Path(raw_path).expanduser().resolve()
        if not candidate.exists():
            raise AgentError(f'Shared project path does not exist: {candidate}')
        if not _is_ancestor(proj_base, candidate) or candidate == proj_base.resolve():
            raise AgentError(f'Refusing writable mount outside projects_root: {candidate}')
        extra_rw.append(candidate)

    extra_ro = []
    for raw_path in (extra_ro_paths or ()):
        candidate = Path(raw_path).expanduser().resolve()
        if candidate.exists():
            extra_ro.append(candidate)

    targets = (ws, out, work, *extra_rw, *extra_ro)
    empty_file = _empty_mask_file()

    deferred_ancestors = []
    for masked in _masked_paths(agent_id):
        if masked.is_dir():
            if any(_is_ancestor(masked, target) for target in targets):
                deferred_ancestors.append(masked)
            else:
                argv.extend(['--tmpfs', str(masked), '--remount-ro', str(masked)])
        elif masked.is_file():
            argv.extend(['--ro-bind', empty_file, str(masked)])

    for anc in deferred_ancestors:
        argv.extend(['--tmpfs', str(anc)])
    for path in (ws, out, *extra_rw):
        argv.extend(['--bind', str(path), str(path)])
    for path in extra_ro:
        argv.extend(['--ro-bind', str(path), str(path)])
    for anc in deferred_ancestors:
        argv.extend(['--remount-ro', str(anc)])

    for path in _state_paths(agent_id):
        argv.extend(['--bind', str(path), str(path)])
    for path in _protected_state_paths(agent_id):
        argv.extend(['--ro-bind', str(path), str(path)])

    argv.extend(['--chdir', str(work), '--'])
    argv.extend(inner_argv)
    return argv


def _env(agent_id, extra_env=None):
    """A minimal environment; credentials are injected by name, never logged."""
    spec = _agent(agent_id)
    env = {'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'),
           'HOME': str(Path.home()), 'LANG': os.environ.get('LANG', 'C.UTF-8'),
           'TERM': 'dumb', 'NO_COLOR': '1'}
    # The service PATH omits the per-user bin directories, so add every place an
    # agent CLI was actually found.
    extra = [str(p) for p in (Path(raw).expanduser() for raw in SEARCH_DIRS) if p.is_dir()]
    if isinstance(extra_env, dict) and extra_env.get('JARVIS_TEAM_BIN'):
        extra.insert(0, str(extra_env['JARVIS_TEAM_BIN']))
    env['PATH'] = ':'.join([*extra[:1], env['PATH'], *extra[1:]]) if (
        isinstance(extra_env, dict) and extra_env.get('JARVIS_TEAM_BIN')
    ) else ':'.join([env['PATH'], *extra])
    for variable, credential in (spec.get('env_credentials') or {}).items():
        if not credential:
            continue
        try:
            from operator_tools import SecretStore
            item = SecretStore().get(credential)
        except Exception:
            continue
        value = str(item.get('value') or '')
        if value:
            env[variable] = value
    if isinstance(extra_env, dict):
        for key, val in extra_env.items():
            if isinstance(key, str) and key.startswith('JARVIS_TEAM_') and val is not None:
                env[key] = str(val)
    return env


def _prompt(agent_id, task):
    """The task plus the non-negotiable working rules."""
    return (
        f"{task.strip()}\n\n"
        f"--- ZASADY PRACY (obowiązkowe) ---\n"
        f"1. Cały komputer jest dla Ciebie tylko do odczytu. Zapis poza Twoim folderem "
        f"kończy się błędem 'Read-only file system' — nie próbuj go obchodzić.\n"
        f"2. Twoje miejsce pracy: {workspace(agent_id)}\n"
        f"3. Gotowy kod, poprawki i pliki odkładasz w: {outbox_path(agent_id)}\n"
        f"4. Potrzebne pliki źródłowe kopiujesz do swojego workspace i pracujesz na kopiach.\n"
        f"5. Nie modyfikuj plików spoza swoich dwóch katalogów, nawet jeśli masz uprawnienia.\n"
        f"6. W outbox/outbox.md napisz krótko: co zrobiłeś, jakie pliki zmieniłeś i czego "
        f"nie udało się sprawdzić. Jarvis to przeczyta i wdroży zmiany.\n"
        f"7. Na początku każdego większego etapu wypisz krótką linię `[STAGE] <opis etapu>`, "
        f"aby właściciel widział na żywo postęp Twojej pracy w panelu Jarvisa.\n"
    )


def _runs_file(agent_id):
    return agent_root(agent_id) / 'runs.json'


def _record_run(agent_id, record):
    """Upsert by run id: a run appears once, first as running and then as finished."""
    _ensure_dirs(agent_id)
    path = _runs_file(agent_id)
    with _RUNS_LOCK:
        try:
            rows = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            rows = []
        if not isinstance(rows, list):
            rows = []
        rows = [row for row in rows if not (isinstance(row, dict) and row.get('id') == record.get('id'))]
        rows.append(record)
        rows = rows[-MAX_RUNS_KEPT:]
        temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.{time.time_ns()}.tmp")
        try:
            temporary.write_text(json.dumps(rows, indent=2), encoding='utf-8')
            os.chmod(temporary, 0o600)
            temporary.replace(path)
        finally:
            try:
                if temporary.exists():
                    temporary.unlink()
            except OSError:
                pass


def runs(agent_id):
    _agent(agent_id)
    with _RUNS_LOCK:
        try:
            rows = json.loads(_runs_file(agent_id).read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return []
    return rows if isinstance(rows, list) else []


def _spawn(argv, cwd, env, log_path):
    """Launch the sandbox from one long-lived thread (see ``_call_in_spawn_thread``).

    ``bwrap --die-with-parent`` asks the kernel to SIGKILL the sandbox root when
    the thread that forked it exits. Team waves and HTTP handlers launch agents
    from short-lived threads, so a direct ``Popen`` there killed the wrapper
    after ~1 s while the inner CLI kept running detached: the run was reported
    ``failed`` (exit -9, empty log) and the work continued unseen. A dedicated
    spawner thread lives as long as the process, so --die-with-parent keeps its
    original meaning: the sandbox dies with Jarvis, not with the caller.
    """
    def _launch():
        log = open(log_path, 'wb')
        try:
            process = subprocess.Popen(argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        except OSError as error:
            log.close()
            raise AgentError(f'The agent could not be started ({type(error).__name__}).') from None
        return process, log

    def _abandon_sandbox(value):
        """After a caller timeout nobody watches the sandbox: kill and close it."""
        if isinstance(value, tuple) and len(value) == 2:
            process, log = value
            try:
                _kill(process)
                process.wait(timeout=15)
            except Exception:
                pass
            try:
                log.close()
            except OSError:
                pass

    return _call_in_spawn_thread(_launch, on_abandoned=_abandon_sandbox)


class _SpawnJob:
    """One queued ``Popen`` for the spawner thread."""

    __slots__ = ('done', 'value', 'error', 'abandoned', 'on_abandoned', 'lock')
    done: threading.Event
    value: Any
    error: BaseException | None

    def __init__(self):
        self.done = threading.Event()
        self.value = None
        self.error = None
        self.abandoned = False
        self.on_abandoned = None
        self.lock = threading.Lock()


def _spawn_worker():
    """Serve the spawn queue forever; this thread is the parent of every sandbox."""
    while True:
        item = _SPAWN_QUEUE.get()
        if item is None:
            return
        fn, job = item
        value = None
        try:
            value = fn()
        except BaseException as error:  # noqa: BLE001 - re-raised in the caller
            job.error = error
        cleanup_value = None
        run_cleanup = False
        with job.lock:
            if job.abandoned:
                # The caller timed out and left: without this, the spawned
                # sandbox keeps running with no watcher (no timeout kill, no
                # final run record) and its log fd never closes.
                if job.error is None:
                    cleanup_value = value
                    run_cleanup = callable(job.on_abandoned)
                job.value = None
                job.error = None
            else:
                job.value = value
            job.done.set()
        if run_cleanup:
            try:
                job.on_abandoned(cleanup_value)
            except Exception:
                pass


def _spawn_thread():
    with _SPAWN_LOCK:
        thread = _SPAWN_THREAD.get('thread')
        if isinstance(thread, threading.Thread) and thread.is_alive():
            return thread
        thread = threading.Thread(target=_spawn_worker, name='jarvis-agent-spawner', daemon=True)
        _SPAWN_THREAD['thread'] = thread
        thread.start()
        return thread


def _call_in_spawn_thread(fn, timeout=60, on_abandoned=None):
    _spawn_thread()
    job = _SpawnJob()
    job.on_abandoned = on_abandoned
    _SPAWN_QUEUE.put((fn, job))
    if not job.done.wait(timeout):
        with job.lock:
            arrived = job.done.is_set()
            if not arrived:
                job.abandoned = True
        if not arrived:
            raise AgentError('The agent could not be started (the spawner thread did not answer).')
    if job.error is not None:
        raise job.error
    return job.value


def _proc_started_at(pid):
    """Wall-clock start time of *pid* from /proc, or None when it is gone."""
    try:
        raw = Path(f'/proc/{pid}/stat').read_text(encoding='utf-8', errors='replace')
        ticks = float(raw[raw.rindex(')') + 2:].split()[19])
        uptime = float(Path('/proc/uptime').read_text(encoding='utf-8').split()[0])
        per_second = float(os.sysconf('SC_CLK_TCK') or 100)
    except (OSError, ValueError, IndexError):
        return None
    return time.time() - max(0.0, uptime - ticks / per_second)


def _reap_orphaned_session(sid, started_at=None):
    """Kill what is left of a run whose sandbox wrapper died on a signal.

    ``bwrap`` is the session leader (``start_new_session``), so its children keep
    the session id after the wrapper is gone. Only processes that started with
    the run are signalled, which makes a recycled id harmless.
    """
    try:
        sid = int(sid)
    except (TypeError, ValueError):
        return []
    if sid <= 1 or sid == os.getsid(0):
        return []
    survivors = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == os.getpid():
            continue
        try:
            raw = (entry / 'stat').read_text(encoding='utf-8', errors='replace')
            if int(raw[raw.rindex(')') + 2:].split()[3]) != sid:
                continue
        except (OSError, ValueError, IndexError):
            continue
        began = _proc_started_at(pid)
        if started_at and began is not None and began < float(started_at) - 1.0:
            continue
        survivors.append(pid)
    if not survivors:
        return []
    for pid in survivors:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.monotonic() + 2.0
    remaining = list(survivors)
    while remaining and time.monotonic() < deadline:
        time.sleep(0.1)
        remaining = [pid for pid in remaining if _pid_alive(pid)]
    for pid in remaining:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    return survivors


_ACTIVE_RUNS = {}
_ACTIVE_RUNS_LOCK = threading.Lock()
_RUNS_LOCK = threading.Lock()
_SPAWN_QUEUE = queue.Queue()
_SPAWN_LOCK = threading.Lock()
_SPAWN_THREAD = {}


def _pid_alive(pid):
    if not isinstance(pid, int) or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _check_running(agent_id):
    """Return (is_running, current_dict), reaping orphaned current.json if the PID died."""
    current_path = agent_root(agent_id) / 'current.json'
    try:
        current = json.loads(current_path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return False, {}
    if not isinstance(current, dict) or not current:
        try:
            current_path.unlink()
        except OSError:
            pass
        return False, {}

    with _ACTIVE_RUNS_LOCK:
        in_process_run = _ACTIVE_RUNS.get(agent_id)
    if in_process_run and (not current.get('run_id') or current.get('run_id') == in_process_run):
        return True, current

    if _pid_alive(current.get('pid')):
        return True, current

    try:
        current_path.unlink()
    except OSError:
        pass
    stale_id = current.get('run_id')
    if stale_id:
        for row in runs(agent_id):
            if isinstance(row, dict) and row.get('id') == stale_id and row.get('status') == 'running':
                started = row.get('started_at') or current.get('started_at')
                elapsed = round(max(0.0, time.time() - float(started)), 1) if started else None
                _record_run(agent_id, dict(row, status='failed', seconds=elapsed))
                break
    return False, {}


def _acquire_lock_fd(agent_id):
    _ensure_dirs(agent_id)
    fd = os.open(agent_root(agent_id) / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise AgentError(f'{AGENTS[agent_id]["label"]} is already running a task.') from None
    except Exception:
        os.close(fd)
        raise
    is_alive, cur = _check_running(agent_id)
    if is_alive:
        os.close(fd)
        raise AgentError(f'{AGENTS[agent_id]["label"]} is already running a task ({cur.get("run_id") or cur.get("pid")}).')
    return fd


def _archive_previous_outbox(agent_id):
    """Archive leftover files from outbox/ before a new run so artifacts and telemetry never mix."""
    out_dir = outbox_path(agent_id)
    if not out_dir.is_dir():
        return None
    try:
        entries = list(out_dir.iterdir())
    except OSError:
        return None
    if not entries:
        return None

    prev_runs = runs(agent_id)
    prev_id = (
        str(prev_runs[-1].get('id'))
        if prev_runs and isinstance(prev_runs[-1], dict) and prev_runs[-1].get('id')
        else time.strftime('%Y%m%d-%H%M%S')
    )
    archive_base = agent_root(agent_id) / 'runs' / 'outbox-archive'
    archive_dir = archive_base / prev_id
    if archive_dir.exists():
        archive_dir = archive_base / f'{prev_id}-{uuid.uuid4().hex[:4]}'
    try:
        archive_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        for item in entries:
            shutil.move(str(item), str(archive_dir / item.name))
        archives = sorted(
            [p for p in archive_base.iterdir() if p.is_dir()],
            key=lambda p: p.stat().st_mtime,
        )
        for old in archives[:-MAX_RUNS_KEPT]:
            shutil.rmtree(old, ignore_errors=True)
    except OSError:
        return None
    return archive_dir


def run(agent_id, task, approved=False, timeout=None, consent='unknown',
        cwd=None, extra_rw_paths=None, extra_ro_paths=None, extra_env=None,
        raw_prompt=False, archive_outbox=True, task_label=None):
    """Start one agent task in the read-only sandbox. Requires explicit approval."""
    spec = _agent(agent_id)
    if approved is not True:
        raise AgentError('An agent run needs explicit approval; nothing was started.')
    if not binary_present(agent_id):
        raise AgentError(f'{spec["label"]} is not installed ({spec["binary"]} not on PATH).')
    if not isinstance(task, str) or not task.strip():
        raise AgentError('A task is required.')
    max_len = MAX_TASK * 4 if raw_prompt else MAX_TASK
    if len(task) > max_len:
        raise AgentError(f'The task is longer than {max_len} characters.')
    config = load_config(agent_id)
    limit = int(timeout or config.get('timeout') or DEFAULT_TIMEOUT)
    limit = max(30, min(limit, 7200))
    lock_fd = _acquire_lock_fd(agent_id)
    try:
        _ensure_dirs(agent_id)
        run_id = time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
        log_path = agent_root(agent_id) / 'runs' / f'{run_id}.log'
        if archive_outbox:
            _archive_previous_outbox(agent_id)
        brief_label = str(task_label or task).strip()
        _write_task_brief(agent_id, run_id, brief_label)
        work_dir = Path(cwd).expanduser().resolve() if cwd else workspace(agent_id)
        prompt_text = task if raw_prompt else _prompt(agent_id, task)
        argv = sandbox_argv(
            agent_id,
            build_argv(agent_id, prompt_text, config),
            cwd=work_dir,
            extra_rw_paths=extra_rw_paths,
            extra_ro_paths=extra_ro_paths,
        )
        started = time.time()
        process, log = _spawn(argv, work_dir, _env(agent_id, extra_env=extra_env), log_path)
        with _ACTIVE_RUNS_LOCK:
            _ACTIVE_RUNS[agent_id] = run_id
        record = {'id': run_id, 'agent': agent_id, 'task': brief_label[:200],
                  'status': 'running', 'started_at': started, 'pid': process.pid,
                  'consent': str(consent or 'unknown')[:20],
                  'log': str(log_path), 'exit_code': None, 'seconds': None}
        _record_run(agent_id, record)
        try:
            (agent_root(agent_id) / 'current.json').write_text(
                json.dumps({'pid': process.pid, 'run_id': run_id, 'started_at': started, 'task': record['task']}),
                encoding='utf-8')
        except OSError:
            pass
        timed_out = False
        try:
            process.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill(process)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                pass
        finally:
            if isinstance(process.returncode, int) and process.returncode < 0:
                _reap_orphaned_session(process.pid, started)
            log.close()
            try:
                (agent_root(agent_id) / 'current.json').unlink()
            except OSError:
                pass
            with _ACTIVE_RUNS_LOCK:
                if _ACTIVE_RUNS.get(agent_id) == run_id:
                    _ACTIVE_RUNS.pop(agent_id, None)
        record = _finalize_finished_run(
            agent_id, run_id, started, log_path, process.returncode, timed_out, record
        )
        return {'ok': record['status'] == 'done', **record,
                'outbox': outbox(agent_id), 'log_tail': tail(agent_id, run_id)}
    finally:
        os.close(lock_fd)


def _kill(process):
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        try:
            process.terminate()
        except Exception:
            pass


def _trim_log(path):
    try:
        if path.stat().st_size > MAX_LOG_BYTES:
            data = path.read_bytes()[-MAX_LOG_BYTES:]
            path.write_bytes(b'[log trimmed]\n' + data)
    except OSError:
        pass


def stop(agent_id):
    _agent(agent_id)
    current = agent_root(agent_id) / 'current.json'
    try:
        info = json.loads(current.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {'ok': True, 'stopped': False, 'note': 'No run is active.'}
    pid = info.get('pid')
    if not isinstance(pid, int):
        try:
            current.unlink()
        except OSError:
            pass
        return {'ok': False, 'stopped': False, 'error': 'The running pid could not be read.'}
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except ProcessLookupError:
        _check_running(agent_id)
        return {'ok': True, 'stopped': False, 'note': 'That process already exited.'}
    except PermissionError:
        return {'ok': False, 'stopped': False, 'error': 'Permission denied when signalling the process.'}
    return {'ok': True, 'stopped': True, 'run_id': info.get('run_id')}


def tail(agent_id, run_id=None):
    """Bounded tail of the newest (or named) run log."""
    _agent(agent_id)
    directory = agent_root(agent_id) / 'runs'
    if run_id:
        path = directory / f'{run_id}.log'
    else:
        try:
            path = max(directory.glob('*.log'), key=lambda item: item.stat().st_mtime)
        except ValueError:
            return ''
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''
    return text[-4000:]


def outbox(agent_id):
    """What the agent produced; Jarvis analyses and applies it, never the agent."""
    directory = outbox_path(agent_id)
    if not directory.is_dir():
        return []
    rows = []
    for path in sorted(directory.rglob('*')):
        if len(rows) >= MAX_OUTBOX_ENTRIES:
            break
        try:
            if not path.is_file():
                continue
            info = path.stat()
        except OSError:
            continue
        rows.append({'path': str(path.relative_to(directory)),
                     'bytes': info.st_size,
                     'modified': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(info.st_mtime))})
    return rows



# --- Live Stage Telemetry & Async Background Agent Orchestration ---
_STAGE_FILE_RE = re.compile(
    r"(?:Creating|Writing|Updated|Saved|Modified|Wrote|Zapisano|Tworzenie|Plik:?|-->|\b)\s*"
    r"([A-Za-z0-9_./-]+\.(?:html|css|js|ts|tsx|jsx|py|json|md|svg|sh))\b",
    re.I,
)
_PROMPT_STALL_RE = re.compile(
    r"(?:\[y/n\]|\(y/n\)|continue\?|proceed\?|press enter|podaj |wybierz |czy chcesz )",
    re.I,
)
_LOG_ERROR_RULES = (
    (
        "quota_exceeded",
        re.compile(
            r"(?:\b429\b|too many requests|rate[-_ ]limit|quota[-_ ]exceeded|"
            r"insufficient_quota|resource_exhausted|credit balance is too low)",
            re.I,
        ),
        "Przekroczono limit zapytań lub kwotę API (429) — przełącz model/providera lub odczekaj.",
    ),
    (
        "auth_failed",
        re.compile(
            r"(?:\b401\b|\b403\b\s*(?:forbidden|unauthorized)|unauthorized|"
            r"invalid[_ -]?api[_ -]?key|authentication[_ -]?error|invalid x-api-key|"
            r"missing api key|not logged in|login required)",
            re.I,
        ),
        "Błąd uwierzytelniania API (401/403) — sprawdź klucz w SecretStore lub logowanie CLI.",
    ),
    (
        "model_rejected",
        re.compile(
            r"(?:model_not_found|unrecognized_model|unknown model|unsupported model|invalid model|"
            r"model [`'\"]?[\w./:-]+[`'\"]? does not exist|"
            r"reasoning_effort[^\n]{0,60}(?:not supported|rejected|invalid|unknown))",
            re.I,
        ),
        "Dostawca odrzucił wskazany model lub parametr reasoning — wybierz wspierany model.",
    ),
    (
        "sandbox_readonly",
        re.compile(r"(?:read-only file system|\berofs\b)", re.I),
        "Agent próbował zapisać plik poza workspace/ i outbox/ (zablokowane przez bwrap EROFS).",
    ),
)


def classify_log_error(log_text):
    """Classify known API/CLI failure causes from run output; returns (kind, hint)."""
    if not isinstance(log_text, str) or not log_text.strip():
        return "", ""
    for kind, pattern, hint in _LOG_ERROR_RULES:
        if pattern.search(log_text):
            return kind, hint
    return "", ""


def _write_task_brief(agent_id, run_id, task, target_hint=""):
    """Write a structured TASK_BRIEF.md inside the agent workspace before launch."""
    ws = workspace(agent_id)
    out = outbox_path(agent_id)
    brief_path = ws / "TASK_BRIEF.md"
    lines = [
        f"# TASK BRIEF — {run_id}",
        "",
        "## Cel zadania",
        task.strip(),
        "",
        "## Kontrakt współpracy z Jarvisem",
        f"- Katalog roboczy (workspace): `{ws}`",
        f"- Katalog wynikowy (outbox): `{out}`",
        "- Zapisuj gotowe pliki wynikowe bezpośrednio w `outbox/` (zachowując podkatalogi projektu).",
        "- W trakcie pracy wypisuj krótkie znaczniki postępu na stdout, np.:",
        "  `[STAGE] Analiza wymagań i architektury`",
        "  `[STAGE] Budowanie struktury i komponentów`",
        "  `[STAGE] Stylowanie i testy`",
        "  `[STAGE] Podsumowanie w outbox/outbox.md`",
        "- Nie zadawaj pytań interaktywnych (stdin jest zamknięty) — podejmuj rozsądne decyzje techniczne i opisz je w `outbox/outbox.md`.",
    ]
    if target_hint:
        lines.insert(5, f"- Docelowy katalog wdrożenia (tylko do odczytu dla Ciebie): `{target_hint}`")
        try:
            import code_index
            ctx_block = code_index.build_context_pack(task, root_dir=target_hint, limit=5)
            if ctx_block:
                lines.extend(["", ctx_block])
        except Exception:
            pass
    try:
        brief_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        pass
    return brief_path


def live_progress(agent_id, run_id=None):
    """Compute live 5-stage progress, detected files, and stall warnings for an agent."""
    _agent(agent_id)
    root = agent_root(agent_id)
    is_running, current = _check_running(agent_id)

    all_runs = runs(agent_id)
    target_id = run_id or current.get("run_id") or (all_runs[-1]["id"] if all_runs else None)
    record = next((r for r in reversed(all_runs) if r.get("id") == target_id), {}) if target_id else {}
    if run_id and current.get("run_id") and run_id != current.get("run_id"):
        is_running = False

    log_text = tail(agent_id, target_id) if target_id else ""
    out_files = outbox(agent_id)
    started_at = (
        current.get("started_at")
        if (is_running and current.get("run_id") == target_id)
        else (record.get("started_at") or current.get("started_at"))
    )
    elapsed = round(max(0.0, time.time() - float(started_at)), 1) if started_at and is_running else record.get("seconds")

    if started_at:
        cutoff = float(started_at) - 0.5
        out_dir = outbox_path(agent_id)
        fresh_out_files = []
        for f in out_files:
            try:
                if (out_dir / f["path"]).stat().st_mtime >= cutoff:
                    fresh_out_files.append(f)
            except OSError:
                pass
    elif target_id:
        fresh_out_files = out_files
    else:
        fresh_out_files = []

    log_path = root / "runs" / f"{target_id}.log" if target_id else None
    idle_seconds = 0.0
    if is_running and log_path and log_path.is_file():
        try:
            idle_seconds = round(max(0.0, time.time() - log_path.stat().st_mtime), 1)
        except OSError:
            idle_seconds = 0.0

    outbox_md_ready = any(f.get("path", "").endswith("outbox.md") for f in fresh_out_files)
    code_files = [f["path"] for f in fresh_out_files if not f.get("path", "").endswith("outbox.md")]
    mentioned = list(dict.fromkeys(_STAGE_FILE_RE.findall(log_text)))[-8:]

    explicit_stages = [
        m.group(1).strip()[:100]
        for m in re.finditer(r"\[STAGE\]\s*(.+)", log_text)
        if m.group(1).strip()
    ]
    non_empty_lines = [ln.strip() for ln in log_text.splitlines() if ln.strip()]
    last_line = non_empty_lines[-1][:160] if non_empty_lines else ""

    stalled = False
    stall_reason = ""
    if is_running:
        if last_line and _PROMPT_STALL_RE.search(last_line) and idle_seconds >= 15:
            stalled = True
            stall_reason = "Agent może oczekiwać na interaktywne potwierdzenie (stdin zamknięty)."
        elif idle_seconds >= 90:
            stalled = True
            stall_reason = f"Brak nowego wyjścia w logu od {int(idle_seconds)} s."

    run_status = "running" if is_running else (record.get("status") or "idle")
    done_ok = run_status == "done"
    failed = run_status in ("failed", "timeout")

    if done_ok or run_status == "idle":
        error_kind, error_hint = "", ""
    elif run_status == "timeout":
        error_kind = record.get("error_kind") or "timeout"
        error_hint = record.get("error_hint") or "Przekroczono limit czasu wykonania."
    else:
        error_kind = record.get("error_kind") or ""
        error_hint = record.get("error_hint") or ""
        if not error_kind:
            error_kind, error_hint = classify_log_error(log_text)

    p1_done = bool(target_id)
    p2_done = bool(target_id and (len(non_empty_lines) >= 3 or code_files or explicit_stages or done_ok))
    p3_done = bool(target_id and ((len(code_files) >= 1 and (outbox_md_ready or done_ok)) or done_ok))
    p4_done = bool(target_id and (outbox_md_ready or done_ok))
    p5_done = bool(target_id and done_ok)

    phases = [
        {"index": 1, "label": "Przygotowanie piaskownicy i TASK_BRIEF.md", "done": p1_done},
        {"index": 2, "label": "Analiza zadania i projektowanie struktury", "done": p2_done},
        {
            "index": 3,
            "label": f"Generowanie kodu i zasobów ({len(code_files)} plików w outbox)"
                     if code_files else "Generowanie kodu i zasobów",
            "done": p3_done,
        },
        {"index": 4, "label": "Raport końcowy w outbox/outbox.md", "done": p4_done},
        {"index": 5, "label": "Gotowe do przeglądu i wdrożenia przez Jarvisa", "done": p5_done},
    ]
    active_idx = next((p["index"] for p in phases if not p["done"]), 5)
    for p in phases:
        p["active"] = bool(is_running and p["index"] == active_idx)

    done_count = sum(1 for p in phases if p["done"])
    percent = 100 if done_ok else min(95, round((done_count / len(phases)) * 100 + (10 if is_running else 0)))
    if not target_id and not is_running:
        percent = 0

    current_stage_label = (
        explicit_stages[-1]
        if (is_running and explicit_stages)
        else (phases[active_idx - 1]["label"] if is_running else (
            "Zakończono pomyślnie" if done_ok else ("Przerwano / błąd" if failed else "Oczekuje na zadanie")
        ))
    )

    return {
        "agent": agent_id,
        "run_id": target_id,
        "running": is_running,
        "status": run_status,
        "task": record.get("task") or current.get("task") or "",
        "elapsed_seconds": elapsed,
        "idle_seconds": idle_seconds,
        "stalled": stalled,
        "stall_reason": stall_reason,
        "error_kind": error_kind,
        "error_hint": error_hint,
        "percent": percent,
        "stage": current_stage_label,
        "phases": phases,
        "outbox_count": len(fresh_out_files),
        "outbox_files": [f["path"] for f in fresh_out_files[:12]],
        "mentioned_files": mentioned,
        "last_line": last_line,
    }


def _finalize_finished_run(agent_id, run_id, started, log_path, returncode, timed_out, record):
    seconds = round(time.time() - started, 1)
    status = "timeout" if timed_out else ("done" if returncode == 0 else "failed")
    _trim_log(log_path)
    log_tail = tail(agent_id, run_id)
    if status == "done":
        error_kind, error_hint = "", ""
    elif timed_out:
        error_kind, error_hint = "timeout", f"Przekroczono limit czasu wykonania ({seconds} s)."
    else:
        error_kind, error_hint = classify_log_error(log_tail)
        if not error_kind and isinstance(returncode, int) and returncode < 0:
            # A negative return code means a signal, not an agent bug: an empty
            # log and -9 is a sandbox wrapper killed before it printed a byte.
            error_kind = "killed"
            error_hint = (f"Proces zakończony sygnałem {-returncode} po {seconds} s "
                          f"(brak wyjścia modelu); sprawdź, czy agent nie działa dalej jako sierota.")
    record.update(
        status=status,
        exit_code=returncode,
        seconds=seconds,
        error_kind=error_kind,
        error_hint=error_hint,
    )
    _record_run(agent_id, record)
    try:
        import agent_router
        agent_router.record_run_outcome(agent_id, record)
    except Exception:
        pass
    try:
        import agent_notes
        agent_notes.write_run_note(agent_id, record, log_tail)
    except Exception as error:
        print(f"[agents] note not written: {type(error).__name__}", file=sys.stderr, flush=True)
    try:
        from operator_modules import reminders
        reminders.notify_job_finished(
            job_id=run_id,
            job_name=f"agent:{agent_id} {record.get('task', '')}",
            status=record["status"],
        )
    except Exception:
        pass
    return record


def start_async(agent_id, task, approved=False, timeout=None, consent="unknown", target_hint="",
                cwd=None, extra_rw_paths=None, extra_ro_paths=None, extra_env=None,
                raw_prompt=False, archive_outbox=True, task_label=None, on_finish=None):
    """Start an external coding agent in the background without blocking Jarvis or the Operator queue."""
    spec = _agent(agent_id)
    if approved is not True:
        raise AgentError("An agent run needs explicit approval; nothing was started.")
    if not binary_present(agent_id):
        raise AgentError(f"{spec['label']} is not installed ({spec['binary']} not on PATH).")
    if not isinstance(task, str) or not task.strip():
        raise AgentError("A task is required.")
    max_len = MAX_TASK * 4 if raw_prompt else MAX_TASK
    if len(task) > max_len:
        raise AgentError(f"The task is longer than {max_len} characters.")

    lock_fd = _acquire_lock_fd(agent_id)
    try:
        config = load_config(agent_id)
        limit = max(30, min(int(timeout or config.get("timeout") or DEFAULT_TIMEOUT), 7200))
        _ensure_dirs(agent_id)
        run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        log_path = agent_root(agent_id) / "runs" / f"{run_id}.log"
        if archive_outbox:
            _archive_previous_outbox(agent_id)
        brief_label = str(task_label or task).strip()
        _write_task_brief(agent_id, run_id, brief_label, target_hint=target_hint)
        work_dir = Path(cwd).expanduser().resolve() if cwd else workspace(agent_id)
        prompt_text = task if raw_prompt else _prompt(agent_id, task)
        argv = sandbox_argv(
            agent_id,
            build_argv(agent_id, prompt_text, config),
            cwd=work_dir,
            extra_rw_paths=extra_rw_paths,
            extra_ro_paths=extra_ro_paths,
        )
        started = time.time()
        process, log = _spawn(argv, work_dir, _env(agent_id, extra_env=extra_env), log_path)
        with _ACTIVE_RUNS_LOCK:
            _ACTIVE_RUNS[agent_id] = run_id
    except Exception:
        os.close(lock_fd)
        raise

    record = {
        "id": run_id,
        "agent": agent_id,
        "task": brief_label[:200],
        "status": "running",
        "background": True,
        "started_at": started,
        "pid": process.pid,
        "consent": str(consent or "unknown")[:20],
        "log": str(log_path),
        "exit_code": None,
        "seconds": None,
    }
    try:
        _record_run(agent_id, record)
        try:
            (agent_root(agent_id) / "current.json").write_text(
                json.dumps({"pid": process.pid, "run_id": run_id, "started_at": started, "task": record["task"]}),
                encoding="utf-8",
            )
        except OSError:
            pass

        def _watch():
            final_rec = None
            try:
                timed_out = False
                try:
                    process.wait(timeout=limit)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _kill(process)
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        pass
                finally:
                    if isinstance(process.returncode, int) and process.returncode < 0:
                        _reap_orphaned_session(process.pid, started)
                    try:
                        log.close()
                    except OSError:
                        pass
                    try:
                        (agent_root(agent_id) / "current.json").unlink()
                    except OSError:
                        pass
                    with _ACTIVE_RUNS_LOCK:
                        if _ACTIVE_RUNS.get(agent_id) == run_id:
                            _ACTIVE_RUNS.pop(agent_id, None)
                final_rec = _finalize_finished_run(
                    agent_id, run_id, started, log_path, process.returncode, timed_out, record
                )
            finally:
                try:
                    os.close(lock_fd)
                except OSError:
                    pass
            if final_rec is not None and callable(on_finish):
                try:
                    on_finish(final_rec)
                except Exception as error:
                    # A silent failure here left a team project stuck in 'running'.
                    print(f'[agents] on_finish failed for {agent_id}/{run_id}: '
                          f'{type(error).__name__}: {error}', file=sys.stderr, flush=True)

        threading.Thread(target=_watch, name=f"jarvis-agent-{agent_id}-{run_id[-6:]}", daemon=True).start()
    except Exception:
        # The sandbox is already running but its watcher never started: a
        # leaked flock fd here left the agent "already running a task" until
        # Jarvis restarted, with an unwatched process and no timeout kill.
        _kill(process)
        try:
            process.wait(timeout=15)
        except Exception:
            pass
        try:
            log.close()
        except OSError:
            pass
        with _ACTIVE_RUNS_LOCK:
            if _ACTIVE_RUNS.get(agent_id) == run_id:
                _ACTIVE_RUNS.pop(agent_id, None)
        try:
            _finalize_finished_run(agent_id, run_id, started, log_path, process.returncode, True, record)
        except Exception:
            pass
        os.close(lock_fd)
        raise
    return {
        "ok": True,
        "background": True,
        "id": run_id,
        "agent": agent_id,
        "status": "running",
        "pid": process.pid,
        "started_at": started,
        "progress": live_progress(agent_id, run_id),
        "note": "Agent started in background; poll status/progress or outbox without blocking Jarvis.",
    }


def status(agent_id, refresh=False):
    spec = _agent(agent_id)
    _ensure_dirs(agent_id)
    progress = live_progress(agent_id)
    active = bool(progress.get('running'))
    rows = runs(agent_id)
    latest = rows[-1] if rows else {}
    try:
        import agent_notes
        note_count = len(agent_notes.notes(agent_id, 100))
    except Exception:
        note_count = 0
    choices = {key: list(value.get('choices') or [])
               for key, value in spec['settings'].items() if value}
    config = load_config(agent_id)
    models_by_provider = {}
    if 'provider' in spec['settings'] and spec['settings']['provider'] is not None:
        choices['provider'] = list_providers(agent_id, refresh=refresh)
        models_by_provider = list_models_by_provider(agent_id, refresh=refresh)
    choices['model'] = list_models(agent_id, provider=config.get('provider'), refresh=refresh)
    return {'id': agent_id, 'label': spec['label'], 'installed': binary_present(agent_id),
            'version': binary_version(agent_id, refresh=refresh), 'running': active,
            'settings': config,
            'supported': {key: (value is not None) for key, value in spec['settings'].items()},
            'choices': choices,
            'models_by_provider': models_by_provider,
            'allow_custom': {key: bool(value.get('allow_custom'))
                             for key, value in spec['settings'].items() if value},
            'hints': {key: value.get('hint') for key, value in spec['settings'].items()
                      if value and value.get('hint')},
            'notes': note_count, 'outbox': len(outbox(agent_id)),
            'progress': progress,
            'last_run': latest or None, 'notes_hint': spec['notes']}


def summary(refresh=False):
    return {'agents': [status(agent_id, refresh=refresh) for agent_id in agent_ids()],
            'sandbox': 'bwrap: whole filesystem read-only, only the agent folder and its CLI state writable'}
