"""Operator tool modules: a small, validated alternative to editing browser_agent.py.

A module is one ``*.py`` file in ``operator_modules/`` exposing::

    TOOL = {
        "name": "weather_now",
        "description": "Read the current weather.",
        "input_schema": {"type": "object", "properties": {}},
        "handler": weather_now,
        "approval": False,
    }

    def weather_now(arguments, context=None):
        return {"ok": True, "temperature": 18}

The handler receives the tool arguments and, if it declares it, a context dict.
Discovery is deterministic, errors are isolated and a module can never shadow a
built-in or another module.

``ToolRegistry.run`` completes every handler output to the standardized 5-key
envelope of ``PROJECT.md`` (``ok``/``success``/``data``/``result``/``error``).
The completion is additive: keys a legacy module already returns are never
renamed or removed, and a full-envelope module passes through untouched.
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_DIR = ROOT / "operator_modules"
STATE = Path.home() / ".jarvis-tools" / "operator-modules.json"
NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")
# The standardized operator envelope of PROJECT.md: a completion target, never
# a filter — legacy task keys always survive.
ENVELOPE_KEYS = ("ok", "success", "data", "result", "error")


def normalize_envelope(name: str, output) -> dict:
    """Complete a handler output to the standardized 5-key envelope.

    Additive only: keys already present are never renamed or removed, so a
    legacy dict (``{"ok": True, "temperature": 18}``) keeps its task keys and a
    full-envelope module (``op_*`` tier) passes through byte-identical.
    """
    if not isinstance(output, dict):
        return {"ok": True, "success": True, "data": output, "result": output, "error": None}
    out = dict(output)
    if "ok" not in out:
        # A dict without a status marker is a legacy payload; any failure
        # raises into ToolRegistryError, so reaching here means success.
        out["ok"] = True
    ok = bool(out.get("ok"))
    if "success" not in out:
        out["success"] = ok
    if "error" not in out:
        out["error"] = None if ok else f"unspecified error in module tool {name}"
    if "data" not in out and "result" not in out:
        payload = {key: value for key, value in out.items() if key not in ENVELOPE_KEYS}
        out["data"] = out["result"] = payload or None
    elif "data" not in out:
        out["data"] = out["result"]
    elif "result" not in out:
        out["result"] = out["data"]
    return out


class ToolRegistryError(Exception):
    pass


class ModuleTool:
    def __init__(self, name: str, description: str, schema: dict, handler, path: Path,
                 approval: bool = False):
        self.name = name
        self.description = description
        self.schema = schema
        self.handler = handler
        self.path = path
        self.approval = bool(approval)

    def declaration(self) -> dict:
        return {"name": self.name, "description": self.description[:1600],
                "input_schema": self.schema}

    def run(self, arguments: dict, context: dict | None = None):
        signature = inspect.signature(self.handler)
        parameters = signature.parameters
        if "context" in parameters:
            return self.handler(arguments or {}, context=context)
        if len(parameters) >= 2:
            return self.handler(arguments or {}, context)
        return self.handler(arguments or {})


class ToolRegistry:
    def __init__(self, directory: Path | None = None, state_path: Path | None = None):
        self.directory = Path(directory or DEFAULT_DIR)
        self.state_path = Path(state_path or STATE)
        self.tools: dict[str, ModuleTool] = {}
        self.errors: list[str] = []
        self.disabled: set[str] = set()
        self._load_state()
        self.reload()

    def _load_state(self) -> None:
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
            self.disabled = {str(item) for item in value.get("disabled", [])}
        except (OSError, ValueError, AttributeError):
            self.disabled = set()

    def _save_state(self) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.state_path.with_name(
                f".{self.state_path.name}-{os.getpid()}-{time.time_ns()}.tmp")
            temporary.write_text(json.dumps({"disabled": sorted(self.disabled)}, indent=2))
            temporary.chmod(0o600)
            temporary.replace(self.state_path)
        except OSError:
            pass

    def reload(self) -> int:
        self.tools.clear()
        self.errors.clear()
        self.directory.mkdir(parents=True, exist_ok=True)
        for path in sorted(self.directory.glob("*.py")):
            if path.name.startswith("_") or path.name == "__init__.py":
                continue
            try:
                module_name = f"jarvis_operator_module_{path.stem}_{abs(hash(str(path.resolve())))}"
                spec = importlib.util.spec_from_file_location(module_name, path)
                if not spec or not spec.loader:
                    raise ToolRegistryError("could not construct an import spec")
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
                self._add(module, path)
            except KeyboardInterrupt:
                raise
            except BaseException as error:
                self.errors.append(f"{path.name}: {type(error).__name__}: {error}")
        return len(self.tools)

    def _add(self, module, path: Path) -> None:
        tool = getattr(module, "TOOL", None)
        if not isinstance(tool, dict):
            raise ToolRegistryError("missing TOOL dict")
        name = tool.get("name")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise ToolRegistryError("TOOL['name'] is invalid")
        if name in self.tools:
            raise ToolRegistryError(f"name {name!r} collides with an existing module")
        description = tool.get("description")
        if not isinstance(description, str) or not description.strip():
            raise ToolRegistryError("TOOL['description'] is required")
        schema = tool.get("input_schema", {"type": "object", "properties": {}})
        if not isinstance(schema, dict) or schema.get("type") != "object":
            raise ToolRegistryError("TOOL['input_schema'] must be an object schema")
        handler = tool.get("handler")
        if not callable(handler):
            raise ToolRegistryError("TOOL['handler'] must be callable")
        self.tools[name] = ModuleTool(name, description.strip(), schema, handler, path,
                                      bool(tool.get("approval", False)))

    def has(self, name: str) -> bool:
        return name in self.tools

    def get(self, name: str) -> ModuleTool | None:
        return self.tools.get(name)

    def declarations(self, existing: set[str] | None = None) -> list[dict]:
        existing = existing or set()
        return [tool.declaration() for name, tool in self.tools.items()
                if name not in existing and name not in self.disabled]

    def approval_reason(self, name: str) -> str:
        tool = self.tools.get(name)
        return f"Module tool {name} asks for approval." if tool and tool.approval else ""

    def run(self, name: str, arguments: dict, context: dict | None = None):
        tool = self.tools.get(name)
        if tool is None:
            raise ToolRegistryError(f"No module tool named {name!r}.")
        if name in self.disabled:
            raise ToolRegistryError(f"Module tool {name!r} is disabled.")
        try:
            return normalize_envelope(name, tool.run(arguments, context))
        except ToolRegistryError:
            raise
        except KeyboardInterrupt:
            raise
        except BaseException as error:
            msg = f"{type(error).__name__}: {error}" if not str(error) or isinstance(error, SystemExit) else str(error)
            raise ToolRegistryError(f"Module tool {name} failed: {msg}") from None

    def set_enabled(self, name: str, enabled: bool) -> bool:
        if name not in self.tools:
            raise ToolRegistryError(f"No module tool named {name!r}.")
        if enabled:
            self.disabled.discard(name)
        else:
            self.disabled.add(name)
        self._save_state()
        return enabled

    def list(self) -> list[dict]:
        return [{"name": tool.name, "description": tool.description,
                 "path": str(tool.path), "approval": tool.approval,
                 "enabled": tool.name not in self.disabled}
                for tool in self.tools.values()]
