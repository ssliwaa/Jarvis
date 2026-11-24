"""Zero-dependency structural codebase mapper and AST symbol extractor.

Inspired by Aider and Continue: builds compact directory trees, extracts class/function
signatures using Python's built-in AST parser, computes symbol reference graphs and
call hierarchies, and packs token-budgeted repository maps within ALLOWED_ROOTS.
Exclusively uses the Python standard library.
"""

from __future__ import annotations

import ast
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional

# Security perimeter: Allowed root directories
HOME = Path.home().resolve()
ALLOWED_ROOTS: tuple[Path, ...] = (
    HOME,
    Path("/tmp").resolve(),
    Path("/mnt").resolve(),
    Path("/media").resolve(),
)

SENSITIVE_PARTS: frozenset[str] = frozenset({
    ".ssh",
    ".gnupg",
    ".password-store",
    ".hermes",
    ".aws",
    ".docker",
    ".kube",
})

SENSITIVE_NAMES: frozenset[str] = frozenset({
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".gitconfig",
    "config.json",
    "secrets.json",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    "shadow",
})

IGNORE_DIRS: frozenset[str] = frozenset({
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".eggs",
    "build",
    "dist",
    ".agents",
})

IGNORE_EXTENSIONS: frozenset[str] = frozenset({
    ".pyc",
    ".pyo",
    ".pyd",
    ".so",
    ".dll",
    ".dylib",
    ".exe",
    ".bin",
    ".zip",
    ".tar",
    ".gz",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".woff",
    ".woff2",
})

MAX_FILE_BYTES: int = 500 * 1024  # 500 KB limit per file to parse
MAX_FILES_SCANNED: int = 2000

VALID_ACTIONS: frozenset[str] = frozenset({
    "build_map",
    "build_repo_map",
    "find_symbol",
    "get_call_hierarchy",
    "map_tree",
    "extract_symbols",
    "find_references",
})


class RepoMapperError(Exception):
    """Base exception for repo_mapper operations."""


class PathSecurityError(RepoMapperError):
    """Raised when path traversal or forbidden boundary escape is detected."""


class SensitivePathError(RepoMapperError):
    """Raised when access to a sensitive credential path is attempted."""


def _envelope_success(data: Any) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator success envelope."""
    return {"ok": True, "success": True, "data": data, "result": data, "error": None}


def _envelope_error(err: str | Exception) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator error envelope."""
    msg = f"{type(err).__name__}: {err}" if isinstance(err, Exception) else str(err)
    return {"ok": False, "success": False, "data": None, "result": None, "error": msg}


def _is_inside_allowed_roots(path: Path) -> bool:
    """Verify that path resides strictly inside ALLOWED_ROOTS."""
    try:
        resolved = Path(os.path.realpath(str(path)))
        for root in ALLOWED_ROOTS:
            try:
                root_res = Path(os.path.realpath(str(root)))
                if resolved == root_res or resolved.is_relative_to(root_res):
                    return True
            except (OSError, RuntimeError, ValueError):
                continue
        return False
    except (OSError, RuntimeError, ValueError):
        return False


def _is_sensitive_path(path: Path) -> bool:
    """Check if any path component touches sensitive credential directories or files."""
    parts = [p.casefold() for p in path.parts]
    for part in parts:
        if part in SENSITIVE_PARTS:
            return True
        if part in SENSITIVE_NAMES:
            return True
    if path.name.casefold() in SENSITIVE_NAMES:
        return True
    return False


def _resolve_and_validate_path(path_str: str, must_exist: bool = True, is_dir: bool | None = None) -> Path:
    """Resolve and validate path against ALLOWED_ROOTS and sensitive filters."""
    if not isinstance(path_str, str) or not path_str.strip():
        raise ValueError("Path must be a non-empty string.")
    if "\0" in path_str:
        raise PathSecurityError("Null bytes are prohibited in file paths.")

    expanded = os.path.expanduser(path_str)
    resolved = Path(os.path.realpath(expanded))

    if not _is_inside_allowed_roots(resolved):
        raise PathSecurityError(f"Path '{path_str}' resolves outside ALLOWED_ROOTS.")

    if _is_sensitive_path(resolved):
        raise SensitivePathError(f"Access to sensitive path '{resolved}' is restricted.")

    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"Path not found: '{path_str}'")

    if resolved.exists():
        if is_dir is True and not resolved.is_dir():
            raise ValueError(f"Path '{path_str}' is not a directory.")
        if is_dir is False and not resolved.is_file():
            raise ValueError(f"Path '{path_str}' is not a regular file.")

    return resolved


class SymbolCollector(ast.NodeVisitor):
    """AST Visitor to extract symbols, signatures, docstrings, calls, and imports."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.classes: list[dict[str, Any]] = []
        self.functions: list[dict[str, Any]] = []
        self.imports: list[str] = []
        self.calls: list[str] = []
        self.current_class: Optional[str] = None
        self.call_hierarchy: dict[str, list[str]] = defaultdict(list)
        self.current_function: Optional[str] = None

    def _format_arg(self, arg: ast.arg) -> str:
        s = arg.arg
        if arg.annotation:
            try:
                s += f": {ast.unparse(arg.annotation)}"
            except Exception:
                pass
        return s

    def _format_signature(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        args_strs = []
        # Positional only
        for arg in getattr(node.args, "posonlyargs", []):
            args_strs.append(self._format_arg(arg))
        if getattr(node.args, "posonlyargs", []):
            args_strs.append("/")

        # Regular args
        defaults_offset = len(node.args.args) - len(node.args.defaults)
        for i, arg in enumerate(node.args.args):
            arg_str = self._format_arg(arg)
            default_idx = i - defaults_offset
            if default_idx >= 0:
                try:
                    arg_str += f"={ast.unparse(node.args.defaults[default_idx])}"
                except Exception:
                    arg_str += "=..."
            args_strs.append(arg_str)

        # Vararg *args
        if node.args.vararg:
            args_strs.append(f"*{self._format_arg(node.args.vararg)}")

        # Keyword-only
        kw_defaults = node.args.kw_defaults
        for i, kwarg in enumerate(node.args.kwonlyargs):
            kw_str = self._format_arg(kwarg)
            if i < len(kw_defaults) and kw_defaults[i] is not None:
                try:
                    kw_str += f"={ast.unparse(kw_defaults[i])}"
                except Exception:
                    kw_str += "=..."
            args_strs.append(kw_str)

        # Kwarg **kwargs
        if node.args.kwarg:
            args_strs.append(f"**{self._format_arg(node.args.kwarg)}")

        sig = f"({', '.join(args_strs)})"
        if node.returns:
            try:
                sig += f" -> {ast.unparse(node.returns)}"
            except Exception:
                pass
        return sig

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for alias in node.names:
            self.imports.append(f"{mod}.{alias.name}" if mod else alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        bases = []
        for b in node.bases:
            try:
                bases.append(ast.unparse(b))
            except Exception:
                pass

        doc = ast.get_docstring(node) or ""
        doc_summary = doc.split("\n")[0].strip() if doc else ""

        class_info: dict[str, Any] = {
            "name": node.name,
            "filepath": self.filepath,
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "bases": bases,
            "docstring": doc_summary,
            "methods": [],
        }

        old_class = self.current_class
        self.current_class = node.name
        self.classes.append(class_info)

        self.generic_visit(node)

        self.current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle_function(node, is_async=True)

    def _handle_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> None:
        sig = self._format_signature(node)
        doc = ast.get_docstring(node) or ""
        doc_summary = doc.split("\n")[0].strip() if doc else ""

        decorators = []
        for dec in node.decorator_list:
            try:
                decorators.append(ast.unparse(dec))
            except Exception:
                pass

        func_info: dict[str, Any] = {
            "name": node.name,
            "filepath": self.filepath,
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "signature": sig,
            "is_async": is_async,
            "is_method": self.current_class is not None,
            "class_name": self.current_class,
            "docstring": doc_summary,
            "decorators": decorators,
        }

        full_name = f"{self.current_class}.{node.name}" if self.current_class else node.name
        old_function = self.current_function
        self.current_function = full_name

        if self.current_class is not None and self.classes:
            self.classes[-1]["methods"].append(func_info)
        else:
            self.functions.append(func_info)

        self.generic_visit(node)
        self.current_function = old_function

    def visit_Call(self, node: ast.Call) -> None:
        call_name = ""
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = node.func.attr

        if call_name:
            self.calls.append(call_name)
            if self.current_function:
                self.call_hierarchy[self.current_function].append(call_name)

        self.generic_visit(node)


def _parse_python_file(filepath: Path) -> Optional[SymbolCollector]:
    """Parse a single python file and extract symbol metadata."""
    if not filepath.is_file() or filepath.stat().st_size > MAX_FILE_BYTES:
        return None
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(content, filename=str(filepath))
        collector = SymbolCollector(str(filepath))
        collector.visit(tree)
        return collector
    except Exception:
        return None


def _action_map_tree(root_dir: Path, max_depth: int) -> dict[str, Any]:
    """Build a hierarchical directory tree up to max_depth."""
    tree_data: dict[str, Any] = {"name": root_dir.name, "type": "directory", "children": []}
    dir_count = 0
    file_count = 0
    total_bytes = 0

    def _walk(curr_dir: Path, curr_node: dict[str, Any], depth: int) -> None:
        nonlocal dir_count, file_count, total_bytes
        if depth > max_depth:
            return

        try:
            entries = sorted(curr_dir.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except (PermissionError, OSError):
            return

        for entry in entries:
            name = entry.name
            if name.startswith(".") and name in IGNORE_DIRS:
                continue
            if name in IGNORE_DIRS:
                continue
            if entry.is_dir():
                dir_count += 1
                child_node = {"name": name, "type": "directory", "children": []}
                curr_node["children"].append(child_node)
                _walk(entry, child_node, depth + 1)
            elif entry.is_file():
                if entry.suffix.lower() in IGNORE_EXTENSIONS:
                    continue
                file_count += 1
                try:
                    size = entry.stat().st_size
                except OSError:
                    size = 0
                total_bytes += size
                curr_node["children"].append({"name": name, "type": "file", "size_bytes": size})

    _walk(root_dir, tree_data, 1)

    return {
        "root": str(root_dir),
        "tree": tree_data,
        "total_directories": dir_count,
        "total_files": file_count,
        "total_size_bytes": total_bytes,
        "max_depth": max_depth,
    }


def _action_extract_symbols(filepath: Path) -> dict[str, Any]:
    """Extract symbol signatures from a single Python file."""
    collector = _parse_python_file(filepath)
    if collector is None:
        raise RepoMapperError(f"Failed to parse Python AST for '{filepath}'")

    return {
        "file": str(filepath),
        "classes": collector.classes,
        "functions": collector.functions,
        "imports": collector.imports,
        "calls_count": len(collector.calls),
    }


def _action_find_symbol(root_dir: Path, symbol_name: str, max_depth: int) -> dict[str, Any]:
    """Find definitions of a symbol across all Python files in the directory."""
    if not symbol_name or not isinstance(symbol_name, str):
        raise ValueError("symbol_name must be a non-empty string.")

    matches: list[dict[str, Any]] = []
    scanned_files = 0

    for curr, dirs, files in os.walk(str(root_dir)):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        rel_depth = len(Path(curr).relative_to(root_dir).parts)
        if rel_depth >= max_depth:
            dirs.clear()

        for f in sorted(files):
            if not f.endswith(".py"):
                continue
            scanned_files += 1
            if scanned_files > MAX_FILES_SCANNED:
                break

            p = Path(curr) / f
            collector = _parse_python_file(p)
            if not collector:
                continue

            # Check classes
            for cls_info in collector.classes:
                if cls_info["name"] == symbol_name:
                    matches.append({
                        "type": "class",
                        "name": cls_info["name"],
                        "file": str(p),
                        "line": cls_info["line"],
                        "end_line": cls_info["end_line"],
                        "bases": cls_info["bases"],
                        "docstring": cls_info["docstring"],
                    })
                # Check methods inside class
                for m_info in cls_info.get("methods", []):
                    if m_info["name"] == symbol_name:
                        matches.append({
                            "type": "method",
                            "name": m_info["name"],
                            "class_name": cls_info["name"],
                            "file": str(p),
                            "line": m_info["line"],
                            "end_line": m_info["end_line"],
                            "signature": m_info["signature"],
                            "is_async": m_info["is_async"],
                            "docstring": m_info["docstring"],
                        })

            # Check standalone functions
            for fn_info in collector.functions:
                if fn_info["name"] == symbol_name:
                    matches.append({
                        "type": "function",
                        "name": fn_info["name"],
                        "file": str(p),
                        "line": fn_info["line"],
                        "end_line": fn_info["end_line"],
                        "signature": fn_info["signature"],
                        "is_async": fn_info["is_async"],
                        "docstring": fn_info["docstring"],
                    })

    return {
        "symbol_name": symbol_name,
        "root_directory": str(root_dir),
        "matches_count": len(matches),
        "matches": matches,
        "scanned_files": scanned_files,
    }


def _action_get_call_hierarchy(root_dir: Path, symbol_name: str, max_depth: int) -> dict[str, Any]:
    """Analyze callers and callees for a given symbol."""
    if not symbol_name or not isinstance(symbol_name, str):
        raise ValueError("symbol_name must be a non-empty string.")

    callers: list[dict[str, Any]] = []
    callees: list[str] = []
    symbol_def: Optional[dict[str, Any]] = None

    scanned_files = 0
    for curr, dirs, files in os.walk(str(root_dir)):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        rel_depth = len(Path(curr).relative_to(root_dir).parts)
        if rel_depth >= max_depth:
            dirs.clear()

        for f in sorted(files):
            if not f.endswith(".py"):
                continue
            scanned_files += 1
            if scanned_files > MAX_FILES_SCANNED:
                break

            p = Path(curr) / f
            collector = _parse_python_file(p)
            if not collector:
                continue

            # Look for caller mappings
            for func_caller, called_symbols in collector.call_hierarchy.items():
                if symbol_name in called_symbols:
                    callers.append({
                        "caller": func_caller,
                        "file": str(p),
                    })

            # Look for definition callees
            for fn_info in collector.functions:
                if fn_info["name"] == symbol_name:
                    symbol_def = fn_info
                    callees.extend(collector.call_hierarchy.get(fn_info["name"], []))

            for cls_info in collector.classes:
                for m_info in cls_info.get("methods", []):
                    full_name = f"{cls_info['name']}.{m_info['name']}"
                    if m_info["name"] == symbol_name or full_name == symbol_name:
                        symbol_def = m_info
                        callees.extend(collector.call_hierarchy.get(full_name, []))

    return {
        "symbol_name": symbol_name,
        "definition": symbol_def,
        "callers": callers,
        "callees": sorted(set(callees)),
        "caller_count": len(callers),
        "callee_count": len(set(callees)),
        "scanned_files": scanned_files,
    }


def _action_find_references(root_dir: Path, symbol_query: str, max_depth: int) -> dict[str, Any]:
    """Find all definition and reference occurrences of symbol_query."""
    if not symbol_query or not isinstance(symbol_query, str):
        raise ValueError("symbol_query must be a non-empty string.")

    references: list[dict[str, Any]] = []
    scanned_files = 0

    for curr, dirs, files in os.walk(str(root_dir)):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        rel_depth = len(Path(curr).relative_to(root_dir).parts)
        if rel_depth >= max_depth:
            dirs.clear()

        for f in sorted(files):
            if not f.endswith(".py"):
                continue
            scanned_files += 1
            if scanned_files > MAX_FILES_SCANNED:
                break

            p = Path(curr) / f
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()
            except Exception:
                continue

            for idx, line in enumerate(lines, start=1):
                if re.search(r"\b" + re.escape(symbol_query) + r"\b", line):
                    references.append({
                        "file": str(p),
                        "line": idx,
                        "snippet": line.strip()[:160],
                    })

    return {
        "symbol_query": symbol_query,
        "root_directory": str(root_dir),
        "total_references": len(references),
        "references": references[:200],  # cap at 200 items
        "scanned_files": scanned_files,
    }


def _action_build_repo_map(root_dir: Path, max_depth: int, token_budget: int) -> dict[str, Any]:
    """Build a compact, ranked AST repository map formatted in Markdown within token_budget."""
    max_chars = token_budget * 4  # heuristic ~4 chars per token
    all_collectors: list[SymbolCollector] = []
    symbol_call_counts: Counter[str] = Counter()

    scanned_files = 0
    for curr, dirs, files in os.walk(str(root_dir)):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        rel_depth = len(Path(curr).relative_to(root_dir).parts)
        if rel_depth >= max_depth:
            dirs.clear()

        for f in sorted(files):
            if not f.endswith(".py"):
                continue
            scanned_files += 1
            if scanned_files > MAX_FILES_SCANNED:
                break

            p = Path(curr) / f
            collector = _parse_python_file(p)
            if collector:
                all_collectors.append(collector)
                symbol_call_counts.update(collector.calls)

    # Rank files by total reference count of their defined symbols
    file_ranks: list[tuple[int, SymbolCollector]] = []
    for c in all_collectors:
        score = 0
        for cls_info in c.classes:
            score += symbol_call_counts[cls_info["name"]]
            for m in cls_info.get("methods", []):
                score += symbol_call_counts[m["name"]]
        for fn_info in c.functions:
            score += symbol_call_counts[fn_info["name"]]
        file_ranks.append((score, c))

    file_ranks.sort(key=lambda x: x[0], reverse=True)

    # Format Markdown map within token budget
    lines: list[str] = [f"# Repository Map for `{root_dir.name}`", ""]
    current_chars = sum(len(line) + 1 for line in lines)
    files_included = 0
    symbols_included = 0

    for score, collector in file_ranks:
        rel_path = os.path.relpath(collector.filepath, str(root_dir))
        file_header = f"### `{rel_path}` (refs: {score})"
        file_lines = [file_header]

        for cls_info in collector.classes:
            bases_str = f"({', '.join(cls_info['bases'])})" if cls_info["bases"] else ""
            file_lines.append(f"- `class {cls_info['name']}{bases_str}`: {cls_info['docstring']}")
            symbols_included += 1
            for m in cls_info.get("methods", []):
                async_prefix = "async " if m["is_async"] else ""
                file_lines.append(f"  - `{async_prefix}def {m['name']}{m['signature']}`")
                symbols_included += 1

        for fn_info in collector.functions:
            async_prefix = "async " if fn_info["is_async"] else ""
            file_lines.append(f"- `{async_prefix}def {fn_info['name']}{fn_info['signature']}`")
            symbols_included += 1

        file_lines.append("")
        block_text = "\n".join(file_lines)

        if current_chars + len(block_text) > max_chars and files_included > 0:
            lines.append("... [truncated to fit token budget]")
            break

        lines.extend(file_lines)
        current_chars += len(block_text) + 1
        files_included += 1

    markdown_map = "\n".join(lines)
    estimated_tokens = max(1, len(markdown_map) // 4)

    return {
        "root_directory": str(root_dir),
        "files_scanned": scanned_files,
        "files_included": files_included,
        "symbols_included": symbols_included,
        "token_budget": token_budget,
        "estimated_tokens": estimated_tokens,
        "repo_map_markdown": markdown_map,
    }


def repo_mapper(arguments: dict[str, Any], context: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Operator tool entrypoint for repo_mapper."""
    if not isinstance(arguments, dict):
        return _envelope_error("Arguments must be a dictionary.")

    action = arguments.get("action")
    if not action or action not in VALID_ACTIONS:
        return _envelope_error(
            f"Invalid or missing action '{action}'. Valid actions: {sorted(VALID_ACTIONS)}"
        )

    try:
        # Determine target path or directory
        raw_path = arguments.get("directory") or arguments.get("path")
        if not raw_path:
            # Default to current directory if valid, else HOME
            cwd = Path.cwd()
            raw_path = str(cwd) if _is_inside_allowed_roots(cwd) else str(HOME)

        max_depth = int(arguments.get("max_depth", 4))
        if max_depth < 1:
            max_depth = 1
        elif max_depth > 20:
            max_depth = 20

        token_budget = int(arguments.get("token_budget", 2048))
        if token_budget < 128:
            token_budget = 128
        elif token_budget > 32768:
            token_budget = 32768

        symbol_name = str(arguments.get("symbol_name") or arguments.get("symbol_query") or "").strip()

        if action in ("build_map", "build_repo_map"):
            root_dir = _resolve_and_validate_path(raw_path, must_exist=True, is_dir=True)
            data = _action_build_repo_map(root_dir, max_depth, token_budget)
            return _envelope_success(data)

        elif action == "map_tree":
            root_dir = _resolve_and_validate_path(raw_path, must_exist=True, is_dir=True)
            data = _action_map_tree(root_dir, max_depth)
            return _envelope_success(data)

        elif action == "extract_symbols":
            filepath = _resolve_and_validate_path(raw_path, must_exist=True, is_dir=False)
            data = _action_extract_symbols(filepath)
            return _envelope_success(data)

        elif action == "find_symbol":
            root_dir = _resolve_and_validate_path(raw_path, must_exist=True, is_dir=True)
            data = _action_find_symbol(root_dir, symbol_name, max_depth)
            return _envelope_success(data)

        elif action == "get_call_hierarchy":
            root_dir = _resolve_and_validate_path(raw_path, must_exist=True, is_dir=True)
            data = _action_get_call_hierarchy(root_dir, symbol_name, max_depth)
            return _envelope_success(data)

        elif action == "find_references":
            root_dir = _resolve_and_validate_path(raw_path, must_exist=True, is_dir=True)
            data = _action_find_references(root_dir, symbol_name, max_depth)
            return _envelope_success(data)

        else:
            return _envelope_error(f"Action '{action}' is not supported.")

    except Exception as exc:
        return _envelope_error(exc)


TOOL = {
    "name": "repo_mapper",
    "description": (
        "Zero-dependency structural codebase mapper and AST symbol extractor. "
        "Builds concise directory trees, extracts class/function signatures, "
        "computes symbol reference graphs, and generates token-budgeted repository maps."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "build_map",
                    "build_repo_map",
                    "find_symbol",
                    "get_call_hierarchy",
                    "map_tree",
                    "extract_symbols",
                    "find_references",
                ],
                "description": "Mapper action to execute.",
            },
            "directory": {
                "type": "string",
                "description": "Directory to inspect (must be within ALLOWED_ROOTS).",
            },
            "path": {
                "type": "string",
                "description": "File or directory path to inspect (alias for directory).",
            },
            "max_depth": {
                "type": "integer",
                "minimum": 1,
                "maximum": 20,
                "description": "Maximum directory traversal depth (default: 4).",
            },
            "token_budget": {
                "type": "integer",
                "minimum": 128,
                "maximum": 32768,
                "description": "Approximate token budget cap for the generated repository map (default: 2048).",
            },
            "symbol_name": {
                "type": "string",
                "description": "Symbol name to locate or inspect.",
            },
            "symbol_query": {
                "type": "string",
                "description": "Symbol query string for find_references.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": repo_mapper,
    "approval": False,
}
