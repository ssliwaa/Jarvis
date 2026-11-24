"""Static Python AST Inspector and Syntax Validator for Jarvis."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import operator_tools as ops

MAX_BYTES = 350_000  # 350 KB matching security_scanner.py


def _format_decorator(dec_node: ast.AST) -> str:
    if isinstance(dec_node, ast.Name):
        name = dec_node.id
    elif isinstance(dec_node, ast.Attribute):
        name = f"{_format_decorator(dec_node.value).lstrip('@')}.{dec_node.attr}"
    elif isinstance(dec_node, ast.Call):
        name = f"{_format_decorator(dec_node.func).lstrip('@')}(...)"
    else:
        name = "decorator"
    return f"@{name}"


def _format_base(base_node: ast.AST) -> str:
    if isinstance(base_node, ast.Name):
        return base_node.id
    if isinstance(base_node, ast.Attribute):
        return f"{_format_base(base_node.value)}.{base_node.attr}"
    return "Base"


def _format_args(args_node: ast.arguments) -> list[str]:
    params: list[str] = []
    for arg in getattr(args_node, "posonlyargs", []):
        params.append(arg.arg)
    if getattr(args_node, "posonlyargs", []):
        params.append("/")
    for arg in args_node.args:
        params.append(arg.arg)
    if args_node.vararg:
        params.append(f"*{args_node.vararg.arg}")
    elif args_node.kwonlyargs:
        params.append("*")
    for arg in args_node.kwonlyargs:
        params.append(arg.arg)
    if args_node.kwarg:
        params.append(f"**{args_node.kwarg.arg}")
    return params


def _extract_function_info(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any]:
    return {
        "name": node.name,
        "is_async": isinstance(node, ast.AsyncFunctionDef),
        "args": _format_args(node.args),
        "docstring": ast.get_docstring(node),
        "lineno": node.lineno,
        "end_lineno": getattr(node, "end_lineno", node.lineno),
        "decorators": [_format_decorator(d) for d in node.decorator_list],
    }


def _extract_class_info(node: ast.ClassDef) -> dict[str, Any]:
    methods: list[dict[str, Any]] = []
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            methods.append(_extract_function_info(item))

    return {
        "name": node.name,
        "bases": [_format_base(b) for b in node.bases],
        "docstring": ast.get_docstring(node),
        "lineno": node.lineno,
        "end_lineno": getattr(node, "end_lineno", node.lineno),
        "decorators": [_format_decorator(d) for d in node.decorator_list],
        "methods": methods,
        "method_count": len(methods),
    }


def code_ast(arguments: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Inspect Python code statically using the AST parser without executing any code."""
    args = arguments if isinstance(arguments, dict) else {}
    action = str(args.get("action") or "outline").strip().lower()

    raw_path = args.get("path")
    raw_code = args.get("code")

    if not raw_path and raw_code is None:
        return {"ok": False, "error": "Either 'path' or 'code' must be provided."}

    source_code = ""
    origin_name = "<string>"

    workspace = (context or {}).get("workspace")
    base = Path(workspace) if workspace else ops.HOME

    if raw_path:
        if not isinstance(raw_path, str):
            return {"ok": False, "error": "Parameter 'path' must be a string."}
        try:
            target_path = ops.resolve_path(raw_path, base=base, must_exist=True)
        except ops.ToolError as err:
            return {"ok": False, "error": str(err)}

        if ops.is_credential_target(target_path):
            return {"ok": False, "error": f"Access to sensitive target {target_path.name!r} is refused."}

        if not target_path.is_file():
            return {"ok": False, "error": f"Path is not a regular file: {target_path}"}

        try:
            stat_res = target_path.stat()
            if stat_res.st_size > MAX_BYTES:
                return {
                    "ok": False,
                    "error": f"File size ({stat_res.st_size} bytes) exceeds maximum limit of {MAX_BYTES} bytes.",
                }
            source_code = target_path.read_text(encoding="utf-8", errors="replace")
            origin_name = target_path.name
        except OSError as err:
            return {"ok": False, "error": f"Failed to read file: {err}"}
    else:
        if not isinstance(raw_code, str):
            return {"ok": False, "error": "Parameter 'code' must be a string."}
        encoded_len = len(raw_code.encode("utf-8"))
        if encoded_len > MAX_BYTES:
            return {
                "ok": False,
                "error": f"Code size ({encoded_len} bytes) exceeds maximum limit of {MAX_BYTES} bytes.",
            }
        source_code = raw_code

    if action == "check_syntax":
        try:
            ast.parse(source_code, filename=origin_name)
            return {
                "ok": True,
                "result": {
                    "valid": True,
                    "line_count": len(source_code.splitlines()),
                    "byte_count": len(source_code.encode("utf-8")),
                },
            }
        except SyntaxError as err:
            return {
                "ok": True,
                "result": {
                    "valid": False,
                    "error": err.msg,
                    "lineno": err.lineno,
                    "offset": err.offset,
                    "text": (err.text or "").strip(),
                },
            }
        except (RecursionError, MemoryError) as err:
            return {"ok": False, "error": f"AST parsing resource limit exceeded: {type(err).__name__}"}

    try:
        tree = ast.parse(source_code, filename=origin_name)
    except SyntaxError as err:
        return {
            "ok": False,
            "error": f"SyntaxError at line {err.lineno}: {err.msg}",
            "lineno": err.lineno,
            "offset": err.offset,
        }
    except (RecursionError, MemoryError) as err:
        return {"ok": False, "error": f"AST parsing resource limit exceeded: {type(err).__name__}"}

    if action == "outline":
        classes: list[dict[str, Any]] = []
        functions: list[dict[str, Any]] = []
        top_level_vars: list[str] = []

        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                classes.append(_extract_class_info(node))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(_extract_function_info(node))
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        top_level_vars.append(target.id)

        return {
            "ok": True,
            "result": {
                "docstring": ast.get_docstring(tree),
                "classes": classes,
                "functions": functions,
                "top_level_vars": top_level_vars,
                "class_count": len(classes),
                "function_count": len(functions),
                "line_count": len(source_code.splitlines()),
            },
        }

    if action == "inspect_imports":
        imports: list[dict[str, Any]] = []
        root_modules: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    root_modules.add(root)
                    imports.append({
                        "type": "import",
                        "module": alias.name,
                        "alias": alias.asname,
                        "lineno": node.lineno,
                    })
            elif isinstance(node, ast.ImportFrom):
                mod_name = node.module or ""
                if mod_name:
                    root_modules.add(mod_name.split(".")[0])
                for alias in node.names:
                    imports.append({
                        "type": "from_import",
                        "module": mod_name,
                        "name": alias.name,
                        "alias": alias.asname,
                        "level": node.level,
                        "lineno": node.lineno,
                    })

        imports.sort(key=lambda item: item["lineno"])
        return {
            "ok": True,
            "result": {
                "modules": sorted(root_modules),
                "imports": imports,
                "count": len(imports),
            },
        }

    return {"ok": False, "error": f"Unsupported action: {action!r}"}


TOOL = {
    "name": "code_ast",
    "description": (
        "Pure static Python AST code analysis and syntax verification. "
        "Extract symbol outline, function signatures, classes, imports, or validate syntax."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["outline", "check_syntax", "inspect_imports"],
                "description": "Analysis action: 'outline', 'check_syntax', or 'inspect_imports' (default: 'outline').",
            },
            "path": {
                "type": "string",
                "description": "Path to a Python file to inspect.",
            },
            "code": {
                "type": "string",
                "description": "Raw Python code string to inspect.",
            },
        },
        "additionalProperties": False,
    },
    "handler": code_ast,
    "approval": False,
}
