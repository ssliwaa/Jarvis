"""Zero-dependency Model Context Protocol (MCP) bridge and schema adapter.

Inspired by FastMCP, Goose, and the MCP Reference Servers: exposes Jarvis operator
modules as standard MCP tool manifests, inspects tool schemas, validates JSON-RPC 2.0
protocol frames, and translates MCP tool execution requests to and from Jarvis envelopes.
Exclusively uses the Python standard library.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional, Union

# Ensure Jarvis root is in sys.path for tool_registry import
JARVIS_ROOT = Path(__file__).resolve().parent.parent
if str(JARVIS_ROOT) not in sys.path:
    sys.path.insert(0, str(JARVIS_ROOT))

try:
    from tool_registry import ToolRegistry
except ImportError:
    ToolRegistry = None

MCP_PROTOCOL_VERSION = "2024-11-05"

VALID_ACTIONS: frozenset[str] = frozenset({
    "export_manifest",
    "list_mcp_tools",
    "inspect_tool",
    "invoke_mcp_tool",
    "execute_mcp_call",
    "validate_rpc",
    "handle_rpc",
})

SUPPORTED_RPC_METHODS: frozenset[str] = frozenset({
    "tools/list",
    "tools/call",
    "initialize",
    "ping",
    "resources/list",
    "prompts/list",
})

# JSON-RPC 2.0 Standard Error Codes
RPC_PARSE_ERROR = -32700
RPC_INVALID_REQUEST = -32600
RPC_METHOD_NOT_FOUND = -32601
RPC_INVALID_PARAMS = -32602
RPC_INTERNAL_ERROR = -32603


class MCPBridgeError(Exception):
    """Base exception for mcp_bridge operations."""


def _envelope_success(data: Any) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator success envelope."""
    return {"ok": True, "success": True, "data": data, "result": data, "error": None}


def _envelope_error(err: str | Exception) -> dict[str, Any]:
    """Return standardized 5-key Jarvis operator error envelope."""
    msg = f"{type(err).__name__}: {err}" if isinstance(err, Exception) else str(err)
    return {"ok": False, "success": False, "data": None, "result": None, "error": msg}


def _get_registry() -> ToolRegistry:
    """Obtain initialized ToolRegistry instance."""
    if ToolRegistry is None:
        raise MCPBridgeError("ToolRegistry could not be imported from Jarvis root.")
    return ToolRegistry()


def _format_mcp_tool_declaration(tool_obj: Any) -> dict[str, Any]:
    """Format a ToolRegistry ModuleTool into an official MCP tool definition."""
    schema = getattr(tool_obj, "schema", {}) or {}
    return {
        "name": tool_obj.name,
        "description": tool_obj.description[:1600],
        "inputSchema": schema,
        "approvalRequired": getattr(tool_obj, "approval", False),
    }


def _action_export_manifest() -> dict[str, Any]:
    """Export all registered Jarvis tools as an MCP-compliant tools/list manifest."""
    registry = _get_registry()
    tools_list = []
    for name in sorted(registry.tools.keys()):
        tool_obj = registry.tools[name]
        tools_list.append(_format_mcp_tool_declaration(tool_obj))

    return {
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "serverInfo": {
            "name": "jarvis-operator-mcp-server",
            "version": "1.0.0",
        },
        "tools": tools_list,
        "count": len(tools_list),
        "registry_errors": registry.errors,
    }


def _action_inspect_tool(tool_name: str) -> dict[str, Any]:
    """Inspect the MCP declaration and parameter details for a specific tool."""
    if not tool_name or not isinstance(tool_name, str):
        raise ValueError("tool_name must be a non-empty string.")

    registry = _get_registry()
    if tool_name not in registry.tools:
        raise KeyError(f"Tool '{tool_name}' not found in registry. Available: {sorted(registry.tools.keys())}")

    tool_obj = registry.tools[tool_name]
    mcp_decl = _format_mcp_tool_declaration(tool_obj)
    schema = mcp_decl["inputSchema"]
    properties = schema.get("properties", {})
    required = schema.get("required", [])

    return {
        "tool": mcp_decl,
        "name": tool_name,
        "description": tool_obj.description,
        "input_schema": schema,
        "properties_count": len(properties),
        "property_names": sorted(properties.keys()),
        "required_fields": required,
        "approval_required": tool_obj.approval,
        "module_path": str(tool_obj.path),
    }


def _action_invoke_mcp_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Invoke a Jarvis operator tool and wrap the output in the standard MCP envelope."""
    if not tool_name or not isinstance(tool_name, str):
        raise ValueError("tool_name must be a non-empty string.")
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be a dictionary.")

    registry = _get_registry()
    if tool_name not in registry.tools:
        raise KeyError(f"Tool '{tool_name}' not found in registry.")

    tool_obj = registry.tools[tool_name]
    raw_result = tool_obj.run(arguments)

    is_error = False
    if isinstance(raw_result, dict):
        if not raw_result.get("ok", True) or not raw_result.get("success", True):
            is_error = True

    try:
        content_text = json.dumps(raw_result, indent=2, default=str)
    except Exception:
        content_text = str(raw_result)

    mcp_response = {
        "content": [
            {
                "type": "text",
                "text": content_text,
            }
        ],
        "isError": is_error,
        "raw_response": raw_result,
    }

    return mcp_response


def _action_validate_rpc(payload: Union[str, dict[str, Any]]) -> dict[str, Any]:
    """Validate a JSON-RPC 2.0 message against MCP protocol standards."""
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            return {
                "is_valid": False,
                "error_code": RPC_PARSE_ERROR,
                "error_message": f"Parse error: {exc.msg}",
                "rpc_response": {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": RPC_PARSE_ERROR,
                        "message": f"Parse error: {exc.msg}",
                    },
                },
            }
    elif isinstance(payload, dict):
        parsed = payload
    else:
        return {
            "is_valid": False,
            "error_code": RPC_INVALID_REQUEST,
            "error_message": "Payload must be a JSON string or dictionary.",
            "rpc_response": {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": RPC_INVALID_REQUEST,
                    "message": "Invalid Request: payload must be an object",
                },
            },
        }

    # Validate JSON-RPC 2.0 requirements
    rpc_id = parsed.get("id")
    jsonrpc_ver = parsed.get("jsonrpc")

    if jsonrpc_ver != "2.0":
        return {
            "is_valid": False,
            "error_code": RPC_INVALID_REQUEST,
            "error_message": f"Invalid JSON-RPC version '{jsonrpc_ver}'. Must be '2.0'.",
            "rpc_response": {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": RPC_INVALID_REQUEST,
                    "message": "Invalid Request: missing or invalid 'jsonrpc' field",
                },
            },
        }

    method = parsed.get("method")
    if not isinstance(method, str) or not method:
        return {
            "is_valid": False,
            "error_code": RPC_INVALID_REQUEST,
            "error_message": "Missing or invalid 'method' field.",
            "rpc_response": {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": RPC_INVALID_REQUEST,
                    "message": "Invalid Request: missing 'method'",
                },
            },
        }

    params = parsed.get("params")
    if params is not None and not isinstance(params, (dict, list)):
        return {
            "is_valid": False,
            "error_code": RPC_INVALID_PARAMS,
            "error_message": "'params' must be an object or array.",
            "rpc_response": {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": RPC_INVALID_PARAMS,
                    "message": "Invalid params: must be an object or array",
                },
            },
        }

    is_supported_method = method in SUPPORTED_RPC_METHODS
    return {
        "is_valid": True,
        "method": method,
        "is_supported_method": is_supported_method,
        "id": rpc_id,
        "params": params,
        "error_code": None,
        "error_message": None,
    }


def _action_handle_rpc(payload: Union[str, dict[str, Any]]) -> dict[str, Any]:
    """Execute a validated JSON-RPC 2.0 request and return compliant JSON-RPC response."""
    val = _action_validate_rpc(payload)
    if not val["is_valid"]:
        return val["rpc_response"]

    method = val["method"]
    rpc_id = val["id"]
    params = val.get("params") or {}

    if method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {},
        }

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": "jarvis-operator-mcp-server",
                    "version": "1.0.0",
                },
            },
        }

    if method == "tools/list":
        manifest = _action_export_manifest()
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "tools": manifest["tools"],
            },
        }

    if method == "tools/call":
        if not isinstance(params, dict):
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": RPC_INVALID_PARAMS,
                    "message": "tools/call requires params to be an object",
                },
            }
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}
        if not tool_name:
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": RPC_INVALID_PARAMS,
                    "message": "Missing 'name' in tools/call params",
                },
            }
        try:
            mcp_res = _action_invoke_mcp_tool(tool_name, arguments)
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": mcp_res["content"],
                    "isError": mcp_res["isError"],
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": RPC_INTERNAL_ERROR,
                    "message": str(exc),
                },
            }

    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {
            "code": RPC_METHOD_NOT_FOUND,
            "message": f"Method '{method}' not found",
        },
    }


def mcp_bridge(arguments: dict[str, Any], context: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Operator tool entrypoint for mcp_bridge."""
    if not isinstance(arguments, dict):
        return _envelope_error("Arguments must be a dictionary.")

    action = arguments.get("action")
    if not action or action not in VALID_ACTIONS:
        return _envelope_error(
            f"Invalid or missing action '{action}'. Valid actions: {sorted(VALID_ACTIONS)}"
        )

    try:
        tool_name = arguments.get("tool_name")
        args_payload = arguments.get("arguments") or {}
        rpc_payload = arguments.get("rpc_payload")

        if action in ("export_manifest", "list_mcp_tools"):
            data = _action_export_manifest()
            return _envelope_success(data)

        elif action == "inspect_tool":
            if not tool_name:
                return _envelope_error("Missing required parameter 'tool_name' for inspect_tool.")
            data = _action_inspect_tool(str(tool_name))
            return _envelope_success(data)

        elif action in ("invoke_mcp_tool", "execute_mcp_call"):
            if not tool_name:
                return _envelope_error("Missing required parameter 'tool_name' for invoke_mcp_tool.")
            data = _action_invoke_mcp_tool(str(tool_name), args_payload)
            return _envelope_success(data)

        elif action == "validate_rpc":
            if rpc_payload is None:
                return _envelope_error("Missing required parameter 'rpc_payload' for validate_rpc.")
            data = _action_validate_rpc(rpc_payload)
            return _envelope_success(data)

        elif action == "handle_rpc":
            if rpc_payload is None:
                return _envelope_error("Missing required parameter 'rpc_payload' for handle_rpc.")
            data = _action_handle_rpc(rpc_payload)
            return _envelope_success(data)

        else:
            return _envelope_error(f"Action '{action}' is not supported.")

    except Exception as exc:
        return _envelope_error(exc)


TOOL = {
    "name": "mcp_bridge",
    "description": (
        "Zero-dependency Model Context Protocol (MCP) bridge and schema adapter. "
        "Exports Jarvis operator modules as standard MCP tool manifests, inspects tool schemas, "
        "validates JSON-RPC 2.0 frames, and executes MCP tool requests."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "export_manifest",
                    "list_mcp_tools",
                    "inspect_tool",
                    "invoke_mcp_tool",
                    "execute_mcp_call",
                    "validate_rpc",
                    "handle_rpc",
                ],
                "description": "MCP bridge action to perform.",
            },
            "tool_name": {
                "type": "string",
                "description": "Specific operator tool name to inspect or call.",
            },
            "arguments": {
                "type": "object",
                "description": "Tool arguments dictionary for invoke_mcp_tool / execute_mcp_call.",
            },
            "rpc_payload": {
                "type": "string",
                "description": "Raw JSON-RPC 2.0 message string for validate_rpc or handle_rpc.",
            },
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": mcp_bridge,
    "approval": False,
}
