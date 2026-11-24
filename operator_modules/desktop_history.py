"""Operator module exposing desktop activity history to the agent."""
from __future__ import annotations

import desktop_tracker


def desktop_history(arguments: dict, context=None) -> dict:
    """Retrieve recent desktop application activity and window titles."""
    limit = arguments.get("limit", 20)
    query = arguments.get("query")
    entries = desktop_tracker.get_history(limit=limit, query=query)
    current = desktop_tracker.get_active_window_info()
    return {
        "ok": True,
        "current_window": current,
        "count": len(entries),
        "history": entries,
    }


TOOL = {
    "name": "desktop_history",
    "description": "Show recent desktop application activity, active window titles, and dwell times.",
    "schema": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Maximum number of history records to return (1-100, default 20).",
                "default": 20,
            },
            "query": {
                "type": "string",
                "description": "Optional search term to filter window titles or application names.",
            },
        },
    },
    "handler": desktop_history,
}
