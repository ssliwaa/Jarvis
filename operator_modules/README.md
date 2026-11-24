# Operator modules

Drop a `*.py` file here to add a tool without editing `browser_agent.py`.

Contract:

```python
TOOL = {
    "name": "system_status",
    "description": "Read CPU, RAM and disk status.",
    "input_schema": {"type": "object", "properties": {}},
    "handler": system_status,
    "approval": False,
}

def system_status(arguments, context=None):
    return {"ok": True, "load": [0.1, 0.2, 0.3]}
```

Discovery is deterministic. A module cannot shadow a built-in, another module,
or a generated Skill Forge skill. Set `approval: true` when the handler changes
state; the Operator will ask before running it in Safe/Standard modes.
