# Project: Jarvis Production Upgrade — Zero-Dependency Operator Modules

## Architecture

Jarvis is an autonomous agent and operator platform that runs on your machine (loopback-only server, state and secrets on disk outside the repo). Only model calls leave the host — DeepSeek API by default.
- **Operator Loading & Discovery**: `tool_registry.py` discovers modules dynamically in `operator_modules/*.py` by importing their module-level `TOOL` specification dictionary.
- **Autonomous Execution Engine**: `browser_agent.py` queries `ToolRegistry.declarations()` and invokes tools via `ToolRegistry.run(name, args, context)`.
- **Operator Boundary & Security Perimeter**: `operator_tools.py` defines `ALLOWED_ROOTS` (`HOME`, `/tmp`, `/mnt`, `/media`), canonical path resolution with symlink resolution (`os.path.realpath`), and blacklists sensitive directories (`.ssh`, `.gnupg`, `.env*`, etc.).
- **Zero External Dependencies**: All new operator modules use exclusively the Python standard library. No pip packages (`psutil`, `requests`, `pandas`, `cryptography`, etc.) are permitted.
- **Contract & Envelope**: Every module exports `TOOL` with `input_schema` having `additionalProperties: False`. Return values always follow the standardized 5-key envelope:
  - Success: `{"ok": True, "success": True, "data": <payload>, "result": <payload>, "error": None}`
  - Error: `{"ok": False, "success": False, "data": None, "result": None, "error": "<ErrorType>: <message>"}`
- **Execution Environment**: All test execution and validation is run under `/path/to/jarvis/.venv/bin/python3`.

```
Jarvis Runtime
  ├── server.py (Web API & UI)
  ├── browser_agent.py (Autonomous Agent Loop)
  ├── tool_registry.py (Dynamic Tool Discovery)
  │     └── operator_modules/*.py (Zero-dependency stdlib operators)
  │           ├── M1: op_net_probe.py, op_process_inspector.py
  │           ├── M2: op_archive_builder.py, op_fs_analyzer.py
  │           ├── M3: op_tabular_data.py, op_config_validator.py
  │           └── M4: op_secret_scanner.py, op_log_summarizer.py
  ├── operator_tools.py (Path Confinement & Security Perimeter)
  └── tests/ (Automated Unittest Suites)
```

## Feature Inventory

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | `net_probe` (TCP ping) | Non-destructive TCP connect probe with sub-second timeout and latency measurement | M1 | survey_explorer_3 |
| 2 | `net_probe` (DNS lookup) | Hostname resolution returning IPv4/IPv6 addresses and CNAME records | M1 | survey_explorer_3 |
| 3 | `net_probe` (TLS cert audit) | Connect to TLS endpoint, extract expiry, issuer, subject, SANs, and cipher | M1 | survey_explorer_3 |
| 4 | `net_probe` (HTTP HEAD check) | Raw socket HTTP HEAD request to verify status code and headers without downloading body | M1 | survey_explorer_3 |
| 5 | `process_inspector` (List/Search) | Linux `/proc` process telemetry (PID, user, state, RSS/VMS memory, command line) | M1 | survey_explorer_3 |
| 6 | `process_inspector` (PID Details) | Deep process inspection: file descriptors, open sockets, environment, threads | M1 | survey_explorer_3 |
| 7 | `process_inspector` (Socket Owners) | Correlate listening TCP/UDP ports from `/proc/net/tcp` to PIDs | M1 | survey_explorer_3 |
| 8 | `process_inspector` (Safe Signal) | Controlled POSIX signaling (SIGTERM/SIGINT/SIGHUP) with PID whitelist & validation (`approval: True`) | M1 | survey_explorer_3 |
| 9 | `archive_builder` (ZIP packaging) | Create ZIP archives from paths with compression level control, path filtering, and bounds | M2 | survey_explorer_3 |
| 10 | `archive_builder` (TAR packaging) | Create tar.gz, tar.bz2, and tar.xz archives with safe permissions and directory recursion | M2 | survey_explorer_3 |
| 11 | `archive_builder` (Stream compress) | In-memory stream compression (gzip/bz2/lzma) with base64 or file destination | M2 | survey_explorer_3 |
| 12 | `archive_builder` (Stream decompress) | In-memory stream decompression (gzip/bz2/lzma) with expansion bomb bounds | M2 | survey_explorer_3 |
| 13 | `fs_analyzer` (Directory Tree) | Hierarchical disk usage tree with depth limiting, entry count, and byte sizing | M2 | survey_explorer_3 |
| 14 | `fs_analyzer` (Find Large Files) | Rapid scan for files exceeding threshold with sorting and human-readable formatting | M2 | survey_explorer_3 |
| 15 | `fs_analyzer` (Broken Symlinks) | Scan directory tree for dangling or circular symbolic links | M2 | survey_explorer_3 |
| 16 | `fs_analyzer` (Hygiene Audit) | Detect temp files, orphaned lock files, empty directories, and permission anomalies | M2 | survey_explorer_3 |
| 17 | `tabular_data` (Format Convert) | Convert tabular data between CSV, TSV, JSON records, and JSON table formats | M3 | survey_explorer_3 |
| 18 | `tabular_data` (Dialect Sniffer) | Automatically detect delimiter, quotechar, and header existence using `csv.Sniffer` | M3 | survey_explorer_3 |
| 19 | `tabular_data` (Column Profiler) | Column statistics: null counts, distinct count, min/max, infer data types (int/float/date/str) | M3 | survey_explorer_3 |
| 20 | `tabular_data` (Markdown Table) | Format tabular data into clean GitHub-flavored Markdown tables with column alignment | M3 | survey_explorer_3 |
| 21 | `config_validator` (JSON Validate) | Verify JSON syntax, schema types, required fields, and disallowed properties | M3 | survey_explorer_3 |
| 22 | `config_validator` (INI Validate) | Verify INI/CFG syntax, required sections, required options, and interpolation safety | M3 | survey_explorer_3 |
| 23 | `config_validator` (Dotenv Validate) | Verify `.env` file syntax, unquoted multiline checks, and variable naming standards | M3 | survey_explorer_3 |
| 24 | `config_validator` (Format Lint) | Structural linting: trailing whitespace, duplicate keys, format consistency | M3 | survey_explorer_3 |
| 25 | `secret_scanner` (Entropy Scan) | Sliding-window Shannon entropy analysis on text/files to detect high-entropy keys/tokens | M4 | survey_explorer_3 |
| 26 | `secret_scanner` (Pattern Match) | Regex detection for AWS, GitHub, SSH private keys, OpenAI, Slack tokens | M4 | survey_explorer_3 |
| 27 | `secret_scanner` (PEM Audit) | Parse PEM/DER blocks, certificate headers, public key types, validity windows | M4 | survey_explorer_3 |
| 28 | `secret_scanner` (Crypto Utils) | Stdlib PBKDF2/HMAC key derivation, constant-time comparison, CSPRNG secure tokens | M4 | survey_explorer_3 |
| 29 | `log_summarizer` (Error Cluster) | Group and fingerprint log error messages by stripping dynamic parameters/timestamps | M4 | survey_explorer_3 |
| 30 | `log_summarizer` (Spike Detect) | Group log events into time buckets and identify anomaly error rate spikes | M4 | survey_explorer_3 |
| 31 | `log_summarizer` (Stacktrace Triage) | Extract and categorize exception types, entry points, and root cause frames | M4 | survey_explorer_3 |
| 32 | `log_summarizer` (PII Masking) | Mask emails, IP addresses, JWT tokens, and credentials in log streams | M4 | survey_explorer_3 |
| 33 | E2E Testing Suite (Tiers 1-4) | Opaque-box requirement-driven test suite validating all 8 modules across all tiers | M-E2E | survey_spec_miner_2 |
| 34 | Adversarial Hardening (Tier 5) | White-box stress-testing, boundary extremes, and security penetration | M5 | survey_spec_miner_2 |

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | System & Network Operations | `op_net_probe.py`, `op_process_inspector.py`, unit tests in `tests/` | None | DONE |
| M2 | Storage & Archive Operations | `op_archive_builder.py`, `op_fs_analyzer.py`, unit tests in `tests/` | None | DONE |
| M3 | Data, Format & Configuration | `op_tabular_data.py`, `op_config_validator.py`, unit tests in `tests/` | None | DONE |
| M4 | Security & Operational Intelligence | `op_secret_scanner.py`, `op_log_summarizer.py`, unit tests in `tests/` | None | DONE |
| M-E2E | E2E Testing Track | Requirement-driven test suite (`tests/test_e2e_production_operators.py`), harness, and `TEST_READY.md` | None (runs in parallel) | DONE |
| M5 | Final Verification & Adversarial Hardening | Pass 100% E2E tests, zero regressions against existing tests & preflight, Tier 5 hardening, Forensic Audit | M1, M2, M3, M4, M-E2E | DONE |

## Interface Contracts

### 1. Module Export Contract
Every module in `operator_modules/<name>.py` must export:
```python
TOOL = {
    "name": "<tool_name>",
    "description": "<detailed_description>",
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": [...]},
            # ... additional arguments
        },
        "required": ["action"],
        "additionalProperties": False,
    },
    "handler": handle_tool_call,  # Callable[[dict, Optional[dict]], dict]
    "approval": bool,            # True for mutating operations, False for read-only
}
```

### 2. Standard Envelope Contract
```python
# Success Envelope:
{
    "ok": True,
    "success": True,
    "data": result_data,
    "result": result_data,
    "error": None
}

# Error Envelope:
{
    "ok": False,
    "success": False,
    "data": None,
    "result": None,
    "error": "ErrorClassName: descriptive error message"
}
```

### 3. Security & Confinement Contracts
- **Path Resolution**: Must use canonical paths (`os.path.realpath`). Must reject paths containing `..` escape attempts.
- **Root Confinement**: Any path target must reside within `ALLOWED_ROOTS = (HOME, Path("/tmp"), Path("/mnt"), Path("/media"))`.
- **Sensitive Path Guard**: Reject targets in sensitive directories (`.ssh`, `.gnupg`, `.password-store`, `.env*`, `config.json`, etc.).
- **Resource Limits**:
  - Max input/output bytes: 10 MB.
  - Streaming chunk size: 64 KB.
  - Socket/network timeout: 10.0 seconds maximum.
  - Max entries/records returned: 500 (with pagination or truncation signal).
  - Atomic file writes: mode `0o600` using sibling temp files and `os.replace`.

## Code Layout

- `operator_modules/op_net_probe.py`: Network diagnostics (TCP, DNS, TLS, HTTP HEAD)
- `operator_modules/op_process_inspector.py`: Process inspection and signaling (/proc)
- `operator_modules/op_archive_builder.py`: Archive creation and stream compression
- `operator_modules/op_fs_analyzer.py`: Disk usage, large files, broken symlinks, hygiene
- `operator_modules/op_tabular_data.py`: Tabular data conversion, profiling, Markdown
- `operator_modules/op_config_validator.py`: Configuration validation (JSON, INI, .env)
- `operator_modules/op_secret_scanner.py`: Entropy scanning, PEM parsing, secure crypto utils
- `operator_modules/op_log_summarizer.py`: Log error clustering, spike detection, triage
- `tests/test_op_net_probe.py`: Unit tests for `op_net_probe`
- `tests/test_op_process_inspector.py`: Unit tests for `op_process_inspector`
- `tests/test_op_archive_builder.py`: Unit tests for `op_archive_builder`
- `tests/test_op_fs_analyzer.py`: Unit tests for `op_fs_analyzer`
- `tests/test_op_tabular_data.py`: Unit tests for `op_tabular_data`
- `tests/test_op_config_validator.py`: Unit tests for `op_config_validator`
- `tests/test_op_secret_scanner.py`: Unit tests for `op_secret_scanner`
- `tests/test_op_log_summarizer.py`: Unit tests for `op_log_summarizer`
- `tests/test_e2e_production_operators.py`: Comprehensive E2E test suite (Tiers 1-4)
- `TEST_INFRA.md`: E2E test suite architecture & methodology
- `TEST_READY.md`: E2E test readiness publication
