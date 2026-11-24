# E2E Test Infra: Jarvis Production Operator Modules

## Test Philosophy
- Opaque-box, requirement-driven test suite derived from `ORIGINAL_REQUEST.md` and production operator use cases.
- Methodology: Category-Partition + Boundary Value Analysis (BVA) + Pairwise Combinatorial Testing + Real-World Workload Scenarios.
- Zero reliance on internal implementation details; exercises modules through `ToolRegistry` dynamic loading and public `TOOL["handler"]`.
- Execution command: `/path/to/jarvis/.venv/bin/python3 -m unittest discover -s tests`.

## Feature Inventory & Test Matrix

| # | Feature | Module | Tier 1 (Coverage) | Tier 2 (Boundary/Edge) | Tier 3 (Cross-Feature) | Tier 4 (Workload) |
|---|---------|--------|:-----------------:|:----------------------:|:----------------------:|:-----------------:|
| 1 | `net_probe` (TCP, DNS, TLS, HTTP) | `op_net_probe.py` | ≥5 cases | ≥5 cases | Pairwise | Real-world infra check |
| 2 | `process_inspector` (Telemetry, Sockets, Signals) | `op_process_inspector.py` | ≥5 cases | ≥5 cases | Pairwise | Real-world process audit |
| 3 | `archive_builder` (ZIP, TAR, Compress/Decompress) | `op_archive_builder.py` | ≥5 cases | ≥5 cases | Pairwise | Real-world backup flow |
| 4 | `fs_analyzer` (Tree, Large, Symlinks, Hygiene) | `op_fs_analyzer.py` | ≥5 cases | ≥5 cases | Pairwise | Real-world disk triage |
| 5 | `tabular_data` (Convert, Sniff, Profile, Markdown) | `op_tabular_data.py` | ≥5 cases | ≥5 cases | Pairwise | Real-world report pipeline |
| 6 | `config_validator` (JSON, INI, Dotenv, Lint) | `op_config_validator.py` | ≥5 cases | ≥5 cases | Pairwise | Real-world config verification |
| 7 | `secret_scanner` (Entropy, Regex, PEM, Crypto) | `op_secret_scanner.py` | ≥5 cases | ≥5 cases | Pairwise | Real-world credential audit |
| 8 | `log_summarizer` (Cluster, Spike, Stacktrace, Mask) | `op_log_summarizer.py` | ≥5 cases | ≥5 cases | Pairwise | Real-world incident triage |

## Test Architecture
- **Location**: `tests/test_e2e_production_operators.py` and dedicated per-module unit tests in `tests/test_<module_name>.py`.
- **Runner**: `/path/to/jarvis/.venv/bin/python3 -m unittest ...`
- **Pass/Fail Semantics**: Standard Python `unittest` assertions (`assertEqual`, `assertTrue`, `assertRaises`). Return code `0` on success.
- **Contract Assurance**:
  - Verify every module is discovered by `tool_registry.ToolRegistry`.
  - Verify `TOOL["input_schema"]["additionalProperties"] is False`.
  - Verify return dictionary matches `{"ok": bool, "success": bool, "data": Any, "result": Any, "error": str | None}`.
  - Verify all exceptions are handled internally with `ok=False, success=False` rather than unhandled tracebacks.

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Incident Triage & Network Diagnostics | `net_probe` + `process_inspector` + `log_summarizer` | High |
| 2 | Production Release Packaging & Audit | `archive_builder` + `fs_analyzer` + `secret_scanner` | High |
| 3 | Config & Data Export Pipeline | `config_validator` + `tabular_data` + `archive_builder` | High |
| 4 | Security & Compliance Hygiene Scan | `secret_scanner` + `fs_analyzer` + `config_validator` | High |
| 5 | Full Fleet Telemetry & Health Audit | `net_probe` + `process_inspector` + `fs_analyzer` + `tabular_data` | High |

## Coverage Thresholds
- Tier 1: ≥5 test cases per feature (≥40 test cases total across 8 modules)
- Tier 2: ≥5 boundary & corner cases per feature (≥40 test cases total)
- Tier 3: Pairwise combinations across interacting modules (≥8 test cases)
- Tier 4: ≥5 realistic end-to-end workload application scenarios
- **Total Minimum Target: ≥93 test cases across the comprehensive test suite**
