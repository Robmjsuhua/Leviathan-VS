# Changelog

All notable changes to Leviathan-VS will be documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [14.2.0] - 2026-02-25

### Added
- `core/cache.py` — SQLite-backed result cache (put/get/list/purge/stats/TTL)
- `core/generate_tasks_md.py` — auto-generates `docs/TASKS.md` from `.vscode/tasks.json`
- `docs/TASKS.md` — 138 tasks across 20+ categories, auto-generated
- `.pre-commit-config.yaml` — ruff lint/format + pre-commit hooks (trailing whitespace, YAML, merge conflicts)
- `tests/test_http_and_cache.py` — 30 unit tests for ResultCache, HTTPToolkit classes, and TASKS.md generator
- `http_toolkit.py`: `SessionManager` class — persists cookies/tokens across requests
- `http_toolkit.py`: `dispatch_json()` — returns JSON-serializable `dict` for automation
- `http_toolkit.py`: `profile_endpoint()` — timing/status distribution analysis over N rounds
- `http_toolkit.py`: `--json` flag on both `dispatch` and `scan` subcommands
- CI: `secrets-scan` job using gitleaks
- CI: dedicated `json-validate` job via `config_schema.py`
- CI: `fail-fast: false` in test matrix for better feedback

### Changed
- `http_toolkit.py`: dispatch retry now uses exponential backoff (`0.5 * 2^attempt`, capped at 30s)
- `http_toolkit.py`: session cookies injected automatically (opt-out via `session=False`)
- `http_toolkit.py`: response cookies persisted to `.http_session.json`
- CI: removed flaky inline JSON validation in favor of `config_schema.py`
- Version bump 14.1.0 → 14.2.0

## [14.1.0] - 2026-02-25

### Added
- `core/doctor.py` — healthcheck & diagnostics (`python core/doctor.py`, `--json`, `--fix`)
- `core/config_schema.py` — config validation for config.json, mcp.json, tasks.json
- `core/cli.py` — unified CLI entrypoint (`leviathan translate|http|doctor|validate|report|version`)
- `pyproject.toml` — package manifest with `[project.scripts]`, ruff/pytest config
- `tests/test_translator.py` — 25+ unit tests for Kraken Engine (roundtrip, case, format, edge cases)
- `.github/workflows/ci.yml` — GitHub Actions: lint, test (Windows+Ubuntu matrix), JSON validation
- `CONTRIBUTING.md` — contributor guide
- `SECURITY.md` — security policy + responsible use + SAFE_MODE docs
- `CHANGELOG.md` — this file
- VS Code tasks: `[LEVIATHAN] Doctor`, `[LEVIATHAN] Validate Configs`, `[LEVIATHAN] Run Tests`, `[LEVIATHAN] Lint`, `[LEVIATHAN] Export Report`
- `SAFE_MODE` environment variable (default=1): excludes DELETE from scans, defensive defaults

### Fixed
- **http_toolkit.py**: 6 bare `except:` clauses → specific exception types (prevents swallowing KeyboardInterrupt/SystemExit)
- **http_toolkit.py**: `os.system('')` called on every `colorize()` → called once at import
- **http_toolkit.py**: `scan()` sends DELETE by default → excluded in SAFE_MODE
- **http_toolkit.py**: `scan()` delay now configurable (`delay` parameter)
- **install.ps1**: validation checks wrong paths (`$scriptPath\translator.py` → `$scriptPath\core\translator.py`)
- **install.ps1**: MCP server path missing `core/` prefix
- **install.ps1**: `$ErrorActionPreference = "SilentlyContinue"` → `"Continue"` (don't suppress errors)

### Changed
- `scan()` method signature: added `delay` and `methods` parameters (backward-compatible defaults)

## [14.0.0] - 2026-02-24

### Added
- 6 new MCP servers: Scapy (15 tools), Radare2 (16 tools), Hashcat (12 tools), APKTool (12 tools), Androguard (15 tools), MITMProxy (14 tools)
- 3 missing MCP servers registered in mcp.json (mitmproxy, apktool, androguard)
- Tasks for new MCPs in tasks.json

### Fixed
- **mcp_frida.py**: 8 calls to undefined `_run_frida_cli` → `_run_frida_cmd`
- **mcp_frida.py**: broken tuple unpacking from `_build_inject_cmd`
- **mcp_frida.py**: missing tmpfile cleanup in 6 handlers
