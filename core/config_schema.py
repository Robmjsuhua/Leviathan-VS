#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - Config Schema Validator
    Valida config.json, mcp.json, tasks.json contra schemas minimos.

    Uso:
        python core/config_schema.py                    # valida tudo
        python core/config_schema.py --file config.json # valida um arquivo
        python core/config_schema.py --json             # output JSON

    Exit codes:
        0 = valido
        1 = erros encontrados
================================================================================
"""

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).parent.resolve()
PROJECT_DIR = BASE_DIR.parent


# ============================================================================
# VALIDATION RESULTS
# ============================================================================


@dataclass
class ValidationError:
    file: str
    path: str
    message: str
    severity: str = "error"  # error | warning


@dataclass
class ValidationReport:
    file: str
    valid: bool = True
    errors: List[ValidationError] = field(default_factory=list)

    def add_error(self, path: str, message: str, severity: str = "error"):
        self.errors.append(ValidationError(self.file, path, message, severity))
        if severity == "error":
            self.valid = False


# ============================================================================
# JSONC PARSER
# ============================================================================


def strip_jsonc_comments(text: str) -> str:
    """Remove // comments from JSONC, preserving strings."""
    result = []
    i = 0
    in_string = False
    escape = False
    while i < len(text):
        ch = text[i]
        if escape:
            result.append(ch)
            escape = False
            i += 1
            continue
        if ch == "\\" and in_string:
            result.append(ch)
            escape = True
            i += 1
            continue
        if ch == '"' and not in_string:
            in_string = True
            result.append(ch)
            i += 1
            continue
        if ch == '"' and in_string:
            in_string = False
            result.append(ch)
            i += 1
            continue
        if not in_string and ch == "/" and i + 1 < len(text):
            if text[i + 1] == "/":
                # Skip to end of line
                while i < len(text) and text[i] != "\n":
                    i += 1
                continue
            elif text[i + 1] == "*":
                # Skip block comment
                i += 2
                while i + 1 < len(text) and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i += 2
                continue
        result.append(ch)
        i += 1
    return "".join(result)


def load_jsonc(path: Path) -> Any:
    """Load a JSONC file, stripping comments and fixing invalid escapes."""
    text = path.read_text(encoding="utf-8")
    clean = strip_jsonc_comments(text)
    clean = _sanitize_json_escapes(clean)
    return json.loads(clean)


def _sanitize_json_escapes(text: str) -> str:
    """Fix invalid backslash escapes inside JSON strings.

    VS Code configs (e.g. tasks.json) often embed PowerShell commands
    containing literal sequences like \\e[ (ANSI escape) that are invalid
    in strict JSON.  This doubles any backslash inside a quoted string
    that is NOT followed by a valid JSON escape character.
    """
    _VALID = frozenset('"\\/bfnrtu')
    result = []
    i = 0
    in_string = False
    while i < len(text):
        ch = text[i]
        if not in_string:
            if ch == '"':
                in_string = True
            result.append(ch)
            i += 1
            continue
        if ch == '"':
            in_string = False
            result.append(ch)
            i += 1
            continue
        if ch == "\\":
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if nxt in _VALID:
                result.append(ch)
                result.append(nxt)
                i += 2
            else:
                result.append("\\")
                result.append("\\")
                i += 1
            continue
        result.append(ch)
        i += 1
    return "".join(result)


# ============================================================================
# VALIDATORS
# ============================================================================


def validate_config_json(path: Optional[Path] = None) -> ValidationReport:
    """Validate core/config.json structure."""
    if path is None:
        path = BASE_DIR / "config.json"
    report = ValidationReport(file=str(path))

    if not path.is_file():
        report.add_error("$", "File not found")
        return report

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        report.add_error("$", f"Invalid JSON: {e}")
        return report

    if not isinstance(data, dict):
        report.add_error("$", "Root must be an object")
        return report

    # Check rules are string->string
    rules = {k: v for k, v in data.items() if not k.startswith("_")}
    if len(rules) == 0:
        report.add_error("$", "No translation rules found")

    for key, val in rules.items():
        if not isinstance(val, str):
            report.add_error(
                f"$.{key}",
                f"Value must be string, got {type(val).__name__}",
                severity="error",
            )

    # Check for duplicate values (multiple keys mapping to same output)
    seen_vals: Dict[str, str] = {}
    for key, val in rules.items():
        if val in seen_vals:
            report.add_error(
                f"$.{key}",
                f"Duplicate target '{val}' — also used by '{seen_vals[val]}'",
                severity="warning",
            )
        else:
            seen_vals[val] = key

    # Meta checks
    if "_version" not in data:
        report.add_error("$._version", "Missing _version metadata", "warning")

    return report


def validate_mcp_json(path: Optional[Path] = None) -> ValidationReport:
    """Validate .vscode/mcp.json structure."""
    if path is None:
        path = PROJECT_DIR / ".vscode" / "mcp.json"
    report = ValidationReport(file=str(path))

    if not path.is_file():
        report.add_error("$", "File not found")
        return report

    try:
        data = load_jsonc(path)
    except json.JSONDecodeError as e:
        report.add_error("$", f"Invalid JSON/JSONC: {e}")
        return report

    if not isinstance(data, dict):
        report.add_error("$", "Root must be an object")
        return report

    servers = data.get("servers", data.get("mcpServers", {}))
    if not isinstance(servers, dict):
        report.add_error("$.servers", "Must be an object")
        return report

    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            report.add_error(
                f"$.servers.{name}",
                f"Server config must be object, got {type(cfg).__name__}",
            )
            continue
        if "command" not in cfg:
            report.add_error(f"$.servers.{name}", "Missing 'command'")
        if "args" in cfg and not isinstance(cfg["args"], list):
            report.add_error(f"$.servers.{name}.args", "Must be array")

    return report


def validate_tasks_json(path: Optional[Path] = None) -> ValidationReport:
    """Validate .vscode/tasks.json basic structure."""
    if path is None:
        path = PROJECT_DIR / ".vscode" / "tasks.json"
    report = ValidationReport(file=str(path))

    if not path.is_file():
        report.add_error("$", "File not found")
        return report

    try:
        data = load_jsonc(path)
    except json.JSONDecodeError as e:
        report.add_error("$", f"Invalid JSON/JSONC: {e}")
        return report

    if not isinstance(data, dict):
        report.add_error("$", "Root must be an object")
        return report

    version = data.get("version")
    if version != "2.0.0":
        report.add_error("$.version", f"Expected '2.0.0', got '{version}'", "warning")

    tasks = data.get("tasks", [])
    if not isinstance(tasks, list):
        report.add_error("$.tasks", "Must be array")
        return report

    labels_seen = set()
    for i, task in enumerate(tasks):
        if not isinstance(task, dict):
            report.add_error(f"$.tasks[{i}]", "Must be object")
            continue
        label = task.get("label", "")
        if not label:
            report.add_error(f"$.tasks[{i}]", "Missing 'label'")
        elif label in labels_seen:
            report.add_error(f"$.tasks[{i}]", f"Duplicate label: '{label}'", "warning")
        else:
            labels_seen.add(label)
        if "type" not in task:
            report.add_error(f"$.tasks[{i}]", "Missing 'type'", "warning")

    return report


# ============================================================================
# MAIN
# ============================================================================


def validate_all() -> List[ValidationReport]:
    """Run all validators and return reports."""
    return [
        validate_config_json(),
        validate_mcp_json(),
        validate_tasks_json(),
    ]


def print_report(reports: List[ValidationReport]):
    """Print validation results to terminal."""
    if os.name == "nt":
        os.system("")
    G = "\033[92m"
    R = "\033[91m"
    Y = "\033[93m"
    B = "\033[1m"
    X = "\033[0m"

    all_valid = True
    for rpt in reports:
        icon = f"{G}✓{X}" if rpt.valid else f"{R}✗{X}"
        print(f"  {icon} {rpt.file}")
        for err in rpt.errors:
            c = R if err.severity == "error" else Y
            print(f"      {c}[{err.severity}]{X} {err.path}: {err.message}")
        if not rpt.valid:
            all_valid = False

    print()
    if all_valid:
        print(f"  {G}{B}All configs valid!{X}")
    else:
        print(f"  {R}{B}Validation errors found.{X}")
    print()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="leviathan-validate", description="LEVIATHAN VS — config validation"
    )
    parser.add_argument("--file", type=str, help="Validate a specific file")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if args.file:
        p = Path(args.file).resolve()
        name = p.name.lower()
        if "config" in name and "mcp" not in name and "task" not in name:
            reports = [validate_config_json(p)]
        elif "mcp" in name:
            reports = [validate_mcp_json(p)]
        elif "task" in name:
            reports = [validate_tasks_json(p)]
        else:
            print(f"Unknown config type: {p.name}", file=sys.stderr)
            sys.exit(1)
    else:
        reports = validate_all()

    if args.json:
        out = []
        for r in reports:
            out.append(
                {
                    "file": r.file,
                    "valid": r.valid,
                    "errors": [asdict(e) for e in r.errors],
                }
            )
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"\n\033[1m\033[96m  LEVIATHAN VS — Config Validator\033[0m\n")
        print_report(reports)

    has_errors = any(not r.valid for r in reports)
    sys.exit(1 if has_errors else 0)


if __name__ == "__main__":
    main()
