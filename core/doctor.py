#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - Doctor (Healthcheck & Diagnostics)
    Verifica integridade do ambiente, dependencias, configs e ferramentas.

    Uso:
        python core/doctor.py              # full check
        python core/doctor.py --json       # machine-readable output
        python core/doctor.py --fix        # tenta corrigir problemas simples

    Exit codes:
        0 = tudo OK
        1 = erros criticos encontrados
        2 = apenas avisos
================================================================================
"""

import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from __version__ import __version__ as VERSION
BASE_DIR = Path(__file__).parent.resolve()
PROJECT_DIR = BASE_DIR.parent


# ============================================================================
# DATA MODELS
# ============================================================================


@dataclass
class CheckResult:
    name: str
    status: str  # "ok", "warn", "fail", "skip"
    message: str
    fix_hint: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DoctorReport:
    timestamp: str = ""
    platform: str = ""
    python_version: str = ""
    project_dir: str = ""
    checks: List[CheckResult] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)

    def add(self, result: CheckResult):
        self.checks.append(result)

    def finalize(self):
        self.timestamp = datetime.now().isoformat()
        self.platform = (
            f"{platform.system()} {platform.release()} ({platform.machine()})"
        )
        self.python_version = platform.python_version()
        self.project_dir = str(PROJECT_DIR)
        counts = {"ok": 0, "warn": 0, "fail": 0, "skip": 0}
        for c in self.checks:
            counts[c.status] = counts.get(c.status, 0) + 1
        self.summary = counts

    @property
    def exit_code(self) -> int:
        if self.summary.get("fail", 0) > 0:
            return 1
        if self.summary.get("warn", 0) > 0:
            return 2
        return 0

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "platform": self.platform,
            "python_version": self.python_version,
            "project_dir": self.project_dir,
            "checks": [asdict(c) for c in self.checks],
            "summary": self.summary,
        }


# ============================================================================
# ANSI HELPERS
# ============================================================================


class _C:
    OK = "\033[92m"
    WARN = "\033[93m"
    FAIL = "\033[91m"
    SKIP = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    CYAN = "\033[96m"


_ICON = {
    "ok": f"{_C.OK}✓{_C.RESET}",
    "warn": f"{_C.WARN}!{_C.RESET}",
    "fail": f"{_C.FAIL}✗{_C.RESET}",
    "skip": f"{_C.SKIP}⊘{_C.RESET}",
}


def _enable_ansi():
    if os.name == "nt":
        os.system("")  # enables VT100 on Win10+


# ============================================================================
# INDIVIDUAL CHECKS
# ============================================================================


def check_python_version(report: DoctorReport):
    """Verifica versao Python >= 3.9."""
    v = sys.version_info
    if v >= (3, 9):
        report.add(
            CheckResult("Python Version", "ok", f"Python {v.major}.{v.minor}.{v.micro}")
        )
    elif v >= (3, 8):
        report.add(
            CheckResult(
                "Python Version",
                "warn",
                f"Python {v.major}.{v.minor}.{v.micro} — recomendado >= 3.9",
                fix_hint="Atualize Python: winget install Python.Python.3.12",
            )
        )
    else:
        report.add(
            CheckResult(
                "Python Version",
                "fail",
                f"Python {v.major}.{v.minor} nao suportado (minimo 3.8)",
                fix_hint="Instale Python 3.12+: winget install Python.Python.3.12",
            )
        )


def check_core_files(report: DoctorReport):
    """Verifica presenca dos arquivos essenciais do core."""
    required = {
        "config.json": BASE_DIR / "config.json",
        "translator.py": BASE_DIR / "translator.py",
        "http_toolkit.py": BASE_DIR / "http_toolkit.py",
        "mcp_server.py": BASE_DIR / "mcp_server.py",
    }
    missing = []
    for name, path in required.items():
        if not path.is_file():
            missing.append(name)
    if not missing:
        report.add(
            CheckResult(
                "Core Files",
                "ok",
                f"Todos os {len(required)} arquivos essenciais presentes",
            )
        )
    else:
        report.add(
            CheckResult(
                "Core Files",
                "fail",
                f"Faltando: {', '.join(missing)}",
                fix_hint="Re-clone o repositorio ou verifique core/",
            )
        )


def check_config_json(report: DoctorReport):
    """Valida sintaxe e estrutura minima de config.json."""
    cfg_path = BASE_DIR / "config.json"
    if not cfg_path.is_file():
        report.add(CheckResult("config.json", "skip", "Arquivo nao encontrado"))
        return
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        report.add(
            CheckResult(
                "config.json",
                "fail",
                f"JSON invalido: {e}",
                fix_hint="Corrija a sintaxe JSON em core/config.json",
            )
        )
        return

    # Count real rules (exclude _meta keys)
    rules = {k: v for k, v in data.items() if not k.startswith("_")}
    meta = {k: v for k, v in data.items() if k.startswith("_")}
    version = meta.get("_version", "unknown")

    if len(rules) < 10:
        report.add(
            CheckResult(
                "config.json",
                "warn",
                f"Apenas {len(rules)} regras — pode estar incompleto",
                details={"rules": len(rules), "version": version},
            )
        )
    else:
        report.add(
            CheckResult(
                "config.json",
                "ok",
                f"{len(rules)} regras de traducao (v{version})",
                details={"rules": len(rules), "version": version},
            )
        )


def check_vscode_configs(report: DoctorReport):
    """Valida .vscode/*.json (sintaxe)."""
    vscode_dir = PROJECT_DIR / ".vscode"
    if not vscode_dir.is_dir():
        report.add(CheckResult("VS Code Configs", "skip", ".vscode/ nao encontrado"))
        return

    configs = [
        "settings.json",
        "tasks.json",
        "mcp.json",
        "extensions.json",
        "launch.json",
        "keybindings.json",
    ]
    errors = []
    found = 0
    for name in configs:
        path = vscode_dir / name
        if not path.is_file():
            continue
        found += 1
        try:
            text = path.read_text(encoding="utf-8")
            # Strip JSONC comments, then fix invalid escapes
            text = _strip_jsonc_comments(text)
            text = _sanitize_json_escapes(text)
            json.loads(text)
        except json.JSONDecodeError:
            # Retry with strict=False (allows control chars in strings)
            try:
                json.loads(text, strict=False)
            except json.JSONDecodeError as e2:
                errors.append(f"{name}: {e2}")

    if errors:
        report.add(
            CheckResult(
                "VS Code Configs",
                "fail",
                f"JSON invalido em: {'; '.join(errors)}",
                fix_hint="Corrija os arquivos .vscode/ indicados",
            )
        )
    elif found > 0:
        report.add(
            CheckResult("VS Code Configs", "ok", f"{found} configs validos em .vscode/")
        )
    else:
        report.add(
            CheckResult("VS Code Configs", "warn", "Nenhum config VS Code encontrado")
        )


def check_mcp_json(report: DoctorReport):
    """Valida que mcp.json tem servers configurados corretamente."""
    mcp_path = PROJECT_DIR / ".vscode" / "mcp.json"
    if not mcp_path.is_file():
        report.add(CheckResult("mcp.json Servers", "skip", "mcp.json nao encontrado"))
        return
    try:
        text = _strip_jsonc_comments(mcp_path.read_text(encoding="utf-8"))
        data = json.loads(text)
    except Exception as e:
        report.add(CheckResult("mcp.json Servers", "fail", f"Erro: {e}"))
        return

    servers = data.get("servers", data.get("mcpServers", {}))
    if not isinstance(servers, dict) or not servers:
        report.add(CheckResult("mcp.json Servers", "warn", "Nenhum server definido"))
        return

    broken = []
    for name, cfg in servers.items():
        if isinstance(cfg, dict) and "command" in cfg:
            args = cfg.get("args", [])
            # Check if the Python script file exists
            for arg in args:
                if arg.endswith(".py"):
                    # Resolve relative to project dir
                    script = PROJECT_DIR / arg.replace("/", os.sep)
                    if not script.is_file():
                        # Try as-is (absolute or module path)
                        if not Path(arg).is_file():
                            broken.append(f"{name}: {arg}")

    if broken:
        report.add(
            CheckResult(
                "mcp.json Servers",
                "warn",
                f"{len(broken)} scripts nao encontrados: {', '.join(broken[:5])}",
                details={"total_servers": len(servers), "broken": broken},
            )
        )
    else:
        report.add(
            CheckResult(
                "mcp.json Servers", "ok", f"{len(servers)} servers configurados"
            )
        )


def check_external_tool(
    report: DoctorReport,
    name: str,
    command: str,
    version_flag: str = "--version",
    required: bool = False,
):
    """Verifica se uma ferramenta externa esta instalada."""
    path = shutil.which(command)
    if path:
        try:
            result = subprocess.run(
                [command, version_flag], capture_output=True, text=True, timeout=10
            )
            ver = (result.stdout.strip() or result.stderr.strip())[:80]
            report.add(
                CheckResult(name, "ok", ver or "installed", details={"path": path})
            )
        except Exception:
            report.add(
                CheckResult(name, "ok", f"found at {path}", details={"path": path})
            )
    else:
        status = "fail" if required else "warn"
        report.add(
            CheckResult(
                name,
                status,
                f"{command} nao encontrado no PATH",
                fix_hint=f"Instale {name} e adicione ao PATH",
            )
        )


def check_pip_packages(report: DoctorReport):
    """Verifica pacotes Python essenciais."""
    packages = {
        "aiohttp": False,
        "requests": False,
        "colorama": False,
        "rich": False,
    }
    for pkg in packages:
        try:
            __import__(pkg)
            packages[pkg] = True
        except ImportError:
            pass

    missing = [p for p, ok in packages.items() if not ok]
    if not missing:
        report.add(
            CheckResult(
                "Python Packages",
                "ok",
                f"Todos os {len(packages)} pacotes essenciais instalados",
            )
        )
    else:
        report.add(
            CheckResult(
                "Python Packages",
                "warn",
                f"Faltando: {', '.join(missing)}",
                fix_hint=f"pip install {' '.join(missing)}",
            )
        )


def check_permissions(report: DoctorReport):
    """Verifica permissoes de escrita nos diretorios-chave."""
    dirs = [BASE_DIR, PROJECT_DIR / ".vscode"]
    issues = []
    for d in dirs:
        if d.is_dir() and not os.access(d, os.W_OK):
            issues.append(str(d))
    if issues:
        report.add(
            CheckResult("Permissions", "warn", f"Sem escrita em: {', '.join(issues)}")
        )
    else:
        report.add(
            CheckResult("Permissions", "ok", "Diretorios com permissao de escrita")
        )


# ============================================================================
# HELPERS
# ============================================================================


from jsonc import load_jsonc  # noqa: E402
from jsonc import sanitize_json_escapes as _sanitize_json_escapes  # noqa: E402
from jsonc import strip_jsonc_comments as _strip_jsonc_comments  # noqa: E402





# ============================================================================
# MAIN DOCTOR
# ============================================================================


def run_doctor(json_output: bool = False, fix_mode: bool = False) -> DoctorReport:
    """Executa todas as verificacoes e retorna o report."""
    report = DoctorReport()

    # Core checks
    check_python_version(report)
    check_core_files(report)
    check_config_json(report)
    check_vscode_configs(report)
    check_mcp_json(report)
    check_pip_packages(report)
    check_permissions(report)

    # External tools (non-blocking)
    tools = [
        ("ADB", "adb"),
        ("Frida", "frida"),
        ("Ghidra (analyzeHeadless)", "analyzeHeadless"),
        ("JADX", "jadx"),
        ("APKTool", "apktool"),
        ("Radare2", "radare2"),
        ("Wireshark (tshark)", "tshark"),
        ("MITMProxy", "mitmproxy"),
        ("Nuclei", "nuclei"),
        ("Nmap", "nmap"),
        ("Hashcat", "hashcat"),
        ("Objection", "objection"),
        ("John the Ripper", "john"),
    ]
    for display, cmd in tools:
        check_external_tool(report, display, cmd)

    # Emulators (Windows-specific)
    if platform.system() == "Windows":
        for emu_name, emu_cmd in [
            ("LDPlayer", "ldconsole.exe"),
            ("BlueStacks", "HD-Player.exe"),
        ]:
            check_external_tool(report, emu_name, emu_cmd)

    report.finalize()
    return report


def print_report(report: DoctorReport):
    """Imprime o report formatado no terminal."""
    _enable_ansi()
    print(f"\n{_C.BOLD}{_C.CYAN}{'='*60}")
    print(f"  LEVIATHAN VS — Doctor (Healthcheck)")
    print(f"{'='*60}{_C.RESET}\n")
    print(f"  Platform : {report.platform}")
    print(f"  Python   : {report.python_version}")
    print(f"  Project  : {report.project_dir}")
    print(f"  Time     : {report.timestamp}\n")

    for check in report.checks:
        icon = _ICON.get(check.status, "?")
        print(f"  {icon} {check.name}: {check.message}")
        if check.fix_hint and check.status in ("fail", "warn"):
            print(f"      {_C.SKIP}→ {check.fix_hint}{_C.RESET}")

    # Summary
    s = report.summary
    print(
        f"\n{_C.BOLD}  Summary: "
        f"{_C.OK}{s.get('ok',0)} ok{_C.RESET}  "
        f"{_C.WARN}{s.get('warn',0)} warn{_C.RESET}  "
        f"{_C.FAIL}{s.get('fail',0)} fail{_C.RESET}  "
        f"{_C.SKIP}{s.get('skip',0)} skip{_C.RESET}\n"
    )

    if report.exit_code == 0:
        print(f"  {_C.OK}{_C.BOLD}All checks passed!{_C.RESET}\n")
    elif report.exit_code == 2:
        print(f"  {_C.WARN}{_C.BOLD}Some warnings — see hints above.{_C.RESET}\n")
    else:
        print(
            f"  {_C.FAIL}{_C.BOLD}Critical issues found — fix before using.{_C.RESET}\n"
        )


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="leviathan-doctor", description="LEVIATHAN VS — healthcheck & diagnostics"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output as JSON (machine-readable)"
    )
    parser.add_argument(
        "--fix", action="store_true", help="Attempt to auto-fix simple issues"
    )
    args = parser.parse_args()

    report = run_doctor(json_output=args.json, fix_mode=args.fix)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print_report(report)

    sys.exit(report.exit_code)


if __name__ == "__main__":
    main()
