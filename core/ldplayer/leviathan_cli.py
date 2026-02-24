#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - Interactive CLI v1.0
    Natural language command interface for LDPlayer automation

    Accepts commands in Portuguese or English like:
        "abra o emulador"
        "abra o app com.example.game"
        "intercepte tudo"
        "analise"
        "mostre o status"
        "pare tudo"

    Usage:
        python -m core.ldplayer.leviathan_cli
        python -m core.ldplayer.leviathan_cli --config path/to/config.json
        python -m core.ldplayer.leviathan_cli --auto com.example.app

    Author: ThiagoFrag / LEVIATHAN VS
    Version: 1.0.0
================================================================================
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Fix imports when run as module or script ──
_BASE_DIR = Path(__file__).resolve().parent
_PROJECT_DIR = _BASE_DIR.parent.parent

if str(_PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(_PROJECT_DIR))


# ═══════════════════════════════════════════════════════════════════════
#  COLORS / UI
# ═══════════════════════════════════════════════════════════════════════


class Colors:
    """ANSI color codes."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"

    @staticmethod
    def enabled():
        """Check if terminal supports colors."""
        if os.name == "nt":
            os.system("")  # Enable ANSI on Windows
        return True


def c(text: str, color: str) -> str:
    """Colorize text."""
    return f"{color}{text}{Colors.RESET}"


def banner():
    """Print the startup banner."""
    print(
        c(
            r"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ██╗     ███████╗██╗   ██╗██╗ █████╗ ████████╗██╗  ██╗      ║
    ║   ██║     ██╔════╝██║   ██║██║██╔══██╗╚══██╔══╝██║  ██║      ║
    ║   ██║     █████╗  ██║   ██║██║███████║   ██║   ███████║      ║
    ║   ██║     ██╔══╝  ╚██╗ ██╔╝██║██╔══██║   ██║   ██╔══██║      ║
    ║   ███████╗███████╗ ╚████╔╝ ██║██║  ██║   ██║   ██║  ██║      ║
    ║   ╚══════╝╚══════╝  ╚═══╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝      ║
    ║                                                               ║
    ║              INTERACTIVE COMMAND CENTER v1.0                   ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """,
            Colors.CYAN,
        )
    )
    print(c("  Digite comandos em linguagem natural (PT-BR / EN)", Colors.DIM))
    print(
        c("  Ex: 'abra o emulador', 'intercepte com.app.game', 'analise'", Colors.DIM)
    )
    print(c("  Digite 'help' para ver todos os comandos\n", Colors.DIM))


def print_ok(msg: str):
    print(c(f"  ✓ {msg}", Colors.GREEN))


def print_err(msg: str):
    print(c(f"  ✗ {msg}", Colors.RED))


def print_info(msg: str):
    print(c(f"  ℹ {msg}", Colors.BLUE))


def print_warn(msg: str):
    print(c(f"  ⚠ {msg}", Colors.YELLOW))


def print_step(step: int, total: int, msg: str):
    print(c(f"  [{step}/{total}] {msg}", Colors.MAGENTA))


def print_data(data: Any, indent: int = 4):
    """Pretty print JSON data."""
    if isinstance(data, (dict, list)):
        text = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        for line in text.split("\n"):
            print(" " * indent + c(line, Colors.DIM))
    else:
        print(" " * indent + str(data))


def print_report(report: Dict):
    """Pretty print analysis report."""
    print()
    print(c("  ╔══════════════════════════════════════════════════╗", Colors.CYAN))
    print(c("  ║              ANALYSIS REPORT                     ║", Colors.CYAN))
    print(c("  ╚══════════════════════════════════════════════════╝", Colors.CYAN))

    summary = report.get("summary", {})
    print(c(f"\n  Target:   {report.get('target', 'N/A')}", Colors.WHITE))
    print(c(f"  PID:      {report.get('pid', 'N/A')}", Colors.WHITE))
    print(c(f"  Duration: {report.get('duration', 'N/A')}", Colors.WHITE))

    print(c("\n  ─── Summary ───", Colors.YELLOW))
    print(f"    Total Events:      {summary.get('total_events', 0)}")
    print(f"    Network Requests:  {summary.get('network_requests', 0)}")
    print(f"    Crypto Operations: {summary.get('crypto_operations', 0)}")
    print(f"    File Operations:   {summary.get('file_operations', 0)}")
    print(f"    Security Findings: {summary.get('security_findings', 0)}")

    # Network
    net = report.get("network_analysis", {})
    if net:
        print(c("\n  ─── Network ───", Colors.YELLOW))
        print(f"    Requests: {net.get('total_requests', 0)}")
        print(f"    Unique URLs: {net.get('unique_urls', 0)}")
        if net.get("domains"):
            print(c("    Top Domains:", Colors.DIM))
            for domain, count in list(net["domains"].items())[:10]:
                print(f"      {domain}: {count}")
        if net.get("methods"):
            print(f"    Methods: {net['methods']}")

    # Crypto
    crypto = report.get("crypto_analysis", {})
    if crypto:
        print(c("\n  ─── Crypto ───", Colors.YELLOW))
        print(f"    Operations: {crypto.get('total_operations', 0)}")
        if crypto.get("algorithms"):
            print(f"    Algorithms: {crypto['algorithms']}")
        if crypto.get("key_sizes"):
            print(f"    Key Sizes: {crypto['key_sizes']}")

    # File I/O
    fio = report.get("file_io_analysis", {})
    if fio:
        print(c("\n  ─── File I/O ───", Colors.YELLOW))
        print(f"    Operations: {fio.get('total_operations', 0)}")
        print(f"    Reads: {fio.get('reads', 0)}, Writes: {fio.get('writes', 0)}")
        if fio.get("files_sample"):
            print(c("    Files:", Colors.DIM))
            for f in fio["files_sample"][:10]:
                print(f"      {f}")

    # Security
    findings = report.get("security_findings", [])
    if findings:
        print(c("\n  ─── Security Findings ───", Colors.RED))
        for f in findings:
            sev = f.get("severity", "INFO")
            sev_color = {
                "HIGH": Colors.RED,
                "MEDIUM": Colors.YELLOW,
                "LOW": Colors.BLUE,
                "INFO": Colors.DIM,
            }.get(sev, Colors.DIM)
            print(f"    {c(f'[{sev}]', sev_color)} {f.get('description', '')}")

    print()


# ═══════════════════════════════════════════════════════════════════════
#  COMMAND PARSER (Natural Language)
# ═══════════════════════════════════════════════════════════════════════


class CommandParser:
    """
    Parses natural language commands in Portuguese or English
    and maps them to orchestrator operations.
    """

    # Patterns: (compiled_regex, action_name, description)
    PATTERNS: List[Tuple[str, str, str]] = [
        # ── FULL PIPELINE ──
        (
            r"(full|completo|pipeline|tudo)\s+(intercept|intercepta|intercepte|analisa|analise)\w*\s+(.+)",
            "full_intercept",
            "Full pipeline: launch → app → bypass → intercept → analyze",
        ),
        # ── EMULATOR ──
        (
            r"(abr[aei]|open|launch|inici[aeo]|start|liga|ligar|rode?|rodar?)\s+(o\s+)?(emulador|emu|ldplayer|instancia|instance)",
            "launch_emulator",
            "Launch LDPlayer emulator",
        ),
        (
            r"(fech[aeo]|close|quit|par[aeo]|stop|deslig|mata|kill)\s+(o\s+)?(emulador|emu|ldplayer|instancia|instance)",
            "close_emulator",
            "Close LDPlayer emulator",
        ),
        # ── APP ──
        (
            r"(abr[aei]|open|launch|inici[aeo]|start|rod[aeo]|run)\s+(o\s+)?(app|aplicativo|jogo|game|apk)?\s*(.+)",
            "open_app",
            "Open an app on the emulator",
        ),
        (
            r"(fech[aeo]|close|par[aeo]|stop|mata|kill)\s+(o\s+)?(app|aplicativo|jogo|game)(\s+(.+))?",
            "close_app",
            "Close the running app",
        ),
        # ── INTERCEPT ──
        (
            r"(intercept[aeo]|hook|capture?|captur[aeo]|espion[aeo]|sniff)\s+(tudo|everything|all|todo)",
            "intercept_all",
            "Start intercepting everything",
        ),
        (
            r"(intercept[aeo]|hook|capture?|captur[aeo]|espion[aeo]|sniff)\s+(.+)",
            "intercept_target",
            "Intercept a specific app",
        ),
        # ── BYPASS ──
        (
            r"(bypass|burla|burle|desativ[aeo]|desbloqu[aeo]|remove?)\s+(prote[çc][ãa]o|protection|ssl|root|frida|emula|all|tud[ao])",
            "bypass",
            "Apply protection bypasses",
        ),
        (
            r"(scan|escane[aeo]|verifi[cq]|detect)\s+(prote[çc]|protection|security|seguran[çc])",
            "scan_protections",
            "Scan app for protections",
        ),
        # ── ANALYZE ──
        (
            r"(analis[aeo]|analyz?e?|report|relator|mostr[aeo]|show)\s+(resultado|result|dados|data|analise|analysis|report|relatorio|tudo)$",
            "analyze",
            "Analyze intercepted data",
        ),
        (
            r"^(analis[aeo]|analyz?e?|report|relatorio)$",
            "analyze",
            "Analyze intercepted data",
        ),
        # ── COLLECT ──
        (
            r"(colet[aeo]|collect|peg[aeo]|get)\s+(dados|data|mensagen|message|tudo)",
            "collect",
            "Collect intercepted messages",
        ),
        (r"(esper[aeo]|wait|aguard)\s+(\d+)", "wait", "Wait N seconds and collect"),
        # ── LIST / INFO ──
        (
            r"(list[aeo]|listar?|show|mostr[aeo])\s+(app|aplicativo|pacote|package|jogo|game)",
            "list_apps",
            "List installed apps",
        ),
        (
            r"(busc[aeo]|find|search|procur[aeo]|pesquis[aeo])\s+(app|aplicativo|pacote|package)?\s*(.+)",
            "find_app",
            "Search for an app",
        ),
        (
            r"(info|informa[çc]|detail|detalh)\w*\s*(do\s+)?(app|aplicativo|pacote)?(\s+(.+))?",
            "app_info",
            "Get app info",
        ),
        (r"(process|processo)\w*", "list_processes", "List running processes"),
        # ── FRIDA ──
        (
            r"(attach|conecta|acopla)\s+(frida\s+)?(ao?\s+)?(.+)",
            "attach_frida",
            "Attach Frida to app",
        ),
        (r"(detach|desconect|desacopl)\w*\s*(frida)?", "detach_frida", "Detach Frida"),
        (
            r"(inject|injet[aeo]|rod[aeo]|run)\s+(script)\s+(.+)",
            "inject_script",
            "Inject a Frida script",
        ),
        (
            r"(enum|enumera|list)\w*\s+(class|classe)\w*\s*(.*)",
            "enum_classes",
            "Enumerate Java classes",
        ),
        (
            r"(hook|ganch)\w*\s+(.+?)(\s*\.\s*(.+))?$",
            "hook",
            "Hook a Java class/method",
        ),
        # ── SCREEN ──
        (
            r"(screenshot|print|captur[aeo]\s+tela|tela)",
            "screenshot",
            "Take a screenshot",
        ),
        (r"(logcat|log|logs?)", "logcat", "Show logcat"),
        # ── STATUS / CONTROL ──
        (r"(status|estado|state)", "status", "Show current status"),
        (
            r"(par[aeo]|stop|encerr[aeo]|finaliz|quit|exit|sai[ra])\s+(tudo|all|everything)",
            "stop_all",
            "Stop everything",
        ),
        (r"(reset|limpa|clear|restart)", "reset", "Reset orchestrator state"),
        (
            r"(salv[aeo]|save|export)\s+(report|relatorio|dados|data|resultado)",
            "save_report",
            "Save report to file",
        ),
        # ── HELP ──
        (r"^(help|ajuda|comando|commands?|\?|h)$", "help", "Show help"),
        (r"^(exit|quit|sai[ra]|tchau|bye|q)$", "exit", "Exit the CLI"),
    ]

    def __init__(self):
        self._compiled = [
            (re.compile(pattern, re.IGNORECASE), action, desc)
            for pattern, action, desc in self.PATTERNS
        ]

    def parse(self, text: str) -> Tuple[str, Dict[str, Any]]:
        """
        Parse user input and return (action, params).
        Returns ("unknown", {}) if no match.
        """
        text = text.strip()
        if not text:
            return ("empty", {})

        for regex, action, _desc in self._compiled:
            match = regex.search(text)
            if match:
                return (action, {"match": match, "groups": match.groups(), "raw": text})

        # Fallback: check if it looks like a package name
        if re.match(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$", text, re.IGNORECASE):
            return ("open_app", {"groups": ("open", "", "", text), "raw": text})

        return ("unknown", {"raw": text})

    def get_help(self) -> List[Tuple[str, str]]:
        """Return list of (action, description)."""
        seen = set()
        result = []
        for _, action, desc in self.PATTERNS:
            if action not in seen:
                seen.add(action)
                result.append((action, desc))
        return result


# ═══════════════════════════════════════════════════════════════════════
#  INTERACTIVE CLI
# ═══════════════════════════════════════════════════════════════════════


class LeviathanCLI:
    """Interactive command-line interface for the orchestrator."""

    def __init__(self, config_path: Optional[str] = None):
        from core.ldplayer.orchestrator import Orchestrator

        self.orch = Orchestrator(config_path=config_path)
        self.parser = CommandParser()
        self.running = True

    def run(self):
        """Main loop."""
        Colors.enabled()
        banner()

        # Show initial state
        self._cmd_status({})

        while self.running:
            try:
                prompt = c("\n  LEVIATHAN", Colors.CYAN) + c(" > ", Colors.BOLD)
                user_input = input(prompt).strip()
                if not user_input:
                    continue

                action, params = self.parser.parse(user_input)
                handler = getattr(self, f"_cmd_{action}", None)
                if handler:
                    handler(params)
                else:
                    print_warn(f"Comando não reconhecido: '{user_input}'")
                    print_info("Digite 'help' para ver os comandos disponíveis")

            except KeyboardInterrupt:
                print(
                    c("\n\n  Ctrl+C detectado. Use 'exit' para sair.\n", Colors.YELLOW)
                )
            except EOFError:
                self.running = False
                print()

        self._cleanup()

    # ─────────────────────────────────────────────────────────────────────
    # COMMAND HANDLERS
    # ─────────────────────────────────────────────────────────────────────

    def _cmd_help(self, params):
        print(c("\n  ══════════════════════════════════════════════════", Colors.CYAN))
        print(c("  COMANDOS DISPONÍVEIS", Colors.CYAN + Colors.BOLD))
        print(c("  ══════════════════════════════════════════════════\n", Colors.CYAN))

        commands = {
            "Emulador": [
                ("abra o emulador", "Inicia o LDPlayer"),
                ("feche o emulador", "Fecha o LDPlayer"),
            ],
            "Aplicativo": [
                ("abra o app com.example.game", "Abre um app pelo package name"),
                ("abra o app [nome]", "Busca e abre o app pelo nome"),
                ("feche o app", "Fecha o app ativo"),
                ("liste apps", "Lista apps instalados"),
                ("busque app [nome]", "Busca app por nome"),
                ("info app", "Informações do app ativo"),
            ],
            "Interceptação": [
                ("intercepte tudo", "Ativa todas as interceptações"),
                ("intercepte [package]", "Abre, conecta e intercepta um app"),
                (
                    "full intercept [package]",
                    "Pipeline completo (emu → app → bypass → intercept → analise)",
                ),
                ("espere [N]", "Espera N segundos coletando dados"),
                ("colete dados", "Coleta mensagens interceptadas"),
            ],
            "Proteção": [
                ("bypass ssl/root/emulator/frida/all", "Aplica bypass específico"),
                ("scan proteção", "Escaneia proteções do app"),
            ],
            "Frida": [
                ("attach frida [package]", "Conecta Frida ao app"),
                ("detach frida", "Desconecta Frida"),
                (
                    "inject script [nome]",
                    "Injeta script (ssl, root, network, crypto, game, universal)",
                ),
                ("enum classes [filtro]", "Enumera classes Java"),
                ("hook [Classe.metodo]", "Faz hook em classe/método"),
            ],
            "Análise": [
                ("analise", "Analisa dados interceptados"),
                ("salve report", "Salva relatório em arquivo JSON"),
                ("screenshot", "Captura tela do emulador"),
                ("logcat", "Mostra logs do Android"),
            ],
            "Controle": [
                ("status", "Mostra estado atual"),
                ("pare tudo", "Para tudo (Frida, app, emulador)"),
                ("reset", "Limpa tudo e recomeça"),
                ("exit", "Sai do CLI"),
            ],
        }

        for category, cmds in commands.items():
            print(c(f"  {category}:", Colors.YELLOW + Colors.BOLD))
            for cmd, desc in cmds:
                print(f"    {c(cmd, Colors.GREEN):50s}  {c(desc, Colors.DIM)}")
            print()

    def _cmd_empty(self, params):
        pass

    def _cmd_unknown(self, params):
        raw = params.get("raw", "")
        print_warn(f"Não entendi: '{raw}'")
        print_info("Tente 'help' para ver os comandos ou use um package name direto")

    def _cmd_exit(self, params):
        print_info("Encerrando Leviathan CLI...")
        self.running = False

    # ── Emulator ──

    def _cmd_launch_emulator(self, params):
        print_step(1, 1, "Iniciando emulador LDPlayer...")
        result = self.orch.launch_emulator()
        if result.get("success"):
            if result.get("was_running"):
                print_ok("Emulador já estava rodando")
            else:
                print_ok(f"Emulador iniciado em {result.get('boot_time', '?')}s")
        else:
            print_err(f"Falha: {result.get('error')}")

    def _cmd_close_emulator(self, params):
        result = self.orch.stop_all(close_emulator=True)
        print_ok(
            "Emulador fechado" if result.get("emulator_closed") else "Comando enviado"
        )

    # ── App ──

    def _cmd_open_app(self, params):
        groups = params.get("groups", ())
        # The package/name is typically the last non-empty group
        target = ""
        for g in reversed(groups):
            if (
                g
                and g.strip()
                and g.strip().lower()
                not in (
                    "o",
                    "app",
                    "aplicativo",
                    "jogo",
                    "game",
                    "apk",
                    "abra",
                    "open",
                    "launch",
                    "inicie",
                    "start",
                    "rode",
                    "run",
                )
            ):
                target = g.strip()
                break

        if not target:
            print_warn(
                "Especifique o app. Ex: 'abra nubank' ou 'abra o app com.example.game'"
            )
            return

        # Smart resolve: try known database + package search
        print_info(f"Resolvendo '{target}'...")
        resolved = self.orch.resolve_app(target)

        if resolved:
            if resolved != target:
                print_ok(f"'{target}' → {c(resolved, Colors.CYAN)}")
            target = resolved
        else:
            # Fallback: search installed apps
            matches = self.orch.find_app(target)
            if not matches:
                print_err(f"App não encontrado: '{target}'")
                print_info(
                    "Tente o nome exato ou o package name (ex: com.nu.production)"
                )
                return
            if len(matches) == 1:
                target = matches[0]
                print_ok(f"Encontrado: {target}")
            else:
                print_info(f"Encontrados {len(matches)} apps:")
                for i, pkg in enumerate(matches[:15], 1):
                    print(f"    {c(str(i), Colors.CYAN)}. {pkg}")
                try:
                    choice = input(c("  Escolha (número): ", Colors.BOLD)).strip()
                    idx = int(choice) - 1
                    if 0 <= idx < len(matches):
                        target = matches[idx]
                    else:
                        print_warn("Opção inválida")
                        return
                except (ValueError, EOFError):
                    print_warn("Cancelado")
                    return

        # Open the app
        total_steps = 4
        step = 1

        # Ensure ADB is connected
        if not self.orch._state["adb_connected"]:
            print_step(step, total_steps, "Conectando ADB...")
            adb_result = self.orch.connect_adb()
            if not adb_result.get("success"):
                print_err(f"ADB falhou: {adb_result.get('error')}")
                return
            print_ok("ADB conectado")
        step += 1

        print_step(step, total_steps, f"Abrindo {target}...")
        result = self.orch.open_app(target)
        if result.get("success"):
            print_ok(f"App aberto: {target} (PID: {result.get('pid', '?')})")
        else:
            print_err(f"Falha ao abrir: {result.get('error')}")

    def _cmd_close_app(self, params):
        groups = params.get("groups", ())
        pkg = None
        # Try to extract package from groups
        for g in groups:
            if g and "." in g:
                pkg = g.strip()
                break

        result = self.orch.close_app(pkg)
        if result.get("success"):
            print_ok(f"App fechado: {result.get('package')}")
        else:
            print_err(result.get("error", "Falha ao fechar app"))

    def _cmd_list_apps(self, params):
        print_info("Listando apps instalados (third-party)...")
        try:
            apps = self.orch.list_apps()
            if apps:
                print_ok(f"{len(apps)} apps encontrados:")
                for pkg in apps[:30]:
                    print(f"    {pkg}")
                if len(apps) > 30:
                    print(c(f"    ... e mais {len(apps) - 30}", Colors.DIM))
            else:
                print_warn("Nenhum app encontrado")
        except Exception as e:
            print_err(str(e))

    def _cmd_find_app(self, params):
        groups = params.get("groups", ())
        keyword = groups[-1].strip() if groups else ""
        if not keyword:
            print_warn("Especifique o que buscar. Ex: 'busque app game'")
            return

        print_info(f"Buscando '{keyword}'...")
        matches = self.orch.find_app(keyword)
        if matches:
            print_ok(f"{len(matches)} resultado(s):")
            for pkg in matches[:20]:
                print(f"    {pkg}")
        else:
            print_warn(f"Nenhum app com '{keyword}'")

    def _cmd_app_info(self, params):
        groups = params.get("groups", ())
        pkg = None
        for g in groups:
            if g and "." in str(g):
                pkg = g.strip()
        result = self.orch.app_info(pkg)
        print_data(result)

    def _cmd_list_processes(self, params):
        try:
            self.orch._require("adb")
            procs = self.orch.adb.list_running_processes()
            print_ok(f"{len(procs)} processos rodando")
            for p in procs[:20]:
                print(f"    {p.get('pid', '?'):>6}  {p.get('name', '?')}")
        except Exception as e:
            print_err(str(e))

    # ── Intercept ──

    def _cmd_intercept_all(self, params):
        if not self.orch._state.get("frida_attached"):
            print_warn("Frida não está conectado. Conectando...")
            pkg = self.orch._state.get("target_package")
            if not pkg:
                print_err("Nenhum app alvo. Use 'abra o app [package]' primeiro.")
                return
            self._ensure_frida_attached(pkg)

        print_step(1, 2, "Aplicando bypasses...")
        bp = self.orch.apply_bypasses()
        print_ok(f"Bypasses: {bp.get('applied', 0)}/{bp.get('total', 0)}")

        print_step(2, 2, "Ativando interceptações...")
        result = self.orch.start_interceptions()
        active = result.get("active", [])
        print_ok(f"Interceptando: {', '.join(active)}")
        print_info("Use 'analise' para ver os dados ou 'espere [N]' para coletar mais")

    def _cmd_intercept_target(self, params):
        groups = params.get("groups", ())
        target = groups[-1].strip() if groups else ""
        if not target or target.lower() in ("tudo", "everything", "all", "todo"):
            self._cmd_intercept_all(params)
            return

        # Full intercept on target — resolve name first
        resolved = self.orch.resolve_app(target)
        if resolved:
            if resolved != target:
                print_ok(f"'{target}' → {c(resolved, Colors.CYAN)}")
            target = resolved
        else:
            print_err(f"App não encontrado: '{target}'")
            return

        print_info(f"Pipeline completo para {target}...")
        result = self.orch.full_intercept(target, wait_time=3, auto_analyze=False)

        if result.get("success"):
            for step in result.get("steps", []):
                name = step.get("step", "?")
                ok = step.get("success", True)
                if ok:
                    print_ok(name)
                else:
                    print_err(f"{name}: {step.get('error', '?')}")
            print_ok("Pipeline completo! Use 'analise' para ver os dados")
        else:
            print_err(f"Pipeline falhou: {result.get('error')}")

    def _cmd_full_intercept(self, params):
        groups = params.get("groups", ())
        target = groups[-1].strip() if groups else ""
        if not target:
            pkg = self.orch._state.get("target_package")
            if pkg:
                target = pkg
            else:
                print_warn("Especifique o app. Ex: 'full intercept com.example.game'")
                return

        print_info(f"⚡ FULL INTERCEPT: {target}")
        print_info("Isso vai: Emulador → App → Bypass → Intercept → Análise")

        result = self.orch.full_intercept(target, wait_time=5, auto_analyze=True)
        if result.get("success"):
            for step in result.get("steps", []):
                name = step.get("step", "?")
                ok = step.get("success", True)
                if ok:
                    print_ok(name)
                else:
                    print_warn(f"{name}: {step.get('error', 'partial')}")

            # Show report
            if result.get("analysis"):
                print_report(result["analysis"])
        else:
            print_err(f"Pipeline falhou: {result.get('error')}")
            for step in result.get("steps", []):
                print_info(
                    f"  {step.get('step')}: {'✓' if step.get('success') else '✗'}"
                )

    # ── Bypass ──

    def _cmd_bypass(self, params):
        groups = params.get("groups", ())
        raw = params.get("raw", "").lower()

        bypasses = None
        if "all" in raw or "tud" in raw:
            bypasses = ["all"]
        else:
            bp_list = []
            if "ssl" in raw:
                bp_list.append("ssl")
            if "root" in raw:
                bp_list.append("root")
            if "emula" in raw:
                bp_list.append("emulator")
            if "frida" in raw:
                bp_list.append("frida")
            if "integri" in raw:
                bp_list.append("integrity")
            if bp_list:
                bypasses = bp_list

        if not self.orch._state.get("frida_attached"):
            print_warn("Frida não conectado. Tentando conectar...")
            pkg = self.orch._state.get("target_package")
            if pkg:
                self._ensure_frida_attached(pkg)
            else:
                print_err("Sem app alvo. Use 'abra o app' primeiro")
                return

        result = self.orch.apply_bypasses(bypasses)
        if result.get("success"):
            print_ok(
                f"Bypasses aplicados: {result.get('applied')}/{result.get('total')}"
            )
        else:
            print_err(f"Falha: {result.get('error')}")

    def _cmd_scan_protections(self, params):
        try:
            result = self.orch.scan_protections()
            print_data(result)
        except Exception as e:
            print_err(str(e))

    # ── Frida ──

    def _cmd_attach_frida(self, params):
        groups = params.get("groups", ())
        target = None
        for g in reversed(groups):
            if g and g.strip() and g.strip().lower() not in ("frida", "ao", "a", "o"):
                target = g.strip()
                break
        target = target or self.orch._state.get("target_package")
        if not target:
            print_err("Especifique o app. Ex: 'attach frida com.example.app'")
            return
        self._ensure_frida_attached(target)

    def _cmd_detach_frida(self, params):
        if self.orch.frida:
            self.orch.frida.detach()
            self.orch._state["frida_attached"] = False
            print_ok("Frida desconectado")
        else:
            print_warn("Frida não está disponível")

    def _cmd_inject_script(self, params):
        groups = params.get("groups", ())
        script_name = groups[-1].strip() if groups else ""
        if not script_name:
            print_warn("Especifique o script. Ex: 'inject script ssl'")
            print_info(
                "Disponíveis: ssl, root, emulator, frida, network, crypto, universal, game"
            )
            return
        result = self.orch.inject_script(script_name)
        if result.get("success"):
            print_ok(f"Script '{script_name}' injetado")
        else:
            print_err(f"Falha: {result.get('error')}")

    def _cmd_enum_classes(self, params):
        groups = params.get("groups", ())
        filter_str = groups[-1].strip() if groups and groups[-1] else ""
        try:
            result = self.orch.enum_classes(filter_str)
            classes = result.get("classes", [])
            print_ok(f"{len(classes)} classes encontradas")
            for cls in classes[:30]:
                print(f"    {cls}")
            if len(classes) > 30:
                print(c(f"    ... e mais {len(classes) - 30}", Colors.DIM))
        except Exception as e:
            print_err(str(e))

    def _cmd_hook(self, params):
        groups = params.get("groups", ())
        raw = params.get("raw", "")
        # Extract class and optional method from "hook Class.method" or "hook Class method"
        parts = raw.split()
        if len(parts) < 2:
            print_warn("Ex: 'hook com.example.MyClass.myMethod'")
            return

        target = parts[-1]
        if "." in target:
            # Could be class.method
            last_dot = target.rfind(".")
            class_name = target[:last_dot]
            method_name = target[last_dot + 1 :]
            # If the "method" starts with uppercase, it's probably part of the class
            if method_name and method_name[0].isupper():
                class_name = target
                method_name = None
        else:
            class_name = target
            method_name = None

        result = self.orch.hook(class_name, method_name)
        if result.get("success"):
            if method_name:
                print_ok(f"Hook em {class_name}.{method_name}")
            else:
                print_ok(f"Hook em toda a classe {class_name}")
        else:
            print_err(f"Falha: {result.get('error')}")

    # ── Analysis ──

    def _cmd_analyze(self, params):
        print_info("Analisando dados interceptados...")
        try:
            report = self.orch.analyze()
            print_report(report)
        except Exception as e:
            print_err(f"Erro na análise: {e}")

    def _cmd_collect(self, params):
        print_info("Coletando mensagens...")
        result = self.orch.collect_data()
        total = result.get("total_messages", 0)
        if total > 0:
            print_ok(f"{total} mensagens coletadas:")
            for cat, count in result.get("breakdown", {}).items():
                if count > 0:
                    print(f"    {cat}: {count}")
        else:
            print_warn("Nenhuma mensagem nova")

    def _cmd_wait(self, params):
        groups = params.get("groups", ())
        seconds = 10
        for g in groups:
            if g and g.isdigit():
                seconds = int(g)
                break

        print_info(f"Aguardando {seconds}s coletando dados...")
        for i in range(seconds):
            time.sleep(1)
            sys.stdout.write(f"\r  ⏳ {i+1}/{seconds}s")
            sys.stdout.flush()
        print()

        result = self.orch.collect_data()
        total = result.get("total_messages", 0)
        print_ok(f"{total} mensagens coletadas")

    def _cmd_save_report(self, params):
        try:
            path = self.orch.save_report()
            print_ok(f"Relatório salvo: {path}")
        except Exception as e:
            print_err(f"Erro ao salvar: {e}")

    # ── Screen / Logs ──

    def _cmd_screenshot(self, params):
        try:
            result = self.orch.screenshot()
            if result.get("success"):
                print_ok(f"Screenshot salvo")
            else:
                print_err(f"Falha: {result.get('error')}")
        except Exception as e:
            print_err(str(e))

    def _cmd_logcat(self, params):
        try:
            output = self.orch.logcat(lines=50)
            if output:
                print(c("  ─── Logcat ───", Colors.YELLOW))
                for line in output.split("\n")[:50]:
                    print(f"    {line}")
            else:
                print_warn("Logcat vazio")
        except Exception as e:
            print_err(str(e))

    # ── Status / Control ──

    def _cmd_status(self, params):
        state = self.orch.get_state()
        print(c("\n  ─── Status ───", Colors.CYAN))
        status_items = [
            (
                "Emulador",
                state.get("emulator_running"),
                state.get("instance_name", "-"),
            ),
            ("ADB", state.get("adb_connected"), "-"),
            (
                "Frida",
                state.get("frida_attached"),
                f"PID {state.get('target_pid', '-')}",
            ),
            ("Bypasses", state.get("bypasses_applied"), "-"),
            ("Interceptando", state.get("intercepting"), "-"),
        ]
        for label, active, detail in status_items:
            icon = c("●", Colors.GREEN) if active else c("○", Colors.RED)
            print(f"    {icon} {label:18s} {c(str(detail), Colors.DIM)}")

        pkg = state.get("target_package")
        if pkg:
            print(c(f"\n    Target: {pkg}", Colors.WHITE))

        data_counts = state.get("intercepted_data_counts", {})
        if any(v > 0 for v in data_counts.values()):
            print(c("\n    Dados coletados:", Colors.DIM))
            for k, v in data_counts.items():
                if v > 0:
                    print(f"      {k}: {v}")

    def _cmd_stop_all(self, params):
        print_info("Parando tudo...")
        result = self.orch.stop_all(close_emulator=False)
        if result.get("frida_detached"):
            print_ok("Frida desconectado")
        if result.get("app_stopped"):
            print_ok("App parado")
        print_ok(
            "Tudo parado. Use 'pare tudo' com emulador aberto para fechar o emu também."
        )

    def _cmd_reset(self, params):
        self.orch.reset()
        print_ok("Estado resetado")

    # ─────────────────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────────────────

    def _ensure_frida_attached(self, package: str):
        """Make sure Frida is attached to the package."""
        # Start server if needed
        print_step(1, 3, "Verificando Frida server...")
        srv = self.orch.start_frida_server()
        if srv.get("success"):
            print_ok("Frida server OK")
        else:
            print_err(f"Frida server: {srv.get('error')}")
            return

        print_step(2, 3, f"Conectando ao {package}...")
        result = self.orch.attach_frida(package)
        if result.get("success"):
            print_ok(f"Frida conectado (PID: {result.get('pid', '?')})")
        else:
            print_err(f"Falha: {result.get('error')}")

    def _cleanup(self):
        """Cleanup on exit."""
        print_info("Saindo do Leviathan CLI...")
        try:
            self.orch.stop_all(close_emulator=False)
        except Exception:
            pass
        print(c("\n  Até a próxima! 🔱\n", Colors.CYAN))


# ═══════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════


def main():
    parser = argparse.ArgumentParser(
        description="LEVIATHAN VS - Interactive Command Center"
    )
    parser.add_argument("--config", help="Path to config_ldplayer.json")
    parser.add_argument(
        "--auto",
        metavar="PACKAGE",
        help="Auto-run full intercept pipeline on a package",
    )
    parser.add_argument(
        "--quick",
        metavar="PACKAGE",
        help="Quick attach to a running app",
    )
    args = parser.parse_args()

    if args.auto:
        # Non-interactive: full pipeline
        from core.ldplayer.orchestrator import Orchestrator

        Colors.enabled()
        banner()
        print_info(f"Auto mode: full intercept on {args.auto}")
        orch = Orchestrator(config_path=args.config)
        result = orch.full_intercept(args.auto, wait_time=10, auto_analyze=True)
        if result.get("success") and result.get("analysis"):
            print_report(result["analysis"])
            path = orch.save_report()
            print_ok(f"Report saved: {path}")
        else:
            print_err(f"Failed: {result.get('error')}")
        return

    if args.quick:
        from core.ldplayer.orchestrator import Orchestrator

        Colors.enabled()
        banner()
        print_info(f"Quick mode: attaching to {args.quick}")
        orch = Orchestrator(config_path=args.config)
        result = orch.quick_attach(args.quick)
        if result.get("success"):
            print_ok("Attached! Entering interactive mode...")
            cli = LeviathanCLI.__new__(LeviathanCLI)
            cli.orch = orch
            cli.parser = CommandParser()
            cli.running = True
            cli.run()
        else:
            print_err(f"Failed: {result.get('error')}")
        return

    # Interactive mode
    cli = LeviathanCLI(config_path=args.config)
    cli.run()


if __name__ == "__main__":
    main()
